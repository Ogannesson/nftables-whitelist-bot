/**
 * Cloudflare Worker — tg-whitelist IP registration gateway
 *
 * Routes:
 *   GET  /        — Cloudflare Access protected; verifies Cf-Access-Jwt-Assertion,
 *                   records CF-Connecting-IP into WHITELIST_KV under pending:<uuid>
 *   POST /pull    — Service-Token protected; returns all pending entries as JSON
 *   POST /ack     — Service-Token protected; deletes pending entries by id list
 *
 * KV key scheme:
 *   pending:<uuid>   TTL 86400s — awaiting server pull
 *   audit:<uuid>     no TTL     — permanent audit trail
 *
 * Required env bindings:
 *   WHITELIST_KV          KV namespace binding
 *   TEAM_DOMAIN           e.g. "https://yourteam.cloudflareaccess.com"
 *   POLICY_AUD            Access Application AUD (from Zero Trust → Access → App)
 *   PULL_CLIENT_ID        Service Token Client ID  (for /pull and /ack)
 *   PULL_CLIENT_SECRET    Service Token Client Secret
 */

import { createRemoteJWKSet, jwtVerify } from 'jose';

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const path = url.pathname;

      if (request.method === 'GET' && path === '/') {
        return handleRegister(request, env);
      }

      if (request.method === 'POST' && path === '/pull') {
        return handlePull(request, env);
      }

      if (request.method === 'POST' && path === '/ack') {
        return handleAck(request, env);
      }

      return new Response('Not Found', { status: 404 });
    } catch (err) {
      // fail-closed: never silently swallow errors
      console.error('Unhandled error:', err);
      return new Response('Internal Server Error', { status: 500 });
    }
  },
};

// ---------------------------------------------------------------------------
// GET / — Access-protected IP registration
// ---------------------------------------------------------------------------
async function handleRegister(request, env) {
  // --- 1. Verify Cloudflare Access JWT (defence in depth) ---
  const token = request.headers.get('Cf-Access-Jwt-Assertion');
  if (!token) {
    return htmlResponse(403, 'Access denied: missing Access JWT.');
  }

  let payload;
  try {
    const teamDomain = env.TEAM_DOMAIN.replace(/\/$/, ''); // strip trailing slash
    const JWKS = createRemoteJWKSet(
      new URL(`${teamDomain}/cdn-cgi/access/certs`)
    );

    const result = await jwtVerify(token, JWKS, {
      issuer: teamDomain,
      audience: env.POLICY_AUD,
    });
    payload = result.payload;
  } catch (err) {
    console.error('JWT verification failed:', err.message);
    return htmlResponse(403, 'Access denied: invalid or expired Access token.');
  }

  // --- 2. Collect registration data ---
  const ip = request.headers.get('CF-Connecting-IP') ?? 'unknown';
  const email = payload.email ?? payload.sub ?? 'unknown';
  const country = request.headers.get('CF-IPCountry') ?? 'unknown';
  const id = crypto.randomUUID();
  const registeredAt = new Date().toISOString();

  const record = JSON.stringify({ ip, email, registeredAt, country });

  // --- 3. Write to KV (fail-closed — any KV error propagates as 500) ---
  await env.WHITELIST_KV.put(`pending:${id}`, record, {
    expirationTtl: 86400,
  });
  await env.WHITELIST_KV.put(`audit:${id}`, record);

  // --- 4. Return friendly HTML ---
  return new Response(
    `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>IP Registered</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 480px; margin: 80px auto; padding: 0 1rem; color: #222; }
    .card { background: #f8f9fa; border-radius: 8px; padding: 2rem; border: 1px solid #dee2e6; }
    h1 { color: #198754; font-size: 1.4rem; margin-top: 0; }
    code { background: #e9ecef; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }
  </style>
</head>
<body>
  <div class="card">
    <h1>IP submitted successfully</h1>
    <p>Your IP address <code>${escapeHtml(ip)}</code> has been registered.</p>
    <p>It will be added to the allowlist within the next pull cycle (typically within a few minutes).</p>
    <p style="color:#666;font-size:0.85em;">Registration ID: <code>${escapeHtml(id)}</code></p>
  </div>
</body>
</html>`,
    {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=UTF-8' },
    }
  );
}

// ---------------------------------------------------------------------------
// POST /pull — server pulls pending IPs
// ---------------------------------------------------------------------------
async function handlePull(request, env) {
  if (!verifyServiceToken(request, env)) {
    return new Response('Unauthorized', { status: 401 });
  }

  // List all pending entries (paginate with cursor until list_complete)
  const allKeys = [];
  let cursor = undefined;
  while (true) {
    const listed = await env.WHITELIST_KV.list({ prefix: 'pending:', cursor });
    allKeys.push(...listed.keys);
    if (listed.list_complete) break;
    cursor = listed.cursor;
  }

  const ips = [];
  for (const key of allKeys) {
    const raw = await env.WHITELIST_KV.get(key.name);
    if (raw === null) continue; // expired between list and get — skip

    let record;
    try {
      record = JSON.parse(raw);
    } catch {
      console.error('Corrupt KV record for', key.name);
      continue;
    }

    // id = key without the "pending:" prefix
    const id = key.name.slice('pending:'.length);
    ips.push({ id, ip: record.ip, email: record.email });
  }

  return Response.json({ ips });
}

// ---------------------------------------------------------------------------
// POST /ack — server acknowledges processed IPs; Worker deletes pending keys
// ---------------------------------------------------------------------------
async function handleAck(request, env) {
  if (!verifyServiceToken(request, env)) {
    return new Response('Unauthorized', { status: 401 });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return new Response('Bad Request: invalid JSON', { status: 400 });
  }

  const ids = body?.ids;
  if (!Array.isArray(ids)) {
    return new Response('Bad Request: "ids" must be an array', { status: 400 });
  }

  // Filter out any empty/non-string ids before deleting
  const validIds = ids.filter((id) => typeof id === 'string' && id.trim() !== '');

  // Delete each pending key — fire-and-forget is acceptable here but we
  // await all for proper error propagation
  await Promise.all(
    validIds.map((id) => env.WHITELIST_KV.delete(`pending:${id}`))
  );

  return Response.json({ ok: true, deleted: validIds.length });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Strict Service Token verification.
 * Both Client-Id and Client-Secret must match exactly (===).
 * Returns false (and logs) on any mismatch — fail-closed.
 */
function verifyServiceToken(request, env) {
  const clientId = request.headers.get('CF-Access-Client-Id');
  const clientSecret = request.headers.get('CF-Access-Client-Secret');

  if (
    clientId === null ||
    clientSecret === null ||
    clientId !== env.PULL_CLIENT_ID ||
    clientSecret !== env.PULL_CLIENT_SECRET
  ) {
    console.warn('Service token mismatch — rejected.');
    return false;
  }
  return true;
}

function htmlResponse(status, message) {
  return new Response(
    `<!DOCTYPE html><html><body><p>${escapeHtml(message)}</p></body></html>`,
    { status, headers: { 'Content-Type': 'text/html; charset=UTF-8' } }
  );
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}
