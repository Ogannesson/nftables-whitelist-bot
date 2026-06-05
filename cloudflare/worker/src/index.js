/**
 * Cloudflare Worker — tg-whitelist IP registration gateway
 *
 * Routes:
 *   GET  /           — Cloudflare Access protected; verifies Cf-Access-Jwt-Assertion,
 *                      returns HTML page with embedded JS that detects client's IPv4
 *                      via my.ip.cn (primary) / api4.ipify.org (fallback); no KV write here
 *   POST /register   — Cloudflare Access protected; receives client-reported IPv4,
 *                      validates it, writes to WHITELIST_KV under pending:<uuid>
 *   POST /pull       — Service-Token protected; returns all pending entries as JSON
 *   POST /ack        — Service-Token protected; deletes pending entries by id list
 *
 * KV key scheme:
 *   pending:<uuid>   TTL 86400s — awaiting server pull
 *   audit:<uuid>     no TTL     — permanent audit trail (includes cfIp for comparison)
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
        return handleIndex(request, env);
      }

      if (request.method === 'POST' && path === '/register') {
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
// Shared JWT verification helper
// ---------------------------------------------------------------------------

/**
 * Verify the Cloudflare Access JWT from the request headers.
 * Returns the decoded payload on success; throws on failure.
 *
 * @param {Request} request
 * @param {object} env
 * @returns {Promise<object>} JWT payload
 */
async function verifyAccessJwt(request, env) {
  const token = request.headers.get('Cf-Access-Jwt-Assertion');
  if (!token) {
    throw Object.assign(new Error('missing Access JWT'), { statusCode: 403 });
  }

  const teamDomain = env.TEAM_DOMAIN.replace(/\/$/, ''); // strip trailing slash
  const JWKS = createRemoteJWKSet(
    new URL(`${teamDomain}/cdn-cgi/access/certs`)
  );

  const result = await jwtVerify(token, JWKS, {
    issuer: teamDomain,
    audience: env.POLICY_AUD,
  });
  return result.payload;
}

// ---------------------------------------------------------------------------
// GET / — Access-protected; returns HTML detection page (no KV write)
// ---------------------------------------------------------------------------
async function handleIndex(request, env) {
  // Verify Access JWT — defence in depth (fail 403 if missing/invalid)
  let payload;
  try {
    payload = await verifyAccessJwt(request, env);
  } catch (err) {
    console.error('JWT verification failed:', err.message);
    const msg = err.message === 'missing Access JWT'
      ? 'Access denied: missing Access JWT.'
      : 'Access denied: invalid or expired Access token.';
    return htmlResponse(403, msg);
  }

  // Collect diagnostic info to embed in page (server-side, not client-reported)
  const cfIp = request.headers.get('CF-Connecting-IP') ?? 'unknown';
  const country = request.headers.get('CF-IPCountry') ?? 'unknown';
  // email is NOT sent to frontend — Worker re-reads it from JWT at POST /register

  const cfIpEscaped = escapeHtml(cfIp);
  const countryEscaped = escapeHtml(country);

  return new Response(
    `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>IP 白名单注册</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 520px; margin: 60px auto; padding: 0 1rem; color: #222; }
    .card { background: #f8f9fa; border-radius: 8px; padding: 2rem; border: 1px solid #dee2e6; }
    h1 { font-size: 1.4rem; margin-top: 0; color: #0d6efd; }
    .row { margin: 0.6rem 0; }
    .label { color: #555; font-size: 0.85em; }
    code { background: #e9ecef; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; font-family: monospace; }
    button { display: inline-block; margin-top: 1.2rem; padding: 0.55rem 1.4rem; background: #0d6efd; color: #fff;
             border: none; border-radius: 6px; font-size: 1rem; cursor: pointer; }
    button:disabled { background: #6c757d; cursor: not-allowed; }
    #status { margin-top: 1rem; font-size: 0.92em; }
    .ok { color: #198754; }
    .err { color: #dc3545; }
    .warn { color: #856404; }
  </style>
</head>
<body>
  <div class="card">
    <h1>IP 白名单注册</h1>

    <div class="row">
      <span class="label">Cloudflare 看到你（可能为 IPv6）：</span><br/>
      <code id="cfIp"></code>
      <span id="cfCountry" style="font-size:0.85em;color:#555;"></span>
    </div>

    <div class="row">
      <span class="label">你的 IPv4 出口（探测中…）：</span><br/>
      <code id="v4display">检测中...</code>
    </div>

    <div id="status"></div>
    <button id="submitBtn" disabled>确认加入白名单</button>
  </div>

  <script>
    // -----------------------------------------------------------------------
    // Server-injected values (HTML-escaped server-side, read-only)
    // -----------------------------------------------------------------------
    document.getElementById('cfIp').textContent = ${JSON.stringify(cfIpEscaped)};
    document.getElementById('cfCountry').textContent =
      ' (' + ${JSON.stringify(countryEscaped)} + ')';

    // -----------------------------------------------------------------------
    // Detect client's true IPv4 via my.ip.cn (CN) with v4-only fallbacks
    // -----------------------------------------------------------------------
    let detectedV4 = null;

    // Accept only a syntactically valid IPv4 string; reject IPv6 / junk so a
    // dual-stack source returning a v6 address is skipped rather than misused.
    function asV4(s) {
      const ip = String(s == null ? '' : s).trim();
      return /^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$/.test(ip) ? ip : null;
    }

    async function detectV4() {
      // Try sources in order; first one yielding a valid IPv4 wins.
      // Primary: my.ip.cn — domestic (CN), reachable without a proxy; returns
      //   plain text like "ip：1.2.3.4 归属地：…" — extract the dotted-quad.
      // Fallbacks: api4.ipify.org / ipv4.icanhazip.com — v4-only resolvers abroad.
      const sources = [
        async () => {
          const t = await (await fetch('https://my.ip.cn/')).text();
          const m = t.match(/(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})/);
          return m ? m[1] : null;
        },
        async () => {
          const d = await (await fetch('https://api4.ipify.org?format=json')).json();
          return d && d.ip;
        },
        async () => await (await fetch('https://ipv4.icanhazip.com')).text(),
      ];

      for (const get of sources) {
        try {
          const v4 = asV4(await get());
          if (v4) return v4;
        } catch (_) { /* try next source */ }
      }
      return null;
    }

    async function init() {
      const v4 = await detectV4();
      detectedV4 = v4;

      const v4el = document.getElementById('v4display');
      const statusEl = document.getElementById('status');
      const btn = document.getElementById('submitBtn');

      if (v4 === null) {
        // No IPv4 route detected — pure IPv6 network
        v4el.textContent = '未检测到';
        statusEl.className = 'warn';
        statusEl.textContent =
          '未检测到 IPv4 出口。本白名单仅支持 IPv4，请确保你的网络有 IPv4 连接后再试。';
        btn.style.display = 'none';
        return;
      }

      // Display detected v4 safely (textContent, not innerHTML)
      v4el.textContent = v4;
      btn.disabled = false;
    }

    init();

    // -----------------------------------------------------------------------
    // Submit detected IPv4 to POST /register
    // -----------------------------------------------------------------------
    document.getElementById('submitBtn').addEventListener('click', async () => {
      const btn = document.getElementById('submitBtn');
      const statusEl = document.getElementById('status');

      if (!detectedV4) return;

      btn.disabled = true;
      statusEl.className = '';
      statusEl.textContent = '提交中…';

      try {
        const res = await fetch('/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: detectedV4 }),
        });

        if (res.ok) {
          const data = await res.json();
          statusEl.className = 'ok';
          // Use textContent for all external data — XSS prevention
          const idEl = document.createElement('code');
          idEl.textContent = data.id ?? '';
          const ipEl = document.createElement('code');
          ipEl.textContent = data.ip ?? detectedV4;
          statusEl.textContent = '';
          statusEl.append(
            '已提交成功。IP: ', ipEl,
            '  Registration ID: ', idEl,
            '  白名单将在下一个 pull 周期内（通常数分钟内）生效。'
          );
        } else {
          const text = await res.text();
          statusEl.className = 'err';
          // Display server error message safely
          statusEl.textContent = '提交失败：' + res.status + ' ' + text;
        }
      } catch (e) {
        statusEl.className = 'err';
        statusEl.textContent = '网络错误，请稍后重试：' + e.message;
      }
    });
  </script>
</body>
</html>`,
    {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=UTF-8' },
    }
  );
}

// ---------------------------------------------------------------------------
// POST /register — Access-protected; validates client-reported IPv4, writes KV
// ---------------------------------------------------------------------------
async function handleRegister(request, env) {
  // --- 1. Verify Cloudflare Access JWT (mandatory — prevent IP forging bypass) ---
  let payload;
  try {
    payload = await verifyAccessJwt(request, env);
  } catch (err) {
    console.error('JWT verification failed:', err.message);
    const msg = err.message === 'missing Access JWT'
      ? 'Access denied: missing Access JWT.'
      : 'Access denied: invalid or expired Access token.';
    return htmlResponse(403, msg);
  }

  // --- 2. Parse request body ---
  let body;
  try {
    body = await request.json();
  } catch {
    return new Response('Bad Request: invalid JSON', { status: 400 });
  }

  const clientIp = body?.ip;

  // --- 3. Validate client-reported IPv4 ---
  if (typeof clientIp !== 'string' || !isPublicIPv4(clientIp)) {
    return new Response('Bad Request: invalid or non-public IPv4', { status: 400 });
  }

  // --- 4. Collect metadata ---
  const email = payload.email ?? payload.sub ?? 'unknown';
  const cfIp = request.headers.get('CF-Connecting-IP') ?? 'unknown'; // audit only
  const country = request.headers.get('CF-IPCountry') ?? 'unknown';
  const id = crypto.randomUUID();
  const registeredAt = new Date().toISOString();

  // --- 5. Write to KV (fail-closed — any KV error propagates as 500) ---
  const record = JSON.stringify({
    ip: clientIp,
    email,
    registeredAt,
    cfIp,
    country,
    source: 'client-reported',
  });

  await env.WHITELIST_KV.put(`pending:${id}`, record, {
    expirationTtl: 86400,
  });
  await env.WHITELIST_KV.put(`audit:${id}`, record);

  // --- 6. Return JSON confirmation ---
  return Response.json({ ok: true, id, ip: clientIp });
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
 * Validate that `ip` is a syntactically correct, publicly routable IPv4 address.
 *
 * Rejects:
 *   - Non-string / non-matching format
 *   - Any octet outside 0–255
 *   - Private: 10/8, 172.16/12, 192.168/16
 *   - Loopback: 127/8
 *   - Link-local: 169.254/16
 *   - CGNAT: 100.64/10
 *   - Reserved: 0/8, 240/4, 255.255.255.255
 *   - Multicast: 224/4
 *
 * Exported for unit testing.
 *
 * @param {string} ip
 * @returns {boolean}
 */
export function isPublicIPv4(ip) {
  if (typeof ip !== 'string') return false;

  const m = ip.match(/^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})$/);
  if (!m) return false;

  const [, a, b, c, d] = m.map(Number);

  // Each octet must be 0–255
  if (a > 255 || b > 255 || c > 255 || d > 255) return false;

  // 0/8 — "this" network
  if (a === 0) return false;

  // 10/8 — private
  if (a === 10) return false;

  // 100.64/10 — CGNAT (100.64.0.0 – 100.127.255.255)
  if (a === 100 && b >= 64 && b <= 127) return false;

  // 127/8 — loopback
  if (a === 127) return false;

  // 169.254/16 — link-local
  if (a === 169 && b === 254) return false;

  // 172.16/12 — private (172.16.0.0 – 172.31.255.255)
  if (a === 172 && b >= 16 && b <= 31) return false;

  // 192.168/16 — private
  if (a === 192 && b === 168) return false;

  // 224/4 — multicast (224.0.0.0 – 239.255.255.255)
  if (a >= 224 && a <= 239) return false;

  // 240/4 — reserved (240.0.0.0 – 255.255.255.254)
  if (a >= 240) return false;

  // 255.255.255.255 — limited broadcast (covered by a>=240 above, explicit for clarity)
  if (a === 255 && b === 255 && c === 255 && d === 255) return false;

  return true;
}

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
