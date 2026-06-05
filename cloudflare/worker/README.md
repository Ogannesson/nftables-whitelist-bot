# tg-whitelist Cloudflare Worker

IP registration gateway. Users visit the protected URL through Cloudflare Access; the Worker returns an HTML page whose JavaScript detects the client's **real IPv4 egress** via a public IP API (`my.ip.cn` primary; `api4.ipify.org` / `ipv4.icanhazip.com` fallback). After the user confirms, the IPv4 is submitted to `POST /register`, validated as a public IPv4, and written to Workers KV. The server-side bot periodically pulls and ACKs.

> Why client-side detection instead of `CF-Connecting-IP`? The nftables allowlist is IPv4-only, but most clients prefer IPv6, so Cloudflare's edge `CF-Connecting-IP` is often an IPv6 address (IPv6 can't be disabled on non-Enterprise plans). The trade-off: the IP becomes client-reported (forgeable) — security relies entirely on the Access policy being scoped to the owner's email only. See `docs/deploy/web-auth.md` → "安全模型".

## 一键部署

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Ogannesson/nftables-whitelist-bot/tree/main/cloudflare/worker)

点击按钮后，Cloudflare 会：
1. 将本 Worker 子目录 clone 成**你账号下一个独立的新仓库**并启用 Workers Builds（push 到该独立仓库自动部署）
2. 自动创建 KV namespace 并绑定（`WHITELIST_KV`）
3. 提示填写 4 个 secret：`TEAM_DOMAIN` / `POLICY_AUD` / `PULL_CLIENT_ID` / `PULL_CLIENT_SECRET`（格式参考 `.dev.vars.example`）

> ⚠️ **部署后改代码往哪推**：Workers Builds 监听的是上面那个**独立仓库**（默认分支通常是 `master`），不是这个主仓库。之后改 Worker 代码，要么推到独立仓库，要么在 Worker → **Settings → Build** 把 Git repository 改连主仓库、branch 设 `main`、**Root directory 设 `cloudflare/worker`**（推主仓库即部署；需确保主仓库 `wrangler.toml` 的 KV `id` 为真实值）。

部署完成后仍需手动配置：
- 在 Cloudflare Zero Trust 创建 Access 应用，保护 Worker 的 `GET /`
- 创建 Service Token，Client ID/Secret 即对应上述 `PULL_CLIENT_ID` / `PULL_CLIENT_SECRET`
- 将 Worker URL + Service Token 填入 bot 的 `config.toml [cf_pull]`（详见 `docs/deploy/web-auth.md`）

## Prerequisites

- Node.js 18+
- Wrangler CLI (`npm install -g wrangler` or use the local devDependency)
- A Cloudflare account with Workers and KV enabled
- Cloudflare Zero Trust (free tier works)

## Quick start (local dev)

```bash
cd cloudflare/worker
npm install
wrangler dev
```

`wrangler dev` runs the Worker locally at `http://localhost:8787`.  
For local testing of `/pull` and `/ack`, set `PULL_CLIENT_ID` and `PULL_CLIENT_SECRET` in a `.dev.vars` file (never commit this file):

```ini
# .dev.vars  — local only, gitignored
TEAM_DOMAIN=https://yourteam.cloudflareaccess.com
POLICY_AUD=your-access-policy-aud
PULL_CLIENT_ID=your-service-token-client-id
PULL_CLIENT_SECRET=your-service-token-client-secret
```

## Unit tests

```bash
npm test        # vitest — covers isPublicIPv4() boundary cases
```

## Local verification notes

- `GET /` and `POST /register` require a valid Cloudflare **Access JWT**
  (`Cf-Access-Jwt-Assertion`). Under plain `wrangler dev` there is no such
  header, so they return **403** — this is expected. End-to-end testing of the
  detection page must be done in a browser through the Access-protected domain.
- `POST /pull` and `POST /ack` only need the Service Token headers, so they can
  be tested locally with `.dev.vars` set:

  ```bash
  curl -X POST http://localhost:8787/pull \
    -H "CF-Access-Client-Id: $PULL_CLIENT_ID" \
    -H "CF-Access-Client-Secret: $PULL_CLIENT_SECRET"
  ```
- The IPv4 validation logic (`isPublicIPv4`) is covered by `npm test` and does
  not require a running Worker.

## Deploy

See `docs/deploy/web-auth.md` in the repository root for the complete step-by-step deployment guide, including:

- Creating the KV namespace and updating `wrangler.toml`
- Uploading secrets with `wrangler secret put`
- Deploying with `wrangler deploy`
- Configuring Cloudflare Access to protect `GET /`
- Creating a Service Token and wiring it into the bot config

## Routes summary

| Method | Path        | Auth                    | Action                                                  |
|--------|-------------|-------------------------|---------------------------------------------------------|
| GET    | /           | Cloudflare Access (JWT) | Return HTML page; JS detects client IPv4 (**no KV write**) |
| POST   | /register   | Cloudflare Access (JWT) | Validate client-reported IPv4, write `pending`+`audit` KV |
| POST   | /pull       | Service Token (header)  | Return all `pending:*` entries as `{id,ip,email}`       |
| POST   | /ack        | Service Token (header)  | Delete `pending:<id>` by id list                        |

## KV key scheme

| Key pattern       | TTL      | Purpose                         |
|-------------------|----------|---------------------------------|
| `pending:<uuid>`  | 86400s   | Awaiting server pull            |
| `audit:<uuid>`    | none     | Permanent audit trail (incl. `cfIp` + `email`) |
