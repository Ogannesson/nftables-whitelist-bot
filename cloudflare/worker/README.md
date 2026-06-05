# tg-whitelist Cloudflare Worker

IP registration gateway. Users visit the protected URL through Cloudflare Access; the Worker records their real IP into Workers KV. The server-side bot periodically pulls and ACKs.

## 一键部署

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Ogannesson/nftables-whitelist-bot/tree/main/cloudflare/worker)

点击按钮后，Cloudflare 会：
1. 将本 Worker 子目录 clone 到你的账号并启用 Workers Builds（后续 push 自动部署）
2. 自动创建 KV namespace 并绑定（`WHITELIST_KV`）
3. 提示填写 4 个 secret：`TEAM_DOMAIN` / `POLICY_AUD` / `PULL_CLIENT_ID` / `PULL_CLIENT_SECRET`（格式参考 `.dev.vars.example`）

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

## Deploy

See `docs/deploy/web-auth.md` in the repository root for the complete step-by-step deployment guide, including:

- Creating the KV namespace and updating `wrangler.toml`
- Uploading secrets with `wrangler secret put`
- Deploying with `wrangler deploy`
- Configuring Cloudflare Access to protect `GET /`
- Creating a Service Token and wiring it into the bot config

## Routes summary

| Method | Path    | Auth                           | Action                          |
|--------|---------|--------------------------------|---------------------------------|
| GET    | /       | Cloudflare Access (JWT)        | Register caller's IP into KV    |
| POST   | /pull   | Service Token (header)         | Return all `pending:*` entries  |
| POST   | /ack    | Service Token (header)         | Delete `pending:<id>` by id list|

## KV key scheme

| Key pattern       | TTL      | Purpose                         |
|-------------------|----------|---------------------------------|
| `pending:<uuid>`  | 86400s   | Awaiting server pull            |
| `audit:<uuid>`    | none     | Permanent audit trail           |
