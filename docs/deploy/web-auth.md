# 部署指南：Cloudflare Worker + Zero Trust Access 白名单注册网关

本文档介绍从零开始部署整套 Web 注册入口的完整步骤：用户通过 Cloudflare Access 认证后访问 Worker，Worker 把真实 IP 写入 KV，服务器 bot 周期性 pull/ack 同步到 nftables 白名单。

**关键点**：服务器只需要**出站** HTTPS（可走现有 SOCKS5 代理），不需要公网入站端口，不需要 cloudflared 隧道。

---

## 前置要求

- Cloudflare 账号（免费套餐即可）
- 已开启 **Zero Trust**（免费套餐包含 50 用户）
- 本地安装 Node.js 18+ 和 Wrangler CLI
- 若要绑定自定义域，需要域名已托管到 Cloudflare DNS

---

## 第 1 步：安装依赖

```bash
cd cloudflare/worker
npm install
```

---

## 第 2 步：创建 Workers KV 命名空间

```bash
npx wrangler kv namespace create WHITELIST_KV
```

输出示例：
```
⛅️ wrangler 3.x.x
Added kv_namespaces to wrangler.toml

[[kv_namespaces]]
binding = "WHITELIST_KV"
id = "abcdef1234567890abcdef1234567890"
```

将输出的 `id` 填入 `wrangler.toml`：

```toml
[[kv_namespaces]]
binding = "WHITELIST_KV"
id      = "abcdef1234567890abcdef1234567890"   # ← 替换为实际 id
```

如果要使用 `wrangler dev` 本地开发，还可选择创建预览命名空间：
```bash
npx wrangler kv namespace create WHITELIST_KV --preview
# 将输出的 preview_id 填入 wrangler.toml 的 preview_id 字段
```

---

## 第 3 步：配置自定义域路由（可选，推荐）

如需绑定自定义域（如 `whitelist.example.com`），在 `wrangler.toml` 中取消注释并修改：

```toml
[[routes]]
pattern   = "whitelist.example.com/*"
zone_name = "example.com"
```

如果只用 `*.workers.dev` 子域名测试，在 `wrangler.toml` 保留 `workers_dev = true`（默认即为 true，无需显式设置）即可跳过此步骤。

---

## 第 4 步：在 Cloudflare Zero Trust 创建 Access 应用

> **目的**：保护 `GET /`，要求用户通过邮箱 OTP 等方式认证，防止未授权注册。认证后 Cloudflare 在请求头注入 `Cf-Access-Jwt-Assertion`，Worker 纵深校验此 JWT。

1. 打开 [Cloudflare Zero Trust Dashboard](https://one.dash.cloudflare.com/) → **Access** → **Applications** → **Add an application**
2. 选择 **Self-hosted**
3. 配置：
   - **Application name**：`tg-whitelist-gateway`（随意）
   - **Application domain**：填写 Worker 的访问地址，例如 `whitelist.example.com` 或 `tg-whitelist-gateway.yourname.workers.dev`
   - **Path**：留空（保护整个域名）或填 `/`
4. 在 **Policies** 页面添加一条规则，例如：
   - Policy name：`Allow authenticated users`
   - Action：**Allow**
   - Include → Emails → 填写允许注册的邮箱列表（或用 Everyone、Email domain 等）
5. 完成创建后，进入应用详情，找到 **Overview** 标签页，复制 **Application Audience (AUD) tag**（一串 hex 字符串）。

**记下 AUD**，下一步要作为 `POLICY_AUD` 注入 Worker。

---

## 第 5 步：创建 Service Token（供 bot 访问 /pull 和 /ack）

> **目的**：bot 服务器访问 `/pull` 和 `/ack` 时不经过浏览器认证流程，使用 Service Token（Client Id + Secret）通过 Worker 内的严格比对鉴权。

1. Zero Trust Dashboard → **Access** → **Service Auth** → **Service Tokens** → **Create Service Token**
2. 名称：`tg-whitelist-bot`（随意）
3. Token Duration：建议 `1 year` 或 `Non-expiring`
4. 点击 **Generate token** — **立即复制** Client ID 和 Client Secret（Secret 只显示一次）

得到两个值：
- `CF_ACCESS_CLIENT_ID`（形如 `xxxxxxxxxxxx.access`）
- `CF_ACCESS_CLIENT_SECRET`（一串长字符串）

> 注意：这个 Service Token **不需要**绑定到 Access 应用——Worker 自己做比对，不走 Cloudflare Access 策略。

---

## 第 6 步：上传 Worker Secrets

以下四个值均为敏感信息，**不要写入 `wrangler.toml`**，用 `wrangler secret put` 上传：

```bash
# Cloudflare Access 团队域名，形如 https://yourteam.cloudflareaccess.com
npx wrangler secret put TEAM_DOMAIN
# 提示输入时粘贴：https://yourteam.cloudflareaccess.com

# 第 4 步记下的 AUD tag
npx wrangler secret put POLICY_AUD
# 提示输入时粘贴 AUD 字符串

# 第 5 步创建的 Service Token Client ID
npx wrangler secret put PULL_CLIENT_ID
# 提示输入时粘贴

# 第 5 步创建的 Service Token Client Secret
npx wrangler secret put PULL_CLIENT_SECRET
# 提示输入时粘贴
```

确认上传：
```bash
npx wrangler secret list
# 应显示 TEAM_DOMAIN、POLICY_AUD、PULL_CLIENT_ID、PULL_CLIENT_SECRET
```

---

## 第 7 步：部署 Worker

```bash
npx wrangler deploy
```

成功输出示例：
```
✨ Successfully published your Worker to:
   https://tg-whitelist-gateway.yourname.workers.dev

Or with custom domain:
   https://whitelist.example.com
```

记下 Worker 的访问 URL（`worker_url`），后面要填入 bot 配置。

---

## 第 8 步：验证部署

### 验证 Access 保护

直接在浏览器访问 `https://whitelist.example.com/`，应跳转到 Cloudflare Access 登录页。用允许的邮箱登录后，应看到「IP 已提交，稍后生效」的 HTML 页面。

### 验证 /pull 鉴权

```bash
# 无 token — 应返回 401
curl -X POST https://whitelist.example.com/pull

# 正确 token — 应返回 {"ips": [...]}
curl -X POST https://whitelist.example.com/pull \
  -H "CF-Access-Client-Id: YOUR_CLIENT_ID" \
  -H "CF-Access-Client-Secret: YOUR_CLIENT_SECRET"
```

---

## 第 9 步：配置 bot

在服务器的 `config.toml` 中填写 `[cf_pull]` 块：

```toml
[cf_pull]
enabled              = true
worker_url           = "https://whitelist.example.com"   # Worker 访问地址（无尾部 /）
access_client_id     = "xxxxxxxxxxxx.access"             # Service Token Client ID
access_client_secret = "your-service-token-client-secret"
```

bot 将定期 POST `/pull`（通过现有 SOCKS5 代理出站），获取 pending IP 列表，处理后 POST `/ack` 删除已处理条目。

---

## 架构说明

```
用户浏览器
    │  HTTPS GET /
    ▼
Cloudflare Access（邮箱 OTP 或其他策略）
    │  认证通过，注入 Cf-Access-Jwt-Assertion
    ▼
Cloudflare Worker（tg-whitelist-gateway）
    │  jose 验证 JWT（issuer + audience）
    │  取 CF-Connecting-IP（真实 IP，不可伪造）
    │  写 KV: pending:<uuid> (TTL 86400s) + audit:<uuid>
    ▼
Workers KV（持久存储）
    ▲
    │  POST /pull  CF-Access-Client-Id/Secret 校验
服务器 bot（走出站代理）
    │  写入 nftables 白名单
    │  POST /ack   删除已处理 pending 条目
```

**安全要点**：
- 服务器侧只出站访问 Worker，无需公网入站端口，无需 cloudflared 隧道
- CF-Connecting-IP 由 Cloudflare 边缘网络填充，无法被客户端伪造
- Service Token 在 Worker 内 `===` 严格比对，不经过 Access 策略（Access 应用只保护 GET /）
- JWT 验证为纵深防御：即使 Access 流量被绕过，无有效 JWT 也无法注册 IP

---

## 故障排查

| 现象 | 可能原因 | 处理 |
|------|----------|------|
| `GET /` 返回 403 "missing Access JWT" | 直接访问 Worker IP 而非域名，绕过了 Access | 确保通过 Access 绑定的域名访问 |
| `GET /` 返回 403 "invalid or expired Access token" | AUD 填写有误，或 TEAM_DOMAIN 末尾有多余 `/` | 检查 `POLICY_AUD` 和 `TEAM_DOMAIN` secret |
| `/pull` 返回 401 | Service Token 头不匹配 | 检查 `PULL_CLIENT_ID` / `PULL_CLIENT_SECRET` |
| KV 写入失败（500） | KV namespace id 填写有误 | 检查 `wrangler.toml` 中的 `id` 字段 |
| bot 无法访问 Worker | 出站代理配置问题 | 确认 bot 的 SOCKS5 代理可访问 Cloudflare |
