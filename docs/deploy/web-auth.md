# 部署指南：Cloudflare Worker + Zero Trust Access 白名单注册网关

本文档介绍从零开始部署整套 Web 注册入口的完整步骤：用户通过 Cloudflare Access 认证后访问 Worker 返回的网页，**网页用 JavaScript 探测访问者真实的 IPv4 出口地址**，用户确认后提交给 Worker，Worker 校验为合法公网 IPv4 后写入 KV，服务器 bot 周期性 pull/ack 同步到 nftables 白名单。

> **为什么由网页探测 IPv4，而不直接用 Cloudflare 回传的访问 IP？** nftables 白名单是 IPv4 only，但多数终端默认 IPv6 优先，Cloudflare 边缘拿到的 `CF-Connecting-IP` 往往是 IPv6（非企业版无法关闭 IPv6），直接用会写入一个永远不会被加白的 v6 地址。改由浏览器 `fetch` 一个 v4-only 的公共 API（`api4.ipify.org`）拿到真实 IPv4 出口，绕开这个问题。代价是 IP 改为客户端自报、可伪造——详见文末「安全模型」。

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
4. 在 **Policies** 页面添加一条规则：
   - Policy name：`Allow owner only`
   - Action：**Allow**
   - Include → Emails → **只填写你自己的邮箱**

   > ⚠️ **安全关键**：本网关的 IP 由客户端网页自报（可被伪造），**Access policy 是唯一的安全兜底**。务必把 Include 限制为你本人的邮箱，**切勿使用 Everyone 或宽泛的 Email domain**——否则任何能通过 Access 的人都能把任意 IPv4 加进你的防火墙白名单。详见文末「安全模型」。
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

### 验证注册页面

直接在浏览器访问 `https://whitelist.example.com/`，应跳转到 Cloudflare Access 登录页。用允许的邮箱登录后，应看到注册页面：

- **Cloudflare 看到你（可能为 IPv6）**：显示边缘看到的 `CF-Connecting-IP`（仅供对比/审计，不会被加白）；
- **你的 IPv4 出口**：网页 JS 自动探测（`api4.ipify.org` → 兜底 `ipv4.icanhazip.com`）；
- 点 **确认加入白名单** → 提交到 `POST /register` → 显示「已提交成功 + Registration ID」。

> 若访问设备**没有 IPv4 出口**（纯 IPv6 网络），页面会提示「未检测到 IPv4 出口」并隐藏提交按钮——这是预期行为（白名单仅支持 v4）。
>
> `GET /` 与 `POST /register` 都受 Access 保护、需浏览器携带有效 JWT，**无法用纯 curl 验证**；端到端验证请在浏览器完成。

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
    │  ① HTTPS GET /
    ▼
Cloudflare Access（邮箱认证，只放行本人）
    │  认证通过，注入 Cf-Access-Jwt-Assertion
    ▼
Cloudflare Worker（GET /）
    │  jose 验证 JWT → 返回探测网页（此阶段不写 KV）
    │  网页内嵌 CF-Connecting-IP（仅对比展示，可能是 v6）
    ▼
用户浏览器内 JavaScript
    │  ② fetch api4.ipify.org（v4-only）→ 探测真实 IPv4 出口
    │     失败兜底 ipv4.icanhazip.com
    │  展示「CF 看到的 IP / 你的 v4 出口」，用户点「确认」
    ▼
Cloudflare Worker（POST /register）
    │  jose 验证 JWT（必须）+ isPublicIPv4 严格校验
    │  写 KV: pending:<uuid> (TTL 86400s) + audit:<uuid>
    │  record = { ip:自报v4, email, cfIp(仅审计), source:"client-reported" }
    ▼
Workers KV（持久存储）
    ▲
    │  ③ POST /pull  CF-Access-Client-Id/Secret 校验 → 返回 {id,ip,email}
服务器 bot（走出站代理）
    │  ipaddress 二次校验（拒非 v4/私有/保留）→ 写入 nftables 白名单
    │  ④ POST /ack   删除已处理 pending 条目
```

**安全要点**：
- 服务器侧只出站访问 Worker，无需公网入站端口，无需 cloudflared 隧道
- `POST /register` **强制验证 Access JWT**（纵深防御）：即使有人绕过页面直接构造请求，无有效 JWT 也无法注册
- `isPublicIPv4` 严格校验：拒绝私有(10/8、172.16/12、192.168/16)、回环(127/8)、链路本地(169.254/16)、CGNAT(100.64/10)、保留(0/8、240/4)、多播(224/4)及前导零等非法格式
- Service Token 在 Worker 内 `===` 严格比对（保护 `/pull`、`/ack`）
- 服务器侧 cf_pull 再用 Python `ipaddress` 校验一遍（拒非 v4/私有/保留），双重防线

---

## 安全模型（务必理解）

与早期方案（Worker 取边缘填充的 `CF-Connecting-IP`，不可伪造）不同，本方案的 IP 由**客户端网页自报**——技术上**可被伪造**（改 JS、或直接构造 `POST /register {"ip":"…"}` 请求）。因此安全边界变为：

1. **Cloudflare Access policy 是第一道也是最关键的防线**：`GET /` 与 `POST /register` 都受 Access 保护，只有通过 policy 的邮箱才能拿到有效 JWT。**务必把 policy 的 Include 限制为你本人的邮箱**（见第 4 步），**不要用 Everyone / 宽泛 domain**——否则任何能过 Access 的人都能把任意公网 IPv4 加进你的防火墙白名单。
2. **Worker 后端 `isPublicIPv4` 校验**：只接受合法公网 IPv4，拒绝私有/回环/保留/多播/CGNAT/非法格式。
3. **服务器侧 cf_pull 二次校验**：pull 回来的 IP 再用 `ipaddress` 校验一遍（拒非 v4/私有/保留），即使 Worker 被绕过也兜底。
4. **审计留痕**：每次注册同时写 `audit:<uuid>`（永久，含 `cfIp` 对比与 `email`），便于事后追溯是谁、从哪个边缘 IP 提交了哪个 v4。

对**个人自用、Access 只放本人邮箱**的场景，这个信任模型可接受（提交者就是你自己）；但**绝不要把 Access policy 放宽到多人/公开**。

---

## 已知限制

- **封城（lockdown）超过 24 小时期间的注册会丢失**：服务器在 lockdown 模式下只把 pull 到的 IP 入库、不灌 nft set 也不 ack（保留 KV `pending:` 待解封后补加）。但 KV `pending:<uuid>` 的 TTL 为 24 小时——若封城持续超过 24h，期间提交的注册条目会因 TTL 过期被静默丢弃，解封后无法再 pull 到，用户需**重新提交**。如预期会长时间封城，可调大 Worker 中 `pending` 的 `expirationTtl`（`cloudflare/worker/src/index.js`，默认 `86400`）。
- **纯 IPv6 网络无法注册**：白名单仅支持 IPv4，无 v4 出口的设备无法通过本入口加白（页面会提示「未检测到 IPv4 出口」）。

---

## 故障排查

| 现象 | 可能原因 | 处理 |
|------|----------|------|
| `GET /` 返回 403 "missing Access JWT" | 直接访问 Worker IP 而非域名，绕过了 Access | 确保通过 Access 绑定的域名访问 |
| `GET /` 返回 403 "invalid or expired Access token" | AUD 填写有误，或 TEAM_DOMAIN 末尾有多余 `/` | 检查 `POLICY_AUD` 和 `TEAM_DOMAIN` secret |
| `/pull` 返回 401 | Service Token 头不匹配 | 检查 `PULL_CLIENT_ID` / `PULL_CLIENT_SECRET` |
| `POST /register` 返回 400 "invalid or non-public IPv4" | 探测到的出口 IP 非合法公网 v4（私有/VPN/代理出口异常） | 关掉 VPN/代理、确认直连公网后重试 |
| 页面提示"未检测到 IPv4 出口" | 访问设备无 IPv4（纯 IPv6 网络） | 切换到带 IPv4 的网络访问；白名单仅支持 v4 |
| KV 写入失败（500） | KV namespace id 填写有误 | 检查 `wrangler.toml` 中的 `id` 字段 |
| bot 无法访问 Worker | 出站代理配置问题 | 确认 bot 的 SOCKS5 代理可访问 Cloudflare |
