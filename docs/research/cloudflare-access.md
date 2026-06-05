# Cloudflare Access Web Auth 自动加白 — 技术调研报告

**调研日期**：2026-06-05  
**调研范围**：tg-whitelist 项目新功能——Cloudflare Access 认证后自动将用户真实 IP 永久写入 nftables 白名单  
**调研人**：researcher agent（安全研究角色）

---

## 背景与目标

在现有 Telegram Bot 白名单管理机器人基础上，新增一个 Web 端点（如 `/auth/whitelist`）。用户经 Cloudflare Access 认证后，后端自动提取其真实公网 IP 并以 `type=ip` 条目永久写入 SQLite `entries` 表，同时触发 `FirewallManager.reconcile()` 使 nftables 规则生效。

---

## Q1. Python JWT 验证方案

### 推荐库：PyJWT（首选）或 python-jose

| 方案 | 库 | 优缺点 |
|---|---|---|
| **首选** | `PyJWT >= 2.x` + `cryptography` | 官方 Cloudflare FastAPI 教程使用；维护活跃；支持 RSA + JWKS |
| 备选 | `python-jose[cryptography]` | API 更高级但依赖更多；适合需要处理复杂 JWE 场景 |

### 验证步骤

```python
import json
import time
import threading
import requests
import jwt  # PyJWT

TEAM_DOMAIN = "https://<your-team>.cloudflareaccess.com"
CERTS_URL   = f"{TEAM_DOMAIN}/cdn-cgi/access/certs"
POLICY_AUD  = "<your-application-aud-tag>"  # 从 CF Access 应用页面复制

# ---- JWKS 缓存（带 TTL + 线程安全） ----
_jwks_cache: list = []
_jwks_fetched_at: float = 0.0
_jwks_ttl: float = 3600.0          # 1 小时；CF 轮换周期 >> 1 小时
_jwks_lock = threading.Lock()

def _fetch_jwks() -> list:
    resp = requests.get(CERTS_URL, timeout=5)
    resp.raise_for_status()
    keys = []
    for key_dict in resp.json()["keys"]:
        pub = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key_dict))
        keys.append(pub)
    return keys

def get_public_keys(force_refresh: bool = False) -> list:
    global _jwks_cache, _jwks_fetched_at
    with _jwks_lock:
        if force_refresh or (time.monotonic() - _jwks_fetched_at) > _jwks_ttl:
            _jwks_cache = _fetch_jwks()
            _jwks_fetched_at = time.monotonic()
    return _jwks_cache

def verify_access_jwt(token: str) -> dict:
    """
    验证 Cloudflare Access JWT，返回 claims dict。
    任何校验失败均抛出 ValueError（fail-closed）。
    """
    last_exc = None
    for attempt in range(2):                   # 最多重试一次（应对 JWKS 轮换）
        keys = get_public_keys(force_refresh=(attempt == 1))
        for key in keys:
            try:
                claims = jwt.decode(
                    token,
                    key=key,
                    algorithms=["RS256"],       # 严格限定算法，防 alg=none 攻击
                    audience=POLICY_AUD,        # 严格校验 aud
                    options={
                        "require": ["exp", "iss", "aud"],
                        "verify_exp": True,
                    },
                )
                # 严格校验 iss
                if claims.get("iss") != TEAM_DOMAIN:
                    raise ValueError(f"iss mismatch: {claims.get('iss')!r}")
                return claims                   # 成功
            except jwt.InvalidTokenError as e:
                last_exc = e
    raise ValueError(f"JWT validation failed: {last_exc}")
```

### JWKS 缓存与轮换策略

- 默认 TTL 1 小时；Cloudflare 密钥轮换周期通常为数周，1 小时远短于轮换周期。
- 发现 key-not-found 时（所有 key 尝试均失败）立即 `force_refresh=True` 重取一次，再重试——处理 CF 主动轮换场景。
- 异步版本改用 `asyncio.Lock()` + `aiohttp.ClientSession`（与 PTB 事件循环共享，避免阻塞）。

---

## Q2. 真实客户端 IP 提取

### 结论：使用 `CF-Connecting-IP` 头，绝不依赖 `X-Forwarded-For`

| 来源 | 可信度 | 说明 |
|---|---|---|
| `CF-Connecting-IP` | **高**（Cloudflare 边缘设置） | CF 边缘节点写入，cloudflared 透传，用户不可伪造 |
| `X-Forwarded-For` 第一值 | **低** | 可由客户端任意伪造；多级代理时顺序不确定 |
| `X-Real-IP` | 低 | 非 CF 标准头，视部署而定 |

### 提取代码（aiohttp/starlette 均适用）

```python
import ipaddress

def extract_real_ip(request) -> str:
    """
    从 CF-Connecting-IP 提取真实客户端 IP。
    若缺失或格式非法，抛出 ValueError（fail-closed）。
    """
    ip_str = request.headers.get("CF-Connecting-IP", "").strip()
    if not ip_str:
        raise ValueError("missing CF-Connecting-IP header")
    # 标准化 + 格式校验（拒绝私有地址加白）
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        raise ValueError(f"invalid IP in CF-Connecting-IP: {ip_str!r}")
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_unspecified:
        raise ValueError(f"refusing to whitelist non-public IP: {ip_str}")
    if not isinstance(addr, ipaddress.IPv4Address):
        raise ValueError(f"IPv6 not supported by whitelist4 set: {ip_str}")
    return str(addr)   # 标准化格式，如 "1.2.3.4"
```

### 伪造风险分析

- 使用 **Cloudflare Tunnel**（cloudflared）：本源监听 localhost，外部流量必须经 CF 边缘 → cloudflared，`CF-Connecting-IP` **无法被外部伪造**，是最安全方式。
- 使用**直接端口暴露**（CF Proxy 模式）：若源站 IP 泄露，攻击者可绕过 CF，直接携带伪造 `CF-Connecting-IP` 头访问。缓解措施：在 nftables 层仅接受来自 [CF IP 段](https://www.cloudflare.com/ips) 的流量。

**推荐：使用 Cloudflare Tunnel，彻底杜绝 IP 伪造风险。**

---

## Q3. nftables 端口暴露策略

### 方案对比

| 方案 | 安全性 | 实现复杂度 | 推荐度 |
|---|---|---|---|
| **A. Cloudflare Tunnel** | 最高（无入站端口） | 低 | **首选** |
| B. CF Proxy + CF IP 段过滤 | 中（源站 IP 须保密） | 中 | 备选 |
| C. 公开端口无过滤 | 低 | 低 | 不推荐 |

### 方案 A：Cloudflare Tunnel（推荐）

工作原理：cloudflared 向 CF 网络建立**出站**长连接（端口 7844 TCP/UDP），CF 边缘反向隧道把流量推进来，**本源无需开放任何入站端口**。

```
用户浏览器 → CF Edge → Cloudflare Tunnel (port 7844 out) → cloudflared → localhost:8080
```

- Web 服务绑定 `127.0.0.1:8080`（仅本地可达）。
- nftables **无需新增任何规则**，现有 `meta nfproto ipv4 drop` 规则对外完全封闭。
- 真实 IP 通过 `CF-Connecting-IP` 头获得（CF 边缘注入，cloudflared 透传）。
- cloudflared 在 systemd 下以普通用户运行，最小权限。

**cloudflared 配置示例（`/etc/cloudflared/config.yml`）**：

```yaml
tunnel: <tunnel-uuid>
credentials-file: /etc/cloudflared/<tunnel-uuid>.json

ingress:
  - hostname: whitelist-auth.example.com
    service: http://127.0.0.1:8080
  - service: http_status:404
```

### 方案 B：CF Proxy + nftables IP 段过滤（备选）

若因某种原因无法部署 Tunnel，需要在 nftables 中添加允许规则。

现有 `input` 链结构（`firewall.py` `_create_table_and_rules`）：

```
lo accept → established/related accept → invalid drop →
tcp dport 22 accept → @whitelist4 accept →
ipv6-icmp accept → meta nfproto ipv4 drop  ← 所有新规则必须在此之前
```

需在 `meta nfproto ipv4 drop` 之前插入：

```nft
# 仅接受来自 Cloudflare IP 段的 Web Auth 端口
ip saddr @cf_ranges tcp dport 8080 accept
```

同时维护 `cf_ranges` set（需定期从 `https://www.cloudflare.com/ips-v4` 拉取更新）。

---

## Q4. 与 PTB asyncio 事件循环共存的 Web 服务架构

### 现状分析

项目使用 `python-telegram-bot >= 22`，其 `Application.run_polling()` 内部创建并管理 asyncio 事件循环。任何 Web 服务必须与这个事件循环**共存**。

### 推荐方案：aiohttp + asyncio.create_task（最简）

```python
# main.py / bot.py 中的启动逻辑
import asyncio
from aiohttp import web
from tgwl.web_auth import build_app   # 新增模块

async def main():
    # 1. 构建 PTB Application
    app_ptb = build_telegram_app()    # Application.builder()...build()

    # 2. 构建 aiohttp Web App
    web_app = build_app()             # 返回 aiohttp.web.Application

    # 3. 启动 aiohttp runner（同一事件循环内）
    runner = web.AppRunner(web_app)
    await runner.setup()
    site = web.TCPSite(runner, host="127.0.0.1", port=8080)
    await site.start()

    # 4. 启动 PTB（接管事件循环直到 stop）
    async with app_ptb:
        await app_ptb.start()
        await app_ptb.updater.start_polling()
        await asyncio.Event().wait()   # 永久等待
        await app_ptb.updater.stop()
        await app_ptb.stop()

    # 5. 清理
    await runner.cleanup()

asyncio.run(main())
```

### 备选方案：uvicorn + starlette（asyncio 原生）

```python
import uvicorn
from starlette.applications import Starlette

# uvicorn 以 loop="none" 模式启动，注入已有事件循环
config = uvicorn.Config(starlette_app, host="127.0.0.1", port=8080, loop="none")
server = uvicorn.Server(config)

# 在 PTB 启动之前或 asyncio.gather 中运行
asyncio.get_event_loop().run_until_complete(server.serve())
```

### 注意事项

- 不要使用 `loop.run_until_complete()` 嵌套调用——PTB 22+ 已在运行中的循环里。
- JWKS 缓存刷新应使用 `aiohttp.ClientSession`（在事件循环创建后初始化），避免在事件循环内调用同步 `requests`（会阻塞）。
- 推荐在 `startup` 钩子里预热 JWKS 缓存：`app.on_startup.append(prefetch_jwks)`。

---

## Q5. 安全 Checklist

### 5.1 Fail-Closed（验证失败绝不加白）

```python
try:
    claims = verify_access_jwt(token)
    real_ip = extract_real_ip(request)
except (ValueError, Exception) as e:
    logger.warning("auth_failed reason=%s", type(e).__name__)  # 不打印 token/IP 原文
    return web.Response(status=403, text="Forbidden")
# 只有走到这里才执行加白
```

- 任何异常路径（JWKS 拉取失败、JWT 解码异常、IP 格式错误）均返回 403，**不执行加白**。
- 绝不使用宽泛 `except: pass`，异常需记录类型供审计。

### 5.2 JWKS 缓存与轮换

- TTL 1 小时，key-not-found 时立即重取一次（如 Q1 所示）。
- JWKS 拉取失败时**不降级**（不跳过验证），而是直接返回 503。

### 5.3 严格 aud/iss 校验

```python
# 算法白名单：仅 RS256，防 alg=none / HMAC 混淆
algorithms=["RS256"]

# iss 字符串精确匹配
if claims["iss"] != TEAM_DOMAIN:
    raise ValueError("iss mismatch")

# aud 由 PyJWT decode 内部校验（audience=POLICY_AUD）
```

- 不接受多 aud 候选（除非业务确实需要多应用）。
- `TEAM_DOMAIN` 和 `POLICY_AUD` 从环境变量注入，不硬编码。

### 5.4 防重放

- JWT 自带 `exp`（有效期）由 PyJWT 自动验证，防止过期 token 复用。
- 如 CF Access JWT 包含 `jti`（JWT ID），可在 Redis/内存集合中记录已使用的 `jti`，拒绝重复使用。
  - 注意：CF Access JWT `exp` 通常为 20-60 分钟，`jti` 黑名单 TTL 可设为与 `exp` 一致。
- 建议同一 JWT token 只能触发一次加白（通过 `jti` 或 `exp+sub` 组合去重）。

### 5.5 限流

```python
# 示例：使用 aiohttp-ratelimiter 或自实现令牌桶
# 按 CF-Connecting-IP 限流（而非按 JWT，防止 IP 穷举）
from collections import defaultdict
import time

_rate_store: dict[str, tuple[int, float]] = defaultdict(lambda: (0, 0.0))
RATE_LIMIT = 5           # 5 次 / 分钟（成功认证后）
RATE_WINDOW = 60.0

def check_rate_limit(ip: str) -> bool:
    count, window_start = _rate_store[ip]
    now = time.monotonic()
    if now - window_start > RATE_WINDOW:
        _rate_store[ip] = (1, now)
        return True
    if count >= RATE_LIMIT:
        return False
    _rate_store[ip] = (count + 1, window_start)
    return True
```

- 限流维度优先选择**源 IP**（`CF-Connecting-IP`），而非 JWT，因为攻击者可能大量生成合法 JWT。
- 认证端点本身也可在 Cloudflare Access 层设置访问策略（仅组织成员可访问）作为第一道防线。

### 5.6 日志脱敏（不打 JWT/IP 凭据）

```python
import logging
logger = logging.getLogger("web_auth")

# 正确：只记录脱敏信息
logger.info("whitelist_add ip=%s email=%s", mask_ip(ip), claims.get("email", "?"))

# 错误：严禁
# logger.debug("token=%s", token)       # 泄露 JWT
# logger.debug("ip=%s", ip)             # 直接记录原始 IP（视合规要求）

def mask_ip(ip: str) -> str:
    """将 IP 最后一段替换为 xxx，如 1.2.3.xxx"""
    parts = ip.split(".")
    if len(parts) == 4:
        parts[-1] = "xxx"
        return ".".join(parts)
    return "<masked>"
```

- JWT token 字符串**绝不**写入日志，异常信息也需过滤（PyJWT 异常 message 有时包含 token 片段）。
- 脱敏级别视合规要求：若需精确审计，可将完整 IP 写入独立审计表（不进普通日志）。

### 5.7 审计（谁/何时/加了哪个 IP）

```python
# 调用 store.add_entry() 时 added_by 传特殊值标记来源
WEB_AUTH_BOT_ID = 0   # 约定：0 = Cloudflare Access 自动加白

entry = store.add_entry(
    entry_type="ip",
    value=real_ip,
    label=f"CF-Access:{claims.get('email', 'unknown')}",  # label 保留邮件供审计
    added_by=WEB_AUTH_BOT_ID,
)
if entry:
    logger.info("whitelist_added ip_masked=%s cf_email=%s", mask_ip(real_ip), claims.get("email"))
else:
    logger.info("whitelist_already_exists ip_masked=%s", mask_ip(real_ip))
```

- `label` 字段存 `CF-Access:<email>`，在 Bot `/list` 命令中可区分手动加白和自动加白。
- `added_by=0` 作为 "系统/自动" 的标记 ID，需在代码中注释说明，并在 Bot `/list` 展示时翻译为 "Cloudflare Access"。

### 5.8 幂等加白

- `store.add_entry()` 已通过 `UNIQUE(type, value)` 实现幂等（重复调用返回 `None` 而非报错）。
- 无论 `add_entry` 返回新条目还是 `None`（已存在），均调用 `reconcile()` 确保 nftables 状态一致。

---

## 实现骨架（web_auth.py）

```python
"""
tgwl/web_auth.py — Cloudflare Access 认证后自动加白端点

GET /auth/whitelist
  - Cloudflare Access 验证 JWT（Cf-Access-Jwt-Assertion header）
  - 提取真实 IP（CF-Connecting-IP header）
  - 幂等写入 SQLite entries 表（type=ip）
  - 触发 FirewallManager.reconcile()
"""

from __future__ import annotations

import logging
from aiohttp import web

from tgwl.store import Store
from tgwl.firewall import FirewallManager
from tgwl.web_auth_jwt import verify_access_jwt, extract_real_ip, check_rate_limit

logger = logging.getLogger("tgwl.web_auth")

WEB_AUTH_BOT_ID = 0  # 标记：Cloudflare Access 自动加白

def build_app(store: Store, fw: FirewallManager) -> web.Application:
    app = web.Application()
    app["store"] = store
    app["fw"] = fw
    app.router.add_get("/auth/whitelist", handle_auth_whitelist)
    return app

async def handle_auth_whitelist(request: web.Request) -> web.Response:
    store: Store = request.app["store"]
    fw: FirewallManager = request.app["fw"]

    # 1. 提取 JWT（优先 header，次选 cookie）
    token = (
        request.headers.get("Cf-Access-Jwt-Assertion")
        or request.cookies.get("CF_Authorization")
        or ""
    )
    if not token:
        return web.Response(status=403, text="missing token")

    # 2. 验证 JWT（fail-closed）
    try:
        claims = verify_access_jwt(token)
    except ValueError as e:
        logger.warning("jwt_invalid reason=%s", type(e).__name__)
        return web.Response(status=403, text="invalid token")

    # 3. 提取真实 IP（fail-closed）
    try:
        real_ip = extract_real_ip(request)
    except ValueError as e:
        logger.warning("ip_extract_failed reason=%s", type(e).__name__)
        return web.Response(status=400, text="cannot determine client IP")

    # 4. 限流
    if not check_rate_limit(real_ip):
        return web.Response(status=429, text="rate limit exceeded")

    # 5. 幂等加白
    email = claims.get("email", "unknown")
    entry = store.add_entry(
        entry_type="ip",
        value=real_ip,
        label=f"CF-Access:{email}",
        added_by=WEB_AUTH_BOT_ID,
    )

    # 6. 触发 reconcile（无论新增还是已存在）
    try:
        await fw.reconcile()
    except Exception as e:
        logger.error("reconcile_failed type=%s", type(e).__name__)
        return web.Response(status=500, text="firewall update failed")

    action = "added" if entry else "already_exists"
    logger.info("whitelist_%s ip_masked=%s cf_email=%s", action, _mask_ip(real_ip), email)

    return web.Response(
        status=200,
        text=f"IP whitelisted ({action}). You may close this page.",
    )

def _mask_ip(ip: str) -> str:
    parts = ip.split(".")
    if len(parts) == 4:
        parts[-1] = "xxx"
        return ".".join(parts)
    return "<masked>"
```

---

## 关键依赖清单

```
PyJWT>=2.8.0          # JWT 解码
cryptography>=41.0    # RSA 密钥支持（PyJWT 依赖）
aiohttp>=3.9          # 异步 Web 服务器（与 PTB 同一事件循环）
requests>=2.31        # 同步 JWKS 预热（或改用 aiohttp）
```

若选择异步 JWKS 拉取，改用 `aiohttp.ClientSession`，在 `app.on_startup` 中初始化。

---

## 环境变量配置

```env
CF_TEAM_DOMAIN=https://your-team.cloudflareaccess.com
CF_POLICY_AUD=<32-char-hex-aud-tag>
WEB_AUTH_HOST=127.0.0.1      # Tunnel 模式固定本地
WEB_AUTH_PORT=8080
```

---

## 参考资料

1. [Cloudflare Access — Validate the Access token with FastAPI](https://developers.cloudflare.com/cloudflare-one/tutorials/fastapi/)
2. [Cloudflare Access — JWT claims structure](https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/)
3. [Cloudflare Tunnel — How it works](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/)
4. [Cloudflare IP Ranges](https://www.cloudflare.com/ips/)
5. [PyJWT Documentation](https://pyjwt.readthedocs.io/en/stable/usage.html#retrieve-rsa-public-keys-from-a-jwks-endpoint)
6. [python-telegram-bot 22.x asyncio integration](https://docs.python-telegram-bot.org/en/stable/examples.customwebhookbot.html)
