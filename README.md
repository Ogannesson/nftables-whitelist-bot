# tg-whitelist — Telegram 机器人 nftables IP 白名单管理

用手机通过 Telegram 管理 Linux 服务器的入站 IP 白名单（基于 nftables）。

- 支持单 IP、IP 段（CIDR）、省级、市级白名单
- 省市白名单自动展开为 CIDR（离线库，无需第三方 API）
- 访问 Telegram 走 SOCKS5 代理
- 与现有 nftables 规则共存（独立 `table inet whitelist`）
- **覆盖两条入站路径**：`input`（本机服务）+ `forward`（docker 发布端口、NAT DNAT 转发）
- 容器/内网主动出网不受影响（私有源 10/8、172.16/12、192.168/16 在 forward chain 放行）
- SSH 22 永久放行（绝不锁死服务器）
- **三态防火墙模式**：正常 / 封城（仅 SSH+established）/ 放行（完全开放）；模式持久化，重启保持
- **web auth 自动加白**：Cloudflare Worker + Access，访客认证后网页探测其真实 IPv4 出口、确认提交，bot 定时 pull 自动入白名单（🤖 标注）
- **归属查询精度提升**：在线优先 IP2Location.io（精确到省市），离线兜底 ip2region xdb，最后 ip-api
- 提供 `/panic` 临时放行（不持久，重启自动恢复白名单）
- **启用即对所有公网入站生效——务必先填白名单再依赖它**

## 目录结构

```
whitelist/
├── src/tgwl/          # 主包
│   ├── bot.py         # 入口
│   ├── config.py      # 配置
│   ├── store.py       # SQLite 存储
│   ├── firewall.py    # nftables 操作
│   ├── geo.py         # 省市 CIDR 查询
│   ├── ui.py          # Inline keyboard
│   ├── handlers/      # Telegram handler
│   └── data/          # 内置行政区划码
├── scripts/
│   └── fetch_geo.py   # 下载省市数据
├── systemd/
│   └── tg-whitelist.service
├── config.example.toml
└── requirements.txt
```

## 快速部署

### 1. 系统依赖

```bash
# Ubuntu/Debian
apt update
apt install -y python3-nftables python3-pip python3-venv nftables

# 验证 nftables 正常运行
systemctl status nftables
```

### 2. 创建用户和目录

```bash
useradd -r -s /sbin/nologin -d /opt/tg-whitelist tgwl
mkdir -p /opt/tg-whitelist
chown tgwl:tgwl /opt/tg-whitelist
```

### 3. 部署代码

```bash
cd /opt/tg-whitelist

# 克隆或上传代码
git clone <repo_url> .

# 创建虚拟环境（必须 --system-site-packages，使用系统 python3-nftables）
python3 -m venv --system-site-packages .venv

# 安装依赖
.venv/bin/pip install -e .
```

### 4. 配置文件

```bash
cp config.example.toml config.toml
chmod 600 config.toml   # 权限收紧，token/密码不外泄
nano config.toml
```

关键字段：

```toml
[bot]
token = "你的 Bot Token"        # 从 @BotFather 获取
primary_admin = 123456789       # 你的 Telegram user_id（@userinfobot 获取）

[proxy]
url = "socks5h://127.0.0.1:1080"   # SOCKS5 代理，socks5h = DNS 由代理端解析

[geo]
data_dir = "/opt/tg-whitelist/data"
# IP2Location.io API Key（可选，免费 50k 次/月，精确到省市）
# ip2location_io_key = "your_key_here"
# ip2region 离线 xdb 路径（可选，离线精度）
# ip2region_xdb = "/opt/tg-whitelist/data/ip2region.xdb"

[database]
path = "/opt/tg-whitelist/whitelist.db"

# CF Worker 自动加白（可选，详见 docs/deploy/web-auth.md）
[cf_pull]
enabled = false
worker_url = ""          # CF Worker 端点 URL
access_client_id = ""    # CF Access Service Token Client ID
access_client_secret = ""  # CF Access Service Token Client Secret
poll_interval_seconds = 300
```

也可以用环境变量覆盖（适合 CI/CD）：

```bash
export TGWL_TOKEN="..."
export TGWL_PRIMARY_ADMIN="123456789"
export TGWL_PROXY_URL="socks5h://..."
```

### 5. 下载省市数据（可选，省级）

```bash
# 以 tgwl 用户身份下载（走代理）
sudo -u tgwl /opt/tg-whitelist/.venv/bin/python scripts/fetch_geo.py --provinces-only

# 下载全部省市（较慢）
sudo -u tgwl /opt/tg-whitelist/.venv/bin/python scripts/fetch_geo.py --all

# 下载 ip2region 离线 xdb（可选，用于离线精度归属）
sudo -u tgwl /opt/tg-whitelist/.venv/bin/python scripts/fetch_geo.py --ip2region-xdb
```

省市数据也可按需下载（首次点选某省时自动触发，会稍慢）。

### 6. 安装 systemd 服务

```bash
cp systemd/tg-whitelist.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable tg-whitelist
systemctl start tg-whitelist

# 查看日志
journalctl -u tg-whitelist -f
```

### 7. 验证

```bash
# 检查整个 whitelist table（含 input + forward 两条 chain）
nft list table inet whitelist

# 检查 input chain 规则顺序（iif lo / established,related / tcp 22 必须在 drop 前）
nft list chain inet whitelist input

# 检查 forward chain（docker 发布端口 / NAT DNAT 转发入站的拦截）
nft list chain inet whitelist forward
```

## 使用说明

向 Bot 发送 `/start` 打开主菜单。

| 按钮 | 功能 |
|---|---|
| 添加白名单 | 引导式：选类型→输入/选省市→确认 |
| 查看/管理 | 列出条目，点删除图标移除；🤖 标注的条目为 web auth 自动加白 |
| 查询 IP 归属 | 输入 IP → 返回省市/ISP（IP2Location.io → xdb → ip-api 三级查询）→ 可一键加白名单 |
| 状态 | 防火墙状态、CIDR 数、代理配置、当前防火墙模式 |
| 管理员管理 | 添加/撤销管理员（仅主管理员） |
| 防火墙模式 | 三态切换（均二次确认）：正常 / 封城 / 放行 |

### 三态防火墙模式说明

| 模式 | 行为 | 持久化 |
|---|---|---|
| **正常（normal）** | 白名单正常生效，默认模式 | 是 |
| **封城（lockdown）** | 清空 whitelist set、只保留 SSH/lo/established，封锁其余公网入站；DB 条目保留，切回正常自动恢复 | 是 |
| **放行（open）** | 删除整个 whitelist table，完全开放，等同原 Panic 效果 | 是 |

三种模式均通过主菜单「防火墙模式」面板操作，每次切换需二次确认。模式持久化存储，重启后自动按上次模式恢复。

`/panic` 指令保留为**临时**放行：效果等同 open 模式，但不持久——重启后 Bot 自动恢复白名单（normal 模式）。

## 防锁死设计与覆盖范围

### chain input（本机直接入站：SSH、本机端口等）

```
1. iif "lo" accept                      ← 回环放行
2. ct state established,related accept  ← 已建连放行（最关键）
3. ct state invalid drop
4. tcp dport 22 accept                  ← SSH 永久放行（防锁死关键）
5. ip saddr @whitelist4 accept          ← 白名单放行
6. ip6 nexthdr ipv6-icmp accept
7. meta nfproto ipv4 drop               ← 最后：仅丢弃非白名单 v4
```

### chain forward（转发类入站：docker 发布端口、NAT DNAT 转发）

```
1. ct state established,related accept                               ← 已建连/回程放行（含容器出网）
2. ct state invalid drop
3. ip saddr @whitelist4 accept                                       ← 白名单公网源（复用同一个 set）
4. ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept  ← 私有源放行（容器/内网出网）
5. ip6 nexthdr ipv6-icmp accept
6. meta nfproto ipv4 drop                                            ← 最后：丢弃公网非白名单转发入站
```

两条 chain 均挂在同一个 `inet whitelist` 表，优先级 -10（先于 docker filter forward 0），复用同一个 `@whitelist4` set——reconcile 只需更新 set，input 和 forward 同步生效。

- **任何情况下**，SSH 22 均可到达（已建连的 SSH session 也不会被切断）
- **容器出网不受影响**：私有源（容器/内网）发出的包在 forward chain 规则 4 放行
- 封城模式下仅保留 SSH/lo/established，白名单 set 清空但 DB 条目保留；切回正常模式自动恢复
- `/panic` 或重启后 Bot 未启动时：table 不存在，现有规则不受影响（fail-open）
- Bot 重启后按持久化的防火墙模式自动从 SQLite 恢复防火墙规则
- **注意**：启用后对所有公网入站立即生效（包括 docker 发布端口）——务必先填好白名单再开启

### 数据库与防火墙的最终一致性

**真相源 = SQLite**。nftables set 只是"当前快照"，两者可能短暂不一致：

| 场景 | 状态 | 恢复方式 |
|---|---|---|
| 条目入库成功，但 reconcile 失败（nft 权限不足、Bot 崩溃等） | DB 有记录，防火墙未生效 | **重启 Bot**：`systemctl restart tg-whitelist`，启动时自动全量重建 |
| `ensure_setup` 重建 table 中途失败（极罕见） | table 暂时不存在，所有 IP 均可访问（fail-open） | 同上，重启 Bot 重建；日志会有 CRITICAL 告警 |
| Bot 正常运行但手动 `nft flush set inet whitelist whitelist4` | set 为空，防火墙不再过滤 | 点「状态 → 同步省市数据」触发 reconcile，或重启 Bot |

**总结**：遇到白名单"加了但不生效"的情况，首先查日志（`journalctl -u tg-whitelist`），再重启服务——Bot 启动时会自动重建防火墙。重启前无需手动操作 nftables。

## 权限说明

- Bot 进程以 `tgwl` 用户（非 root）运行
- 通过 `AmbientCapabilities=CAP_NET_ADMIN` 授权操作 nftables
- `RestrictAddressFamilies` 含 `AF_NETLINK`（nftables 内核通信必需）
- 所有管理指令和按钮回调都校验权限，非授权用户静默拒绝

## 配置说明

### 代理

`proxy.url` 格式：`socks5h://[user:pass@]host:port`

- `socks5h` = DNS 交给代理端解析，防止 DNS 泄漏
- 如无需密码：`socks5h://host:port`
- 代理不通时 Bot 无法收发消息，但本地 nftables 规则不受影响

### 在线 IP 查询 Provider

`/whois`（查询 IP 归属）按以下三级优先级查询，走配置的 SOCKS5 代理：

| 优先级 | Provider | 说明 |
|---|---|---|
| 1 | **IP2Location.io**（在线，有 key）| 精确到省市，免费 50k 次/月；需在 `[geo]` 配置 `ip2location_io_key` |
| 2 | **ip2region xdb**（离线，有文件）| 本地精度优化，无网络依赖；需先用 `scripts/fetch_geo.py --ip2region-xdb` 下载 |
| 3 | **ip-api.com**（在线，免 key）| 兜底方案，无需任何 API 凭据 |

三个 provider 均未配置时，`/whois` 返回无法查询提示。省市白名单反查纯离线（metowolf/iplist），无需在线 API。

注意：在线 provider 仅支持正向查询（IP → 省市），不能反查省市的 IP 段。
省市 IP 段反查依赖离线 `metowolf/iplist` 数据。

## 在线归属查询安全

API key 通过 `config.toml`（`chmod 600`）或环境变量传入，不硬编码在代码中。ip2location_io_key 可选，留空时自动跳过，不存在 key 泄漏面；ip-api.com 作为兜底无需任何凭据。

## web auth 自动加白

通过 Cloudflare Workers + Cloudflare Access 提供一个网页注册入口：访客通过 Access 认证后，**网页用 JavaScript 探测其真实的 IPv4 出口地址**（浏览器 fetch 公共 v4-only API），展示并由用户确认后提交；Worker 校验为合法公网 IPv4 后写入 KV，Bot 定时经 SOCKS5 pull 并自动永久加白。

> **为什么网页探测 v4 而非用 Cloudflare 回传的访问 IP？** nftables 白名单是 IPv4 only，但终端常 IPv6 优先，边缘 `CF-Connecting-IP` 往往是 v6（非企业版无法关闭 IPv6），直接用会写入永远加不进的 v6。代价：IP 改为客户端自报、可伪造，安全依赖 Access policy 只放本人邮箱——详见 [`docs/deploy/web-auth.md`](docs/deploy/web-auth.md) 的「安全模型」。

### 一键部署 Cloudflare Worker

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Ogannesson/nftables-whitelist-bot/tree/main/cloudflare/worker)

点击按钮，Cloudflare 会把本 Worker 子目录 clone 成**你账号下一个独立的新仓库**、自动创建 KV、配 Workers Builds（CI/CD）、提示填 4 个 secret：

| Secret | 说明 |
|---|---|
| `TEAM_DOMAIN` | Cloudflare Access team 域名，如 `https://yourteam.cloudflareaccess.com` |
| `POLICY_AUD` | 你在 Access 创建的应用 AUD tag |
| `PULL_CLIENT_ID` | Service Token Client ID（含 `.access` 后缀） |
| `PULL_CLIENT_SECRET` | Service Token Client Secret |

> ⚠️ **部署后改了代码该往哪推？** 一键部署会创建一个**独立仓库**，Workers Builds 监听的是**那个独立仓库**（默认分支通常是 `master`），不是你 clone 的这个主仓库。所以之后你改 Worker 代码、想让它重新部署，二选一：
> - **把改动推到那个独立仓库**；或
> - **改连本主仓库**（推荐 monorepo 维护者）：Worker → **Settings → Build**，Git repository 改成本仓库、Git branch 设 `main`、**Root directory 设 `cloudflare/worker`**；之后直接推主仓库即自动部署。注意此时要确保本仓库 `cloudflare/worker/wrangler.toml` 的 KV `id` 是真实值（独立仓库那份由 Cloudflare 自动填，主仓库这份需手动填一次）。

部署后仍需在 Cloudflare Zero Trust 创建 Access 应用保护 Worker 的 `GET /`、创建 Service Token，并把 Worker URL + Service Token 填入 bot 的 `config.toml [cf_pull]`。

- 服务器无需开放任何入站端口（无 Webhook、无 cloudflared）
- 加白条目在列表中以 🤖 标注，来源可追溯
- 封城/放行模式下 pull 只写 DB，不影响当前防火墙状态
- 详细部署步骤见 [`docs/deploy/web-auth.md`](docs/deploy/web-auth.md)

## 常见问题

**Q: Bot 启动报 `nftables 仅在 Linux 系统上可用`**
A: 这是 Windows/macOS 开发环境的正常提示，部署到 Linux 服务器后自动解决。

**Q: 报 `Cannot import nftables` 或 `ModuleNotFoundError`**
A: 虚拟环境需要 `--system-site-packages` 才能使用系统安装的 `python3-nftables`：
```bash
python3 -m venv --system-site-packages .venv
```

**Q: Bot 有权限但 nft 操作失败（Permission denied）**
A: 检查 systemd 单元的 `AmbientCapabilities=CAP_NET_ADMIN` 是否生效：
```bash
systemctl show tg-whitelist | grep Cap
```

**Q: 省市数据显示 0 条 CIDR**
A: 先运行 `scripts/fetch_geo.py` 下载数据，或点「状态→同步省市数据」。

**Q: 误操作想撤销防火墙**
A: 点主菜单「防火墙模式」，切换到 open（二次确认后 table 立即删除）。也可发送 `/panic`（临时放行，不写入持久状态，重启后自动恢复白名单）。若只是想开放部分入站，切 normal 或 lockdown 即可。
```

## 开发

```bash
# 安装开发依赖
pip install -e ".[dev]"

# 运行测试
pytest tests/ -v

# 所有测试均可在 Windows/macOS 运行（nftables 调用已 mock）
```
