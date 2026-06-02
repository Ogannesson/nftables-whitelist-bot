# tg-whitelist — Telegram 机器人 nftables IP 白名单管理

用手机通过 Telegram 管理 Linux 服务器的入站 IP 白名单（基于 nftables）。

- 支持单 IP、IP 段（CIDR）、省级、市级白名单
- 省市白名单自动展开为 CIDR（离线库，无需第三方 API）
- 访问 Telegram 走 SOCKS5 代理
- 与现有 nftables 规则共存（独立 `table inet whitelist`）
- SSH 22 永久放行（绝不锁死服务器）
- 提供 `/panic` 紧急解除一切限制

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

[database]
path = "/opt/tg-whitelist/whitelist.db"
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
# 检查 nftables 规则
nft list table inet whitelist

# 检查链规则顺序（iif lo / established,related / tcp 22 必须在 drop 前）
nft list chain inet whitelist input
```

## 使用说明

向 Bot 发送 `/start` 打开主菜单。

| 按钮 | 功能 |
|---|---|
| 添加白名单 | 引导式：选类型→输入/选省市→确认 |
| 查看/管理 | 列出条目，点删除图标移除 |
| 查询 IP 归属 | 输入 IP → 返回省市/ISP → 可一键加白名单 |
| 状态 | 防火墙状态、CIDR 数、代理配置 |
| 管理员管理 | 添加/撤销管理员（仅主管理员） |
| 紧急解除（Panic） | 删除整个 whitelist table，立即解除所有限制 |

紧急情况也可直接发送 `/panic` 指令（需二次确认）。

## 防锁死设计

nftables chain 规则顺序（严格保证）：

```
1. iif "lo" accept                      ← 回环放行
2. ct state established,related accept  ← 已建连放行（最关键）
3. ct state invalid drop
4. tcp dport 22 accept                  ← SSH 永久放行（防锁死关键）
5. ip saddr @whitelist4 accept          ← 白名单放行
6. ip6 nexthdr ipv6-icmp accept
7. meta nfproto ipv4 drop               ← 最后：仅丢弃非白名单 v4
```

- **任何情况下**，SSH 22 均可到达（已建连的 SSH session 也不会被切断）
- `/panic` 或重启后 Bot 未启动时：table 不存在，现有规则不受影响（fail-open）
- Bot 重启后自动从 SQLite 恢复防火墙规则

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

`/whois` 使用免 key 的 `ip-api.com`（`lang=zh-CN`，走配置的 SOCKS5 代理），查不到时离线库兜底。省市白名单反查纯离线（metowolf/iplist + ip2region），无需任何在线 API key。

注意：在线 provider 仅支持正向查询（IP → 省市），不能反查省市的 IP 段。
省市 IP 段反查依赖离线 `metowolf/iplist` 数据。

## 在线归属查询安全

已移除需要 API key 的腾讯地图和高德 provider，仅保留免 key 的 ip-api.com，无 key 泄漏面。

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
A: 发送 `/panic` 或点主菜单「紧急解除」，二次确认后 table 立即删除。
```

## 开发

```bash
# 安装开发依赖
pip install -e ".[dev]"

# 运行测试
pytest tests/ -v

# 所有测试均可在 Windows/macOS 运行（nftables 调用已 mock）
```
