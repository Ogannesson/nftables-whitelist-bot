# tg-whitelist 手动测试清单

**适用场景**：在有真实 Telegram Bot Token + SOCKS5 代理 + Linux 服务器的环境中，
按此清单逐项验证 bot 交互流和部署行为。

**测试前提**：
- 已完成 README 快速部署步骤（apt 依赖、venv、config.toml、systemd 服务）
- 已有至少两个 Telegram 账号：一个用于主管理员操作，一个用于非授权用户测试

---

## 第一部分：部署冒烟测试

### D-1 systemd 服务启动

```bash
systemctl status tg-whitelist
# 期望：active (running)，无 error 日志

journalctl -u tg-whitelist -n 30 --no-pager
# 期望：看到 "Bot started"/"已启动" 日志，无 traceback
```

**验收**：[ ] 服务 active，[ ] 无错误日志

### D-2 nftables 规则自动建立

```bash
nft list table inet whitelist
# 期望：输出含 set whitelist4, chain input

nft list chain inet whitelist input
# 期望：规则顺序：lo > established > invalid > 22 > whitelist4 > ipv6-icmp > ipv4 drop
```

**验收**：[ ] table 存在，[ ] chain 规则顺序正确（逐行比对 README 防锁死设计）

### D-3 CAP_NET_ADMIN 权限验证

```bash
systemctl show tg-whitelist | grep Cap
# 期望：CapabilityBoundingSet 含 cap_net_admin

ps aux | grep tgwl | grep -v grep
# 期望：进程以 tgwl 用户运行，非 root
```

**验收**：[ ] 非 root 运行，[ ] 有 CAP_NET_ADMIN 能力

---

## 第二部分：Bot 基础指令测试

### B-1 /start 主菜单

**操作**：向 bot 发送 `/start`

**期望**：
- 返回主菜单消息，含 inline keyboard
- 按钮至少包含：添加白名单、查看/管理、查询 IP 归属、状态、管理员管理、紧急解除

**验收**：[ ] 菜单正常显示，[ ] 按钮可点击

### B-2 /menu 指令

**操作**：发送 `/menu`

**期望**：与 `/start` 相同效果，打开主菜单

**验收**：[ ] 菜单正常显示

---

## 第三部分：添加白名单流程

### A-1 添加单 IP

**操作**：
1. 点 "添加白名单"
2. 点 "单 IP"
3. 发送 `203.0.113.100`（RFC 5737 测试用 IP，可改为实际需要的 IP）
4. 点 "✅ 确认"

**期望**：
- bot 回复「IP 已添加」
- 服务器执行 `nft list set inet whitelist whitelist4` 能看到该 IP

**验收**：[ ] 添加成功，[ ] nft set 中可见

### A-2 添加 CIDR

**操作**：
1. 点 "添加白名单" -> "IP 段"
2. 发送 `10.99.0.0/16`
3. 点 "✅ 确认"

**期望**：bot 回复成功，nft set 含 `10.99.0.0/16`

**验收**：[ ] 添加成功

### A-3 输入格式校验

**操作**：
1. 点 "添加白名单" -> "单 IP"
2. 发送非法内容：`not-an-ip`

**期望**：bot 回复格式错误提示，不崩溃，不乱写规则

**验收**：[ ] 错误提示友好，[ ] nft set 未被污染

### A-4 添加省级白名单

**操作**：
1. 点 "添加白名单" -> "省"
2. 在省份列表中选择「浙江」
3. bot 回显 CIDR 数量（期望约 1000+ 条），点 "✅ 确认"

**期望**：
- bot 显示「浙江省 ≈ N 条 CIDR，确认添加？」
- 确认后 nft set 元素数量增加

**验收**：[ ] 省份列表正常，[ ] CIDR 数量级合理（500~2000），[ ] 确认后规则生效

### A-5 添加市级白名单

**操作**：
1. 点 "添加白名单" -> "市"
2. 选择省份（如广东）
3. 选择城市（如深圳）
4. 确认添加

**期望**：成功添加深圳市 CIDR 列表

**验收**：[ ] 二级联动正常，[ ] 添加成功

---

## 第四部分：查看/管理流程

### M-1 查看白名单列表

**操作**：点 "查看/管理"

**期望**：
- 显示按类型分组的条目（单 IP/CIDR/省/市）
- 每个条目有 🗑 删除按钮

**验收**：[ ] 列表正常，[ ] 分组显示

### M-2 删除单条目

**操作**：点某个条目的 🗑，再点 "🗑 确认删除"

**期望**：
- bot 回复删除成功
- 重新查看列表，该条目消失
- nft set 对应 CIDR 已移除（或 reconcile 后消失）

**验收**：[ ] 删除成功，[ ] 二次确认有效，[ ] nft 同步更新

### M-3 取消删除

**操作**：点某个 🗑 按钮，再点 "❌ 取消"

**期望**：条目未被删除

**验收**：[ ] 取消有效

---

## 第五部分：查询 IP 归属

### Q-1 查询已知 IP

**操作**：
1. 点 "查询 IP 归属"
2. 发送 `8.8.8.8`

**期望**：
- bot 返回归属信息（如「美国 / Google」）
- 提示「是否加入白名单？」按钮

**验收**：[ ] 归属信息返回，[ ] 一键添加按钮出现

### Q-2 查询国内 IP

**操作**：发送一个中国 IP（如 `114.114.114.114`）

**期望**：返回省/市/ISP 信息（中文）

**验收**：[ ] 中文省市正确显示

---

## 第六部分：状态查询

### S-1 查看状态

**操作**：点 "状态"

**期望**：
- 显示 table 是否就绪（是）
- 显示当前 CIDR 条数（与 nft set 一致）
- 显示代理连通状态
- 显示数据文件版本/时间
- 有「同步省市数据」按钮

**验收**：[ ] 所有字段显示，[ ] CIDR 数准确

### S-2 同步省市数据

**操作**：点「同步省市数据」按钮

**期望**：bot 触发数据下载，完成后回复更新结果

**验收**：[ ] 不崩溃，[ ] 完成后已有省级白名单的 CIDR 自动更新

---

## 第七部分：管理员管理（仅主管理员）

### AD-1 查看管理员列表

**操作**：点 "管理员管理"

**期望**：显示当前管理员列表（至少含主管理员自己），有撤销按钮

**验收**：[ ] 列表正常，[ ] 主管理员自己不可撤销（或有保护逻辑）

### AD-2 添加新管理员

**操作**：
1. 点 "添加管理员"
2. 发送第二个测试账号的 user_id（数字）

**期望**：bot 添加成功，第二账号现在也能使用主菜单

**验收**：[ ] 添加成功，[ ] 第二账号权限生效

### AD-3 撤销管理员

**操作**：点新添加管理员旁的 🗑 撤销按钮

**期望**：撤销成功，第二账号失去权限

**验收**：[ ] 撤销后第二账号被拦截

---

## 第八部分：权限拦截测试

### P-1 非管理员访问拦截

**操作**：使用第三个（未授权）Telegram 账号向 bot 发送 `/start`

**期望**：
- bot 拒绝请求（静默或回复无权限）
- 不返回主菜单
- 服务器日志有拒绝记录

**验收**：[ ] 非授权用户被拦截

### P-2 非管理员按钮回调拦截

**背景**：即使 bot 不向非管理员显示按钮，必须在 callback 层也校验权限

**操作**：用非授权账号伪造 callback_data（如直接回放已知的 callback_data 字符串）

**期望**：callback 被拒绝，不执行操作

**注意**：此项需要技术手段构造回放请求，可先记录为「已知设计防护」，验证日志中有权限拒绝记录即可

**验收**：[ ] callback 权限校验已实现（review 确认）或 [ ] 实测拒绝

### P-3 非主管理员不能管理员管理

**操作**：用普通管理员账号（非主管理员）点击菜单

**期望**：主菜单不显示「管理员管理」按钮，或点击后被拒绝

**验收**：[ ] 普通管理员看不到/访问不到管理员管理

---

## 第九部分：Panic 测试

### PA-1 Panic 正常流程

**操作**：点 "紧急解除（Panic）" -> 看到二次确认 -> 点确认

**期望**：
- bot 回复「已解除全部限制」
- 服务器执行 `nft list tables` 看不到 `inet whitelist`
- SSH 仍然可以连接（现有已建连的 session 不中断）

**验收**：[ ] table 已删除，[ ] SSH 连接正常

### PA-2 Panic 取消

**操作**：点 "紧急解除" -> 点 "❌ 取消"

**期望**：什么都不发生，table 仍存在

**验收**：[ ] 取消有效

### PA-3 /panic 指令

**操作**：直接发送 `/panic` 指令

**期望**：同 PA-1 流程（同样需要二次确认）

**验收**：[ ] 指令有效，[ ] 需要二次确认

### PA-4 Bot 重启后自动恢复

**操作**：
1. 添加若干白名单条目
2. 执行 panic 删除 table
3. 重启 bot 服务：`systemctl restart tg-whitelist`

**期望**：
- Bot 重启后自动从 SQLite 重建 table/chain/set
- `nft list set inet whitelist whitelist4` 再次包含之前的条目

**验收**：[ ] 自动恢复，[ ] 条目完整

---

## 第十部分：异常与边界测试

### E-1 代理不通时 Bot 行为

**操作**：临时关闭 SOCKS5 代理，观察 bot 日志

**期望**：
- Bot 不崩溃，持续重试
- 本地 nftables 规则不受影响
- 日志有清晰的「代理连接失败」提示

**验收**：[ ] 不崩溃，[ ] nft 规则保持，[ ] 日志有提示

### E-2 Bot 崩溃后恢复

**操作**：强制 kill bot 进程 `systemctl kill -s SIGKILL tg-whitelist`

**期望**：
- systemd 自动重启（配置了 Restart=on-failure 或 always）
- 重启后规则自动恢复

**验收**：[ ] 自动重启，[ ] 规则恢复

### E-3 并发操作

**操作**：两个管理员账号同时发起添加操作

**期望**：不死锁、不数据竞争，两次操作都成功或有序排队

**验收**：[ ] 无崩溃，[ ] 规则最终一致

---

## 第十一部分：三态防火墙切换验收

> 前提：已有白名单条目（至少含一个公网 IP/CIDR），且有一个非 SSH 的开放测试端口（如 8080）可供验证被拒绝行为。

### FW-1 normal → lockdown：公网入站被封，SSH / 已建连不受影响

**操作**：
1. 确认当前模式为 normal（`nft list chain inet whitelist input` 能看到 `@whitelist4` accept 规则）
2. 点主菜单「防火墙模式」→「封城模式（lockdown）」→ 二次确认
3. 立即在**已有** SSH session 中执行 `echo ok`（测已建连不断）
4. 从**另一台机器**尝试连接测试端口（如 `nc -zv <server_ip> 8080`）
5. 从另一台机器尝试 SSH（`ssh ...`，**新连接**）

**期望**：
- bot 回复切换成功
- 已建 SSH session 不中断（步骤 3 正常返回）
- 步骤 4 新连接被拒（Connection refused 或 timeout）
- 步骤 5 新 SSH 连接也被拒（端口 22 同样受 lockdown 限制，除非已在 SSH 白名单）
- `nft list set inet whitelist whitelist4` 输出为空（set 已 flush）
- 数据库中原白名单条目仍存在（`sqlite3 whitelist.db "SELECT count(*) FROM whitelist_entries"`）

**验收**：[ ] 已建连不断，[ ] 新公网入站被拒，[ ] nft set 为空，[ ] DB 条目保留

### FW-2 lockdown → open：table 整个删除

**操作**：
1. 当前处于 lockdown 模式
2. 点「防火墙模式」→「放行模式（open）」→ 二次确认
3. 执行 `nft list tables`
4. 从另一台机器测试连接任意端口

**期望**：
- bot 回复切换成功
- `nft list tables` 看不到 `inet whitelist`（table 已删除）
- 所有入站端口均可连接（防火墙完全开放）

**验收**：[ ] table 已删除，[ ] 连通性完全恢复

### FW-3 open → normal：白名单自动恢复

**操作**：
1. 当前处于 open 模式
2. 点「防火墙模式」→「正常模式（normal）」→ 二次确认
3. 执行 `nft list set inet whitelist whitelist4`

**期望**：
- bot 回复切换成功，并提示已恢复 N 条规则
- nft set 中重新出现原白名单条目（从 DB 重建）
- 公网入站再次受白名单控制

**验收**：[ ] set 条目恢复，[ ] 防火墙重新生效

### FW-4 重启持久性验证

**操作**：
1. 将模式切换到 lockdown，确认 bot 回复成功
2. 执行 `systemctl restart tg-whitelist`
3. 重启后检查 nftables 状态

**期望**：
- 重启后仍处于 lockdown 状态（nft set 为空，chain 保留 SSH/lo/established 规则）
- Bot 日志显示「从持久状态恢复：lockdown」或类似提示

**验收**：[ ] 重启后持久 lockdown，[ ] 非 normal 规则自动重建

### FW-5 /panic 临时放行（不持久）

**操作**：
1. 确认当前模式为 normal（或 lockdown）
2. 发送 `/panic` → 二次确认
3. 验证 `nft list tables` 看不到 `inet whitelist`
4. 执行 `systemctl restart tg-whitelist`
5. 重启后再次检查 nftables 状态

**期望**：
- `/panic` 后 table 立即删除（同 open 效果）
- 重启后自动恢复到 `/panic` 之前的持久模式（如 normal），nft set 含原白名单
- `/panic` 不更改持久化模式记录

**验收**：[ ] panic 立即放行，[ ] 重启后恢复持久模式，[ ] DB 条目未丢失

---

## 第十二部分：归属查询精度验收

> 前提：准备两种测试状态——（A）`config.toml` 中 `ip2location_io_key` 已填写有效 key；（B）key 置空或注释掉。

### GEO-1 IP2Location.io 在线查询（国内 IP）

**操作**：
1. 确认 `ip2location_io_key` 已配置（状态 A）
2. 点「查询 IP 归属」，发送一个中国大陆 IP（如 `114.114.114.114`）

**期望**：
- 返回结果来源标注 IP2Location.io（或精确到省市 ISP）
- 省市信息中文显示，精度优于 ip-api

**验收**：[ ] 省市信息准确，[ ] 标注 provider 为 ip2location_io

### GEO-2 IP2Location.io 在线查询（境外 IP）

**操作**：发送 `8.8.8.8`（Google DNS，美国）

**期望**：
- 返回「美国」+ 具体地区/ASN
- 同样来源标注 IP2Location.io

**验收**：[ ] 境外归属正确，[ ] provider 标注一致

### GEO-3 key 不可用时回落至 ip2region xdb

**操作**：
1. 将 `ip2location_io_key` 注释掉（状态 B），确认 `ip2region_xdb` 路径已配置且文件存在
2. 重启 bot（`systemctl restart tg-whitelist`）
3. 查询同一国内 IP

**期望**：
- 返回结果来自 ip2region 离线库（可在返回消息或日志中确认 provider）
- 不因 key 缺失崩溃，不请求 ip2location.io

**验收**：[ ] 离线 xdb 生效，[ ] 无报错

### GEO-4 xdb 也不可用时回落至 ip-api

**操作**：
1. 注释 `ip2location_io_key` 和 `ip2region_xdb`（两者均不配置）
2. 重启 bot
3. 查询国内 IP

**期望**：
- 返回结果来自 ip-api.com（最终兜底）
- 功能正常，不崩溃

**验收**：[ ] ip-api 兜底生效，[ ] 响应正常

### GEO-5 全部 provider 不可用时的提示

**操作**：
1. 注释所有 geo provider，且断开 SOCKS5 代理（使 ip-api 也不可达）
2. 查询任意 IP

**期望**：
- bot 返回友好提示（如「归属查询暂不可用」）
- 不崩溃，不返回空白消息

**验收**：[ ] 友好提示，[ ] 不崩溃

---

## 第十三部分：web auth 自动加白验收

> 前提：已按 `docs/deploy/web-auth.md` 完成 Cloudflare Worker 部署，并在 `config.toml` 的 `[cf_pull]` 中填写正确的 `worker_url`、`access_client_id`、`access_client_secret`，`enabled = true`。

### CF-1 浏览器认证 + 自报 v4 触发加白（完整流程）

**操作**：
1. 确认 `[cf_pull]` 已启用，`poll_interval_seconds` 建议临时改为 `30` 便于测试
2. 用尚未加白的设备访问受 Cloudflare Access 保护的 Worker URL（`GET /`）
3. 完成 Access 认证（policy 只放行本人邮箱）
4. 页面应展示两行：**Cloudflare 看到你**（可能是 IPv6）/ **你的 IPv4 出口**（网页 JS 探测：国内 `my.ip.cn` → 兜底 `api4.ipify.org`/`ipv4.icanhazip.com`）
5. 核对探测到的 v4 是你的真实出口，点「确认加入白名单」→ 页面显示「已提交成功 + Registration ID」
6. 等待最多一个 poll 周期（30 秒）
7. 在 Telegram 点「查看/管理」检查白名单列表
8. 服务器执行 `nft list set inet whitelist whitelist4`

**期望**：
- 列表中出现新条目，IP 为**网页探测到的 IPv4 出口**（不是 CF 看到的 v6），标注 🤖（自动加白）
- nft set 中包含该 IPv4
- bot 日志显示 `cf_pull: pulled N new IP(s)` 或类似提示

**验收**：[ ] 页面正确展示 CF-IP / v4 对比，[ ] 🤖 条目为 v4 出口（非 v6），[ ] nft set 生效，[ ] 日志有拉取记录

### CF-2 重复 pull 不重复写入

**操作**：
1. 等待再过至少两个 poll 周期
2. 检查白名单列表中该 IP 的条目数量

**期望**：
- 同一 IP 不会被重复写入，列表中只出现一次
- 日志显示「已存在，跳过」或 pull 幂等行为

**验收**：[ ] 无重复条目

### CF-3 封城模式下 pull 只写 DB 不解除封城

**操作**：
1. 切换到 lockdown 模式（确认 nft set 为空）
2. 用新 IP 访问 Worker 完成认证，等待 poll
3. 检查 bot 日志和白名单列表
4. 检查 nftables set

**期望**：
- DB 中出现新的 🤖 条目（pull 写入成功）
- nft set 仍为空（封城未解除）
- bot 日志提示「当前 lockdown 模式，IP 已入库但未更新 nft」或类似

**验收**：[ ] DB 有新条目，[ ] nft set 仍为空，[ ] 封城状态未变

### CF-4 Service Token 认证失败的错误处理

**操作**：
1. 临时将 `access_client_secret` 改为错误值
2. 等待一个 poll 周期
3. 检查 bot 日志

**期望**：
- 日志显示认证失败（401/403）错误
- Bot 不崩溃，继续运行
- 白名单不受影响

**验收**：[ ] 错误日志明确，[ ] bot 不崩溃，[ ] 不污染白名单

### CF-5 纯 IPv6 网络：页面提示无 v4 出口，不误加白

**操作**：
1. 用**纯 IPv6**（无 IPv4 出口）的网络设备访问 Worker URL，完成 Access 认证
2. 观察页面

**期望**：
- 页面「你的 IPv4 出口」显示「未检测到」，并提示需要 IPv4 网络
- **不显示**「确认加入白名单」按钮（无法提交）
- 不会把 CF 看到的 v6 地址写入白名单（v6 永远进不了 whitelist4）

**验收**：[ ] 提示无 v4 出口，[ ] 提交按钮隐藏，[ ] 白名单无 v6 条目

### CF-6 伪造非法/私有 IP 被 `/register` 拒绝（信任模型边界）

**背景**：IP 由客户端自报、可伪造，后端 `isPublicIPv4` 必须拦截非法/私有/保留地址。

**操作**：用**有效 Access 会话**（浏览器开发者工具 Console 或脚本）直接构造 `POST /register`，分别提交：
- 私有：`{"ip":"192.168.1.1"}`、`{"ip":"10.0.0.1"}`
- 回环：`{"ip":"127.0.0.1"}`
- CGNAT：`{"ip":"100.64.0.1"}`
- 非法格式：`{"ip":"01.02.03.04"}`（前导零）、`{"ip":"999.1.1.1"}`
- IPv6：`{"ip":"2001:db8::1"}`

**期望**：
- 每个请求都返回 **400 `Bad Request: invalid or non-public IPv4`**
- 这些地址都**不会**进入 KV / 白名单
- 另测：**不带** Access JWT 直接 `POST /register` 应返回 **403**（防绕过页面）

**验收**：[ ] 私有/回环/CGNAT/非法/v6 全部被拒（400），[ ] 无 JWT 被拒（403），[ ] 白名单未被污染

---

## 附：服务器端快速验证命令

```bash
# 查看完整 whitelist table
nft list table inet whitelist

# 查看 set 元素（CIDR 列表）
nft list set inet whitelist whitelist4

# 查看 chain 规则（规则顺序）
nft list chain inet whitelist input

# 统计 CIDR 条数
nft list set inet whitelist whitelist4 | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?" | wc -l

# 查看 bot 最新日志
journalctl -u tg-whitelist -n 50 --no-pager

# 运行 nftables 集成测试脚本（需 root）
sudo bash tests/integration_nftables.sh
```
