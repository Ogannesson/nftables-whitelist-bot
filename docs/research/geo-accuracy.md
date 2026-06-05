# IP 地理定位精度调研报告

> 调研日期：2026-06-05  
> 项目：tg-whitelist — Telegram nftables 入站 IP 白名单管理机器人  
> 调研人：researcher agent  
> 目标：为 `geo.py` 选型高精度 IP 定位方案，覆盖离线库（正查）、在线 API（正查）、反查（区域→CIDR）三个维度。

---

## 背景与现状

当前实现：

| 层级 | 当前方案 | 问题 |
|---|---|---|
| 正查（在线） | `ip-api.com` 免费接口，无 key，`lang=zh-CN` | 免费层精度一般，中国省市边界数据有偏差 |
| 正查（离线） | `ip2region ipv4_source.txt`（仅作兜底） | 数据不规律更新，仅文本扫描，未用 xdb 二进制索引 |
| 反查（区域→CIDR） | `metowolf/iplist` CDN（`cncity/{code}.txt`） | 依赖第三方 CDN，数据更新节奏依赖 metowolf 维护 |

需求：提升正查的省/市/ISP 准确率，尤其是中国境内 IP 的省市边界；同时保持反查能力。

---

## 一、离线库对比

### 1.1 候选库汇总表

| 库 | 协议 | 文件大小 | 查询速度 | Python 支持 | 中国城市精度 | 数据更新 | 反查支持 |
|---|---|---|---|---|---|---|---|
| **ip2region xdb v2.0** | Apache-2.0 | ~11 MiB (IPv4) | ~10 μs（全内存模式） | `py-ip2region` v3.0.4 | 城市级，格式 `Country\|Province\|City\|ISP` | 项目数据不规律；商业数据每日 | **不支持**（仅正查） |
| **MaxMind GeoLite2** | CC BY-SA 4.0（需注册） | 65-75 MiB | 亚毫秒 | `geoip2` | 中国城市约 65-75%；ISP 85.69% | 每周一次 | 不支持 |
| **qqwry / ChunZhen** | 非商业免费 | ~12 MiB | 快 | `qqwry` Python 库 | ISP 准确率仅 27.24%（独立测评） | 每 5 天 | 不支持 |
| **IPIP.net** | 商业（免费版极受限） | — | — | ipdb Python SDK | 中国行业标准，精度最高 | 每日（付费） | 不支持 |
| **DB-IP Lite** | CC BY 4.0（Lite 免费） | ~35 MiB（MMDB） | 亚毫秒 | `geoip2` | Lite 版覆盖率和精度削减，中国城市偏低 | 每月 | 不支持 |
| **metowolf/iplist** | 无明确协议（GitHub 公开） | 按需下载 | 网络 I/O | 自实现 HTTP 下载 | 聚合多源，按行政区划维护 | 每日 CI 更新 | **原生支持**（反查核心） |

### 1.2 ip2region xdb v2.0 详细说明

- **格式**：`Country|ISP|Province|City|ISP`（实际字段顺序为 `国家|0|省|市|ISP|二位国家码`）
- **Python 包**：`pip install py-ip2region`（PyPI v3.0.4，2026-03-03 发布，Apache-2.0）
- **三种内存模式**：
  1. `file_search`：仅文件 I/O，内存极省，约 1-2 ms/次
  2. `vector_index_search`：加载向量索引（512 KB），约 100 μs/次
  3. `content_search`（全内存）：整个 xdb 载入内存（~11 MiB），约 10 μs/次，线程安全
- **API**：
  ```python
  from xdbSearcher import XdbSearcher
  searcher = XdbSearcher.newWithFileOnly("ip2region.xdb")  # 或 loadContent
  region = searcher.search("1.2.3.4")
  # → "中国|0|北京|北京市|电信"
  country, _, province, city, isp = region.split("|")
  ```
- **IPv6**：官方项目有单独 IPv6 xdb（文件更大）
- **数据问题**：项目自带数据（`data/` 目录）更新"不规律"；若需每日更新，可从 `adysec/IP_database` GitHub repo 获取每日同步的 xdb 文件，或购买 `ip2region.net` 商业数据

### 1.3 推荐

**离线库首选：ip2region xdb v2.0 + py-ip2region v3.0.4**

理由：
- Apache-2.0 协议，商业友好，无需注册
- 10 μs 级查询（全内存模式），适合高频鉴权场景
- 中国省市 ISP 字段完备，字段格式与现有 `OfflineGeo.get_cidrs_from_ip2region` 兼容
- 比 qqwry 精度高，比 MaxMind GeoLite2 对中国 ISP 路由更熟悉
- 可通过 `adysec/IP_database` 实现自动化每日更新，无需购买商业版

---

## 二、在线 API 对比

### 2.1 候选 API 汇总表

| API | 免费额度 | 是否需要 Key | 中国省市精度 | 中文输出 | HTTPS + 代理 | 稳定性/备注 |
|---|---|---|---|---|---|---|
| **ip-api.com**（当前） | 无限（非商业） | 否 | 一般 | 是（`lang=zh-CN`） | HTTP（免费层不支持 HTTPS） | 快，但无 HTTPS 免费层 |
| **ipgeolocation.io** | 1,000 次/天 | 是（免费注册） | 省+市，覆盖中国 | 英文（可选 lang） | HTTPS | 稳定，文档齐全 |
| **ip2location.io** | 50,000 次/月（带 Key）/ 1,000 次/天（无 Key） | 可选（强烈建议注册） | >75% 城市准确率，>99.5% 国家 | 英文 | HTTPS | 数据每日/每周更新 |
| **ipinfo.io** | 仅国家级（2025 后变更） | 否（免费国家级）/ Key（城市级需 $49/月 Core 套餐） | 城市级需付费 | 英文 | HTTPS | **已淘汰**：免费版 2025 后去掉省市字段 |
| **ipdata.co** | 1,500 次/天（非商业） | 是（免费注册） | 返回 region/city，中国精度无公开基准 | 英文 | HTTPS | 文档 2026 年初未更新；非商业限制 |
| **高德 (Amap) IP API** | 个人月配额（约 300 万次） | 是（免费注册） | 精确到区/县 + adcode | 中文（province/city 字段） | HTTPS | 2025-05-20 新定价；返回 adcode 可直接映射 cncity.json |
| **腾讯位置服务 IP 定位** | 个人 1 万次/天，企业 30 万次/天 | 是（免费注册） | 精确到区/县 + adcode（6位） | 中文 | HTTPS | 文档明确返回 province/city/district/adcode |
| **百度地图 IP API** | 约 1M 次/天（免费 AK） | 是（AK） | 官方自称"精度较差" | 中文 | HTTPS | **不推荐**：官方文档承认精度低 |
| **IPIP.net API** | 免费版极受限（需联系） | 是（需购买） | 中国行业最高精度 | 中文 | HTTPS | 商业产品，成本高 |

### 2.2 高德 IP API 详细说明

- 接口：`https://restapi.amap.com/v3/ip?ip=<IP>&key=<Key>`
- 返回示例：
  ```json
  {
    "status": "1",
    "province": "浙江省",
    "city": "杭州市",
    "adcode": "330100",
    "rectangle": "119.6379,29.77849;121.2986,30.56074"
  }
  ```
- **adcode 可直接作为 cncity.json 的 code 字段使用**（6 位行政区划码格式一致）
- Key 免费注册，2025-05-20 后新定价，个人/企业都有月配额
- 支持 IPv4；IPv6 支持情况需验证

### 2.3 腾讯位置服务 IP 定位详细说明

- 接口：`https://apis.map.qq.com/ws/location/v1/ip?ip=<IP>&key=<KEY>`
- 返回字段：`nation / province / city / district / adcode`（含6位 adcode，与 cncity 码一致）
- 个人免费额度 1 万次/天，企业 30 万次/天
- 支持 IPv6
- 精度：最高到区/县级

### 2.4 推荐

**在线 API 首选：高德 (Amap) IP API**

理由：
- 免费注册，月配额充足（个人约 300 万次）
- 直接返回中文 province/city + 6 位 adcode，与项目 `cncity.json` 的 code 格式一致
- HTTPS，支持通过项目现有 SOCKS5 代理路由
- 国内公信力高，中国 IP 精度优于境外服务
- adcode 可消除省市名称匹配歧义（现有 ip-api.com 方案须做字符串模糊匹配）

**备选：腾讯位置服务 IP 定位**（同样返回 adcode，个人 1 万/天略少，但精度相当）

**境外备选：ipgeolocation.io**（1,000 次/天免费，适合在国内 API 失效时兜底，不返回 adcode 需名称匹配）

---

## 三、反查（区域→CIDR）能力分析

### 3.1 结论

**所有离线正查库（ip2region、MaxMind、qqwry 等）均不原生支持反查。**

反查的定义：给定省/市代码 → 返回该区域所有 IP 段（CIDR 列表）。这需要遍历整个 IP 空间、按区域聚合，属于数据集编排工作，不是正查库的设计目标。

### 3.2 现有 ip2region 扫描方案评估

`geo.py` 中已有 `get_cidrs_from_ip2region(province, city)` 作为紧急兜底，其逻辑为：
1. 读取 `ipv4_source.txt`（约 600 万行）
2. 按省市字符串过滤
3. 用 `ipaddress.collapse_addresses()` 聚合 CIDR

**缺点**：
- 每次调用需全量扫描文本文件（单次 5-15 秒）
- 字符串匹配依赖名称完全一致，易出错
- 文件 600+ MiB，不宜频繁重读
- 不适合作主路径，仍是紧急兜底

### 3.3 建议：保留 metowolf/iplist 为反查主路径

`metowolf/iplist`（`cncity/{code}.txt`）：
- 每日自动 CI 更新（GitHub Actions 驱动）
- 直接按 6 位行政区划码组织，与项目 code 体系完全对应
- 每个文件只含该区域 CIDR，无需遍历整个 IP 空间
- `_read_txt` 对每行做 `ipaddress.ip_network` 强校验，过滤脏数据

**结论**：`lookup_cidrs_for_area` 的主路径继续保留 metowolf CDN 下载；ip2region 扫描保留为兜底（当 CDN 不可达时）。不需要修改反查逻辑。

---

## 四、数据更新方案

### 4.1 ip2region xdb 更新

推荐使用 `adysec/IP_database` 仓库（每日 CI 同步多源数据库）：

```
https://github.com/adysec/IP_database/raw/main/ip2region/ip2region.xdb
```

可在 `scripts/fetch_geo.py` 中新增 `--ip2region-xdb` 子命令，替换当前 `--ip2region`（下载 `ipv4_source.txt`）。

### 4.2 高德 API Key 管理

Key 写入 `config.toml`，通过现有 `redact_credentials()` 脱敏。参考现有 `geo.cfg.amap_key` 字段（若不存在则新增）。

---

## 五、geo.py 最小改造路径

> **原则**：不改变 `GeoService.lookup_ip()` 和 `GeoService.lookup_cidrs_for_area()` 的对外签名；只替换内部实现细节。

### 5.1 离线正查：从 ipv4_source.txt → xdb 二进制索引

**当前**：`OfflineGeo.get_cidrs_from_ip2region()` 全量扫描文本文件（兜底用）

**改造**：新增 `XdbSearcher` 封装，替换文本扫描，作为在线 API 失效时的主离线路径：

```python
# geo.py 新增（在 OfflineGeo 内或独立类）
from xdbSearcher import XdbSearcher  # pip install py-ip2region

class XdbGeo:
    def __init__(self, xdb_path: Path):
        content = xdb_path.read_bytes()
        self._searcher = XdbSearcher.newWithBuffer(content)  # 全内存，线程安全

    def lookup(self, ip: str) -> IpInfo | None:
        region = self._searcher.search(ip)
        if not region:
            return None
        parts = region.split("|")
        # 格式: Country|0|Province|City|ISP
        country = parts[0]
        province = parts[2] if len(parts) > 2 else ""
        city = parts[3] if len(parts) > 3 else ""
        isp = parts[4] if len(parts) > 4 else ""
        return IpInfo(ip=ip, country=country, province=province, city=city, isp=isp)
```

### 5.2 在线正查：新增高德 Provider

**当前**：`OnlineGeo` 仅有 ip-api.com（一个 provider）

**改造**：新增 `AmapOnlineGeo`（或在 `OnlineGeo` 内部扩展 provider 列表）：

```python
class AmapOnlineGeo:
    """高德 IP 定位（返回 adcode，直接映射 cncity 码）"""
    BASE = "https://restapi.amap.com/v3/ip"

    def __init__(self, key: str, proxy_url: str = ""):
        self._key = key
        self._proxy = {"all://": proxy_url} if proxy_url else None

    def lookup(self, ip: str) -> IpInfo | None:
        import httpx
        params = {"ip": ip, "key": self._key, "output": "json"}
        with httpx.Client(proxies=self._proxy, timeout=10) as client:
            r = client.get(self.BASE, params=params)
            r.raise_for_status()
        data = r.json()
        if data.get("status") != "1":
            return None
        return IpInfo(
            ip=ip,
            country="中国",
            province=data.get("province", ""),
            city=data.get("city", ""),
            isp="",
            adcode=str(data.get("adcode", "")),  # 6 位行政区划码
        )
```

**注意**：`IpInfo` 可选加 `adcode: str = ""` 字段，供 `GeoService.lookup_ip` 调用方使用（adcode 可直接传给 `lookup_cidrs_for_area` 而无需名称匹配）。

### 5.3 GeoService 级联顺序建议

```
lookup_ip(ip):
  1. AmapOnlineGeo（高德，带 key，HTTPS，精度最高）
  2. IpApiOnlineGeo（现有 ip-api.com，无 key，免费兜底）
  3. XdbGeo（本地 xdb，离线兜底）
  4. ip2region 文本扫描（最后兜底，保留现有逻辑）
```

### 5.4 config.toml 新增字段

```toml
[geo]
data_dir = "data"
amap_key = ""          # 高德 IP API Key（新增）
ip2region_xdb = ""     # xdb 文件路径，留空则跳过 XdbGeo（新增）
```

### 5.5 fetch_geo.py 新增子命令

```bash
python scripts/fetch_geo.py --ip2region-xdb    # 下载 xdb 二进制索引（替代 --ip2region 的文本源）
```

下载 URL：`https://github.com/adysec/IP_database/raw/main/ip2region/ip2region.xdb`

---

## 六、各维度最终推荐

| 维度 | 推荐 | 备注 |
|---|---|---|
| **离线正查** | ip2region xdb v2.0 + py-ip2region | Apache-2.0，10 μs，11 MiB，支持全内存线程安全模式；数据从 adysec/IP_database 每日同步 |
| **在线正查（主）** | 高德 Amap IP API | 免费 key，月配额充足，返回中文+adcode，HTTPS+代理支持 |
| **在线正查（境外兜底）** | ipgeolocation.io | 1,000 次/天免费，城市+省，API key，HTTPS |
| **反查（区域→CIDR）** | 保留 metowolf/iplist | 无需改动，每日 CI 更新，按 adcode 组织 |

---

## 七、风险与注意事项

1. **ip2region 数据更新**：项目自带数据不规律更新；必须配合 adysec/IP_database 或购买商业版才能保持精度
2. **高德 API Key 安全**：Key 写入 config 并经 `redact_credentials()` 脱敏，不得硬编码或提交至 git；高德文档建议不在前端暴露 Key
3. **高德新定价（2025-05-20）**：月配额和 QPS 限制以注册时实际政策为准，需定期检查
4. **ipinfo.io 已淘汰**：2025 年后免费层仅返回国家级，不适合省市场景
5. **百度 IP API**：官方文档自称"精度较差"，不建议用于高精度场景
6. **DB-IP Lite**：Lite 版精度打折，中国城市覆盖不足，不推荐
7. **qqwry**：ISP 准确率仅 27.24%（第三方测评），不适合需要 ISP 信息的场景
8. **adcode 字段兼容性**：若 `IpInfo` 新增 `adcode` 字段，需确保现有调用方兼容（加默认值 `""` 即可，不破坏现有接口）

---

## 参考资料

- ip2region 官方：https://github.com/lionsoul2014/ip2region
- py-ip2region PyPI：https://pypi.org/project/py-ip2region/
- adysec/IP_database（每日同步）：https://github.com/adysec/IP_database
- MaxMind GeoLite2 精度报告：https://www.maxmind.com/en/geoip2-city-accuracy
- 高德 IP 定位 API 文档：https://lbs.qq.com/service/webService/webServiceGuide/webServiceIp
- 腾讯位置服务 IP 定位：https://lbs.qq.com/service/webService/webServiceGuide/webServiceIp
- ipgeolocation.io：https://ipgeolocation.io/
- ip2location.io 定价：https://www.ip2location.io/pricing
- IPIP.net 产品：https://en.ipip.net/product/ip.html
- DB-IP Lite：https://db-ip.com/db/lite.php
- metowolf/iplist：https://github.com/metowolf/iplist
