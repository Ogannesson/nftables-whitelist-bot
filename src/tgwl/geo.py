"""
geo.py — 地理 IP 能力

两大功能：
1. 离线反查：省/市名 → CIDR 列表
   - 主路径：下载 metowolf/iplist cncity/{code}.txt（缓存到 data/cncity/）
   - 兜底路径：读 ip2region ipv4_source.txt，按省/市过滤，转 CIDR

2. 在线正向查询：IP → 省市/ISP（不支持反查）
   - provider：ip-api.com（免 key，无需配置任何 API key）
   - 所有 HTTP 请求走配置的 SOCKS5 代理（httpx）

行政区划码：6 位数字，省级 xx0000，市级 xxxxxx
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx

from tgwl.config import redact_credentials

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# 行政区划码数据（内嵌 JSON）                                                   #
# --------------------------------------------------------------------------- #

_CNCITY_JSON = Path(__file__).parent / "data" / "cncity.json"


@dataclass
class GeoArea:
    code: str          # 6 位行政区划码
    name: str          # 完整名称（"浙江省"）
    short: str         # 简称（"浙江"）
    is_province: bool
    province_code: str  # 省级码（市级有效；省级 = code 本身）


class RegionRegistry:
    """行政区划码注册表（从内嵌 JSON 加载）。"""

    def __init__(self) -> None:
        with open(_CNCITY_JSON, encoding="utf-8") as f:
            data = json.load(f)

        self._by_code: dict[str, GeoArea] = {}
        self._provinces: list[GeoArea] = []
        self._cities: list[GeoArea] = []

        for p in data["provinces"]:
            area = GeoArea(
                code=p["code"],
                name=p["name"],
                short=p["short"],
                is_province=True,
                province_code=p["code"],
            )
            self._by_code[p["code"]] = area
            self._provinces.append(area)

        for c in data["cities"]:
            area = GeoArea(
                code=c["code"],
                name=c["name"],
                short=c["short"],
                is_province=False,
                province_code=c["province_code"],
            )
            self._by_code[c["code"]] = area
            self._cities.append(area)

    def get_by_code(self, code: str) -> Optional[GeoArea]:
        return self._by_code.get(code)

    def search(self, query: str) -> list[GeoArea]:
        """
        模糊搜索省市，返回匹配候选（优先精确匹配，再前缀/包含）。
        `query` 支持：省市全名、简称、行政区划码。
        """
        q = query.strip()
        if not q:
            return []

        # 1. 行政区划码精确匹配
        if re.fullmatch(r"\d{6}", q):
            area = self._by_code.get(q)
            return [area] if area else []

        candidates: list[GeoArea] = []
        seen: set[str] = set()

        all_areas = self._provinces + self._cities

        # 2. 精确名称匹配（name / short）
        for area in all_areas:
            if area.name == q or area.short == q:
                if area.code not in seen:
                    candidates.append(area)
                    seen.add(area.code)

        # 3. 前缀匹配（name.startswith / short.startswith）
        for area in all_areas:
            if area.code in seen:
                continue
            if area.name.startswith(q) or area.short.startswith(q):
                candidates.append(area)
                seen.add(area.code)

        # 4. 包含匹配
        for area in all_areas:
            if area.code in seen:
                continue
            if q in area.name or q in area.short:
                candidates.append(area)
                seen.add(area.code)

        return candidates

    def list_provinces(self) -> list[GeoArea]:
        return list(self._provinces)

    def list_cities_by_province(self, province_code: str) -> list[GeoArea]:
        return [c for c in self._cities if c.province_code == province_code]


# 全局注册表单例
_registry: RegionRegistry | None = None


def get_registry() -> RegionRegistry:
    global _registry
    if _registry is None:
        _registry = RegionRegistry()
    return _registry


# --------------------------------------------------------------------------- #
# 离线反查 — CIDR 获取                                                          #
# --------------------------------------------------------------------------- #

IPLIST_BASE_URL = "https://metowolf.github.io/iplist/data/cncity"


class OfflineGeo:
    """
    离线省市 CIDR 查询。

    主路径：从 metowolf/iplist CDN 下载 {code}.txt（缓存）。
    兜底路径：读 ip2region ipv4_source.txt。
    """

    def __init__(
        self,
        data_dir: Path,
        proxy_url: str = "",
        http_timeout: float = 30.0,
    ) -> None:
        self._data_dir = data_dir
        self._cncity_dir = data_dir / "cncity"
        self._cncity_dir.mkdir(parents=True, exist_ok=True)
        self._proxy_url = proxy_url
        self._timeout = http_timeout

    # ------------------------------------------------------------------ #
    # 主路径：iplist txt                                                   #
    # ------------------------------------------------------------------ #

    def get_cidrs_for_code(self, code: str) -> list[str]:
        """
        返回指定行政区划码的 CIDR 列表。
        先读缓存，缓存不存在则网络下载。
        """
        cache_file = self._cncity_dir / f"{code}.txt"
        if cache_file.exists():
            return self._read_txt(cache_file)
        # 尝试下载
        return self._download_and_cache(code)

    def refresh_code(self, code: str) -> list[str]:
        """强制重新下载并更新缓存。"""
        return self._download_and_cache(code)

    def _read_txt(self, path: Path) -> list[str]:
        """从文件读取 CIDR 列表（每行一个，忽略注释和空行）。"""
        lines = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                lines.append(line)
        return lines

    def _download_and_cache(self, code: str) -> list[str]:
        """下载 iplist CDN 的 {code}.txt，写缓存，返回 CIDR 列表。"""
        url = f"{IPLIST_BASE_URL}/{code}.txt"
        proxies = {"all://": self._proxy_url} if self._proxy_url else None
        try:
            with httpx.Client(
                proxies=proxies,
                timeout=self._timeout,
                follow_redirects=True,
            ) as client:
                resp = client.get(url)
                resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                logger.warning("iplist 无 code=%s 的数据（404），返回空列表", code)
                return []
            raise
        except Exception as e:
            logger.error("下载 iplist code=%s 失败: %s", code, redact_credentials(str(e)))
            raise

        content = resp.text
        cache_file = self._cncity_dir / f"{code}.txt"
        cache_file.write_text(content, encoding="utf-8")
        logger.debug("已缓存 %s CIDR 数据 -> %s", code, cache_file)
        return self._read_txt(cache_file)

    # ------------------------------------------------------------------ #
    # 兜底路径：ip2region                                                  #
    # ------------------------------------------------------------------ #

    def get_cidrs_from_ip2region(
        self, province: str = "", city: str = ""
    ) -> list[str]:
        """
        从 ip2region ipv4_source.txt 按省/市名过滤，返回 CIDR 列表。

        ipv4_source.txt 格式（每行）：
          startIP|endIP|国|区|省|市|ISP
        """
        source_file = self._data_dir / "ipv4_source.txt"
        if not source_file.exists():
            logger.warning("ip2region 兜底文件不存在: %s", source_file)
            return []

        ranges: list[tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]] = []
        try:
            with open(source_file, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("|")
                    if len(parts) < 6:
                        continue
                    start_ip_int, end_ip_int = int(parts[0]), int(parts[1])
                    line_province = parts[4].strip()
                    line_city = parts[5].strip()

                    match = True
                    if province and province not in line_province:
                        match = False
                    if city and city not in line_city:
                        match = False
                    if not match:
                        continue

                    try:
                        start = ipaddress.IPv4Address(start_ip_int)
                        end = ipaddress.IPv4Address(end_ip_int)
                        ranges.append((start, end))
                    except Exception:
                        continue
        except Exception as e:
            logger.error("读取 ip2region 兜底文件失败: %s", e)
            return []

        # 转 CIDR
        cidrs: list[str] = []
        for start, end in ranges:
            try:
                nets = list(ipaddress.summarize_address_range(start, end))
                cidrs.extend(str(n) for n in nets)
            except Exception:
                continue

        return cidrs


# --------------------------------------------------------------------------- #
# CIDR 工具                                                                     #
# --------------------------------------------------------------------------- #

def collapse_cidrs(cidr_list: list[str]) -> list[str]:
    """
    将 CIDR 字符串列表去重合并，返回最小覆盖列表（已排序）。
    无效输入静默跳过。
    """
    networks: list[ipaddress.IPv4Network] = []
    for s in cidr_list:
        s = s.strip()
        if not s:
            continue
        try:
            net = ipaddress.ip_network(s, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                networks.append(net)
        except ValueError:
            logger.debug("collapse_cidrs: 跳过无效 CIDR %r", s)

    if not networks:
        return []
    return [str(n) for n in ipaddress.collapse_addresses(networks)]


# --------------------------------------------------------------------------- #
# 在线正向查询（IP → 省市/ISP）                                                 #
# --------------------------------------------------------------------------- #

@dataclass
class IpInfo:
    ip: str
    country: str = ""
    province: str = ""
    city: str = ""
    isp: str = ""
    raw: dict = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.raw is None:
            self.raw = {}

    def display(self) -> str:
        parts = [p for p in [self.country, self.province, self.city, self.isp] if p]
        return " / ".join(parts) if parts else "未知"


class OnlineGeo:
    """
    在线 IP 归属查询（正向查询，IP → 省市）。
    注意：在线 provider 不支持反查（省市 → IP 段）。

    唯一支持的 provider：ip-api.com（免 key，无需任何 API 凭据）。
    若 online_provider 配置为其他值，回退到 ip-api 并记录警告。
    """

    def __init__(
        self,
        provider: str = "ip-api",
        proxy_url: str = "",
        timeout: float = 10.0,
    ) -> None:
        if provider != "ip-api":
            logger.warning(
                "OnlineGeo: 不支持的 provider %r，已回退到 ip-api（免 key）",
                provider,
            )
        self._provider = "ip-api"
        self._proxy_url = proxy_url
        self._timeout = timeout

    def _make_client(self) -> httpx.Client:
        proxies = {"all://": self._proxy_url} if self._proxy_url else None
        return httpx.Client(
            proxies=proxies,
            timeout=self._timeout,
            follow_redirects=True,
        )

    def lookup(self, ip: str) -> IpInfo:
        """查询 IP 归属地。失败时抛出异常。"""
        try:
            ipaddress.ip_address(ip)
        except ValueError as e:
            raise ValueError(f"无效 IP 地址: {ip!r}") from e

        return self._lookup_ip_api(ip)

    def _lookup_ip_api(self, ip: str) -> IpInfo:
        """ip-api.com 查询（免 key，lang=zh-CN）。"""
        url = f"http://ip-api.com/json/{ip}?lang=zh-CN&fields=status,country,regionName,city,isp"
        with self._make_client() as client:
            resp = client.get(url)
            resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            raise RuntimeError(f"ip-api 查询失败: {data}")
        return IpInfo(
            ip=ip,
            country=data.get("country", ""),
            province=data.get("regionName", ""),
            city=data.get("city", ""),
            isp=data.get("isp", ""),
            raw=data,
        )


# --------------------------------------------------------------------------- #
# GeoService — 统一入口（供 handlers 调用）                                     #
# --------------------------------------------------------------------------- #

class GeoService:
    """
    统一地理服务入口：
    - lookup_cidrs_for_area(code) → 离线反查 CIDR（省/市）
    - lookup_ip(ip) → 在线正向查询
    - search_area(query) → 模糊搜索省市
    """

    def __init__(
        self,
        data_dir: Path,
        proxy_url: str = "",
        online_provider: str = "ip-api",
    ) -> None:
        self._offline = OfflineGeo(data_dir=data_dir, proxy_url=proxy_url)
        self._online = OnlineGeo(
            provider=online_provider,
            proxy_url=proxy_url,
        )
        self._registry = get_registry()

    def lookup_cidrs_for_area(
        self, code: str, force_refresh: bool = False
    ) -> list[str]:
        """
        给定行政区划码，返回展开并去重的 CIDR 列表。
        省级码：直接查 {code}.txt。
        市级码：也直接查 {code}.txt（iplist 有市级数据）。
        """
        if force_refresh:
            raw = self._offline.refresh_code(code)
        else:
            raw = self._offline.get_cidrs_for_code(code)
        return collapse_cidrs(raw)

    def lookup_ip(self, ip: str) -> IpInfo:
        """在线正向查询 IP 归属地。"""
        return self._online.lookup(ip)

    def search_area(self, query: str) -> list[GeoArea]:
        """模糊搜索省市（同 RegionRegistry.search）。"""
        return self._registry.search(query)

    def get_area(self, code: str) -> Optional[GeoArea]:
        return self._registry.get_by_code(code)

    def list_provinces(self) -> list[GeoArea]:
        return self._registry.list_provinces()

    def list_cities_by_province(self, province_code: str) -> list[GeoArea]:
        return self._registry.list_cities_by_province(province_code)

    def ip2region_fallback(self, code: str) -> list[str]:
        """使用 ip2region 兜底查询（code 对应的省/市名）。"""
        area = self._registry.get_by_code(code)
        if area is None:
            logger.warning("ip2region 兜底：未知行政区划码 %s", code)
            return []
        if area.is_province:
            return collapse_cidrs(
                self._offline.get_cidrs_from_ip2region(province=area.short)
            )
        else:
            return collapse_cidrs(
                self._offline.get_cidrs_from_ip2region(city=area.short)
            )
