"""
tests/test_geo.py — geo.py 单元测试

测试：
  - 行政区划码注册表（RegionRegistry）搜索与查询
  - 离线反查：CIDR 文件解析、ip2region 区间 → CIDR 转换
  - 在线查询：mock httpx，验证解析逻辑
  - collapse_cidrs 去重合并
"""

from __future__ import annotations

import ipaddress
import json
import struct
import pytest
import httpx
from pathlib import Path
from unittest.mock import MagicMock, patch

from tgwl.geo import (
    GeoArea,
    RegionRegistry,
    OfflineGeo,
    OnlineGeo,
    GeoService,
    IpInfo,
    collapse_cidrs,
    get_registry,
)


# --------------------------------------------------------------------------- #
# RegionRegistry 测试                                                           #
# --------------------------------------------------------------------------- #

class TestRegionRegistry:
    @pytest.fixture
    def registry(self) -> RegionRegistry:
        return RegionRegistry()

    def test_load_provinces(self, registry: RegionRegistry):
        provinces = registry.list_provinces()
        assert len(provinces) >= 30
        codes = {p.code for p in provinces}
        assert "330000" in codes  # 浙江
        assert "440000" in codes  # 广东

    def test_load_cities_for_province(self, registry: RegionRegistry):
        cities = registry.list_cities_by_province("330000")
        assert len(cities) >= 10  # 浙江至少 11 市
        names = {c.name for c in cities}
        assert "杭州市" in names
        assert "宁波市" in names

    def test_get_by_code_province(self, registry: RegionRegistry):
        area = registry.get_by_code("330000")
        assert area is not None
        assert area.name == "浙江省"
        assert area.short == "浙江"
        assert area.is_province is True

    def test_get_by_code_city(self, registry: RegionRegistry):
        area = registry.get_by_code("330100")
        assert area is not None
        assert area.name == "杭州市"
        assert area.is_province is False
        assert area.province_code == "330000"

    def test_get_by_code_not_exist(self, registry: RegionRegistry):
        assert registry.get_by_code("999999") is None

    def test_search_exact_name(self, registry: RegionRegistry):
        results = registry.search("浙江省")
        assert len(results) >= 1
        assert any(r.code == "330000" for r in results)

    def test_search_short_name(self, registry: RegionRegistry):
        results = registry.search("浙江")
        assert len(results) >= 1
        assert any(r.code == "330000" for r in results)

    def test_search_by_code(self, registry: RegionRegistry):
        results = registry.search("330000")
        assert len(results) == 1
        assert results[0].code == "330000"

    def test_search_prefix(self, registry: RegionRegistry):
        results = registry.search("广")
        # 应该命中广东省、广西、广州市、广安市等
        assert len(results) >= 2

    def test_search_city_name(self, registry: RegionRegistry):
        results = registry.search("杭州")
        assert any(r.code == "330100" for r in results)

    def test_search_empty(self, registry: RegionRegistry):
        assert registry.search("") == []

    def test_search_no_match(self, registry: RegionRegistry):
        assert registry.search("不存在的城市名xyz") == []

    def test_province_code_format(self, registry: RegionRegistry):
        """省级码末 4 位应为 0000。"""
        for p in registry.list_provinces():
            assert p.code.endswith("0000"), f"{p.code} 不是省级码格式"

    def test_city_province_code_valid(self, registry: RegionRegistry):
        """市级条目的 province_code 必须是已知省级码。"""
        province_codes = {p.code for p in registry.list_provinces()}
        for p_code in province_codes:
            cities = registry.list_cities_by_province(p_code)
            for c in cities:
                assert c.province_code == p_code


# --------------------------------------------------------------------------- #
# OfflineGeo 测试                                                               #
# --------------------------------------------------------------------------- #

class TestOfflineGeo:
    @pytest.fixture
    def geo(self, tmp_path: Path) -> OfflineGeo:
        return OfflineGeo(data_dir=tmp_path, proxy_url="")

    def test_read_txt_from_cache(self, geo: OfflineGeo, tmp_path: Path):
        """缓存文件存在时直接读取，不发网络请求。"""
        cache_file = tmp_path / "cncity" / "330000.txt"
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(
            "# comment\n1.0.0.0/8\n2.0.0.0/8\n\n3.0.0.0/8\n",
            encoding="utf-8",
        )
        cidrs = geo.get_cidrs_for_code("330000")
        assert cidrs == ["1.0.0.0/8", "2.0.0.0/8", "3.0.0.0/8"]

    def test_download_and_cache(self, geo: OfflineGeo, tmp_path: Path):
        """无缓存时触发下载，写入缓存。"""
        mock_response = MagicMock()
        mock_response.text = "10.0.0.0/24\n11.0.0.0/24\n"
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.Client") as mock_client_class:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get = MagicMock(return_value=mock_response)
            mock_client_class.return_value = mock_client

            cidrs = geo.refresh_code("330000")

        assert "10.0.0.0/24" in cidrs
        # 缓存文件应已创建
        assert (tmp_path / "cncity" / "330000.txt").exists()

    def test_ip2region_province_filter(self, geo: OfflineGeo, tmp_path: Path):
        """ip2region 兜底：按省过滤并正确转 CIDR。"""
        # 写一个最小的 ipv4_source.txt
        # 格式: startIP|endIP|国|区|省|市|ISP（IP 为整数）
        def ip_int(s: str) -> int:
            return int(ipaddress.IPv4Address(s))

        lines = [
            f"{ip_int('1.0.0.0')}|{ip_int('1.0.0.255')}|中国|华东|浙江省|杭州市|电信",
            f"{ip_int('2.0.0.0')}|{ip_int('2.0.0.255')}|中国|华南|广东省|广州市|联通",
            f"{ip_int('3.0.0.0')}|{ip_int('3.0.0.127')}|中国|华东|浙江省|宁波市|移动",
        ]
        source = tmp_path / "ipv4_source.txt"
        source.write_text("\n".join(lines), encoding="utf-8")

        result = geo.get_cidrs_from_ip2region(province="浙江")
        # 应包含浙江的两段
        assert any("1.0.0.0" in r for r in result), f"期望含 1.0.0.0/24，实际: {result}"
        assert any("3.0.0.0" in r for r in result), f"期望含 3.0.0.0/25，实际: {result}"
        # 广东的不应包含
        assert not any("2.0.0.0" in r for r in result)

    def test_ip2region_city_filter(self, geo: OfflineGeo, tmp_path: Path):
        """ip2region 兜底：按市过滤。"""
        def ip_int(s: str) -> int:
            return int(ipaddress.IPv4Address(s))

        lines = [
            f"{ip_int('1.0.0.0')}|{ip_int('1.0.0.255')}|中国|华东|浙江省|杭州市|电信",
            f"{ip_int('2.0.0.0')}|{ip_int('2.0.0.255')}|中国|华东|浙江省|宁波市|联通",
        ]
        source = tmp_path / "ipv4_source.txt"
        source.write_text("\n".join(lines), encoding="utf-8")

        result = geo.get_cidrs_from_ip2region(city="杭州")
        assert any("1.0.0.0" in r for r in result)
        assert not any("2.0.0.0" in r for r in result)

    def test_ip2region_file_not_exist(self, geo: OfflineGeo):
        """兜底文件不存在时返回空列表，不崩溃。"""
        result = geo.get_cidrs_from_ip2region(province="浙江")
        assert result == []


# --------------------------------------------------------------------------- #
# collapse_cidrs 测试                                                           #
# --------------------------------------------------------------------------- #

class TestCollapseCidrs:
    def test_merges_adjacent(self):
        result = collapse_cidrs(["10.0.0.0/25", "10.0.0.128/25"])
        assert "10.0.0.0/24" in result

    def test_dedup(self):
        result = collapse_cidrs(["192.168.1.0/24", "192.168.1.0/24"])
        assert len(result) == 1

    def test_invalid_skipped(self):
        result = collapse_cidrs(["invalid", "1.0.0.0/8"])
        assert len(result) == 1
        assert result[0] == "1.0.0.0/8"

    def test_empty_returns_empty(self):
        assert collapse_cidrs([]) == []

    def test_host_bits_normalized(self):
        result = collapse_cidrs(["10.0.0.1/24"])
        assert "10.0.0.0/24" in result

    def test_sorted_output(self):
        result = collapse_cidrs(["200.0.0.0/8", "100.0.0.0/8", "1.0.0.0/8"])
        ips = [ipaddress.IPv4Network(r) for r in result]
        assert ips == sorted(ips)


# --------------------------------------------------------------------------- #
# OnlineGeo 测试（mock httpx）                                                  #
# --------------------------------------------------------------------------- #

class TestOnlineGeo:
    def _make_mock_response(self, json_data: dict) -> MagicMock:
        mock_resp = MagicMock()
        mock_resp.json.return_value = json_data
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    def _make_client_context(self, response: MagicMock) -> MagicMock:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get = MagicMock(return_value=response)
        return mock_client

    def test_ip_api_success(self):
        geo = OnlineGeo(provider="ip-api")
        resp_data = {
            "status": "success",
            "country": "中国",
            "regionName": "浙江省",
            "city": "杭州市",
            "isp": "中国电信",
        }
        resp = self._make_mock_response(resp_data)
        with patch("httpx.Client", return_value=self._make_client_context(resp)):
            info = geo.lookup("1.2.3.4")
        assert info.province == "浙江省"
        assert info.city == "杭州市"
        assert info.isp == "中国电信"
        assert info.country == "中国"

    def test_ip_api_failure_raises(self):
        geo = OnlineGeo(provider="ip-api")
        resp_data = {"status": "fail", "message": "private range"}
        resp = self._make_mock_response(resp_data)
        with patch("httpx.Client", return_value=self._make_client_context(resp)):
            with pytest.raises(RuntimeError, match="ip-api 查询失败"):
                geo.lookup("192.168.1.1")

    def test_unknown_provider_falls_back_to_ip_api(self):
        """未知 provider 回退到 ip-api（而非抛异常），查询正常进行。"""
        geo = OnlineGeo(provider="unknown_provider")
        # 回退后 _provider 应为 ip-api
        assert geo._provider == "ip-api"

    def test_invalid_ip_raises(self):
        geo = OnlineGeo(provider="ip-api")
        with pytest.raises(ValueError, match="无效 IP"):
            geo.lookup("not-an-ip")

    def test_ipinfo_display(self):
        info = IpInfo(ip="1.2.3.4", country="中国", province="浙江省", city="杭州市", isp="电信")
        assert "浙江省" in info.display()
        assert "杭州市" in info.display()

    def test_ipinfo_display_empty(self):
        info = IpInfo(ip="1.2.3.4")
        assert info.display() == "未知"


# --------------------------------------------------------------------------- #
# GeoService 整合测试                                                           #
# --------------------------------------------------------------------------- #

class TestGeoService:
    @pytest.fixture
    def service(self, tmp_path: Path) -> GeoService:
        return GeoService(data_dir=tmp_path, proxy_url="")

    def test_search_area(self, service: GeoService):
        results = service.search_area("浙江")
        assert any(r.code == "330000" for r in results)

    def test_list_provinces(self, service: GeoService):
        provinces = service.list_provinces()
        assert len(provinces) >= 30

    def test_list_cities_by_province(self, service: GeoService):
        cities = service.list_cities_by_province("330000")
        assert len(cities) >= 10

    def test_get_area(self, service: GeoService):
        area = service.get_area("330000")
        assert area is not None
        assert area.name == "浙江省"

    def test_lookup_cidrs_from_cache(self, service: GeoService, tmp_path: Path):
        """使用缓存文件验证 lookup_cidrs_for_area。"""
        cache_dir = tmp_path / "cncity"
        cache_dir.mkdir(parents=True, exist_ok=True)
        (cache_dir / "330000.txt").write_text(
            "\n".join([f"1.{i}.0.0/24" for i in range(5)]),
            encoding="utf-8",
        )
        cidrs = service.lookup_cidrs_for_area("330000")
        assert len(cidrs) == 5

    def test_ip2region_fallback(self, service: GeoService, tmp_path: Path):
        """ip2region 兜底路径验证。"""
        def ip_int(s: str) -> int:
            return int(ipaddress.IPv4Address(s))

        source = tmp_path / "ipv4_source.txt"
        source.write_text(
            f"{ip_int('10.0.0.0')}|{ip_int('10.0.0.255')}|中国|华东|浙江省|杭州市|电信\n",
            encoding="utf-8",
        )
        result = service.ip2region_fallback("330000")
        assert any("10.0.0.0" in r for r in result)
