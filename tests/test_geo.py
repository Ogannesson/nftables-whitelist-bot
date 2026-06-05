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
    IP2LocationIoGeo,
    XdbGeo,
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


# --------------------------------------------------------------------------- #
# IpInfo 新字段测试                                                             #
# --------------------------------------------------------------------------- #

class TestIpInfoAdcode:
    def test_adcode_default_empty(self):
        """adcode 字段默认值应为空字符串，保持向后兼容。"""
        info = IpInfo(ip="1.2.3.4")
        assert info.adcode == ""

    def test_adcode_can_be_set(self):
        info = IpInfo(ip="1.2.3.4", adcode="330100")
        assert info.adcode == "330100"

    def test_existing_construction_unchanged(self):
        """原有构造方式（不传 adcode）不受影响。"""
        info = IpInfo(ip="5.6.7.8", country="中国", province="浙江省",
                      city="杭州市", isp="电信")
        assert info.country == "中国"
        assert info.adcode == ""


# --------------------------------------------------------------------------- #
# IP2LocationIoGeo 测试（mock httpx）                                           #
# --------------------------------------------------------------------------- #

class TestIP2LocationIoGeo:
    def _make_mock_response(self, json_data: dict, status_code: int = 200) -> MagicMock:
        mock_resp = MagicMock()
        mock_resp.json.return_value = json_data
        mock_resp.status_code = status_code
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    def _make_client_context(self, response: MagicMock) -> MagicMock:
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get = MagicMock(return_value=response)
        return mock_client

    def test_empty_key_raises(self):
        """空 key 在构造时抛 ValueError。"""
        with pytest.raises(ValueError, match="key"):
            IP2LocationIoGeo(key="")

    def test_success_field_mapping(self):
        """正确解析 country_name/region_name/city_name/isp -> IpInfo 字段。"""
        geo = IP2LocationIoGeo(key="testkey")
        resp_data = {
            "country_name": "China",
            "region_name": "Zhejiang",
            "city_name": "Hangzhou",
            "isp": "China Telecom",
        }
        resp = self._make_mock_response(resp_data)
        with patch("httpx.Client", return_value=self._make_client_context(resp)):
            info = geo.lookup("1.2.3.4")
        assert info.ip == "1.2.3.4"
        assert info.country == "China"
        assert info.province == "Zhejiang"
        assert info.city == "Hangzhou"
        assert info.isp == "China Telecom"
        assert info.raw == resp_data

    def test_http_error_raises(self):
        """HTTP 非 200 时（raise_for_status 抛异常）应向上传播。"""
        geo = IP2LocationIoGeo(key="testkey")
        resp = self._make_mock_response({}, status_code=403)
        resp.raise_for_status.side_effect = Exception("403 Forbidden")
        with patch("httpx.Client", return_value=self._make_client_context(resp)):
            with pytest.raises(Exception, match="403"):
                geo.lookup("1.2.3.4")

    def test_error_key_in_response_raises(self):
        """响应 JSON 含 error 键时抛 RuntimeError。"""
        geo = IP2LocationIoGeo(key="testkey")
        resp_data = {"error": {"error_code": 10001, "error_message": "Invalid API key."}}
        resp = self._make_mock_response(resp_data)
        with patch("httpx.Client", return_value=self._make_client_context(resp)):
            with pytest.raises(RuntimeError, match="ip2location.io"):
                geo.lookup("8.8.8.8")

    def test_invalid_ip_raises(self):
        """无效 IP 字符串在 lookup 时抛 ValueError。"""
        geo = IP2LocationIoGeo(key="testkey")
        with pytest.raises(ValueError, match="无效 IP"):
            with patch("httpx.Client"):
                geo.lookup("not-an-ip")

    def test_missing_fields_default_empty(self):
        """响应中缺少某些字段时，对应 IpInfo 字段为空字符串。"""
        geo = IP2LocationIoGeo(key="testkey")
        resp_data = {"country_name": "United States"}
        resp = self._make_mock_response(resp_data)
        with patch("httpx.Client", return_value=self._make_client_context(resp)):
            info = geo.lookup("8.8.8.8")
        assert info.country == "United States"
        assert info.province == ""
        assert info.city == ""
        assert info.isp == ""

    def test_http_status_error_does_not_leak_key(self):
        """HTTP 错误重新包装后，异常消息中不应含 API key（防止 key 泄漏进日志）。"""
        import httpx

        api_key = "super_secret_api_key_xyz"
        geo = IP2LocationIoGeo(key=api_key)

        # 构造一个带有完整 URL（含 key）的 HTTPStatusError，模拟 httpx 原生行为
        fake_request = httpx.Request(
            "GET",
            f"https://api.ip2location.io/?key={api_key}&ip=1.2.3.4",
        )
        fake_response = MagicMock(spec=httpx.Response)
        fake_response.status_code = 403
        http_err = httpx.HTTPStatusError(
            f"Client error '403 Forbidden' for url "
            f"'https://api.ip2location.io/?key={api_key}&ip=1.2.3.4'",
            request=fake_request,
            response=fake_response,
        )

        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = http_err
        mock_client_ctx = self._make_client_context(mock_resp)

        with patch("httpx.Client", return_value=mock_client_ctx):
            with pytest.raises(RuntimeError) as exc_info:
                geo.lookup("1.2.3.4")

        raised_msg = str(exc_info.value)
        assert api_key not in raised_msg, (
            f"API key 泄漏进异常消息！raised: {raised_msg!r}"
        )
        # 应只含状态码，不含 URL 或 key
        assert "403" in raised_msg

    def test_request_error_does_not_leak_key(self):
        """网络错误（RequestError）重新包装后，异常消息中不应含 API key。"""
        import httpx

        api_key = "another_secret_key_abc"
        geo = IP2LocationIoGeo(key=api_key)

        fake_request = httpx.Request(
            "GET",
            f"https://api.ip2location.io/?key={api_key}&ip=1.2.3.4",
        )
        net_err = httpx.ConnectError("Connection refused", request=fake_request)

        mock_resp = MagicMock()
        mock_client_ctx = self._make_client_context(mock_resp)
        # 让 client.get() 直接抛 RequestError
        mock_client_ctx.get.side_effect = net_err

        with patch("httpx.Client", return_value=mock_client_ctx):
            with pytest.raises(RuntimeError) as exc_info:
                geo.lookup("1.2.3.4")

        raised_msg = str(exc_info.value)
        assert api_key not in raised_msg, (
            f"API key 泄漏进异常消息！raised: {raised_msg!r}"
        )


# --------------------------------------------------------------------------- #
# XdbGeo 测试                                                                   #
# --------------------------------------------------------------------------- #

class TestXdbGeo:
    def test_no_xdb_package_returns_none(self, monkeypatch):
        """py-ip2region 包未安装时，lookup 返回 None，不崩溃。"""
        import tgwl.geo as geo_module
        monkeypatch.setattr(geo_module, "_xdb_searcher", None)
        monkeypatch.setattr(geo_module, "_xdb_util", None)
        xdb = XdbGeo(xdb_path="/nonexistent/path.xdb")
        assert xdb.lookup("1.2.3.4") is None

    def test_missing_file_returns_none(self, tmp_path):
        """xdb 文件路径不存在时，lookup 返回 None，不崩溃。"""
        xdb = XdbGeo(xdb_path=str(tmp_path / "nonexistent.xdb"))
        assert xdb.lookup("1.2.3.4") is None

    def test_empty_path_returns_none(self):
        """路径为空字符串时，lookup 返回 None，不崩溃。"""
        xdb = XdbGeo(xdb_path="")
        assert xdb.lookup("1.2.3.4") is None

    def test_successful_parse(self, tmp_path, monkeypatch):
        """mock py-ip2region 正常返回管道分隔字符串时，正确解析各字段。"""
        import tgwl.geo as geo_module

        fake_xdb = tmp_path / "test.xdb"
        fake_xdb.write_bytes(b"\x00" * 16)

        mock_searcher = MagicMock()
        # py-ip2region 真实格式：国家|省|市|ISP|iso
        mock_searcher.search.return_value = "中国|浙江省|杭州市|中国电信|CN"

        mock_xdb_mod = MagicMock()
        mock_xdb_mod.new_with_buffer.return_value = mock_searcher

        mock_util = MagicMock()
        mock_util.load_content_from_file.return_value = b"\x00" * 16
        mock_util.IPv4 = 0

        monkeypatch.setattr(geo_module, "_xdb_searcher", mock_xdb_mod)
        monkeypatch.setattr(geo_module, "_xdb_util", mock_util)

        xdb = XdbGeo(xdb_path=str(fake_xdb))
        info = xdb.lookup("1.2.3.4")

        assert info is not None
        assert info.country == "中国"
        assert info.province == "浙江省"
        assert info.city == "杭州市"
        assert info.isp == "中国电信"

    def test_zero_fields_cleaned(self, tmp_path, monkeypatch):
        """pipe 分隔结果中 0 值应被清为空字符串。"""
        import tgwl.geo as geo_module

        fake_xdb = tmp_path / "test.xdb"
        fake_xdb.write_bytes(b"\x00" * 16)

        mock_searcher = MagicMock()
        mock_searcher.search.return_value = "中国|0|0|0|0"

        mock_xdb_mod = MagicMock()
        mock_xdb_mod.new_with_buffer.return_value = mock_searcher

        mock_util = MagicMock()
        mock_util.load_content_from_file.return_value = b"\x00" * 16
        mock_util.IPv4 = 0

        monkeypatch.setattr(geo_module, "_xdb_searcher", mock_xdb_mod)
        monkeypatch.setattr(geo_module, "_xdb_util", mock_util)

        xdb = XdbGeo(xdb_path=str(fake_xdb))
        info = xdb.lookup("1.2.3.4")

        assert info is not None
        assert info.country == "中国"
        assert info.province == ""
        assert info.city == ""
        assert info.isp == ""

    def test_search_exception_returns_none(self, tmp_path, monkeypatch):
        """searcher.search() 抛异常时 lookup 返回 None，不崩溃。"""
        import tgwl.geo as geo_module

        fake_xdb = tmp_path / "test.xdb"
        fake_xdb.write_bytes(b"\x00" * 16)

        mock_searcher = MagicMock()
        mock_searcher.search.side_effect = RuntimeError("xdb error")

        mock_xdb_mod = MagicMock()
        mock_xdb_mod.new_with_buffer.return_value = mock_searcher

        mock_util = MagicMock()
        mock_util.load_content_from_file.return_value = b"\x00" * 16
        mock_util.IPv4 = 0

        monkeypatch.setattr(geo_module, "_xdb_searcher", mock_xdb_mod)
        monkeypatch.setattr(geo_module, "_xdb_util", mock_util)

        xdb = XdbGeo(xdb_path=str(fake_xdb))
        assert xdb.lookup("1.2.3.4") is None

    def test_load_content_failure_returns_none(self, tmp_path, monkeypatch):
        """load_content_from_file 抛异常时 XdbGeo 不可用，lookup 返回 None。"""
        import tgwl.geo as geo_module

        fake_xdb = tmp_path / "test.xdb"
        fake_xdb.write_bytes(b"\x00" * 16)

        mock_xdb_mod = MagicMock()

        mock_util = MagicMock()
        mock_util.load_content_from_file.side_effect = OSError("read error")
        mock_util.IPv4 = 0

        monkeypatch.setattr(geo_module, "_xdb_searcher", mock_xdb_mod)
        monkeypatch.setattr(geo_module, "_xdb_util", mock_util)

        xdb = XdbGeo(xdb_path=str(fake_xdb))
        assert xdb.lookup("1.1.1.1") is None


# --------------------------------------------------------------------------- #
# GeoService 级联测试（新增）                                                    #
# --------------------------------------------------------------------------- #

class TestGeoServiceCascade:
    @pytest.fixture(autouse=True)
    def mock_registry(self, monkeypatch):
        """阻止 GeoService.__init__ 触发 RegionRegistry 文件读取。"""
        import tgwl.geo as geo_module
        monkeypatch.setattr(geo_module, "get_registry", lambda: MagicMock())

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

    def test_ip2location_used_when_key_provided(self, tmp_path):
        """提供 ip2location_io_key 时，lookup_ip 使用 IP2LocationIoGeo 结果。"""
        resp_data = {
            "country_name": "Japan",
            "region_name": "Tokyo",
            "city_name": "Tokyo",
            "isp": "NTT",
        }
        resp = self._make_mock_response(resp_data)
        svc = GeoService(data_dir=tmp_path, ip2location_io_key="testkey")
        with patch("httpx.Client", return_value=self._make_client_context(resp)):
            info = svc.lookup_ip("1.2.3.4")
        assert info.country == "Japan"
        assert info.province == "Tokyo"

    def test_ip2location_error_falls_to_ip_api(self, tmp_path):
        """IP2LocationIoGeo 抛异常时降级至 ip-api（OnlineGeo）。"""
        ip_api_data = {
            "status": "success",
            "country": "中国",
            "regionName": "浙江省",
            "city": "杭州市",
            "isp": "电信",
        }

        svc = GeoService(data_dir=tmp_path, ip2location_io_key="badkey")

        def client_factory(*args, **kwargs):
            ctx = MagicMock()
            ctx.__enter__ = MagicMock(return_value=ctx)
            ctx.__exit__ = MagicMock(return_value=False)

            def smart_get(url, **kw):
                if "ip2location.io" in url:
                    raise RuntimeError("network error")
                return self._make_mock_response(ip_api_data)

            ctx.get = smart_get
            return ctx

        with patch("httpx.Client", side_effect=client_factory):
            info = svc.lookup_ip("1.2.3.4")
        assert info.province == "浙江省"

    def test_xdb_used_when_ip2location_absent(self, tmp_path, monkeypatch):
        """无 ip2location key、有 xdb 时，lookup_ip 使用 XdbGeo 结果。"""
        import tgwl.geo as geo_module

        fake_xdb = tmp_path / "test.xdb"
        fake_xdb.write_bytes(b"\x00" * 16)

        mock_searcher = MagicMock()
        # py-ip2region 格式：国家|省|市|ISP|iso
        mock_searcher.search.return_value = "中国|上海市|上海市|联通|CN"

        mock_xdb_mod = MagicMock()
        mock_xdb_mod.new_with_buffer.return_value = mock_searcher

        mock_util = MagicMock()
        mock_util.load_content_from_file.return_value = b"\x00" * 16
        mock_util.IPv4 = 0

        monkeypatch.setattr(geo_module, "_xdb_searcher", mock_xdb_mod)
        monkeypatch.setattr(geo_module, "_xdb_util", mock_util)

        svc = GeoService(data_dir=tmp_path, ip2region_xdb=str(fake_xdb))
        info = svc.lookup_ip("1.2.3.4")
        assert info.city == "上海市"
        assert info.isp == "联通"

    def test_xdb_none_falls_to_ip_api(self, tmp_path, monkeypatch):
        """xdb 返回 None 时降级至 ip-api。"""
        import tgwl.geo as geo_module

        fake_xdb = tmp_path / "test.xdb"
        fake_xdb.write_bytes(b"\x00" * 16)

        mock_searcher = MagicMock()
        mock_searcher.search.return_value = ""

        mock_xdb_mod = MagicMock()
        mock_xdb_mod.new_with_buffer.return_value = mock_searcher

        mock_util = MagicMock()
        mock_util.load_content_from_file.return_value = b"\x00" * 16
        mock_util.IPv4 = 0

        monkeypatch.setattr(geo_module, "_xdb_searcher", mock_xdb_mod)
        monkeypatch.setattr(geo_module, "_xdb_util", mock_util)

        ip_api_data = {
            "status": "success",
            "country": "德国",
            "regionName": "Bavaria",
            "city": "Munich",
            "isp": "Deutsche Telekom",
        }
        resp = self._make_mock_response(ip_api_data)

        svc = GeoService(data_dir=tmp_path, ip2region_xdb=str(fake_xdb))
        with patch("httpx.Client", return_value=self._make_client_context(resp)):
            info = svc.lookup_ip("5.6.7.8")
        assert info.country == "德国"

    def test_no_new_providers_uses_ip_api(self, tmp_path):
        """不传新参数时行为与原 GeoService 一致（只用 ip-api）。"""
        ip_api_data = {
            "status": "success",
            "country": "美国",
            "regionName": "California",
            "city": "San Jose",
            "isp": "Cloudflare",
        }
        resp = self._make_mock_response(ip_api_data)
        svc = GeoService(data_dir=tmp_path)
        with patch("httpx.Client", return_value=self._make_client_context(resp)):
            info = svc.lookup_ip("1.1.1.1")
        assert info.country == "美国"
