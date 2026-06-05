"""
tests/test_reconcile.py — 单元测试 tgwl.reconcile 模块

使用纯 Python fake 对象，不依赖 PTB / nftables / SQLite。
"""

from __future__ import annotations

import ipaddress
import pytest

from tgwl.reconcile import reconcile_from_store, apply_firewall_mode


# --------------------------------------------------------------------------- #
# Fake helpers                                                                  #
# --------------------------------------------------------------------------- #

class FakeEntry:
    def __init__(self, value: str):
        self.value = value


class FakeStore:
    def __init__(self, ip_values: list[str], geo_codes: list[str]):
        self._ip = [FakeEntry(v) for v in ip_values]
        self._geo = [FakeEntry(c) for c in geo_codes]
        self.settings: dict[str, str] = {}

    def get_all_ip_entries(self):
        return list(self._ip)

    def get_all_geo_entries(self):
        return list(self._geo)

    def set_setting(self, key: str, value: str) -> None:
        self.settings[key] = value

    def get_setting(self, key: str):
        return self.settings.get(key)


class FakeGeo:
    """Maps geo code → list of CIDR strings."""
    def __init__(self, mapping: dict[str, list[str]]):
        self._map = mapping

    def lookup_cidrs_for_area(self, code: str) -> list[str]:
        return list(self._map.get(code, []))


class FakeFw:
    def __init__(self):
        self.reconcile_calls: list[set] = []
        self.ensure_setup_count = 0
        self.panic_count = 0
        self._reconcile_return = 0

    def ensure_setup(self) -> None:
        self.ensure_setup_count += 1

    def reconcile(self, nets: set) -> int:
        self.reconcile_calls.append(frozenset(nets))
        return len(nets)

    def panic(self) -> None:
        self.panic_count += 1


# --------------------------------------------------------------------------- #
# Tests for reconcile_from_store                                                #
# --------------------------------------------------------------------------- #

def test_reconcile_from_store_aggregates_ip_and_geo():
    """IP 条目 + geo 展开的 CIDR 都应传给 fw.reconcile。"""
    store = FakeStore(
        ip_values=["1.2.3.4/32", "10.0.0.0/8"],
        geo_codes=["330000"],
    )
    geo = FakeGeo({"330000": ["192.168.1.0/24"]})
    fw = FakeFw()

    count = reconcile_from_store(store, geo, fw)

    assert len(fw.reconcile_calls) == 1
    called_nets = fw.reconcile_calls[0]

    expected = {
        ipaddress.IPv4Network("1.2.3.4/32"),
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("192.168.1.0/24"),
    }
    assert called_nets == expected
    assert count == len(expected)


def test_reconcile_from_store_empty_store():
    """空 store 应以空集合调用 fw.reconcile。"""
    store = FakeStore(ip_values=[], geo_codes=[])
    geo = FakeGeo({})
    fw = FakeFw()

    count = reconcile_from_store(store, geo, fw)

    assert len(fw.reconcile_calls) == 1
    assert fw.reconcile_calls[0] == frozenset()
    assert count == 0


def test_reconcile_from_store_collapse_overlapping():
    """10.0.0.0/24 被 10.0.0.0/8 覆盖，collapse 后 fw.reconcile 收到合并结果。"""
    store = FakeStore(
        ip_values=["10.0.0.0/8", "10.0.0.0/24"],
        geo_codes=[],
    )
    geo = FakeGeo({})
    fw = FakeFw()

    reconcile_from_store(store, geo, fw)

    # 10.0.0.0/24 应被 10.0.0.0/8 吸收
    called_nets = fw.reconcile_calls[0]
    assert ipaddress.IPv4Network("10.0.0.0/8") in called_nets
    assert ipaddress.IPv4Network("10.0.0.0/24") not in called_nets


# --------------------------------------------------------------------------- #
# Tests for apply_firewall_mode                                                 #
# --------------------------------------------------------------------------- #

def test_apply_firewall_mode_normal():
    """normal 模式：ensure_setup → reconcile_from_store，写 settings。"""
    store = FakeStore(ip_values=["1.1.1.1/32"], geo_codes=[])
    geo = FakeGeo({})
    fw = FakeFw()

    result = apply_firewall_mode("normal", store, geo, fw)

    assert fw.ensure_setup_count == 1
    assert len(fw.reconcile_calls) == 1
    assert fw.panic_count == 0
    assert store.settings.get("firewall_mode") == "normal"
    assert result == 1  # one net


def test_apply_firewall_mode_lockdown():
    """lockdown 模式：ensure_setup → reconcile(空集合)，写 settings。"""
    store = FakeStore(ip_values=["1.1.1.1/32"], geo_codes=[])
    geo = FakeGeo({})
    fw = FakeFw()

    result = apply_firewall_mode("lockdown", store, geo, fw)

    assert fw.ensure_setup_count == 1
    assert len(fw.reconcile_calls) == 1
    assert fw.reconcile_calls[0] == frozenset()  # 空集合
    assert fw.panic_count == 0
    assert store.settings.get("firewall_mode") == "lockdown"
    assert result == 0


def test_apply_firewall_mode_open():
    """open 模式：panic()，写 settings，返回 0。"""
    store = FakeStore(ip_values=[], geo_codes=[])
    geo = FakeGeo({})
    fw = FakeFw()

    result = apply_firewall_mode("open", store, geo, fw)

    assert fw.panic_count == 1
    assert fw.ensure_setup_count == 0
    assert fw.reconcile_calls == []
    assert store.settings.get("firewall_mode") == "open"
    assert result == 0


def test_apply_firewall_mode_invalid_raises():
    """无效 mode 应立即抛出 ValueError，不写 settings。"""
    store = FakeStore(ip_values=[], geo_codes=[])
    geo = FakeGeo({})
    fw = FakeFw()

    with pytest.raises(ValueError, match="Unknown firewall mode"):
        apply_firewall_mode("flying_spaghetti", store, geo, fw)

    assert "firewall_mode" not in store.settings


def test_apply_firewall_mode_settings_written_after_success():
    """确认 set_setting 只在成功后调用（open 路径无异常时）。"""
    store = FakeStore(ip_values=[], geo_codes=[])
    geo = FakeGeo({})
    fw = FakeFw()

    apply_firewall_mode("open", store, geo, fw)
    assert store.settings["firewall_mode"] == "open"
