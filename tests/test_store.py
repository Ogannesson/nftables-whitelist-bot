"""
tests/test_store.py — store.py 单元测试

使用内存数据库（":memory:"）不产生临时文件。
"""

from __future__ import annotations

import pytest
from datetime import timezone

from tgwl.store import Store, Entry, Admin


# --------------------------------------------------------------------------- #
# Fixtures                                                                      #
# --------------------------------------------------------------------------- #

@pytest.fixture
def store(tmp_path) -> Store:
    """每个测试用独立的临时 DB 文件（避免 :memory: 跨线程共享问题）。"""
    db = tmp_path / "test.db"
    return Store(db)


PRIMARY_ID = 10001
ADMIN_ID   = 10002
OTHER_ID   = 10003


# --------------------------------------------------------------------------- #
# 管理员测试                                                                    #
# --------------------------------------------------------------------------- #

class TestAdmins:
    def test_ensure_primary_admin_creates(self, store: Store):
        store.ensure_primary_admin(PRIMARY_ID)
        admin = store.get_admin(PRIMARY_ID)
        assert admin is not None
        assert admin.user_id == PRIMARY_ID
        assert admin.is_primary is True

    def test_ensure_primary_admin_idempotent(self, store: Store):
        store.ensure_primary_admin(PRIMARY_ID)
        store.ensure_primary_admin(PRIMARY_ID)  # 重复调用
        admins = store.list_admins()
        primary_admins = [a for a in admins if a.user_id == PRIMARY_ID]
        assert len(primary_admins) == 1
        assert primary_admins[0].is_primary is True

    def test_add_admin(self, store: Store):
        store.ensure_primary_admin(PRIMARY_ID)
        result = store.add_admin(ADMIN_ID, added_by=PRIMARY_ID)
        assert result is True
        admin = store.get_admin(ADMIN_ID)
        assert admin is not None
        assert admin.is_primary is False
        assert admin.added_by == PRIMARY_ID

    def test_add_admin_duplicate_returns_false(self, store: Store):
        store.ensure_primary_admin(PRIMARY_ID)
        store.add_admin(ADMIN_ID, added_by=PRIMARY_ID)
        result = store.add_admin(ADMIN_ID, added_by=PRIMARY_ID)
        assert result is False

    def test_is_admin_true(self, store: Store):
        store.ensure_primary_admin(PRIMARY_ID)
        assert store.is_admin(PRIMARY_ID) is True

    def test_is_admin_false(self, store: Store):
        assert store.is_admin(OTHER_ID) is False

    def test_is_primary_admin(self, store: Store):
        store.ensure_primary_admin(PRIMARY_ID)
        store.add_admin(ADMIN_ID, added_by=PRIMARY_ID)
        assert store.is_primary_admin(PRIMARY_ID) is True
        assert store.is_primary_admin(ADMIN_ID) is False

    def test_remove_admin_success(self, store: Store):
        store.ensure_primary_admin(PRIMARY_ID)
        store.add_admin(ADMIN_ID, added_by=PRIMARY_ID)
        result = store.remove_admin(ADMIN_ID)
        assert result is True
        assert store.get_admin(ADMIN_ID) is None

    def test_remove_admin_not_exist(self, store: Store):
        result = store.remove_admin(OTHER_ID)
        assert result is False

    def test_remove_primary_admin_raises(self, store: Store):
        store.ensure_primary_admin(PRIMARY_ID)
        with pytest.raises(PermissionError):
            store.remove_admin(PRIMARY_ID)

    def test_list_admins_primary_first(self, store: Store):
        store.ensure_primary_admin(PRIMARY_ID)
        store.add_admin(ADMIN_ID, added_by=PRIMARY_ID)
        admins = store.list_admins()
        assert len(admins) == 2
        assert admins[0].user_id == PRIMARY_ID  # 主管理员排首位

    def test_get_admin_none(self, store: Store):
        assert store.get_admin(99999) is None


# --------------------------------------------------------------------------- #
# 白名单条目测试                                                                #
# --------------------------------------------------------------------------- #

class TestEntries:
    def setup_method(self):
        self.user_id = PRIMARY_ID

    def test_add_ip_entry(self, store: Store):
        entry = store.add_entry("ip", "1.2.3.4", "1.2.3.4", self.user_id)
        assert entry is not None
        assert entry.type == "ip"
        assert entry.value == "1.2.3.4"
        assert entry.label == "1.2.3.4"
        assert entry.added_by == self.user_id
        assert entry.id > 0

    def test_add_cidr_entry(self, store: Store):
        entry = store.add_entry("cidr", "192.168.0.0/24", "192.168.0.0/24", self.user_id)
        assert entry is not None
        assert entry.type == "cidr"

    def test_add_province_entry(self, store: Store):
        entry = store.add_entry("province", "330000", "浙江省", self.user_id)
        assert entry is not None
        assert entry.type == "province"
        assert entry.value == "330000"
        assert entry.label == "浙江省"

    def test_add_city_entry(self, store: Store):
        entry = store.add_entry("city", "330100", "杭州市", self.user_id)
        assert entry is not None
        assert entry.type == "city"

    def test_add_duplicate_returns_none(self, store: Store):
        store.add_entry("ip", "1.2.3.4", "1.2.3.4", self.user_id)
        result = store.add_entry("ip", "1.2.3.4", "1.2.3.4", self.user_id)
        assert result is None  # 幂等，重复返回 None

    def test_add_invalid_type_raises(self, store: Store):
        with pytest.raises(ValueError, match="非法 entry type"):
            store.add_entry("invalid", "1.2.3.4", "x", self.user_id)  # type: ignore

    def test_remove_entry_success(self, store: Store):
        entry = store.add_entry("ip", "10.0.0.1", "10.0.0.1", self.user_id)
        assert entry is not None
        result = store.remove_entry(entry.id)
        assert result is True
        assert store.get_entry(entry.id) is None

    def test_remove_entry_not_exist(self, store: Store):
        result = store.remove_entry(99999)
        assert result is False

    def test_list_entries_all(self, store: Store):
        store.add_entry("ip", "1.1.1.1", "1.1.1.1", self.user_id)
        store.add_entry("cidr", "10.0.0.0/8", "10.0.0.0/8", self.user_id)
        store.add_entry("province", "440000", "广东省", self.user_id)
        entries = store.list_entries()
        assert len(entries) == 3

    def test_list_entries_by_type(self, store: Store):
        store.add_entry("ip", "1.1.1.1", "1.1.1.1", self.user_id)
        store.add_entry("cidr", "10.0.0.0/8", "10.0.0.0/8", self.user_id)
        store.add_entry("province", "440000", "广东省", self.user_id)
        ip_entries = store.list_entries("ip")
        assert len(ip_entries) == 1
        assert ip_entries[0].type == "ip"

    def test_list_entries_paged(self, store: Store):
        for i in range(15):
            store.add_entry("ip", f"10.0.0.{i}", f"10.0.0.{i}", self.user_id)
        page0, total = store.list_entries_paged(entry_type="ip", page=0, page_size=10)
        assert total == 15
        assert len(page0) == 10
        page1, total2 = store.list_entries_paged(entry_type="ip", page=1, page_size=10)
        assert total2 == 15
        assert len(page1) == 5

    def test_count_entries(self, store: Store):
        store.add_entry("ip", "1.1.1.1", "1.1.1.1", self.user_id)
        store.add_entry("ip", "2.2.2.2", "2.2.2.2", self.user_id)
        store.add_entry("province", "330000", "浙江省", self.user_id)
        counts = store.count_entries()
        assert counts["ip"] == 2
        assert counts["province"] == 1
        assert counts["total"] == 3

    def test_entry_exists(self, store: Store):
        store.add_entry("province", "330000", "浙江省", self.user_id)
        assert store.entry_exists("province", "330000") is True
        assert store.entry_exists("province", "440000") is False
        assert store.entry_exists("ip", "330000") is False  # 不同类型

    def test_get_all_geo_entries(self, store: Store):
        store.add_entry("ip", "1.1.1.1", "1.1.1.1", self.user_id)
        store.add_entry("province", "330000", "浙江省", self.user_id)
        store.add_entry("city", "330100", "杭州市", self.user_id)
        geo = store.get_all_geo_entries()
        types = {e.type for e in geo}
        assert "province" in types
        assert "city" in types
        assert "ip" not in types

    def test_get_all_ip_entries(self, store: Store):
        store.add_entry("ip", "1.1.1.1", "1.1.1.1", self.user_id)
        store.add_entry("cidr", "10.0.0.0/8", "10.0.0.0/8", self.user_id)
        store.add_entry("province", "330000", "浙江省", self.user_id)
        ip_entries = store.get_all_ip_entries()
        types = {e.type for e in ip_entries}
        assert "ip" in types
        assert "cidr" in types
        assert "province" not in types

    def test_entry_added_at_is_utc(self, store: Store):
        entry = store.add_entry("ip", "8.8.8.8", "8.8.8.8", self.user_id)
        assert entry is not None
        # added_at 应带时区信息
        assert entry.added_at.tzinfo is not None


# --------------------------------------------------------------------------- #
# 设置测试                                                                      #
# --------------------------------------------------------------------------- #

class TestSettings:
    def test_set_and_get_setting(self, store: Store):
        store.set_setting("foo", "bar")
        assert store.get_setting("foo") == "bar"

    def test_get_setting_not_exist_returns_none(self, store: Store):
        assert store.get_setting("nonexistent_key") is None

    def test_set_setting_overwrite(self, store: Store):
        store.set_setting("key1", "value1")
        store.set_setting("key1", "value2")
        assert store.get_setting("key1") == "value2"

    def test_set_multiple_settings_independent(self, store: Store):
        store.set_setting("a", "alpha")
        store.set_setting("b", "beta")
        assert store.get_setting("a") == "alpha"
        assert store.get_setting("b") == "beta"
