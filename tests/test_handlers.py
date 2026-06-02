"""
tests/test_handlers.py — handlers 权限与核心逻辑单元测试

使用 MagicMock 模拟 Update / ContextTypes，验证：
  - 非管理员被权限装饰器拒绝
  - IP/CIDR 解析工具函数正确性
  - callback_data 格式校验
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path

from tgwl.handlers.common import (
    parse_ip_or_cidr,
    entry_type_for_text,
    is_single_ip,
    require_admin,
)
from tgwl.store import Store


# --------------------------------------------------------------------------- #
# 工具函数测试                                                                  #
# --------------------------------------------------------------------------- #

class TestParseIpOrCidr:
    def test_valid_ip(self):
        # 单 IP 被标准化为 /32（host route），这是正确的防火墙格式
        result = parse_ip_or_cidr("1.2.3.4")
        assert result in ("1.2.3.4", "1.2.3.4/32")

    def test_valid_cidr(self):
        assert parse_ip_or_cidr("192.168.0.0/24") == "192.168.0.0/24"

    def test_host_bits_normalized(self):
        result = parse_ip_or_cidr("10.0.0.1/24")
        assert result == "10.0.0.0/24"

    def test_invalid_returns_none(self):
        assert parse_ip_or_cidr("not-an-ip") is None
        assert parse_ip_or_cidr("999.0.0.0") is None
        assert parse_ip_or_cidr("") is None

    def test_with_spaces(self):
        result = parse_ip_or_cidr("  1.2.3.4  ")
        assert result in ("1.2.3.4", "1.2.3.4/32")


class TestEntryTypeForText:
    def test_ip(self):
        assert entry_type_for_text("1.2.3.4") == "ip"

    def test_cidr(self):
        assert entry_type_for_text("10.0.0.0/8") == "cidr"

    def test_host_cidr(self):
        assert entry_type_for_text("1.2.3.4/32") == "cidr"

    def test_invalid(self):
        assert entry_type_for_text("invalid") is None

    def test_ipv6_returns_none(self):
        # 只支持 v4
        assert entry_type_for_text("::1") is None


class TestIsSingleIp:
    def test_is_single(self):
        assert is_single_ip("8.8.8.8") is True

    def test_cidr_not_single(self):
        assert is_single_ip("8.8.8.0/24") is False

    def test_invalid_not_single(self):
        assert is_single_ip("not-ip") is False


# --------------------------------------------------------------------------- #
# 权限装饰器测试                                                                #
# --------------------------------------------------------------------------- #

def make_update(user_id: int, has_callback: bool = False) -> MagicMock:
    """构造一个最小化的 Update mock。"""
    update = MagicMock()
    update.effective_user = MagicMock()
    update.effective_user.id = user_id
    update.effective_user.username = f"user{user_id}"
    if has_callback:
        update.callback_query = AsyncMock()
        update.callback_query.answer = AsyncMock()
        update.message = None
    else:
        update.callback_query = None
        update.message = AsyncMock()
        update.message.reply_text = AsyncMock()
    return update


def make_context(store: Store) -> MagicMock:
    """构造 context mock，注入 store。"""
    context = MagicMock()
    context.bot_data = {"store": store}
    return context


PRIMARY_ID = 10001
ADMIN_ID   = 10002
OTHER_ID   = 10099


@pytest.fixture
def store(tmp_path: Path) -> Store:
    s = Store(tmp_path / "test.db")
    s.ensure_primary_admin(PRIMARY_ID)
    s.add_admin(ADMIN_ID, added_by=PRIMARY_ID)
    return s


class TestRequireAdmin:
    @pytest.mark.asyncio
    async def test_admin_allowed(self, store: Store):
        """管理员可以访问受限功能。"""
        call_log = []

        @require_admin
        async def handler(update, context):
            call_log.append("called")

        update = make_update(ADMIN_ID)
        context = make_context(store)
        await handler(update, context)
        assert call_log == ["called"]

    @pytest.mark.asyncio
    async def test_primary_admin_allowed(self, store: Store):
        """主管理员也可以访问。"""
        call_log = []

        @require_admin
        async def handler(update, context):
            call_log.append("called")

        update = make_update(PRIMARY_ID)
        context = make_context(store)
        await handler(update, context)
        assert call_log == ["called"]

    @pytest.mark.asyncio
    async def test_non_admin_rejected_message(self, store: Store):
        """非管理员（message 路径）被拒，reply_text 被调用。"""
        @require_admin
        async def handler(update, context):
            raise AssertionError("不应被调用")

        update = make_update(OTHER_ID, has_callback=False)
        context = make_context(store)
        await handler(update, context)
        update.message.reply_text.assert_called_once()
        msg = update.message.reply_text.call_args[0][0]
        assert "权限" in msg

    @pytest.mark.asyncio
    async def test_non_admin_rejected_callback(self, store: Store):
        """非管理员（callback_query 路径）被拒，query.answer 被调用。"""
        @require_admin
        async def handler(update, context):
            raise AssertionError("不应被调用")

        update = make_update(OTHER_ID, has_callback=True)
        context = make_context(store)
        await handler(update, context)
        update.callback_query.answer.assert_called_once()
        call_args = update.callback_query.answer.call_args
        assert call_args[0][0] == "无权限" or "无权限" in str(call_args)

    @pytest.mark.asyncio
    async def test_no_user_returns_none(self, store: Store):
        """effective_user 为 None 时静默返回。"""
        @require_admin
        async def handler(update, context):
            raise AssertionError("不应被调用")

        update = MagicMock()
        update.effective_user = None
        context = make_context(store)
        result = await handler(update, context)
        assert result is None


# --------------------------------------------------------------------------- #
# ui callback_data 格式测试                                                     #
# --------------------------------------------------------------------------- #

class TestCallbackDataFormats:
    def test_main_menu_has_add_button(self):
        from tgwl import ui
        keyboard = ui.main_menu(is_primary_admin=False)
        all_data = [
            btn.callback_data
            for row in keyboard.inline_keyboard
            for btn in row
            if btn.callback_data
        ]
        assert "add:type" in all_data
        assert "mgr:list:all:0" in all_data
        assert "whois:prompt" in all_data
        assert "status:main" in all_data
        assert "panic:confirm" in all_data
        # 非主管理员不含 admin:list
        assert "admin:list" not in all_data

    def test_main_menu_primary_admin_has_admin_button(self):
        from tgwl import ui
        keyboard = ui.main_menu(is_primary_admin=True)
        all_data = [
            btn.callback_data
            for row in keyboard.inline_keyboard
            for btn in row
            if btn.callback_data
        ]
        assert "admin:list" in all_data

    def test_add_type_keyboard_formats(self):
        from tgwl import ui
        keyboard = ui.add_type_keyboard()
        all_data = [
            btn.callback_data
            for row in keyboard.inline_keyboard
            for btn in row
            if btn.callback_data
        ]
        assert "add:ip" in all_data
        assert "add:cidr" in all_data
        assert "add:province" in all_data
        assert "add:city" in all_data
        assert "add:cancel" in all_data

    def test_confirm_add_keyboard(self):
        from tgwl import ui
        keyboard = ui.confirm_add_keyboard("ip", "1.2.3.4")
        all_data = [
            btn.callback_data
            for row in keyboard.inline_keyboard
            for btn in row
            if btn.callback_data
        ]
        assert any("add:confirm:ip:" in d for d in all_data)
        assert "add:cancel" in all_data

    def test_panic_confirm_keyboard(self):
        from tgwl import ui
        keyboard = ui.panic_confirm_keyboard()
        all_data = [
            btn.callback_data
            for row in keyboard.inline_keyboard
            for btn in row
            if btn.callback_data
        ]
        assert "panic:do" in all_data
        assert "menu:main" in all_data

    def test_province_list_keyboard(self):
        from tgwl import ui
        from tgwl.geo import GeoArea
        provinces = [
            GeoArea(code=f"{i:06d}", name=f"省{i}", short=f"省{i}", is_province=True, province_code=f"{i:06d}")
            for i in range(20)
        ]
        keyboard = ui.province_list_keyboard(provinces, page=0)
        all_data = [
            btn.callback_data
            for row in keyboard.inline_keyboard
            for btn in row
            if btn.callback_data
        ]
        # 应有省份按钮
        assert any("add:sel_prov:" in d for d in all_data)
        # 应有下一页按钮（共 20 个，超过 PROV_PAGE_SIZE=12）
        assert any("prov_page:1" in d for d in all_data)

    def test_confirm_delete_keyboard(self):
        from tgwl import ui
        keyboard = ui.confirm_delete_keyboard(42)
        all_data = [
            btn.callback_data
            for row in keyboard.inline_keyboard
            for btn in row
            if btn.callback_data
        ]
        assert "mgr:del:42" in all_data

    def test_admin_list_keyboard_non_primary_has_rm(self):
        from tgwl import ui
        from tgwl.store import Admin
        from datetime import datetime, timezone
        admins = [
            Admin(user_id=1001, is_primary=True, added_by=1001,
                  added_at=datetime.now(timezone.utc)),
            Admin(user_id=1002, is_primary=False, added_by=1001,
                  added_at=datetime.now(timezone.utc)),
        ]
        keyboard = ui.admin_list_keyboard(admins)
        all_data = [
            btn.callback_data
            for row in keyboard.inline_keyboard
            for btn in row
            if btn.callback_data
        ]
        assert "admin:rm_confirm:1002" in all_data
        # 主管理员不应有撤销按钮
        assert "admin:rm_confirm:1001" not in all_data
