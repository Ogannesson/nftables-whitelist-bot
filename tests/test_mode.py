"""
tests/test_mode.py — 单元测试 handlers/mode.py 中的三态执行 handler

覆盖：
  - cb_mode_do_normal / cb_mode_do_lockdown / cb_mode_do_open
    各自以正确 mode 调用 apply_firewall_mode 一次
  - normal/lockdown 后 firewall_ok is True；open 后 is False
  - apply_firewall_mode 抛异常时 handler 不抛，调用 edit_message_text 给出失败提示
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# --------------------------------------------------------------------------- #
# 公共 fixture                                                                  #
# --------------------------------------------------------------------------- #

def _make_update() -> MagicMock:
    """构造带 callback_query 和 effective_user 的 Update mock。"""
    update = MagicMock()
    update.effective_user = MagicMock(id=123, username="test_user")
    cq = AsyncMock()
    cq.answer = AsyncMock()
    cq.edit_message_text = AsyncMock()
    update.callback_query = cq
    return update


def _make_context(admin: bool = True) -> MagicMock:
    """构造含 bot_data 的 Context mock。"""
    context = MagicMock()
    store = MagicMock()
    store.is_admin.return_value = admin
    store.is_primary_admin.return_value = admin
    geo = MagicMock()
    firewall = MagicMock()
    context.bot_data = {
        "store": store,
        "geo": geo,
        "firewall": firewall,
    }
    return context


# --------------------------------------------------------------------------- #
# 测试：三态 do-handler 正常流程                                                  #
# --------------------------------------------------------------------------- #

class TestModeDoHandlersSuccess:
    """apply_firewall_mode 成功时的行为验证。"""

    @pytest.mark.asyncio
    async def test_do_normal_calls_apply_with_normal(self):
        """cb_mode_do_normal 调用 apply_firewall_mode('normal', ...)。"""
        from tgwl.handlers.mode import cb_mode_do_normal

        update = _make_update()
        context = _make_context()

        with patch("tgwl.handlers.mode.reconcile.apply_firewall_mode", return_value=5) as mock_apply:
            await cb_mode_do_normal(update, context)

        mock_apply.assert_called_once()
        call_args = mock_apply.call_args[0]
        assert call_args[0] == "normal"

    @pytest.mark.asyncio
    async def test_do_lockdown_calls_apply_with_lockdown(self):
        """cb_mode_do_lockdown 调用 apply_firewall_mode('lockdown', ...)。"""
        from tgwl.handlers.mode import cb_mode_do_lockdown

        update = _make_update()
        context = _make_context()

        with patch("tgwl.handlers.mode.reconcile.apply_firewall_mode", return_value=0) as mock_apply:
            await cb_mode_do_lockdown(update, context)

        mock_apply.assert_called_once()
        call_args = mock_apply.call_args[0]
        assert call_args[0] == "lockdown"

    @pytest.mark.asyncio
    async def test_do_open_calls_apply_with_open(self):
        """cb_mode_do_open 调用 apply_firewall_mode('open', ...)。"""
        from tgwl.handlers.mode import cb_mode_do_open

        update = _make_update()
        context = _make_context()

        with patch("tgwl.handlers.mode.reconcile.apply_firewall_mode", return_value=0) as mock_apply:
            await cb_mode_do_open(update, context)

        mock_apply.assert_called_once()
        call_args = mock_apply.call_args[0]
        assert call_args[0] == "open"

    @pytest.mark.asyncio
    async def test_apply_receives_store_geo_fw(self):
        """apply_firewall_mode 收到的 store/geo/fw 与 bot_data 一致。"""
        from tgwl.handlers.mode import cb_mode_do_normal

        update = _make_update()
        context = _make_context()

        with patch("tgwl.handlers.mode.reconcile.apply_firewall_mode", return_value=3) as mock_apply:
            await cb_mode_do_normal(update, context)

        _, store_arg, geo_arg, fw_arg = mock_apply.call_args[0]
        assert store_arg is context.bot_data["store"]
        assert geo_arg is context.bot_data["geo"]
        assert fw_arg is context.bot_data["firewall"]


# --------------------------------------------------------------------------- #
# 测试：firewall_ok 设置逻辑                                                     #
# --------------------------------------------------------------------------- #

class TestFirewallOkFlag:
    """验证 firewall_ok 在不同模式下的值。"""

    @pytest.mark.asyncio
    async def test_normal_sets_firewall_ok_true(self):
        from tgwl.handlers.mode import cb_mode_do_normal

        update = _make_update()
        context = _make_context()

        with patch("tgwl.handlers.mode.reconcile.apply_firewall_mode", return_value=4):
            await cb_mode_do_normal(update, context)

        assert context.bot_data["firewall_ok"] is True

    @pytest.mark.asyncio
    async def test_lockdown_sets_firewall_ok_true(self):
        from tgwl.handlers.mode import cb_mode_do_lockdown

        update = _make_update()
        context = _make_context()

        with patch("tgwl.handlers.mode.reconcile.apply_firewall_mode", return_value=0):
            await cb_mode_do_lockdown(update, context)

        assert context.bot_data["firewall_ok"] is True

    @pytest.mark.asyncio
    async def test_open_sets_firewall_ok_false(self):
        from tgwl.handlers.mode import cb_mode_do_open

        update = _make_update()
        context = _make_context()

        with patch("tgwl.handlers.mode.reconcile.apply_firewall_mode", return_value=0):
            await cb_mode_do_open(update, context)

        assert context.bot_data["firewall_ok"] is False


# --------------------------------------------------------------------------- #
# 测试：apply_firewall_mode 抛异常时的失败处理                                    #
# --------------------------------------------------------------------------- #

class TestModeDoHandlersFailure:
    """apply_firewall_mode 抛异常时 handler 应捕获并给出失败提示。"""

    @pytest.mark.asyncio
    async def test_normal_exception_does_not_raise(self):
        """cb_mode_do_normal 在 apply 抛异常时不传播异常。"""
        from tgwl.handlers.mode import cb_mode_do_normal

        update = _make_update()
        context = _make_context()

        with patch(
            "tgwl.handlers.mode.reconcile.apply_firewall_mode",
            side_effect=RuntimeError("nft broken"),
        ):
            # 不应抛异常
            await cb_mode_do_normal(update, context)

    @pytest.mark.asyncio
    async def test_lockdown_exception_calls_edit_message_text(self):
        """cb_mode_do_lockdown 在 apply 失败后调用 edit_message_text 提示。"""
        from tgwl.handlers.mode import cb_mode_do_lockdown

        update = _make_update()
        context = _make_context()

        with patch(
            "tgwl.handlers.mode.reconcile.apply_firewall_mode",
            side_effect=RuntimeError("connection refused"),
        ):
            await cb_mode_do_lockdown(update, context)

        update.callback_query.edit_message_text.assert_called_once()
        call_text = update.callback_query.edit_message_text.call_args[0][0]
        # 失败提示应包含"失败"字样
        assert "失败" in call_text

    @pytest.mark.asyncio
    async def test_open_exception_sets_firewall_ok_false(self):
        """apply 抛异常时，except 分支应将 firewall_ok 置为 False（Fix 2）。"""
        from tgwl.handlers.mode import cb_mode_do_open

        update = _make_update()
        context = _make_context()
        # 预置为 True，验证异常分支会将其改为 False
        context.bot_data["firewall_ok"] = True

        with patch(
            "tgwl.handlers.mode.reconcile.apply_firewall_mode",
            side_effect=OSError("nft not found"),
        ):
            await cb_mode_do_open(update, context)

        # Fix 2：异常分支现在会把 firewall_ok 重置为 False
        assert context.bot_data["firewall_ok"] is False

    @pytest.mark.asyncio
    async def test_any_mode_exception_sets_firewall_ok_false(self):
        """任意模式切换失败时，firewall_ok 应被设为 False（Fix 2 通用验证）。"""
        from tgwl.handlers.mode import cb_mode_do_normal, cb_mode_do_lockdown

        for handler in (cb_mode_do_normal, cb_mode_do_lockdown):
            update = _make_update()
            context = _make_context()
            context.bot_data["firewall_ok"] = True

            with patch(
                "tgwl.handlers.mode.reconcile.apply_firewall_mode",
                side_effect=RuntimeError("simulated failure"),
            ):
                await handler(update, context)

            assert context.bot_data["firewall_ok"] is False, (
                f"{handler.__name__} 异常分支未将 firewall_ok 重置为 False"
            )

    @pytest.mark.asyncio
    async def test_normal_exception_edit_message_text_called(self):
        """cb_mode_do_normal 在 apply 失败后也要调用 edit_message_text。"""
        from tgwl.handlers.mode import cb_mode_do_normal

        update = _make_update()
        context = _make_context()

        with patch(
            "tgwl.handlers.mode.reconcile.apply_firewall_mode",
            side_effect=ValueError("bad mode"),
        ):
            await cb_mode_do_normal(update, context)

        update.callback_query.edit_message_text.assert_called_once()


# --------------------------------------------------------------------------- #
# 测试：非管理员被 require_admin 拒绝                                              #
# --------------------------------------------------------------------------- #

class TestRequireAdminGuard:
    """非 admin 用户调用 do-handler 时应被拒绝，不执行 apply_firewall_mode。"""

    @pytest.mark.asyncio
    async def test_non_admin_normal_rejected(self):
        from tgwl.handlers.mode import cb_mode_do_normal

        update = _make_update()
        context = _make_context(admin=False)

        with patch(
            "tgwl.handlers.mode.reconcile.apply_firewall_mode"
        ) as mock_apply:
            await cb_mode_do_normal(update, context)

        mock_apply.assert_not_called()

    @pytest.mark.asyncio
    async def test_non_admin_open_rejected(self):
        from tgwl.handlers.mode import cb_mode_do_open

        update = _make_update()
        context = _make_context(admin=False)

        with patch(
            "tgwl.handlers.mode.reconcile.apply_firewall_mode"
        ) as mock_apply:
            await cb_mode_do_open(update, context)

        mock_apply.assert_not_called()

    @pytest.mark.asyncio
    async def test_non_admin_gets_answer_called(self):
        """非 admin 时 callback_query.answer 应被调用（无权限提示）。"""
        from tgwl.handlers.mode import cb_mode_do_lockdown

        update = _make_update()
        context = _make_context(admin=False)

        with patch("tgwl.handlers.mode.reconcile.apply_firewall_mode"):
            await cb_mode_do_lockdown(update, context)

        update.callback_query.answer.assert_called_once()
