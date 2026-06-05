"""
handlers/mode.py — 防火墙三态模式开关

模式：
  normal   — 正常白名单模式（默认）
  lockdown — 封锁所有入站（仅留 SSH 等已有连接）
  open     — 删除防火墙表，完全放行（等同原 panic）

所有 handler 均需管理员权限（@require_admin）。
切换采用二次确认（mode:set:* → 展示后果 → mode:do:*）防止误触。
"""

from __future__ import annotations

import logging

from telegram import Update
from telegram.ext import ContextTypes

from tgwl import ui
from tgwl.handlers.common import require_admin
import tgwl.reconcile as reconcile

logger = logging.getLogger(__name__)

_MODE_LABELS = {
    "normal":   "正常（白名单）",
    "lockdown": "封锁（Lockdown）",
    "open":     "放行（完全开放）",
}

_MODE_DESCRIPTIONS = {
    "normal": (
        "切换到「正常」模式：\n"
        "• 从数据库重建白名单规则\n"
        "• 仅白名单中的 IP/段可入站\n"
    ),
    "lockdown": (
        "切换到「封锁」模式：\n"
        "• 清空白名单 set（保留 table/chain）\n"
        "• 封锁所有新入站连接（已建立连接不受影响）\n"
        "• 适用于应急封锁，白名单数据不会丢失\n"
    ),
    "open": (
        "切换到「放行」模式：\n"
        "• 删除整个 whitelist table\n"
        "• 所有入站流量完全开放，无任何限制\n"
        "• 此操作等同于原 Panic，Bot 重启后可从数据库恢复规则\n"
    ),
}


def _store(context: ContextTypes.DEFAULT_TYPE):
    return context.bot_data["store"]


def _fw(context: ContextTypes.DEFAULT_TYPE):
    return context.bot_data["firewall"]


def _geo(context: ContextTypes.DEFAULT_TYPE):
    return context.bot_data["geo"]


@require_admin
async def cb_mode_panel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """callback_data=mode:panel — 显示当前防火墙模式面板。"""
    query = update.callback_query
    await query.answer()

    store = _store(context)
    fw = _fw(context)

    current_mode = store.get_setting("firewall_mode") or "normal"
    current_label = _MODE_LABELS.get(current_mode, current_mode)

    try:
        status = fw.status()
        if status.table_exists:
            if status.element_count > 0:
                hw_state = f"table 存在，set 有 {status.element_count} 条 CIDR"
            else:
                hw_state = "table 存在，set 为空"
        else:
            hw_state = "table 不存在（已 panic / open 状态）"
    except Exception as e:
        hw_state = f"状态查询失败：{e}"

    text = (
        "防火墙模式面板\n\n"
        f"当前模式：{current_label}\n"
        f"硬件状态：{hw_state}\n\n"
        "选择要切换的目标模式："
    )
    await query.edit_message_text(text, reply_markup=ui.firewall_mode_panel_keyboard(current_mode))


# --------------------------------------------------------------------------- #
# 二次确认入口（mode:set:*）                                                    #
# --------------------------------------------------------------------------- #

@require_admin
async def cb_mode_set_normal(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """callback_data=mode:set:normal"""
    query = update.callback_query
    await query.answer()
    desc = _MODE_DESCRIPTIONS["normal"]
    await query.edit_message_text(
        desc + "\n确认切换到「正常」模式？",
        reply_markup=ui.mode_confirm_keyboard("normal"),
    )


@require_admin
async def cb_mode_set_lockdown(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """callback_data=mode:set:lockdown"""
    query = update.callback_query
    await query.answer()
    desc = _MODE_DESCRIPTIONS["lockdown"]
    await query.edit_message_text(
        desc + "\n确认切换到「封锁」模式？",
        reply_markup=ui.mode_confirm_keyboard("lockdown"),
    )


@require_admin
async def cb_mode_set_open(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """callback_data=mode:set:open"""
    query = update.callback_query
    await query.answer()
    desc = _MODE_DESCRIPTIONS["open"]
    await query.edit_message_text(
        desc + "\n确认切换到「放行」模式？",
        reply_markup=ui.mode_confirm_keyboard("open"),
    )


# --------------------------------------------------------------------------- #
# 执行切换（mode:do:*）                                                         #
# --------------------------------------------------------------------------- #

async def _do_switch(update: Update, context: ContextTypes.DEFAULT_TYPE, mode: str) -> None:
    """公共执行逻辑，由三个 do-handler 调用。"""
    query = update.callback_query
    await query.answer("切换中...")

    store = _store(context)
    geo = _geo(context)
    fw = _fw(context)
    user = update.effective_user
    label = _MODE_LABELS.get(mode, mode)

    try:
        result = reconcile.apply_firewall_mode(mode, store, geo, fw)
        context.bot_data["firewall_ok"] = (mode != "open")
        logger.warning(
            "防火墙模式已切换：%s，user_id=%d (@%s)，CIDR 条数=%d",
            mode,
            user.id,
            user.username or "无",
            result,
        )
        if mode == "normal":
            detail = f"已重建白名单，共 {result} 条 CIDR。"
        elif mode == "lockdown":
            detail = "已清空入站白名单，所有新入站连接被封锁。"
        else:
            detail = "已删除防火墙表，所有入站完全开放。此状态已持久化，重启后仍保持放行——需手动切回「正常」模式才会恢复白名单。"
        await query.edit_message_text(
            f"已切换到「{label}」模式。\n\n{detail}"
        )
    except Exception as e:
        context.bot_data["firewall_ok"] = False
        logger.error("防火墙模式切换失败 mode=%s: %s", mode, e)
        await query.edit_message_text(
            f"切换到「{label}」模式失败：{e}\n\n"
            "请检查服务器日志或尝试重启 Bot。"
        )


@require_admin
async def cb_mode_do_normal(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """callback_data=mode:do:normal"""
    await _do_switch(update, context, "normal")


@require_admin
async def cb_mode_do_lockdown(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """callback_data=mode:do:lockdown"""
    await _do_switch(update, context, "lockdown")


@require_admin
async def cb_mode_do_open(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """callback_data=mode:do:open"""
    await _do_switch(update, context, "open")
