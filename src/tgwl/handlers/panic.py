"""
handlers/panic.py — 紧急解除（/panic 指令 + Panic 按钮）

执行 nft delete table inet whitelist，立即解除所有白名单限制。
需要二次确认，防止误触。
"""

from __future__ import annotations

import logging

from telegram import Update
from telegram.ext import ContextTypes

from tgwl import ui
from tgwl.handlers.common import require_admin
from tgwl.firewall import FirewallManager

logger = logging.getLogger(__name__)


def _fw(context: ContextTypes.DEFAULT_TYPE) -> FirewallManager:
    return context.bot_data["firewall"]


@require_admin
async def cmd_panic(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/panic 指令，显示二次确认（不直接执行，防误触）。"""
    await update.message.reply_text(
        "即将删除整个 whitelist table，解除所有白名单限制！\n\n"
        "此操作不可逆（但 Bot 重启后可从数据库恢复）。\n"
        "确认执行？",
        reply_markup=ui.panic_confirm_keyboard(),
    )


@require_admin
async def cb_panic_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """callback_data=panic:confirm，显示二次确认界面。"""
    query = update.callback_query
    await query.answer()
    await query.edit_message_text(
        "即将删除整个 whitelist table，解除所有白名单限制！\n\n"
        "此操作不可逆（但 Bot 重启后可从数据库恢复）。\n"
        "确认执行？",
        reply_markup=ui.panic_confirm_keyboard(),
    )


@require_admin
async def cb_panic_do(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """callback_data=panic:do，执行 panic。"""
    query = update.callback_query
    await query.answer("执行中...")

    fw = _fw(context)
    user = update.effective_user
    try:
        fw.panic()
        context.bot_data["firewall_ok"] = False
        logger.warning(
            "PANIC 已执行！user_id=%d (@%s) 删除了 whitelist table",
            user.id,
            user.username or "无",
        )
        await query.edit_message_text(
            "已删除 table inet whitelist\n"
            "所有白名单限制已解除，SSH 等端口现在对所有 IP 开放。\n\n"
            "此操作为临时紧急放行，不持久化；Bot 重启后将从数据库自动恢复白名单。"
        )
    except RuntimeError as e:
        logger.error("panic 执行失败: %s", e)
        await query.edit_message_text(
            f"Panic 执行失败：{e}\n\n"
            "可手动执行：nft delete table inet whitelist"
        )
