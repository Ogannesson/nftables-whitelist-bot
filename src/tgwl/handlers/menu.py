"""
handlers/menu.py — 主菜单 + /start /menu 指令
"""

from __future__ import annotations

import logging

from telegram import Update
from telegram.ext import ContextTypes

from tgwl.handlers.common import require_admin
from tgwl import ui

logger = logging.getLogger(__name__)


@require_admin
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """处理 /start 和 /menu 指令，显示主菜单。"""
    store = context.bot_data["store"]
    user = update.effective_user
    is_primary = store.is_primary_admin(user.id)
    keyboard = ui.main_menu(is_primary_admin=is_primary)
    text = (
        "Telegram IP 白名单管理\n"
        f"当前管理员：{user.first_name}（{'主管理员' if is_primary else '管理员'}）\n\n"
        "请选择操作："
    )
    if update.message:
        await update.message.reply_text(text, reply_markup=keyboard)
    elif update.callback_query:
        await update.callback_query.edit_message_text(text, reply_markup=keyboard)


@require_admin
async def cb_menu_main(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """callback_data=menu:main，返回主菜单。"""
    query = update.callback_query
    await query.answer()
    store = context.bot_data["store"]
    user = update.effective_user
    is_primary = store.is_primary_admin(user.id)
    keyboard = ui.main_menu(is_primary_admin=is_primary)
    await query.edit_message_text("请选择操作：", reply_markup=keyboard)
