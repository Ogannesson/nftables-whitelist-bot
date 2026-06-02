"""
handlers/admin_mgr.py — 管理员管理（仅主管理员）

添加管理员支持两种方式：
  1. 转发用户的任意消息（解析 forward_from）
  2. 直接发送数字 user_id
"""

from __future__ import annotations

import logging

from telegram import Update
from telegram.ext import (
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    CallbackQueryHandler,
    CommandHandler,
    filters,
)

from tgwl import ui
from tgwl.handlers.common import require_admin, require_primary_admin
from tgwl.store import Store

logger = logging.getLogger(__name__)

WAIT_ADD_ADMIN = "admin_wait_add"


def _store(context: ContextTypes.DEFAULT_TYPE) -> Store:
    return context.bot_data["store"]


@require_admin
@require_primary_admin
async def cb_admin_list(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """callback_data=admin:list，显示管理员列表。"""
    query = update.callback_query
    await query.answer()
    store = _store(context)
    admins = store.list_admins()
    text = f"当前管理员列表（共 {len(admins)} 人）："
    await query.edit_message_text(text, reply_markup=ui.admin_list_keyboard(admins))


@require_admin
@require_primary_admin
async def cb_admin_rm_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """callback_data=admin:rm_confirm:{uid}，撤销管理员二次确认。"""
    query = update.callback_query
    await query.answer()
    uid = int(query.data.split(":")[2])
    store = _store(context)
    admin = store.get_admin(uid)
    if admin is None:
        await query.answer("该用户不是管理员", show_alert=True)
        return
    await query.edit_message_text(
        f"确认撤销管理员 {uid} 的权限？",
        reply_markup=ui.confirm_remove_admin_keyboard(uid),
    )


@require_admin
@require_primary_admin
async def cb_admin_rm(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """callback_data=admin:rm:{uid}，执行撤销。"""
    query = update.callback_query
    await query.answer()
    uid = int(query.data.split(":")[2])
    store = _store(context)
    try:
        result = store.remove_admin(uid)
    except PermissionError as e:
        await query.answer(str(e), show_alert=True)
        return

    if result:
        await query.edit_message_text(
            f"已撤销管理员 {uid} 的权限。",
            reply_markup=ui.admin_list_keyboard(store.list_admins()),
        )
    else:
        await query.edit_message_text(f"用户 {uid} 不是管理员。")


@require_admin
@require_primary_admin
async def cb_admin_add_prompt(update: Update, context: ContextTypes.DEFAULT_TYPE) -> str:
    """callback_data=admin:add，提示添加管理员。"""
    query = update.callback_query
    await query.answer()
    await query.edit_message_text(
        "请转发目标用户的任意消息，或直接发送其数字 user_id：\n"
        "（发送 /cancel 取消）",
    )
    return WAIT_ADD_ADMIN


async def recv_add_admin(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """接收管理员添加信息。"""
    store: Store = context.bot_data["store"]
    user = update.effective_user
    if user is None or not store.is_primary_admin(user.id):
        logger.warning(
            "权限拒绝: user_id=%d (@%s) 尝试在 admin 对话中添加管理员（非主管理员）",
            user.id if user else -1,
            user.username or "无" if user else "未知",
        )
        await update.message.reply_text("需要主管理员权限")
        return ConversationHandler.END

    message = update.message
    target_id: int | None = None

    # 方式 1：转发消息
    if message.forward_origin is not None:
        from telegram import MessageOriginUser
        if isinstance(message.forward_origin, MessageOriginUser):
            target_id = message.forward_origin.sender_user.id
    # 方式 2：直接发送 user_id（纯数字文本）
    elif message.text and message.text.strip().isdigit():
        target_id = int(message.text.strip())

    if target_id is None:
        await message.reply_text(
            "未能识别用户 ID，请转发消息或直接发送数字 user_id：",
        )
        return WAIT_ADD_ADMIN

    if target_id == user.id:
        await message.reply_text("不能将自己再次添加为管理员（您已经是主管理员）")
        return ConversationHandler.END

    success = store.add_admin(target_id, added_by=user.id)
    if success:
        await message.reply_text(f"已添加管理员：{target_id}")
    else:
        await message.reply_text(f"用户 {target_id} 已经是管理员，无需重复添加。")

    return ConversationHandler.END


async def admin_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if update.message:
        await update.message.reply_text("已取消")
    return ConversationHandler.END


def build_admin_conversation() -> ConversationHandler:
    return ConversationHandler(
        entry_points=[
            CallbackQueryHandler(cb_admin_add_prompt, pattern=r"^admin:add$"),
        ],
        states={
            WAIT_ADD_ADMIN: [
                MessageHandler(
                    (filters.TEXT | filters.FORWARDED) & ~filters.COMMAND,
                    recv_add_admin,
                ),
            ],
        },
        fallbacks=[
            CommandHandler("cancel", admin_cancel),
        ],
        per_message=False,
        per_chat=True,
        per_user=True,
        allow_reentry=True,
    )
