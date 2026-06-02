"""
handlers/whois.py — IP 归属查询流程
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
from tgwl.handlers.common import require_admin
from tgwl.geo import GeoService

logger = logging.getLogger(__name__)

WAIT_WHOIS_IP = "whois_wait_ip"


def _geo(context: ContextTypes.DEFAULT_TYPE) -> GeoService:
    return context.bot_data["geo"]


@require_admin
async def cb_whois_prompt(update: Update, context: ContextTypes.DEFAULT_TYPE) -> str:
    """callback_data=whois:prompt，提示用户发送 IP。"""
    query = update.callback_query
    await query.answer()
    msg = await query.edit_message_text(
        "请发送要查询归属地的 IPv4 地址：",
        reply_markup=ui.cancel_keyboard(),
    )
    # 记录 prompt 消息位置，用于收到文本后清除取消按钮
    if msg:
        context.user_data["whois_prompt_chat_id"] = msg.chat_id
        context.user_data["whois_prompt_message_id"] = msg.message_id
    return WAIT_WHOIS_IP


async def _clear_whois_prompt_keyboard(context: ContextTypes.DEFAULT_TYPE) -> None:
    """清除 whois prompt 消息上的 inline 取消按钮（孤儿按钮清理）。"""
    chat_id = context.user_data.pop("whois_prompt_chat_id", None)
    message_id = context.user_data.pop("whois_prompt_message_id", None)
    if chat_id and message_id:
        try:
            await context.bot.edit_message_reply_markup(
                chat_id=chat_id,
                message_id=message_id,
                reply_markup=None,
            )
        except Exception:
            # 消息已被删除或无法编辑时静默忽略
            pass


async def recv_whois_ip(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """收到 IP 文本，查询归属地。"""
    from tgwl.store import Store
    store: Store = context.bot_data["store"]
    if update.effective_user is None or not store.is_admin(update.effective_user.id):
        user = update.effective_user
        logger.warning(
            "权限拒绝: user_id=%d (@%s) 尝试使用 whois 功能（非管理员）",
            user.id if user else -1,
            user.username or "无" if user else "未知",
        )
        await update.message.reply_text("无权限")
        return ConversationHandler.END

    text = update.message.text.strip()
    geo = _geo(context)

    try:
        info = geo.lookup_ip(text)
        result_text = (
            f"IP 归属查询结果：\n"
            f"  IP: {info.ip}\n"
            f"  地区: {info.display()}\n"
            f"  国家: {info.country}\n"
            f"  省份: {info.province}\n"
            f"  城市: {info.city}\n"
            f"  ISP: {info.isp}"
        )
        # 清除 prompt 消息上残留的取消按钮
        await _clear_whois_prompt_keyboard(context)
        await update.message.reply_text(
            result_text,
            reply_markup=ui.whois_result_keyboard(text),
        )
    except ValueError as e:
        await update.message.reply_text(
            f"无效 IP 地址：{e}\n请重新输入：",
            reply_markup=ui.cancel_keyboard(),
        )
        return WAIT_WHOIS_IP
    except Exception as e:
        from tgwl.config import redact_credentials as _redact
        safe_msg = _redact(str(e))
        logger.error("whois 查询失败: %s: %s", type(e).__name__, safe_msg)
        await update.message.reply_text(
            "查询失败，可能是网络/代理问题，请稍后重试。",
            reply_markup=ui.cancel_keyboard(),
        )
        return WAIT_WHOIS_IP

    return ConversationHandler.END


@require_admin
async def cb_whois_add(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    callback_data=whois:add:{ip}（ip 中 . 替换为 _）
    将查询结果的 IP 加入白名单流程。
    """
    query = update.callback_query
    await query.answer()
    ip_encoded = query.data.split(":", 2)[2]
    ip = ip_encoded.replace("_", ".")
    # 直接跳到确认界面
    await query.edit_message_text(
        f"将添加 IP {ip} 到白名单，确认？",
        reply_markup=ui.confirm_add_keyboard("ip", ip),
    )


async def whois_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    if update.message:
        await update.message.reply_text("已取消")
    return ConversationHandler.END


@require_admin
async def _whois_cb_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """
    whois 对话内的取消按钮（callback_data=add:cancel）。

    BUG-3 修复：原实现使用 lambda + 非协程 answer()，导致协程从未被 await，
    点击取消按钮无响应且对话状态不正常退出。
    改为正规 async 函数，await answer()，并正确返回 ConversationHandler.END。
    """
    query = update.callback_query
    await query.answer("已取消")
    store = context.bot_data["store"]
    user = update.effective_user
    is_primary = store.is_primary_admin(user.id)
    from tgwl import ui as _ui
    await query.edit_message_text(
        "已取消，请选择操作：",
        reply_markup=_ui.main_menu(is_primary_admin=is_primary),
    )
    return ConversationHandler.END


def build_whois_conversation() -> ConversationHandler:
    return ConversationHandler(
        entry_points=[
            CallbackQueryHandler(cb_whois_prompt, pattern=r"^whois:prompt$"),
        ],
        states={
            WAIT_WHOIS_IP: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, recv_whois_ip),
                # BUG-3 修复：使用正规 async 函数替代无法 await 的 lambda
                CallbackQueryHandler(_whois_cb_cancel, pattern=r"^add:cancel$"),
            ],
        },
        fallbacks=[
            CommandHandler("cancel", whois_cancel),
        ],
        per_message=False,
        per_chat=True,
        per_user=True,
        allow_reentry=True,
    )
