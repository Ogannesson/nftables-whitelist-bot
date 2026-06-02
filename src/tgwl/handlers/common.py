"""
handlers/common.py — 权限装饰器与公共工具

所有 handler 的权限校验都用 require_admin() / require_primary_admin()。
这两个函数既可以当装饰器（装饰同步/异步函数），也可以在 handler 内直接调用。
"""

from __future__ import annotations

import functools
import ipaddress
import logging
from typing import Callable, Optional

from telegram import Update
from telegram.ext import ContextTypes

from tgwl.store import Store

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# 权限检查                                                                      #
# --------------------------------------------------------------------------- #

def _get_store(context: ContextTypes.DEFAULT_TYPE) -> Store:
    """从 bot_data 获取 Store 实例。"""
    return context.bot_data["store"]


def _is_admin(user_id: int, context: ContextTypes.DEFAULT_TYPE) -> bool:
    store: Store = _get_store(context)
    return store.is_admin(user_id)


def _is_primary_admin(user_id: int, context: ContextTypes.DEFAULT_TYPE) -> bool:
    store: Store = _get_store(context)
    return store.is_primary_admin(user_id)


def require_admin(func: Callable) -> Callable:
    """
    装饰器：要求 effective_user 是管理员（含主管理员）。
    非授权用户的请求静默拒绝并写日志。
    适用于 async def handler(update, context) 签名。
    """
    @functools.wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user = update.effective_user
        if user is None:
            return
        if not _is_admin(user.id, context):
            logger.warning(
                "权限拒绝: user_id=%d (@%s) 尝试访问受限功能 [%s]",
                user.id,
                user.username or "无",
                func.__name__,
            )
            if update.callback_query:
                await update.callback_query.answer("无权限", show_alert=True)
            elif update.message:
                await update.message.reply_text("您没有权限执行此操作。")
            return
        return await func(update, context, *args, **kwargs)
    return wrapper


def require_primary_admin(func: Callable) -> Callable:
    """
    装饰器：要求 effective_user 是主管理员。
    """
    @functools.wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
        user = update.effective_user
        if user is None:
            return
        if not _is_primary_admin(user.id, context):
            logger.warning(
                "主管理员权限拒绝: user_id=%d (@%s) 尝试访问主管理员功能 [%s]",
                user.id,
                user.username or "无",
                func.__name__,
            )
            if update.callback_query:
                await update.callback_query.answer("需要主管理员权限", show_alert=True)
            elif update.message:
                await update.message.reply_text("此操作需要主管理员权限。")
            return
        return await func(update, context, *args, **kwargs)
    return wrapper


# --------------------------------------------------------------------------- #
# IP / CIDR 校验工具                                                            #
# --------------------------------------------------------------------------- #

def parse_ip_or_cidr(text: str) -> Optional[str]:
    """
    解析并标准化 IP 或 CIDR 字符串。
    返回标准化字符串，无效输入返回 None。
    """
    text = text.strip()
    # 尝试 CIDR
    try:
        net = ipaddress.IPv4Network(text, strict=False)
        return str(net)
    except ValueError:
        pass
    # 尝试纯 IP（/32）
    try:
        addr = ipaddress.IPv4Address(text)
        return str(addr)
    except ValueError:
        pass
    return None


def is_single_ip(text: str) -> bool:
    """判断是否是单个 IPv4 地址（不含掩码或 /32）。"""
    try:
        ipaddress.IPv4Address(text.strip())
        return True
    except ValueError:
        return False


def entry_type_for_text(text: str) -> Optional[str]:
    """
    根据输入文本判断 entry type（"ip" / "cidr"）。
    "/" 判断为 cidr，否则尝试 ip；无效返回 None。
    """
    text = text.strip()
    if "/" in text:
        try:
            ipaddress.IPv4Network(text, strict=False)
            return "cidr"
        except ValueError:
            return None
    else:
        try:
            ipaddress.IPv4Address(text)
            return "ip"
        except ValueError:
            return None
