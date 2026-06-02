"""
handlers/add.py — 添加白名单流程

流程（ConversationHandler 状态机）：
  WAIT_IP_TEXT  — 等待用户输入 IP / CIDR 文本
  WAIT_CONFIRM  — 等待用户确认（IP/CIDR 路径）

省/市路径通过 InlineKeyboard 回调完成，无需对话状态：
  add:province → 省列表 → add:sel_prov:{code} → 确认 → add:confirm:province:{code}
  add:city → 省列表 → add:sel_prov:{code}（city mode）→ 市列表 →
             add:sel_city:{code} → 确认 → add:confirm:city:{code}
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Optional

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
from tgwl.handlers.common import require_admin, parse_ip_or_cidr, entry_type_for_text
from tgwl.firewall import FirewallManager, collapse_cidrs
from tgwl.store import Store
from tgwl.geo import GeoService

logger = logging.getLogger(__name__)

# 对话状态
WAIT_IP_TEXT = "add_wait_ip_text"
WAIT_IP_CONFIRM = "add_wait_ip_confirm"


def _services(context: ContextTypes.DEFAULT_TYPE) -> tuple[Store, FirewallManager, GeoService]:
    bd = context.bot_data
    return bd["store"], bd["firewall"], bd["geo"]


async def _do_reconcile(
    store: Store,
    fw: FirewallManager,
    geo: GeoService,
    context: ContextTypes.DEFAULT_TYPE | None = None,
) -> int:
    """
    全量重建 nftables whitelist4 set，返回 CIDR 条数。

    若 context 提供且 bot_data["firewall_ok"] 为 False，
    说明启动时防火墙初始化失败，此时拒绝执行并抛出 RuntimeError，
    避免用户误以为操作成功但实际防火墙未生效。
    """
    if context is not None and not context.bot_data.get("firewall_ok", False):
        raise RuntimeError(
            "防火墙未就绪（启动时初始化失败）。"
            "请检查 nftables 权限并重启 Bot 后再操作。"
        )

    ip_entries = store.get_all_ip_entries()
    geo_entries = store.get_all_geo_entries()

    all_cidrs: list[str] = []
    # IP / CIDR 直接用
    for e in ip_entries:
        all_cidrs.append(e.value)
    # 省市展开
    for e in geo_entries:
        cidrs = geo.lookup_cidrs_for_area(e.value)
        all_cidrs.extend(cidrs)

    collapsed = collapse_cidrs(all_cidrs)
    nets = {ipaddress.IPv4Network(c) for c in collapsed}
    return fw.reconcile(nets)


# --------------------------------------------------------------------------- #
# 按钮路由（直接通过 CallbackQueryHandler 处理的非对话路径）                    #
# --------------------------------------------------------------------------- #

@require_admin
async def cb_add_type(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """callback_data=add:type，显示添加类型选择。"""
    query = update.callback_query
    await query.answer()
    await query.edit_message_text(
        "请选择要添加的类型：",
        reply_markup=ui.add_type_keyboard(),
    )


@require_admin
async def cb_add_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """callback_data=add:cancel，取消并返回主菜单。"""
    query = update.callback_query
    await query.answer("已取消")
    store = context.bot_data["store"]
    user = update.effective_user
    is_primary = store.is_primary_admin(user.id)
    await query.edit_message_text(
        "已取消，请选择操作：",
        reply_markup=ui.main_menu(is_primary_admin=is_primary),
    )


@require_admin
async def cb_add_province_list(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """callback_data=add:province，显示省份列表。"""
    query = update.callback_query
    await query.answer()
    context.user_data["add_city_mode"] = False  # 不是选市的前置
    geo: GeoService = context.bot_data["geo"]
    provinces = geo.list_provinces()
    await query.edit_message_text(
        "请选择要添加的省份：",
        reply_markup=ui.province_list_keyboard(provinces, page=0),
    )


@require_admin
async def cb_add_city_prov_list(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """callback_data=add:city，先选省（为选市做前置）。"""
    query = update.callback_query
    await query.answer()
    context.user_data["add_city_mode"] = True
    geo: GeoService = context.bot_data["geo"]
    provinces = geo.list_provinces()
    await query.edit_message_text(
        "请先选择省份（下一步选择市）：",
        reply_markup=ui.province_list_keyboard(
            provinces, page=0, action_prefix="add:city_prov"
        ),
    )


@require_admin
async def cb_add_prov_page(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """callback_data=add:prov_page:{page}，翻页。"""
    query = update.callback_query
    await query.answer()
    _, _, page_str = query.data.split(":", 2)
    page = int(page_str)
    geo: GeoService = context.bot_data["geo"]
    provinces = geo.list_provinces()
    await query.edit_message_text(
        "请选择要添加的省份：",
        reply_markup=ui.province_list_keyboard(provinces, page=page),
    )


@require_admin
async def cb_sel_province(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    callback_data=add:sel_prov:{code}
    直接显示确认（省级白名单）。
    """
    query = update.callback_query
    await query.answer()
    code = query.data.split(":", 2)[2]
    if not re.fullmatch(r"\d{6}", code):
        await query.answer("区划码格式非法", show_alert=True)
        return
    geo: GeoService = context.bot_data["geo"]
    area = geo.get_area(code)
    if area is None:
        await query.answer("未知区划码", show_alert=True)
        return

    # 展开 CIDR 数（用缓存）
    cidrs = geo.lookup_cidrs_for_area(code)
    count = len(cidrs)
    await query.edit_message_text(
        f"将添加【{area.name}】的 IP 白名单\n"
        f"预计 CIDR 条目数：约 {count} 条\n\n"
        "确认添加？",
        reply_markup=ui.confirm_add_keyboard("province", code),
    )


@require_admin
async def cb_city_prov_selected(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    callback_data=add:city_prov:{prov_code}
    选好省后，显示该省的市列表。
    """
    query = update.callback_query
    await query.answer()
    prov_code = query.data.split(":", 2)[2]
    if not re.fullmatch(r"\d{6}", prov_code):
        await query.answer("区划码格式非法", show_alert=True)
        return
    geo: GeoService = context.bot_data["geo"]
    cities = geo.list_cities_by_province(prov_code)
    prov = geo.get_area(prov_code)
    prov_name = prov.name if prov else prov_code
    await query.edit_message_text(
        f"已选择【{prov_name}】，请选择城市：",
        reply_markup=ui.city_list_keyboard(cities, prov_code, page=0),
    )


@require_admin
async def cb_city_page(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """callback_data=add:city_page:{prov_code}:{page}，市列表翻页。"""
    query = update.callback_query
    await query.answer()
    parts = query.data.split(":")
    # add:city_page:{prov_code}:{page}
    prov_code = parts[2]
    if not re.fullmatch(r"\d{6}", prov_code):
        await query.answer("区划码格式非法", show_alert=True)
        return
    page = int(parts[3])
    geo: GeoService = context.bot_data["geo"]
    cities = geo.list_cities_by_province(prov_code)
    await query.edit_message_text(
        "请选择城市：",
        reply_markup=ui.city_list_keyboard(cities, prov_code, page=page),
    )


@require_admin
async def cb_sel_city(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """callback_data=add:sel_city:{code}，显示市级确认。"""
    query = update.callback_query
    await query.answer()
    code = query.data.split(":", 2)[2]
    if not re.fullmatch(r"\d{6}", code):
        await query.answer("区划码格式非法", show_alert=True)
        return
    geo: GeoService = context.bot_data["geo"]
    area = geo.get_area(code)
    if area is None:
        await query.answer("未知区划码", show_alert=True)
        return

    cidrs = geo.lookup_cidrs_for_area(code)
    count = len(cidrs)
    await query.edit_message_text(
        f"将添加【{area.name}】的 IP 白名单\n"
        f"预计 CIDR 条目数：约 {count} 条\n\n"
        "确认添加？",
        reply_markup=ui.confirm_add_keyboard("city", code),
    )


@require_admin
async def cb_confirm_add(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    callback_data=add:confirm:{type}:{value}
    执行实际添加（入库 + reconcile）。
    """
    query = update.callback_query
    await query.answer()
    # 格式：add:confirm:{type}:{value}（value 中 : 已替换为 _）
    parts = query.data.split(":", 3)
    if len(parts) < 4:
        await query.answer("回调参数错误", show_alert=True)
        return

    entry_type = parts[2]
    raw_value = parts[3].replace("_", ".")  # 还原 IP 中的 .（省市 code 无影响）

    # 对于省市，还原可能被替换的分隔符（行政区划码是纯数字，无特殊字符）
    if entry_type in ("province", "city"):
        value = parts[3]  # 行政区划码本身无点，直接用
    else:
        value = raw_value

    # --- BUG-1 修复：入库前校验 entry_type 合法性 + IP/CIDR 格式 ---
    # callback_data 可被恶意构造，必须在服务端再次校验，不能信任客户端传入的值。
    from tgwl.store import VALID_ENTRY_TYPES
    if entry_type not in VALID_ENTRY_TYPES:
        logger.warning(
            "cb_confirm_add: 非法 entry_type %r（user_id=%d），拒绝入库",
            entry_type,
            update.effective_user.id if update.effective_user else -1,
        )
        await query.answer("非法操作参数", show_alert=True)
        return

    if entry_type in ("ip", "cidr"):
        # 严格校验 IP/CIDR 格式，防止恶意构造的 callback_data 污染数据库
        parsed = parse_ip_or_cidr(value)
        if parsed is None:
            logger.warning(
                "cb_confirm_add: 非法 IP/CIDR 值 %r（user_id=%d），拒绝入库",
                value,
                update.effective_user.id if update.effective_user else -1,
            )
            await query.answer("IP/CIDR 格式非法，拒绝操作", show_alert=True)
            return
        value = parsed  # 使用标准化后的值入库
    elif entry_type in ("province", "city"):
        # 行政区划码必须是 6 位纯数字，且在已知注册表中
        import re as _re
        if not _re.fullmatch(r"\d{6}", value):
            logger.warning(
                "cb_confirm_add: 非法行政区划码 %r（user_id=%d），拒绝入库",
                value,
                update.effective_user.id if update.effective_user else -1,
            )
            await query.answer("行政区划码格式非法，拒绝操作", show_alert=True)
            return

    store, fw, geo = _services(context)
    user = update.effective_user

    # 确定 label
    if entry_type in ("province", "city"):
        area = geo.get_area(value)
        label = area.name if area else value
    else:
        label = value

    # 幂等入库
    entry = store.add_entry(
        entry_type=entry_type,  # type: ignore[arg-type]
        value=value,
        label=label,
        added_by=user.id,
    )

    if entry is None:
        await query.edit_message_text(
            f"已存在相同条目（{label}），无需重复添加。",
            reply_markup=ui.main_menu(
                is_primary_admin=store.is_primary_admin(user.id)
            ),
        )
        return

    # 重建防火墙 set
    try:
        count = await _do_reconcile(store, fw, geo, context=context)
        await query.edit_message_text(
            f"已添加【{label}】到白名单\n当前生效 CIDR 共 {count} 条。",
            reply_markup=ui.main_menu(
                is_primary_admin=store.is_primary_admin(user.id)
            ),
        )
    except RuntimeError as e:
        logger.error("reconcile 失败: %s", e)
        await query.edit_message_text(
            f"条目已入库，但防火墙同步失败：{e}\n"
            "请检查 nftables 权限或重启 Bot。",
        )


# --------------------------------------------------------------------------- #
# 对话 Handler — 等待 IP/CIDR 文本                                             #
# --------------------------------------------------------------------------- #

@require_admin
async def cb_add_ip_prompt(update: Update, context: ContextTypes.DEFAULT_TYPE) -> str:
    """callback_data=add:ip，提示输入单 IP。"""
    query = update.callback_query
    await query.answer()
    context.user_data["add_mode"] = "ip"
    msg = await query.edit_message_text(
        "请发送要添加的 IPv4 地址（如 1.2.3.4）：",
        reply_markup=ui.cancel_keyboard(),
    )
    # 记录 prompt 消息位置，用于收到文本后清除取消按钮
    if msg:
        context.user_data["add_prompt_chat_id"] = msg.chat_id
        context.user_data["add_prompt_message_id"] = msg.message_id
    return WAIT_IP_TEXT


@require_admin
async def cb_add_cidr_prompt(update: Update, context: ContextTypes.DEFAULT_TYPE) -> str:
    """callback_data=add:cidr，提示输入 CIDR 段。"""
    query = update.callback_query
    await query.answer()
    context.user_data["add_mode"] = "cidr"
    msg = await query.edit_message_text(
        "请发送要添加的 IPv4 CIDR 段（如 192.168.0.0/24）：",
        reply_markup=ui.cancel_keyboard(),
    )
    # 记录 prompt 消息位置，用于收到文本后清除取消按钮
    if msg:
        context.user_data["add_prompt_chat_id"] = msg.chat_id
        context.user_data["add_prompt_message_id"] = msg.message_id
    return WAIT_IP_TEXT


async def _clear_prompt_keyboard(context: ContextTypes.DEFAULT_TYPE) -> None:
    """清除 add_prompt 消息上的 inline 取消按钮（孤儿按钮清理）。"""
    chat_id = context.user_data.pop("add_prompt_chat_id", None)
    message_id = context.user_data.pop("add_prompt_message_id", None)
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


async def recv_ip_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> str:
    """收到文本，校验 IP/CIDR，显示确认按钮。"""
    if update.effective_user is None:
        return ConversationHandler.END
    store: Store = context.bot_data["store"]
    if not store.is_admin(update.effective_user.id):
        user = update.effective_user
        logger.warning(
            "权限拒绝: user_id=%d (@%s) 尝试在 add 对话中发送 IP 文本（非管理员）",
            user.id,
            user.username or "无",
        )
        await update.message.reply_text("无权限")
        return ConversationHandler.END

    text = update.message.text.strip()
    mode = context.user_data.get("add_mode", "ip")
    parsed = parse_ip_or_cidr(text)
    if parsed is None:
        await update.message.reply_text(
            f"无效的 IP 地址或 CIDR 格式：{text}\n请重新输入：",
            reply_markup=ui.cancel_keyboard(),
        )
        return WAIT_IP_TEXT  # 留在当前状态，等待重新输入

    # 根据解析结果判断类型
    etype = entry_type_for_text(parsed)
    if etype is None:
        etype = mode

    # 清除 prompt 消息上残留的取消按钮
    await _clear_prompt_keyboard(context)

    await update.message.reply_text(
        f"将添加以下条目到白名单：\n  类型：{etype}\n  值：{parsed}\n\n确认？",
        reply_markup=ui.confirm_add_keyboard(etype, parsed),
    )
    return ConversationHandler.END


async def conv_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """对话取消。"""
    if update.message:
        await update.message.reply_text("已取消")
    return ConversationHandler.END


def build_add_conversation() -> ConversationHandler:
    """构建 IP/CIDR 添加对话 Handler。"""
    return ConversationHandler(
        entry_points=[
            CallbackQueryHandler(cb_add_ip_prompt, pattern=r"^add:ip$"),
            CallbackQueryHandler(cb_add_cidr_prompt, pattern=r"^add:cidr$"),
        ],
        states={
            WAIT_IP_TEXT: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, recv_ip_text),
                CallbackQueryHandler(cb_add_cancel, pattern=r"^add:cancel$"),
            ],
        },
        fallbacks=[
            CommandHandler("cancel", conv_cancel),
            CallbackQueryHandler(cb_add_cancel, pattern=r"^add:cancel$"),
        ],
        per_message=False,
        per_chat=True,
        per_user=True,
        allow_reentry=True,
    )
