"""
handlers/manage.py — 查看 / 管理白名单（条目列表 + 删除流程）
"""

from __future__ import annotations

import logging

from telegram import Update
from telegram.ext import ContextTypes

from tgwl import ui
from tgwl.handlers.common import require_admin
from tgwl.handlers.add import _do_reconcile
from tgwl.store import Store
from tgwl.firewall import FirewallManager
from tgwl.geo import GeoService

logger = logging.getLogger(__name__)

ENTRY_PAGE_SIZE = ui.ENTRY_PAGE_SIZE

TYPE_LABEL = {
    "all": "全部",
    "ip": "单 IP",
    "cidr": "IP 段",
    "province": "省份",
    "city": "城市",
}


def _services(context: ContextTypes.DEFAULT_TYPE) -> tuple[Store, FirewallManager, GeoService]:
    bd = context.bot_data
    return bd["store"], bd["firewall"], bd["geo"]


@require_admin
async def cb_mgr_list(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    callback_data=mgr:list:{type}:{page}
    显示白名单条目列表（分页）。
    type=all 显示全部；否则按类型过滤。
    """
    query = update.callback_query
    await query.answer()
    parts = query.data.split(":")
    entry_type = parts[2]   # "all" | "ip" | "cidr" | "province" | "city"
    page = int(parts[3])

    store, _, _ = _services(context)
    etype_filter = None if entry_type == "all" else entry_type
    entries, total = store.list_entries_paged(
        entry_type=etype_filter,  # type: ignore[arg-type]
        page=page,
        page_size=ENTRY_PAGE_SIZE,
    )
    count_info = store.count_entries()

    if total == 0:
        text = f"【{TYPE_LABEL.get(entry_type, entry_type)}】暂无白名单条目"
    else:
        total_pages = (total + ENTRY_PAGE_SIZE - 1) // ENTRY_PAGE_SIZE
        text = (
            f"【{TYPE_LABEL.get(entry_type, entry_type)}】白名单条目"
            f"（共 {total} 条，第 {page+1}/{total_pages} 页）\n"
            f"IP: {count_info.get('ip', 0)} | "
            f"CIDR: {count_info.get('cidr', 0)} | "
            f"省: {count_info.get('province', 0)} | "
            f"市: {count_info.get('city', 0)}"
        )

    keyboard = ui.entry_list_keyboard(entries, entry_type, page, total)
    await query.edit_message_text(text, reply_markup=keyboard)


@require_admin
async def cb_mgr_del_confirm(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    callback_data=mgr:del_confirm:{id}
    删除前二次确认。
    """
    query = update.callback_query
    await query.answer()
    entry_id = int(query.data.split(":")[2])

    store, _, _ = _services(context)
    entry = store.get_entry(entry_id)
    if entry is None:
        await query.answer("条目不存在（已被删除？）", show_alert=True)
        return

    await query.edit_message_text(
        f"确认删除以下白名单条目？\n"
        f"  类型：{entry.type}\n"
        f"  值：{entry.value}\n"
        f"  标签：{entry.label}",
        reply_markup=ui.confirm_delete_keyboard(entry_id),
    )


@require_admin
async def cb_mgr_del(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    callback_data=mgr:del:{id}
    执行删除条目 + reconcile。
    """
    query = update.callback_query
    await query.answer()
    entry_id = int(query.data.split(":")[2])

    store, fw, geo = _services(context)
    entry = store.get_entry(entry_id)
    if entry is None:
        await query.edit_message_text("条目已不存在，可能已被删除。")
        return

    label = entry.label or entry.value
    success = store.remove_entry(entry_id)
    if not success:
        await query.edit_message_text(f"删除失败：条目 {label} 不存在。")
        return

    try:
        count = await _do_reconcile(store, fw, geo, context=context)
        user = update.effective_user
        await query.edit_message_text(
            f"已删除【{label}】\n当前生效 CIDR 共 {count} 条。",
            reply_markup=ui.main_menu(
                is_primary_admin=store.is_primary_admin(user.id)
            ),
        )
    except RuntimeError as e:
        logger.error("reconcile 失败: %s", e)
        await query.edit_message_text(
            f"条目已从数据库删除，但防火墙同步失败：{e}\n"
            "请检查 nftables 权限或重启 Bot。"
        )


@require_admin
async def cb_mgr_noop(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """callback_data=mgr:noop:{id}，点击条目名称时无操作（弹出提示）。"""
    query = update.callback_query
    entry_id = int(query.data.split(":")[2])
    store, _, _ = _services(context)
    entry = store.get_entry(entry_id)
    if entry:
        if entry.added_by == 0:
            source_line = "来源：自动加白(Cloudflare Access)"
        else:
            source_line = f"来源：管理员 {entry.added_by}"
        await query.answer(
            f"类型: {entry.type}\n值: {entry.value}\n标签: {entry.label}\n{source_line}",
            show_alert=True,
        )
    else:
        await query.answer("条目不存在", show_alert=True)
