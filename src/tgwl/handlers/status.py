"""
handlers/status.py — 状态页 + 同步省市数据
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from telegram import Update
from telegram.ext import ContextTypes

from tgwl import ui
from tgwl.config import Config, redact_credentials
from tgwl.handlers.common import require_admin
from tgwl.handlers.add import _do_reconcile
from tgwl.firewall import FirewallManager
from tgwl.store import Store
from tgwl.geo import GeoService

logger = logging.getLogger(__name__)


def _services(context: ContextTypes.DEFAULT_TYPE) -> tuple[Store, FirewallManager, GeoService]:
    bd = context.bot_data
    return bd["store"], bd["firewall"], bd["geo"]


@require_admin
async def cb_status(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """callback_data=status:main，显示系统状态。"""
    query = update.callback_query
    await query.answer()
    store, fw, geo = _services(context)

    # 防火墙状态
    try:
        fw_status = fw.status()
        fw_text = (
            f"table: {'正常' if fw_status.table_exists else '不存在'} | "
            f"chain: {'正常' if fw_status.chain_exists else '不存在'} | "
            f"set: {'正常' if fw_status.set_exists else '不存在'}\n"
            f"当前 CIDR 条数: {fw_status.element_count}\n"
            f"后端: {fw_status.backend}"
        )
    except Exception as e:
        fw_text = f"查询失败: {e}"

    # 逻辑条目计数
    counts = store.count_entries()
    entries_text = (
        f"IP: {counts.get('ip', 0)} | "
        f"CIDR: {counts.get('cidr', 0)} | "
        f"省: {counts.get('province', 0)} | "
        f"市: {counts.get('city', 0)} | "
        f"共: {counts.get('total', 0)}"
    )

    # 代理连通性（简单探测）
    proxy_url = context.bot_data.get("proxy_url", "")
    proxy_text = Config._redact_proxy_url(proxy_url) if proxy_url else "(不走代理)"

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    text = (
        f"系统状态 [{now_utc}]\n\n"
        f"【防火墙】\n{fw_text}\n\n"
        f"【白名单条目】\n{entries_text}\n\n"
        f"【代理配置】\n{proxy_text}\n\n"
        f"（点「同步省市数据」重新下载最新 IP 段）"
    )
    await query.edit_message_text(text, reply_markup=ui.status_keyboard())


@require_admin
async def cb_status_sync(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    callback_data=status:sync
    重新下载已有省市条目的 CIDR，并重建防火墙 set。
    """
    query = update.callback_query
    await query.answer("正在同步，请稍候...")

    store, fw, geo = _services(context)

    # 找出所有省市条目
    geo_entries = store.get_all_geo_entries()
    if not geo_entries:
        await query.edit_message_text(
            "当前没有省市白名单条目，无需同步。",
            reply_markup=ui.status_keyboard(),
        )
        return

    refreshed = 0
    failed = 0
    for entry in geo_entries:
        try:
            geo.lookup_cidrs_for_area(entry.value, force_refresh=True)
            refreshed += 1
        except Exception as e:
            logger.error("同步省市数据失败 code=%s: %s", entry.value, redact_credentials(str(e)))
            failed += 1

    # 重建防火墙
    try:
        count = await _do_reconcile(store, fw, geo, context=context)
        await query.edit_message_text(
            f"同步完成：成功 {refreshed} / 失败 {failed}\n"
            f"当前生效 CIDR 共 {count} 条。",
            reply_markup=ui.status_keyboard(),
        )
    except RuntimeError as e:
        logger.error("reconcile 失败: %s", e)
        await query.edit_message_text(
            f"数据已更新（成功 {refreshed} / 失败 {failed}），但防火墙同步失败：{e}",
            reply_markup=ui.status_keyboard(),
        )
