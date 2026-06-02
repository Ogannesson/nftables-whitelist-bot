"""
bot.py — Bot 主程序入口

启动流程：
  1. 加载配置（config.py）
  2. 初始化 Store、FirewallManager、GeoService
  3. 写入主管理员到 SQLite
  4. ensure_setup() + reconcile()（恢复防火墙规则）
  5. 构建 Application（走 SOCKS5 代理）
  6. 注册所有 handlers
  7. 启动 polling

非 Linux 或无 nftables 权限时，Bot 仍可启动（防火墙调用会记录错误），
方便 Windows 开发机测试其他功能。
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from telegram import BotCommand, Update
from telegram.ext import (
    Application,
    ApplicationBuilder,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
)

from tgwl.config import Config, init_config, redact_credentials
from tgwl.store import Store
from tgwl.firewall import FirewallManager, collapse_cidrs, get_firewall_manager
from tgwl.geo import GeoService
from tgwl.handlers.common import require_admin

import tgwl.handlers.menu as menu_h
import tgwl.handlers.add as add_h
import tgwl.handlers.manage as manage_h
import tgwl.handlers.whois as whois_h
import tgwl.handlers.status as status_h
import tgwl.handlers.admin_mgr as admin_h
import tgwl.handlers.panic as panic_h

logger = logging.getLogger(__name__)


def setup_logging(level: int = logging.INFO) -> None:
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # 屏蔽 httpx 过多日志
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


async def _post_init(application: Application) -> None:
    """Bot 初始化完成后注册命令菜单（走已配置的代理）。"""
    await application.bot.set_my_commands([
        BotCommand("start", "打开主菜单"),
        BotCommand("menu", "打开主菜单"),
        BotCommand("panic", "紧急解除所有白名单限制"),
    ])
    logger.info("Bot 命令菜单已注册")


def build_application(cfg: Config) -> Application:
    """构建 Telegram Application（带 SOCKS5 代理）。"""
    builder = ApplicationBuilder().token(cfg.bot.token).post_init(_post_init)
    if cfg.proxy.url:
        builder = builder.proxy(cfg.proxy.url).get_updates_proxy(cfg.proxy.url)
    return builder.build()


@require_admin
async def _cb_admin_noop(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """callback_data=admin:noop，无操作占位（带权限检查）。"""
    await update.callback_query.answer()


def register_handlers(app: Application) -> None:
    """注册所有指令、回调、对话 Handler。"""

    # ---- 指令 ----
    app.add_handler(CommandHandler(["start", "menu"], menu_h.cmd_start))
    app.add_handler(CommandHandler("panic", panic_h.cmd_panic))

    # ---- ConversationHandlers（优先注册，防被 CallbackQueryHandler 截断）----
    app.add_handler(add_h.build_add_conversation())
    app.add_handler(whois_h.build_whois_conversation())
    app.add_handler(admin_h.build_admin_conversation())

    # ---- 主菜单 ----
    app.add_handler(CallbackQueryHandler(menu_h.cb_menu_main, pattern=r"^menu:main$"))

    # ---- 添加白名单 ----
    app.add_handler(CallbackQueryHandler(add_h.cb_add_type, pattern=r"^add:type$"))
    app.add_handler(CallbackQueryHandler(add_h.cb_add_cancel, pattern=r"^add:cancel$"))
    app.add_handler(CallbackQueryHandler(add_h.cb_add_province_list, pattern=r"^add:province$"))
    app.add_handler(CallbackQueryHandler(add_h.cb_add_city_prov_list, pattern=r"^add:city$"))
    app.add_handler(CallbackQueryHandler(add_h.cb_add_prov_page, pattern=r"^add:prov_page:\d+$"))
    app.add_handler(
        CallbackQueryHandler(add_h.cb_sel_province, pattern=r"^add:sel_prov:\d{6}$")
    )
    app.add_handler(
        CallbackQueryHandler(add_h.cb_city_prov_selected, pattern=r"^add:city_prov:\d{6}$")
    )
    app.add_handler(
        CallbackQueryHandler(add_h.cb_city_page, pattern=r"^add:city_page:\d+:\d+$")
    )
    app.add_handler(
        CallbackQueryHandler(add_h.cb_sel_city, pattern=r"^add:sel_city:\d{6}$")
    )
    app.add_handler(
        CallbackQueryHandler(add_h.cb_confirm_add, pattern=r"^add:confirm:")
    )

    # ---- 查看 / 管理 ----
    app.add_handler(
        CallbackQueryHandler(manage_h.cb_mgr_list, pattern=r"^mgr:list:")
    )
    app.add_handler(
        CallbackQueryHandler(manage_h.cb_mgr_del_confirm, pattern=r"^mgr:del_confirm:\d+$")
    )
    app.add_handler(
        CallbackQueryHandler(manage_h.cb_mgr_del, pattern=r"^mgr:del:\d+$")
    )
    app.add_handler(
        CallbackQueryHandler(manage_h.cb_mgr_noop, pattern=r"^mgr:noop:\d+$")
    )

    # ---- 归属查询 ----
    app.add_handler(
        CallbackQueryHandler(whois_h.cb_whois_add, pattern=r"^whois:add:")
    )

    # ---- 状态 ----
    app.add_handler(CallbackQueryHandler(status_h.cb_status, pattern=r"^status:main$"))
    app.add_handler(CallbackQueryHandler(status_h.cb_status_sync, pattern=r"^status:sync$"))

    # ---- 管理员管理 ----
    app.add_handler(
        CallbackQueryHandler(admin_h.cb_admin_list, pattern=r"^admin:list$")
    )
    app.add_handler(
        CallbackQueryHandler(admin_h.cb_admin_rm_confirm, pattern=r"^admin:rm_confirm:\d+$")
    )
    app.add_handler(
        CallbackQueryHandler(admin_h.cb_admin_rm, pattern=r"^admin:rm:\d+$")
    )

    # ---- Panic ----
    app.add_handler(
        CallbackQueryHandler(panic_h.cb_panic_confirm, pattern=r"^panic:confirm$")
    )
    app.add_handler(
        CallbackQueryHandler(panic_h.cb_panic_do, pattern=r"^panic:do$")
    )

    # ---- Noop ----
    app.add_handler(
        CallbackQueryHandler(_cb_admin_noop, pattern=r"^admin:noop$")
    )


def main(config_path: str | Path | None = None) -> None:
    setup_logging()

    # 加载配置
    cfg = init_config(config_path)
    logger.info("配置已加载: %s", cfg.safe_repr())

    # 初始化各服务
    store = Store(cfg.database.path)
    store.ensure_primary_admin(cfg.bot.primary_admin)
    logger.info("主管理员: %d", cfg.bot.primary_admin)

    fw = get_firewall_manager()

    geo = GeoService(
        data_dir=cfg.geo.data_dir,
        proxy_url=cfg.proxy.url,
        online_provider=cfg.geo.online_provider,
    )

    # 启动时恢复防火墙
    # 策略：
    #   - ensure_setup 成功 → 正常运行
    #   - ensure_setup 失败（含建表失败的危险状态）→ 记录 CRITICAL 日志，
    #     在 bot_data 中标记 firewall_ok=False，所有防火墙变更操作拒绝执行
    #     （不能静默继续，否则用户以为添加了白名单但实际无效）
    #   - 若平台非 Linux 或无权限 → 同上，fail 模式（开发环境正常）
    import ipaddress as _ipaddress
    firewall_ok = False
    try:
        fw.ensure_setup()
        logger.info("防火墙 table 已就绪")
        # 从 SQLite 重建 whitelist4
        ip_entries = store.get_all_ip_entries()
        geo_entries = store.get_all_geo_entries()
        all_cidrs: list[str] = [e.value for e in ip_entries]
        for e in geo_entries:
            all_cidrs.extend(geo.lookup_cidrs_for_area(e.value))
        collapsed = collapse_cidrs(all_cidrs)
        nets = {_ipaddress.IPv4Network(c) for c in collapsed}
        count = fw.reconcile(nets)
        logger.info("防火墙白名单已恢复：%d 条 CIDR", count)
        firewall_ok = True
    except Exception as e:
        logger.critical(
            "防火墙初始化失败，Bot 将以「防火墙不可用」模式运行。"
            "所有添加/删除白名单操作将被拒绝，直到重启并修复问题。"
            "错误: %s",
            redact_credentials(str(e)),
        )

    # 构建 Application
    app = build_application(cfg)

    # 把服务注入 bot_data（所有 handler 共享）
    app.bot_data["store"] = store
    app.bot_data["firewall"] = fw
    app.bot_data["geo"] = geo
    app.bot_data["proxy_url"] = cfg.proxy.url
    # 防火墙就绪标志：False 时 reconcile 操作应拒绝，并提示用户重启
    app.bot_data["firewall_ok"] = firewall_ok

    register_handlers(app)
    logger.info("Bot 启动，开始 polling...")
    app.run_polling(allowed_updates=["message", "callback_query"])


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="tg-whitelist Bot")
    parser.add_argument("--config", default=None, help="配置文件路径")
    args = parser.parse_args()
    main(config_path=args.config)
