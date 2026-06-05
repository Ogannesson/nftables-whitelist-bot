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

import asyncio
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
from tgwl.cf_pull import CFPullClient
from tgwl.store import Store
from tgwl.firewall import FirewallManager, collapse_cidrs, get_firewall_manager
from tgwl.geo import GeoService
from tgwl.reconcile import reconcile_from_store
from tgwl.handlers.common import require_admin

import tgwl.handlers.menu as menu_h
import tgwl.handlers.add as add_h
import tgwl.handlers.manage as manage_h
import tgwl.handlers.whois as whois_h
import tgwl.handlers.status as status_h
import tgwl.handlers.admin_mgr as admin_h
import tgwl.handlers.panic as panic_h
import tgwl.handlers.mode as mode_h

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

    # ---- 模式切换 ----
    app.add_handler(
        CallbackQueryHandler(mode_h.cb_mode_panel, pattern=r"^mode:panel$")
    )
    app.add_handler(
        CallbackQueryHandler(mode_h.cb_mode_set_normal, pattern=r"^mode:set:normal$")
    )
    app.add_handler(
        CallbackQueryHandler(mode_h.cb_mode_set_lockdown, pattern=r"^mode:set:lockdown$")
    )
    app.add_handler(
        CallbackQueryHandler(mode_h.cb_mode_set_open, pattern=r"^mode:set:open$")
    )
    app.add_handler(
        CallbackQueryHandler(mode_h.cb_mode_do_normal, pattern=r"^mode:do:normal$")
    )
    app.add_handler(
        CallbackQueryHandler(mode_h.cb_mode_do_lockdown, pattern=r"^mode:do:lockdown$")
    )
    app.add_handler(
        CallbackQueryHandler(mode_h.cb_mode_do_open, pattern=r"^mode:do:open$")
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
        ip2location_io_key=cfg.geo.ip2location_io_key,
        ip2region_xdb=cfg.geo.ip2region_xdb,
    )

    # 启动时按持久化模式恢复防火墙
    mode = store.get_setting("firewall_mode") or "normal"
    if mode not in ("normal", "lockdown", "open"):
        logger.warning("firewall_mode 无效值 %r，降级为 normal", mode)
        mode = "normal"
    firewall_ok = False
    try:
        if mode == "open":
            logger.info("firewall_mode=open：启动时不建表，完全放行（fail-open）")
            # 不建表；firewall_ok 保持 False
        else:
            fw.ensure_setup()
            if mode == "lockdown":
                fw.reconcile(set())
                logger.info("firewall_mode=lockdown：已封锁所有新入站")
            else:
                count = reconcile_from_store(store, geo, fw)
                logger.info("firewall_mode=normal：白名单已恢复，%d 条 CIDR", count)
            firewall_ok = True
    except Exception as e:
        logger.critical("防火墙初始化失败，以「不可用」模式运行... 错误: %s", redact_credentials(str(e)))

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

    # CF Worker 自动加白定时任务
    if cfg.cf_pull.enabled and cfg.cf_pull.worker_url:
        async def _cf_pull_job(context: ContextTypes.DEFAULT_TYPE) -> None:
            if not context.bot_data.get("firewall_ok"):
                logger.warning("cf_pull: firewall_ok=False，跳过本次拉取")
                return
            _store = context.bot_data["store"]
            _geo = context.bot_data["geo"]
            _fw = context.bot_data["firewall"]
            client = CFPullClient(
                cfg.cf_pull.worker_url,
                cfg.cf_pull.access_client_id,
                cfg.cf_pull.access_client_secret,
                proxy_url=cfg.proxy.url,
            )
            try:
                await asyncio.to_thread(client.process, _store, _geo, _fw)
            except Exception as e:
                logger.error("cf_pull job 失败: %s", redact_credentials(str(e)))

        app.job_queue.run_repeating(
            _cf_pull_job,
            interval=cfg.cf_pull.poll_interval_seconds,
            first=10,
        )
        logger.info(
            "CF Pull 定时任务已启用，间隔 %d 秒，首次执行延迟 10 秒",
            cfg.cf_pull.poll_interval_seconds,
        )

    logger.info("Bot 启动，开始 polling...")
    app.run_polling(allowed_updates=["message", "callback_query"])


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="tg-whitelist Bot")
    parser.add_argument("--config", default=None, help="配置文件路径")
    args = parser.parse_args()
    main(config_path=args.config)
