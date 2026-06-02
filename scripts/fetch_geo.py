#!/usr/bin/env python3
"""
scripts/fetch_geo.py — 下载/更新省市地理数据

用途：
  - 下载 metowolf/iplist cncity/*.txt（全部省/市 CIDR）到 data/cncity/
  - 可选：下载 ip2region ipv4_source.txt 兜底库

使用方法：
  python scripts/fetch_geo.py [--config config.toml] [--all] [--ip2region]
  python scripts/fetch_geo.py --code 330000    # 只下载浙江
  python scripts/fetch_geo.py --all            # 下载所有省市

依赖 config.toml（或环境变量）中的 proxy.url 和 geo.data_dir 配置。
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

# 把项目 src 目录加入 sys.path，支持直接运行脚本
_REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from tgwl.config import Config, redact_credentials
from tgwl.geo import OfflineGeo, get_registry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("fetch_geo")

IP2REGION_SOURCE_URL = (
    "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/"
    "data/ipv4_source.txt"
)


def download_all_provinces(geo: OfflineGeo, delay: float = 0.3) -> int:
    """下载所有省级数据。返回成功下载的数量。"""
    registry = get_registry()
    provinces = registry.list_provinces()
    success = 0
    for p in provinces:
        try:
            cidrs = geo.refresh_code(p.code)
            logger.info("[%s] %s (%s): %d 条 CIDR", p.code, p.name, p.short, len(cidrs))
            success += 1
        except Exception as e:
            logger.warning("[%s] %s 下载失败: %s", p.code, p.name, redact_credentials(str(e)))
        time.sleep(delay)
    return success


def download_all_cities(geo: OfflineGeo, delay: float = 0.2) -> int:
    """下载所有市级数据。返回成功下载的数量。"""
    registry = get_registry()
    provinces = registry.list_provinces()
    success = 0
    for p in provinces:
        cities = registry.list_cities_by_province(p.code)
        for c in cities:
            try:
                cidrs = geo.refresh_code(c.code)
                logger.info("  [%s] %s: %d 条 CIDR", c.code, c.name, len(cidrs))
                success += 1
            except Exception as e:
                logger.warning("  [%s] %s 下载失败: %s", c.code, c.name, redact_credentials(str(e)))
            time.sleep(delay)
    return success


def download_ip2region(data_dir: Path, proxy_url: str = "") -> None:
    """下载 ip2region ipv4_source.txt 到 data_dir。"""
    import httpx
    out_file = data_dir / "ipv4_source.txt"
    logger.info("下载 ip2region ipv4_source.txt ...")
    proxies = {"all://": proxy_url} if proxy_url else None
    try:
        with httpx.Client(proxies=proxies, timeout=120, follow_redirects=True) as client:
            with client.stream("GET", IP2REGION_SOURCE_URL) as resp:
                resp.raise_for_status()
                total = int(resp.headers.get("content-length", 0))
                downloaded = 0
                with open(out_file, "wb") as f:
                    for chunk in resp.iter_bytes(chunk_size=65536):
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total:
                            pct = downloaded * 100 // total
                            print(f"\r进度: {pct}% ({downloaded}/{total} bytes)", end="", flush=True)
        print()  # 换行
        logger.info("ip2region 下载完成: %s", out_file)
    except Exception as e:
        logger.error("ip2region 下载失败: %s", redact_credentials(str(e)))
        raise


def main() -> None:
    parser = argparse.ArgumentParser(
        description="下载/更新省市地理 IP 数据"
    )
    parser.add_argument("--config", default=None, help="配置文件路径（默认自动查找）")
    parser.add_argument("--all", action="store_true", help="下载所有省市数据")
    parser.add_argument("--provinces-only", action="store_true", help="只下载省级数据")
    parser.add_argument("--cities-only", action="store_true", help="只下载市级数据")
    parser.add_argument("--code", help="只下载指定行政区划码（如 330000）")
    parser.add_argument("--ip2region", action="store_true", help="同时下载 ip2region 兜底库")
    parser.add_argument("--delay", type=float, default=0.3, help="下载间隔（秒），默认 0.3")
    args = parser.parse_args()

    # 加载配置
    try:
        cfg = Config.load(args.config)
    except ValueError as e:
        logger.error("配置错误: %s", redact_credentials(str(e)))
        sys.exit(1)

    data_dir = cfg.geo.data_dir
    data_dir.mkdir(parents=True, exist_ok=True)
    proxy_url = cfg.proxy.url

    geo = OfflineGeo(data_dir=data_dir, proxy_url=proxy_url)

    if args.code:
        logger.info("下载单个行政区划码: %s", args.code)
        cidrs = geo.refresh_code(args.code)
        logger.info("完成: %d 条 CIDR", len(cidrs))

    elif args.all:
        logger.info("开始下载所有省市数据（省 + 市）...")
        n_p = download_all_provinces(geo, delay=args.delay)
        n_c = download_all_cities(geo, delay=args.delay)
        logger.info("全量下载完成：省 %d / 市 %d", n_p, n_c)

    elif args.provinces_only:
        logger.info("下载省级数据...")
        n = download_all_provinces(geo, delay=args.delay)
        logger.info("省级下载完成: %d", n)

    elif args.cities_only:
        logger.info("下载市级数据...")
        n = download_all_cities(geo, delay=args.delay)
        logger.info("市级下载完成: %d", n)

    else:
        # 默认：只下载省级
        logger.info("默认：下载省级数据（可加 --all 下载市级）")
        n = download_all_provinces(geo, delay=args.delay)
        logger.info("省级下载完成: %d", n)

    if args.ip2region:
        download_ip2region(data_dir, proxy_url=proxy_url)

    logger.info("数据目录: %s", data_dir.resolve())


if __name__ == "__main__":
    main()
