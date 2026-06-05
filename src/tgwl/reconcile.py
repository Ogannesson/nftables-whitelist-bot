"""
reconcile.py — 防火墙白名单重建工具函数

提供两个公共函数：
  reconcile_from_store(store, geo, fw) -> int
      从 SQLite 读取所有 IP/CIDR 和地理条目，展开后整体 reconcile 防火墙，
      返回最终写入 nftables 的 CIDR 条数。

  apply_firewall_mode(mode, store, geo, fw) -> int
      三态编排：normal / lockdown / open，并将模式持久化到 store settings。
"""

from __future__ import annotations

import ipaddress

from tgwl.firewall import collapse_cidrs


def reconcile_from_store(store, geo, fw) -> int:
    """
    全量从 store 重建防火墙白名单。

    聚合所有 IP/CIDR 条目与地理条目（经 geo 展开为 CIDR），
    折叠合并后调用 fw.reconcile()，返回 CIDR 条数。

    注意：本函数不调用 fw.ensure_setup()，调用方按需在此之前调用。
    """
    ip_entries = store.get_all_ip_entries()
    geo_entries = store.get_all_geo_entries()

    all_cidrs: list[str] = [e.value for e in ip_entries]
    for e in geo_entries:
        all_cidrs.extend(geo.lookup_cidrs_for_area(e.value))

    collapsed = collapse_cidrs(all_cidrs)
    nets = {ipaddress.IPv4Network(c) for c in collapsed}
    return fw.reconcile(nets)


def apply_firewall_mode(mode: str, store, geo, fw) -> int:
    """
    三态防火墙模式编排器。

    mode="normal"   — ensure_setup() 后全量重建白名单
    mode="lockdown" — ensure_setup() 后 reconcile(空集合)，封锁所有入站
    mode="open"     — panic()，移除防火墙表（完全开放）
    其他值          — 抛出 ValueError

    成功后将 mode 写入 store settings["firewall_mode"]，返回 CIDR 条数
    （open 模式返回 0）。
    """
    if mode == "normal":
        fw.ensure_setup()
        result = reconcile_from_store(store, geo, fw)
    elif mode == "lockdown":
        fw.ensure_setup()
        result = fw.reconcile(set())
    elif mode == "open":
        fw.panic()
        result = 0
    else:
        raise ValueError(f"Unknown firewall mode: {mode!r}")

    store.set_setting("firewall_mode", mode)
    return result
