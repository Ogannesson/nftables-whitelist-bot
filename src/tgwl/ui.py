"""
ui.py — InlineKeyboard 构建与 callback_data 路由前缀

所有 callback_data 格式：<前缀>:<动作>:<参数>
例如：
  menu:main            — 主菜单
  add:type             — 选择添加类型
  add:ip               — 单 IP 流程开始
  add:cidr             — IP 段流程开始
  add:province         — 选省流程开始
  add:city             — 选市流程开始（先选省）
  add:sel_prov:{code}  — 选中省 {code}
  add:sel_city:{code}  — 选中市 {code}
  add:confirm:{type}:{value}  — 确认添加
  add:cancel           — 取消
  mgr:list:{type}:{page}      — 查看管理，分页
  mgr:del_confirm:{id}        — 确认删除条目
  mgr:del:{id}                — 执行删除
  whois:add:{ip}              — 将查询结果加入白名单
  admin:list           — 管理员列表
  admin:rm_confirm:{uid}      — 确认撤销管理员
  admin:rm:{uid}              — 执行撤销
  admin:add            — 添加管理员
  status:main          — 状态页
  status:sync          — 同步省市数据
  panic:confirm        — Panic 二次确认
  panic:do             — 执行 panic
"""

from __future__ import annotations

from typing import Optional
from telegram import InlineKeyboardButton, InlineKeyboardMarkup

# 每页最多显示的省份/城市按钮数
PROV_PAGE_SIZE = 12   # 省份按钮，每行 2 个
CITY_PAGE_SIZE = 16   # 市按钮，每行 2 个
ENTRY_PAGE_SIZE = 8   # 条目列表每页条数


# --------------------------------------------------------------------------- #
# 主菜单                                                                        #
# --------------------------------------------------------------------------- #

def main_menu(is_primary_admin: bool = False) -> InlineKeyboardMarkup:
    """主菜单（/start /menu）。"""
    buttons = [
        [InlineKeyboardButton("添加白名单", callback_data="add:type")],
        [InlineKeyboardButton("查看 / 管理白名单", callback_data="mgr:list:all:0")],
        [InlineKeyboardButton("查询 IP 归属", callback_data="whois:prompt")],
        [InlineKeyboardButton("状态", callback_data="status:main")],
    ]
    if is_primary_admin:
        buttons.append(
            [InlineKeyboardButton("管理员管理", callback_data="admin:list")]
        )
    buttons.append(
        [InlineKeyboardButton("紧急解除（Panic）", callback_data="panic:confirm")]
    )
    return InlineKeyboardMarkup(buttons)


# --------------------------------------------------------------------------- #
# 添加白名单流程                                                                #
# --------------------------------------------------------------------------- #

def add_type_keyboard() -> InlineKeyboardMarkup:
    """选择添加类型。"""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("单 IP", callback_data="add:ip"),
            InlineKeyboardButton("IP 段", callback_data="add:cidr"),
        ],
        [
            InlineKeyboardButton("省份", callback_data="add:province"),
            InlineKeyboardButton("城市", callback_data="add:city"),
        ],
        [InlineKeyboardButton("取消", callback_data="add:cancel")],
    ])


def province_list_keyboard(
    provinces: list,
    page: int = 0,
    action_prefix: str = "add:sel_prov",
) -> InlineKeyboardMarkup:
    """
    省份选择列表（支持分页）。
    `provinces` 是 GeoArea 列表。
    """
    start = page * PROV_PAGE_SIZE
    page_items = provinces[start: start + PROV_PAGE_SIZE]
    total_pages = (len(provinces) + PROV_PAGE_SIZE - 1) // PROV_PAGE_SIZE

    rows: list[list[InlineKeyboardButton]] = []
    # 每行 2 个省份按钮
    for i in range(0, len(page_items), 2):
        row = []
        for area in page_items[i: i + 2]:
            row.append(
                InlineKeyboardButton(
                    area.short,
                    callback_data=f"{action_prefix}:{area.code}",
                )
            )
        rows.append(row)

    # 翻页按钮
    nav = []
    if page > 0:
        nav.append(
            InlineKeyboardButton("上一页", callback_data=f"add:prov_page:{page-1}")
        )
    if page < total_pages - 1:
        nav.append(
            InlineKeyboardButton("下一页", callback_data=f"add:prov_page:{page+1}")
        )
    if nav:
        rows.append(nav)

    rows.append([InlineKeyboardButton("取消", callback_data="add:cancel")])
    return InlineKeyboardMarkup(rows)


def city_list_keyboard(
    cities: list,
    province_code: str,
    page: int = 0,
) -> InlineKeyboardMarkup:
    """市级选择列表（支持分页）。"""
    start = page * CITY_PAGE_SIZE
    page_items = cities[start: start + CITY_PAGE_SIZE]
    total_pages = (len(cities) + CITY_PAGE_SIZE - 1) // CITY_PAGE_SIZE

    rows: list[list[InlineKeyboardButton]] = []
    for i in range(0, len(page_items), 2):
        row = []
        for area in page_items[i: i + 2]:
            row.append(
                InlineKeyboardButton(
                    area.short,
                    callback_data=f"add:sel_city:{area.code}",
                )
            )
        rows.append(row)

    nav = []
    if page > 0:
        nav.append(
            InlineKeyboardButton(
                "上一页",
                callback_data=f"add:city_page:{province_code}:{page-1}",
            )
        )
    if page < total_pages - 1:
        nav.append(
            InlineKeyboardButton(
                "下一页",
                callback_data=f"add:city_page:{province_code}:{page+1}",
            )
        )
    if nav:
        rows.append(nav)

    rows.append([InlineKeyboardButton("返回省列表", callback_data="add:province")])
    rows.append([InlineKeyboardButton("取消", callback_data="add:cancel")])
    return InlineKeyboardMarkup(rows)


def confirm_add_keyboard(entry_type: str, value: str) -> InlineKeyboardMarkup:
    """添加确认按钮。"""
    safe_value = value.replace(":", "_")  # callback_data 中 : 作分隔符，需转义
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton(
                "确认添加",
                callback_data=f"add:confirm:{entry_type}:{safe_value}",
            ),
            InlineKeyboardButton("取消", callback_data="add:cancel"),
        ]
    ])


def cancel_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("取消", callback_data="add:cancel")]
    ])


# --------------------------------------------------------------------------- #
# 查看 / 管理白名单                                                             #
# --------------------------------------------------------------------------- #

def entry_list_keyboard(
    entries: list,
    entry_type: str,
    page: int,
    total: int,
) -> InlineKeyboardMarkup:
    """
    白名单条目列表（带 🗑 删除按钮）。
    每行显示条目标签 + 删除按钮。
    """
    rows: list[list[InlineKeyboardButton]] = []
    for entry in entries:
        rows.append([
            InlineKeyboardButton(
                f"{entry.label or entry.value}",
                callback_data=f"mgr:noop:{entry.id}",
            ),
            InlineKeyboardButton(
                "删除",
                callback_data=f"mgr:del_confirm:{entry.id}",
            ),
        ])

    total_pages = (total + ENTRY_PAGE_SIZE - 1) // ENTRY_PAGE_SIZE if total > 0 else 1
    nav = []
    if page > 0:
        nav.append(
            InlineKeyboardButton(
                "上一页",
                callback_data=f"mgr:list:{entry_type}:{page-1}",
            )
        )
    if page < total_pages - 1:
        nav.append(
            InlineKeyboardButton(
                "下一页",
                callback_data=f"mgr:list:{entry_type}:{page+1}",
            )
        )
    if nav:
        rows.append(nav)

    # 分类过滤按钮
    filter_row = []
    for t, label in [("all", "全部"), ("ip", "单IP"), ("cidr", "IP段"),
                     ("province", "省"), ("city", "市")]:
        if t != entry_type:
            filter_row.append(
                InlineKeyboardButton(label, callback_data=f"mgr:list:{t}:0")
            )
    if filter_row:
        rows.append(filter_row)

    rows.append([InlineKeyboardButton("返回主菜单", callback_data="menu:main")])
    return InlineKeyboardMarkup(rows)


def confirm_delete_keyboard(entry_id: int) -> InlineKeyboardMarkup:
    """删除二次确认。"""
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton(
                "确认删除",
                callback_data=f"mgr:del:{entry_id}",
            ),
            InlineKeyboardButton("取消", callback_data="mgr:list:all:0"),
        ]
    ])


# --------------------------------------------------------------------------- #
# 状态页                                                                        #
# --------------------------------------------------------------------------- #

def status_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("同步省市数据", callback_data="status:sync")],
        [InlineKeyboardButton("返回主菜单", callback_data="menu:main")],
    ])


# --------------------------------------------------------------------------- #
# 管理员管理                                                                    #
# --------------------------------------------------------------------------- #

def admin_list_keyboard(admins: list) -> InlineKeyboardMarkup:
    """管理员列表（主管理员不可删除）。"""
    rows: list[list[InlineKeyboardButton]] = []
    for admin in admins:
        label = f"{'[主] ' if admin.is_primary else ''}{admin.user_id}"
        row = [InlineKeyboardButton(label, callback_data="admin:noop")]
        if not admin.is_primary:
            row.append(
                InlineKeyboardButton(
                    "撤销",
                    callback_data=f"admin:rm_confirm:{admin.user_id}",
                )
            )
        rows.append(row)

    rows.append([InlineKeyboardButton("添加管理员", callback_data="admin:add")])
    rows.append([InlineKeyboardButton("返回主菜单", callback_data="menu:main")])
    return InlineKeyboardMarkup(rows)


def confirm_remove_admin_keyboard(user_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton(
                "确认撤销",
                callback_data=f"admin:rm:{user_id}",
            ),
            InlineKeyboardButton("取消", callback_data="admin:list"),
        ]
    ])


# --------------------------------------------------------------------------- #
# Panic                                                                         #
# --------------------------------------------------------------------------- #

def panic_confirm_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("确认解除所有限制", callback_data="panic:do"),
            InlineKeyboardButton("取消", callback_data="menu:main"),
        ]
    ])


# --------------------------------------------------------------------------- #
# Whois                                                                         #
# --------------------------------------------------------------------------- #

def whois_result_keyboard(ip: str) -> InlineKeyboardMarkup:
    """归属查询结果，提供「加入白名单」按钮。"""
    safe_ip = ip.replace(".", "_")
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("加入白名单", callback_data=f"whois:add:{safe_ip}")],
        [InlineKeyboardButton("返回主菜单", callback_data="menu:main")],
    ])
