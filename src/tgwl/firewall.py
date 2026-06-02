"""
firewall.py — nftables 抽象层

设计原则：
  - 独立 table inet whitelist，不触碰任何现有规则
  - 防锁死：规则顺序严格保证 SSH 22 / established / lo 先于 drop
  - 原子操作：优先 python3-nftables JSON 事务，回退 subprocess nft
  - subprocess 路径绝不用 shell=True，参数单独传递防注入
  - 非 Linux 或无权限时相关调用会抛异常，调用方负责处理

规则结构（每次 ensure_setup 都按此顺序建立）：
  chain input {
      type filter hook input priority -10; policy accept;
      iif "lo" accept                          # 1. 回环
      ct state established,related accept      # 2. 已建连（防锁死关键）
      ct state invalid drop                    # 3. 丢弃无效包
      tcp dport 22 accept                      # 4. SSH 永久放行（防锁死关键）
      ip saddr @whitelist4 accept              # 5. 白名单放行
      ip6 nexthdr ipv6-icmp accept             # 6. IPv6 邻居发现
      meta nfproto ipv4 drop                   # 7. 非白名单 v4 丢弃（最后）
  }
"""

from __future__ import annotations

import ipaddress
import json
import logging
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Union

logger = logging.getLogger(__name__)

# nft 二进制的绝对路径（模块加载时一次性定位，避免 systemd 窄 PATH 问题）
# 搜索顺序：PATH → /usr/sbin/nft → /sbin/nft（Debian/Ubuntu 常见位置）
def _locate_nft() -> str | None:
    """定位 nft 二进制的绝对路径。找不到时返回 None。"""
    found = shutil.which("nft")
    if found:
        return found
    for fallback in ("/usr/sbin/nft", "/sbin/nft"):
        if shutil.which(fallback) is not None:
            return fallback
        # 直接检查文件存在性（which 要求可执行位，os.path.isfile 宽松些）
        import os
        if os.path.isfile(fallback) and os.access(fallback, os.X_OK):
            return fallback
    return None

_NFT_BIN: str | None = None  # 延迟初始化，首次使用时锁定

# nftables 表 / 链 / set 名称常量
TABLE_FAMILY = "inet"
TABLE_NAME   = "whitelist"
SET_NAME     = "whitelist4"
CHAIN_NAME   = "input"

# 链 hook 优先级（-10，在默认 filter 0 之前）
CHAIN_PRIORITY = -10


# --------------------------------------------------------------------------- #
# 状态数据类                                                                    #
# --------------------------------------------------------------------------- #

@dataclass
class FirewallStatus:
    table_exists: bool
    chain_exists: bool
    set_exists: bool
    element_count: int    # set 中当前 CIDR 条数
    backend: str          # "nftables_lib" | "subprocess" | "mock"


# --------------------------------------------------------------------------- #
# 后端抽象                                                                      #
# --------------------------------------------------------------------------- #

class _NftBackend:
    """nft 操作后端基类（供 mock 测试继承）。"""

    def run_json(self, cmd_obj: list) -> dict:
        raise NotImplementedError

    def run_text(self, args: list[str]) -> str:
        raise NotImplementedError

    @property
    def name(self) -> str:
        return "base"


class _LibBackend(_NftBackend):
    """python3-nftables 绑定（系统包，非 pip）。"""

    def __init__(self) -> None:
        import nftables  # type: ignore[import]
        self._nft = nftables.Nftables()
        self._nft.set_json_output(True)
        self._nft.set_stateless_output(False)
        # 预定位 nft 二进制，run_text 用绝对路径，避免 systemd 窄 PATH 问题
        self._nft_bin = _get_nft_bin()

    def run_json(self, cmd_obj: list) -> dict:
        payload = {"nftables": cmd_obj}
        rc, out, err = self._nft.json_cmd(json.dumps(payload))
        if rc != 0:
            raise RuntimeError(f"nftables json_cmd 失败 (rc={rc}): {err.strip()}")
        return json.loads(out) if out else {}

    def run_text(self, args: list[str]) -> str:
        """
        用绝对路径 subprocess 调用 nft，补充 JSON 不支持的查询场景（如 list table）。
        使用预定位的绝对路径，与 json_cmd 后端保持一致，避免 PATH 缺失时的混乱状态。
        """
        return _run_nft_subprocess(args, nft_bin=self._nft_bin)

    @property
    def name(self) -> str:
        return "nftables_lib"


class _SubprocessBackend(_NftBackend):
    """subprocess 调 nft 命令行（回退方案）。"""

    def __init__(self) -> None:
        self._nft_bin = _get_nft_bin()

    def run_json(self, cmd_obj: list) -> dict:
        # 把 JSON 结构序列化为 -j 模式的输入
        payload = json.dumps({"nftables": cmd_obj})
        result = subprocess.run(
            [self._nft_bin, "-j", "-f", "-"],
            input=payload,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"nft subprocess 失败 (rc={result.returncode}): {result.stderr.strip()}"
            )
        return json.loads(result.stdout) if result.stdout.strip() else {}

    def run_text(self, args: list[str]) -> str:
        return _run_nft_subprocess(args, nft_bin=self._nft_bin)

    @property
    def name(self) -> str:
        return "subprocess"


def _get_nft_bin() -> str:
    """
    获取 nft 二进制绝对路径（全局单例，首次调用时定位）。
    找不到时抛出 RuntimeError（在后端初始化阶段快速失败）。
    """
    global _NFT_BIN
    if _NFT_BIN is None:
        _NFT_BIN = _locate_nft()
    if _NFT_BIN is None:
        raise RuntimeError(
            "未找到 nft 二进制（已搜索 PATH、/usr/sbin/nft、/sbin/nft）。\n"
            "请安装 nftables：apt install nftables"
        )
    return _NFT_BIN


def _run_nft_subprocess(args: list[str], nft_bin: str | None = None) -> str:
    """
    以参数列表方式调用 nft，不使用 shell=True，防止命令注入。
    args 不含 "nft" 本身。
    nft_bin：nft 二进制绝对路径；None 时自动定位（仅测试 / 回退用）。
    """
    bin_path = nft_bin or _get_nft_bin()
    cmd = [bin_path] + args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"nft 命令失败: {' '.join(cmd)}\n"
            f"stderr: {result.stderr.strip()}"
        )
    return result.stdout


def _detect_backend() -> _NftBackend:
    """
    探测可用后端：优先 python3-nftables，回退 subprocess nft。

    两个后端的 __init__ 都会调用 _get_nft_bin()（对于 _LibBackend 是 run_text 用的
    绝对路径），若 nft 不在任何已知路径，_get_nft_bin() 会抛出 RuntimeError，
    这意味着 _LibBackend 即使 import 成功也无法正常工作，需要同时找到 nft 二进制。
    """
    # 先验证 nft 二进制可用（两个后端都需要，快速失败比到调用时才报错更安全）
    nft_bin = _locate_nft()
    if nft_bin is None:
        raise RuntimeError(
            "未找到 nft 二进制（已搜索 PATH、/usr/sbin/nft、/sbin/nft）。\n"
            "请安装 nftables：apt install nftables"
        )
    # 锁定全局路径
    global _NFT_BIN
    _NFT_BIN = nft_bin

    try:
        backend = _LibBackend()
        logger.debug("使用 python3-nftables 绑定后端 (nft=%s)", nft_bin)
        return backend
    except ImportError:
        logger.debug("python3-nftables 不可用，回退 subprocess 后端 (nft=%s)", nft_bin)

    return _SubprocessBackend()


# --------------------------------------------------------------------------- #
# FirewallManager                                                               #
# --------------------------------------------------------------------------- #

class FirewallManager:
    """
    nftables 白名单操作封装。

    使用方式：
        fw = FirewallManager()          # 自动探测后端
        fw.ensure_setup()               # 创建/确保 table/chain/set 存在
        fw.reconcile(cidr_set)          # 全量刷新白名单 set
        fw.panic()                      # 删除整个 table（紧急解除）
        status = fw.status()            # 查询状态
    """

    def __init__(self, backend: _NftBackend | None = None) -> None:
        self._backend: _NftBackend
        if backend is not None:
            self._backend = backend
        elif sys.platform == "linux":
            self._backend = _detect_backend()
        else:
            # 非 Linux 开发环境：延迟到真正调用时再报错
            self._backend = _NoopBackend()
            logger.warning("非 Linux 平台，nftables 调用将不可用")

    @property
    def backend_name(self) -> str:
        return self._backend.name

    # ------------------------------------------------------------------ #
    # 公开 API                                                             #
    # ------------------------------------------------------------------ #

    def ensure_setup(self) -> None:
        """
        确保 table / set / chain 及所有规则存在且顺序正确。

        本方法设计为幂等：若 table 已存在，先 delete 再重建，
        保证规则顺序始终符合防锁死要求。

        警告：重建期间（极短）白名单失效，policy accept 兜底不影响连通性。

        异常处理：
        - _delete_table_if_exists 成功但 _create_table_and_rules 失败时，
          系统处于"table 不存在"的暴露状态（所有防火墙规则消失）。
          本方法会写 ERROR 日志并重新抛出异常——调用方必须处理此异常，
          不得静默忽略（bot.py 应拒绝后续指令并告警）。
        """
        self._delete_table_if_exists()
        try:
            self._create_table_and_rules()
        except Exception as e:
            # 关键：table 已删除但重建失败，防火墙处于完全开放状态
            logger.error(
                "ensure_setup 严重错误：table 已删除但重建失败，"
                "防火墙规则已丢失，服务器处于完全开放状态！错误: %s",
                e,
            )
            raise  # 调用方必须处理
        logger.info("ensure_setup 完成：table inet %s 已就绪", TABLE_NAME)

    def reconcile(
        self,
        cidr_set: set[Union[ipaddress.IPv4Network, ipaddress.IPv4Address]],
    ) -> int:
        """
        全量重建 whitelist4 set。

        步骤：flush set → 批量 add element（单原子事务）。
        入参应已经过 ipaddress.collapse_addresses() 去重。
        返回最终写入的元素数量。

        注意：IPv4Address 对象（无前缀长度）通过 str() 转换后得到 "a.b.c.d"，
        在 _flush_and_add_elements 内部经 ip_network(..., strict=False) 规范化
        为 "a.b.c.d/32"（单主机路由）。这是预期的语义——单 IP 白名单在 nftables
        中以 /32 主机路由存储，功能等价。
        """
        if not cidr_set:
            # 空集：仅 flush
            self._flush_set()
            logger.info("reconcile: 白名单为空，已 flush set")
            return 0

        # 规范化为字符串列表（CIDR 格式）
        elements = [str(n) for n in cidr_set]
        self._flush_and_add_elements(elements)
        logger.info("reconcile: 已写入 %d 条 CIDR 到 %s", len(elements), SET_NAME)
        return len(elements)

    def panic(self) -> None:
        """
        紧急解除：删除整个 table inet whitelist。
        执行后本 bot 的所有防火墙规则立即消失，SSH 等限制解除。
        """
        self._backend.run_text(["delete", "table", TABLE_FAMILY, TABLE_NAME])
        logger.warning("panic: 已删除 table %s %s，所有白名单规则已解除", TABLE_FAMILY, TABLE_NAME)

    def status(self) -> FirewallStatus:
        """查询当前防火墙状态。"""
        table_exists = self._table_exists()
        chain_exists = False
        set_exists = False
        element_count = 0

        if table_exists:
            chain_exists = self._chain_exists()
            set_exists = self._set_exists()
            if set_exists:
                element_count = self._count_set_elements()

        return FirewallStatus(
            table_exists=table_exists,
            chain_exists=chain_exists,
            set_exists=set_exists,
            element_count=element_count,
            backend=self._backend.name,
        )

    # ------------------------------------------------------------------ #
    # 内部：table/chain/set 操作                                          #
    # ------------------------------------------------------------------ #

    def _delete_table_if_exists(self) -> None:
        """
        删除 table（若存在）。不存在时静默忽略。

        捕获范围：
        - RuntimeError：nft 返回非零退出码，其中"no such table"型错误静默，其余重抛
        - FileNotFoundError / OSError：nft 二进制不在 PATH（subprocess 路径会抛此类异常）
          此类错误属于系统环境问题，不应静默——直接重抛让调用方感知

        注意：FileNotFoundError 是 OSError 的子类，此处分开处理，
        避免把"nft 命令不存在"误判为"nftables table 不存在"。
        """
        try:
            self._backend.run_text(["delete", "table", TABLE_FAMILY, TABLE_NAME])
        except FileNotFoundError:
            # nft 二进制不在 PATH——重抛，不静默
            raise
        except OSError as e:
            # 其他 OS 层面错误（权限不足等）——重抛
            raise
        except RuntimeError as e:
            # nft 返回非零：区分"table 不存在"（正常）和其他错误
            err_str = str(e).lower()
            if "no such" in err_str or "does not exist" in err_str:
                pass  # table 不存在是预期状态，静默
            else:
                raise

    def _create_table_and_rules(self) -> None:
        """
        用单个 JSON 事务创建 table、set 和 chain（含全部规则）。

        规则顺序（严格，防锁死）：
          1. iif "lo" accept
          2. ct state established,related accept   ← 防锁死关键
          3. ct state invalid drop
          4. tcp dport 22 accept                   ← 防锁死关键
          5. ip saddr @whitelist4 accept
          6. ip6 nexthdr ipv6-icmp accept
          7. meta nfproto ipv4 drop                ← 最后，仅丢弃 v4 非白名单
        """
        cmd = [
            # 1. 创建 table
            {"add": {"table": {"family": TABLE_FAMILY, "name": TABLE_NAME}}},

            # 2. 创建 set whitelist4
            {
                "add": {
                    "set": {
                        "family": TABLE_FAMILY,
                        "table": TABLE_NAME,
                        "name": SET_NAME,
                        "type": "ipv4_addr",
                        "flags": ["interval"],
                        "auto-merge": True,
                    }
                }
            },

            # 3. 创建 chain input
            {
                "add": {
                    "chain": {
                        "family": TABLE_FAMILY,
                        "table": TABLE_NAME,
                        "name": CHAIN_NAME,
                        "type": "filter",
                        "hook": "input",
                        "prio": CHAIN_PRIORITY,
                        "policy": "accept",
                    }
                }
            },

            # 规则 1：回环接口放行
            {
                "add": {
                    "rule": {
                        "family": TABLE_FAMILY,
                        "table": TABLE_NAME,
                        "chain": CHAIN_NAME,
                        "expr": [
                            {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}},
                            {"accept": None},
                        ],
                    }
                }
            },

            # 规则 2：已建连 / 相关包放行（防锁死关键）
            {
                "add": {
                    "rule": {
                        "family": TABLE_FAMILY,
                        "table": TABLE_NAME,
                        "chain": CHAIN_NAME,
                        "expr": [
                            {
                                "match": {
                                    "op": "in",
                                    "left": {"ct": {"key": "state"}},
                                    "right": ["established", "related"],
                                }
                            },
                            {"accept": None},
                        ],
                    }
                }
            },

            # 规则 3：无效包丢弃
            {
                "add": {
                    "rule": {
                        "family": TABLE_FAMILY,
                        "table": TABLE_NAME,
                        "chain": CHAIN_NAME,
                        "expr": [
                            {
                                "match": {
                                    "op": "in",
                                    "left": {"ct": {"key": "state"}},
                                    "right": ["invalid"],
                                }
                            },
                            {"drop": None},
                        ],
                    }
                }
            },

            # 规则 4：SSH 22 永久放行（防锁死关键）
            {
                "add": {
                    "rule": {
                        "family": TABLE_FAMILY,
                        "table": TABLE_NAME,
                        "chain": CHAIN_NAME,
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                                    "right": 22,
                                }
                            },
                            {"accept": None},
                        ],
                    }
                }
            },

            # 规则 5：白名单 IP 放行
            {
                "add": {
                    "rule": {
                        "family": TABLE_FAMILY,
                        "table": TABLE_NAME,
                        "chain": CHAIN_NAME,
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                                    "right": {"set": f"@{SET_NAME}"},
                                }
                            },
                            {"accept": None},
                        ],
                    }
                }
            },

            # 规则 6：IPv6 ICMPv6 放行（邻居发现，避免 v6 异常）
            {
                "add": {
                    "rule": {
                        "family": TABLE_FAMILY,
                        "table": TABLE_NAME,
                        "chain": CHAIN_NAME,
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {"payload": {"protocol": "ip6", "field": "nexthdr"}},
                                    "right": "ipv6-icmp",
                                }
                            },
                            {"accept": None},
                        ],
                    }
                }
            },

            # 规则 7：仅丢弃 v4 非白名单包（最后，v6 由 policy accept 兜底）
            {
                "add": {
                    "rule": {
                        "family": TABLE_FAMILY,
                        "table": TABLE_NAME,
                        "chain": CHAIN_NAME,
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {"meta": {"key": "nfproto"}},
                                    "right": "ipv4",
                                }
                            },
                            {"drop": None},
                        ],
                    }
                }
            },
        ]

        self._backend.run_json(cmd)

    def _flush_set(self) -> None:
        """清空 set whitelist4（不删除 set 本身）。"""
        self._backend.run_text(
            ["flush", "set", TABLE_FAMILY, TABLE_NAME, SET_NAME]
        )

    def _flush_and_add_elements(self, elements: list[str]) -> None:
        """
        原子事务：flush set + 批量添加元素。
        优先 JSON 事务；subprocess 后端 fallback 到两步操作（同样安全，
        因为 flush 后 drop 期极短且 policy accept 兜底）。
        """
        # 验证所有元素都是合法 IP/CIDR，防止注入（即使 subprocess 不用 shell）
        validated = []
        for elem in elements:
            try:
                net = ipaddress.ip_network(elem, strict=False)
                if not isinstance(net, ipaddress.IPv4Network):
                    logger.warning("跳过非 IPv4 元素: %s", elem)
                    continue
                validated.append(str(net))
            except ValueError:
                logger.warning("跳过无效 CIDR: %s", elem)

        if not validated:
            self._flush_set()
            return

        cmd = [
            # flush set
            {
                "flush": {
                    "set": {
                        "family": TABLE_FAMILY,
                        "table": TABLE_NAME,
                        "name": SET_NAME,
                    }
                }
            },
            # add elements
            {
                "add": {
                    "element": {
                        "family": TABLE_FAMILY,
                        "table": TABLE_NAME,
                        "name": SET_NAME,
                        "elem": validated,
                    }
                }
            },
        ]
        self._backend.run_json(cmd)

    # ------------------------------------------------------------------ #
    # 内部：状态查询                                                       #
    # ------------------------------------------------------------------ #

    def _table_exists(self) -> bool:
        try:
            self._backend.run_text(["list", "table", TABLE_FAMILY, TABLE_NAME])
            return True
        except RuntimeError as e:
            if "no such" in str(e).lower() or "does not exist" in str(e).lower():
                return False
            raise

    def _chain_exists(self) -> bool:
        try:
            self._backend.run_text(
                ["list", "chain", TABLE_FAMILY, TABLE_NAME, CHAIN_NAME]
            )
            return True
        except RuntimeError as e:
            if "no such" in str(e).lower() or "does not exist" in str(e).lower():
                return False
            raise

    def _set_exists(self) -> bool:
        try:
            self._backend.run_text(
                ["list", "set", TABLE_FAMILY, TABLE_NAME, SET_NAME]
            )
            return True
        except RuntimeError as e:
            if "no such" in str(e).lower() or "does not exist" in str(e).lower():
                return False
            raise

    def _count_set_elements(self) -> int:
        """
        统计 set 中 CIDR 条数。
        解析 `nft -j list set` 的 JSON 输出。
        """
        try:
            out = self._backend.run_text(
                ["-j", "list", "set", TABLE_FAMILY, TABLE_NAME, SET_NAME]
            )
            data = json.loads(out)
            for item in data.get("nftables", []):
                if "set" in item:
                    elems = item["set"].get("elem", [])
                    return len(elems)
            return 0
        except Exception as e:
            logger.debug("_count_set_elements 解析失败: %s", e)
            return -1  # 未知，不阻断


# --------------------------------------------------------------------------- #
# Noop 后端（非 Linux 开发用，延迟报错）                                        #
# --------------------------------------------------------------------------- #

class _NoopBackend(_NftBackend):
    """
    非 Linux 平台占位后端。
    导入时不报错，调用时抛出明确的运行时错误。
    """

    def run_json(self, cmd_obj: list) -> dict:
        raise RuntimeError("nftables 仅在 Linux 系统上可用")

    def run_text(self, args: list[str]) -> str:
        raise RuntimeError("nftables 仅在 Linux 系统上可用")

    @property
    def name(self) -> str:
        return "noop"


# --------------------------------------------------------------------------- #
# 便捷工厂                                                                      #
# --------------------------------------------------------------------------- #

def get_firewall_manager(backend: _NftBackend | None = None) -> FirewallManager:
    """获取 FirewallManager 实例（供 bot.py 调用）。"""
    return FirewallManager(backend=backend)


# --------------------------------------------------------------------------- #
# CIDR 工具函数（供 reconcile 调用前预处理）                                    #
# --------------------------------------------------------------------------- #

def collapse_cidrs(
    networks: list[str],
) -> set[ipaddress.IPv4Network]:
    """
    将字符串 CIDR 列表去重/合并，返回最小覆盖 IPv4Network 集合。
    无效输入静默跳过并记录 warning。
    """
    parsed: list[ipaddress.IPv4Network] = []
    for n in networks:
        try:
            net = ipaddress.ip_network(n, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                parsed.append(net)
            else:
                logger.warning("collapse_cidrs: 跳过非 IPv4 网络 %s", n)
        except ValueError:
            logger.warning("collapse_cidrs: 跳过无效 CIDR %s", n)

    if not parsed:
        return set()
    return set(ipaddress.collapse_addresses(parsed))
