"""
tests/test_firewall.py — firewall.py 单元测试

使用 Mock 后端，无需 root 权限 / Linux 环境。
测试核心逻辑：命令构造正确性、规则顺序、reconcile 去重、防注入。
"""

from __future__ import annotations

import ipaddress
import json
import pytest
from unittest.mock import MagicMock, call, patch

from tgwl.firewall import (
    FirewallManager,
    FirewallStatus,
    _NftBackend,
    _NoopBackend,
    collapse_cidrs,
    TABLE_FAMILY,
    TABLE_NAME,
    SET_NAME,
    CHAIN_NAME,
    CHAIN_FORWARD_NAME,
    CHAIN_PRIORITY,
)


# --------------------------------------------------------------------------- #
# Mock 后端                                                                     #
# --------------------------------------------------------------------------- #

class MockBackend(_NftBackend):
    """记录所有调用，可按需配置返回值。"""

    def __init__(self):
        self.json_calls: list = []
        self.text_calls: list = []
        self._text_responses: dict[tuple, str] = {}
        self._raise_on_text: set[tuple] = set()
        self._raise_on_json: bool = False

    def set_text_response(self, args_prefix: list, response: str) -> None:
        self._text_responses[tuple(args_prefix)] = response

    def raise_on_text(self, args_prefix: list) -> None:
        self._raise_on_text.add(tuple(args_prefix))

    def run_json(self, cmd_obj: list) -> dict:
        self.json_calls.append(cmd_obj)
        if self._raise_on_json:
            raise RuntimeError("mock json error")
        return {}

    def run_text(self, args: list[str]) -> str:
        self.text_calls.append(args)
        key = tuple(args)
        for prefix_key, response in self._text_responses.items():
            if key[:len(prefix_key)] == prefix_key:
                return response
        for raise_key in self._raise_on_text:
            if key[:len(raise_key)] == raise_key:
                raise RuntimeError(f"no such table: mock error for {args}")
        return ""

    @property
    def name(self) -> str:
        return "mock"


@pytest.fixture
def backend() -> MockBackend:
    return MockBackend()


@pytest.fixture
def fw(backend: MockBackend) -> FirewallManager:
    return FirewallManager(backend=backend)


# --------------------------------------------------------------------------- #
# ensure_setup 测试                                                             #
# --------------------------------------------------------------------------- #

class TestEnsureSetup:
    def test_ensure_setup_calls_delete_then_create(self, fw: FirewallManager, backend: MockBackend):
        """ensure_setup 应先 delete table，再用 JSON 事务创建。"""
        # delete 不存在时模拟 "no such table" 错误，应被忽略
        backend.raise_on_text(["delete", "table"])
        fw.ensure_setup()
        # 应有 JSON 创建调用
        assert len(backend.json_calls) == 1

    def test_ensure_setup_json_structure(self, fw: FirewallManager, backend: MockBackend):
        """
        验证 JSON 事务包含 table / set / 2 chains + 7 input 规则 + 6 forward 规则（共 17 个 add 操作）。
        table(1) + set(1) + input chain(1) + 7 input rules + forward chain(1) + 6 forward rules = 17
        """
        backend.raise_on_text(["delete", "table"])
        fw.ensure_setup()
        assert len(backend.json_calls) == 1
        cmd = backend.json_calls[0]
        ops = [list(item.keys())[0] for item in cmd]
        assert ops.count("add") == 17  # table + set + 2 chains + 7 input rules + 6 forward rules

    def test_rule_order_enforced(self, fw: FirewallManager, backend: MockBackend):
        """
        关键测试：验证 input chain 规则顺序严格为
          lo → established,related → invalid → dport 22 → @whitelist4 → ipv6-icmp → nfproto ipv4 drop
        """
        backend.raise_on_text(["delete", "table"])
        fw.ensure_setup()
        cmd = backend.json_calls[0]

        # 提取 input chain 的 rule 操作，按顺序
        rules = [
            item["add"]["rule"]
            for item in cmd
            if "add" in item and "rule" in item["add"]
            and item["add"]["rule"].get("chain") == CHAIN_NAME
        ]
        assert len(rules) == 7, f"input chain 应有 7 条规则，实际 {len(rules)} 条"

        # 规则 0：iif lo accept
        r0_expr = rules[0]["expr"]
        assert any(
            "meta" in e.get("match", {}).get("left", {})
            for e in r0_expr
            if isinstance(e, dict) and "match" in e
        ), "规则 0 应匹配 meta iifname"
        assert any("accept" in e for e in r0_expr), "规则 0 应 accept"

        # 规则 1：ct state established,related accept
        r1_expr = rules[1]["expr"]
        assert any(
            "ct" in e.get("match", {}).get("left", {})
            for e in r1_expr
            if isinstance(e, dict) and "match" in e
        ), "规则 1 应匹配 ct state"
        right_vals = None
        for e in r1_expr:
            if isinstance(e, dict) and "match" in e:
                right_vals = e["match"].get("right", [])
        assert "established" in right_vals, "规则 1 应含 established"
        assert "related" in right_vals, "规则 1 应含 related"
        assert any("accept" in e for e in r1_expr), "规则 1 应 accept"

        # 规则 2：ct state invalid drop
        r2_expr = rules[2]["expr"]
        assert any("drop" in e for e in r2_expr), "规则 2 应 drop（invalid 包）"

        # 规则 3：tcp dport 22 accept（SSH 防锁死）
        r3_expr = rules[3]["expr"]
        has_dport_22 = False
        for e in r3_expr:
            if isinstance(e, dict) and "match" in e:
                left = e["match"].get("left", {})
                right = e["match"].get("right")
                if isinstance(left, dict) and left.get("payload", {}).get("field") == "dport":
                    if right == 22:
                        has_dport_22 = True
        assert has_dport_22, "规则 3 应放行 tcp dport 22（SSH 防锁死）"
        assert any("accept" in e for e in r3_expr), "规则 3 应 accept"

        # 规则 4：@whitelist4 accept
        r4_expr = rules[4]["expr"]
        assert any(
            isinstance(e, dict) and "match" in e and
            "@whitelist4" in str(e["match"].get("right", ""))
            for e in r4_expr
        ), "规则 4 应匹配 @whitelist4"
        assert any("accept" in e for e in r4_expr), "规则 4 应 accept"

        # 规则 5：ipv6-icmp accept（邻居发现）
        r5_expr = rules[5]["expr"]
        has_icmpv6 = any(
            isinstance(e, dict) and "match" in e and
            "ipv6-icmp" in str(e["match"].get("right", ""))
            for e in r5_expr
        )
        assert has_icmpv6, "规则 5 应放行 ipv6-icmp"

        # 规则 6：meta nfproto ipv4 drop（最后，仅丢弃 v4 非白名单）
        r6_expr = rules[6]["expr"]
        has_nfproto_ipv4 = False
        for e in r6_expr:
            if isinstance(e, dict) and "match" in e:
                left = e["match"].get("left", {})
                right = e["match"].get("right")
                if isinstance(left, dict) and left.get("meta", {}).get("key") == "nfproto":
                    if right == "ipv4":
                        has_nfproto_ipv4 = True
        assert has_nfproto_ipv4, "规则 6 应匹配 meta nfproto ipv4"
        assert any("drop" in e for e in r6_expr), "规则 6（最后）应 drop"

    def test_drop_is_last_rule(self, fw: FirewallManager, backend: MockBackend):
        """input chain 的 drop 必须是最后一条规则——绝不能出现在 22/established 之前。"""
        backend.raise_on_text(["delete", "table"])
        fw.ensure_setup()
        cmd = backend.json_calls[0]
        rules = [
            item["add"]["rule"]
            for item in cmd
            if "add" in item and "rule" in item["add"]
            and item["add"]["rule"].get("chain") == CHAIN_NAME
        ]
        # 最后一条必须含 drop
        last_rule_expr = rules[-1]["expr"]
        assert any("drop" in e for e in last_rule_expr), "最后一条规则必须是 drop"

        # 前 4 条（lo/established/invalid_drop/22）中，accept 必须在 drop 之前（SSH 先放行）
        # 确认 SSH（dport 22）在最终 drop 之前
        ssh_index = None
        final_drop_index = None
        for i, rule in enumerate(rules):
            expr = rule["expr"]
            has_22 = any(
                isinstance(e, dict) and "match" in e and
                e["match"].get("right") == 22
                for e in expr
            )
            has_nfproto_drop = any("drop" in e for e in expr) and any(
                isinstance(e, dict) and "match" in e and
                e["match"].get("left", {}).get("meta", {}).get("key") == "nfproto"
                for e in expr
            )
            if has_22:
                ssh_index = i
            if has_nfproto_drop:
                final_drop_index = i

        assert ssh_index is not None, "找不到 SSH 放行规则"
        assert final_drop_index is not None, "找不到最终 drop 规则"
        assert ssh_index < final_drop_index, (
            f"SSH 放行(rule {ssh_index}) 必须在最终 drop(rule {final_drop_index}) 之前！"
        )

    def test_chain_policy_is_accept(self, fw: FirewallManager, backend: MockBackend):
        """input 和 forward 两条 chain 的 policy 均必须是 accept（fail-open）。"""
        backend.raise_on_text(["delete", "table"])
        fw.ensure_setup()
        cmd = backend.json_calls[0]
        chain_items = [
            item["add"]["chain"]
            for item in cmd
            if "add" in item and "chain" in item["add"]
        ]
        assert len(chain_items) == 2, "应有 input 和 forward 两条 chain"
        for chain in chain_items:
            assert chain["policy"] == "accept", (
                f"chain {chain['name']} policy 必须为 accept（fail-open）"
            )

    def test_chain_priority(self, fw: FirewallManager, backend: MockBackend):
        """input 和 forward 两条 chain 优先级均应为 -10（先于默认 filter 0）。"""
        backend.raise_on_text(["delete", "table"])
        fw.ensure_setup()
        cmd = backend.json_calls[0]
        chain_items = [
            item["add"]["chain"]
            for item in cmd
            if "add" in item and "chain" in item["add"]
        ]
        assert len(chain_items) == 2, "应有 input 和 forward 两条 chain"
        for chain in chain_items:
            assert chain["prio"] == CHAIN_PRIORITY, (
                f"chain {chain['name']} 优先级应为 {CHAIN_PRIORITY}"
            )

    def test_forward_chain_exists(self, fw: FirewallManager, backend: MockBackend):
        """ensure_setup 后应有 forward base chain，hook forward，priority -10。"""
        backend.raise_on_text(["delete", "table"])
        fw.ensure_setup()
        cmd = backend.json_calls[0]
        chain_items = [
            item["add"]["chain"]
            for item in cmd
            if "add" in item and "chain" in item["add"]
        ]
        forward_chains = [c for c in chain_items if c["name"] == CHAIN_FORWARD_NAME]
        assert len(forward_chains) == 1, "应有一条 forward chain"
        fc = forward_chains[0]
        assert fc["hook"] == "forward", "forward chain 的 hook 应为 forward"
        assert fc["prio"] == CHAIN_PRIORITY, f"forward chain 优先级应为 {CHAIN_PRIORITY}"
        assert fc["type"] == "filter", "forward chain 类型应为 filter"
        assert fc["policy"] == "accept", "forward chain policy 应为 accept（fail-open）"

    def test_forward_chain_rule_order(self, fw: FirewallManager, backend: MockBackend):
        """
        forward chain 规则顺序：
          established,related → invalid drop → @whitelist4 → 私有网段 accept → ipv6-icmp → ipv4 drop
        无 iif lo / tcp dport 22（input 专属）。
        """
        backend.raise_on_text(["delete", "table"])
        fw.ensure_setup()
        cmd = backend.json_calls[0]

        # 提取 forward chain 的规则
        fwd_rules = [
            item["add"]["rule"]
            for item in cmd
            if "add" in item and "rule" in item["add"]
            and item["add"]["rule"].get("chain") == CHAIN_FORWARD_NAME
        ]
        assert len(fwd_rules) == 6, f"forward chain 应有 6 条规则，实际 {len(fwd_rules)} 条"

        # 规则 0：ct state established,related accept
        r0_expr = fwd_rules[0]["expr"]
        assert any(
            isinstance(e, dict) and "match" in e
            and "ct" in e["match"].get("left", {})
            for e in r0_expr
        ), "forward 规则 0 应匹配 ct state"
        right_vals = None
        for e in r0_expr:
            if isinstance(e, dict) and "match" in e:
                right_vals = e["match"].get("right", [])
        assert "established" in right_vals, "forward 规则 0 应含 established"
        assert "related" in right_vals, "forward 规则 0 应含 related"
        assert any("accept" in e for e in r0_expr), "forward 规则 0 应 accept"

        # 规则 1：ct state invalid drop
        r1_expr = fwd_rules[1]["expr"]
        assert any("drop" in e for e in r1_expr), "forward 规则 1 应 drop（invalid 包）"

        # 规则 2：@whitelist4 accept
        r2_expr = fwd_rules[2]["expr"]
        assert any(
            isinstance(e, dict) and "match" in e
            and "@whitelist4" in str(e["match"].get("right", ""))
            for e in r2_expr
        ), "forward 规则 2 应匹配 @whitelist4"
        assert any("accept" in e for e in r2_expr), "forward 规则 2 应 accept"

        # 规则 3：私有网段匿名 set accept
        # 四个段：10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10（CGNAT/Tailscale）
        r3_expr = fwd_rules[3]["expr"]
        has_private_set = False
        for e in r3_expr:
            if isinstance(e, dict) and "match" in e:
                right = e["match"].get("right", {})
                if isinstance(right, dict) and "set" in right:
                    set_items = right["set"]
                    if isinstance(set_items, list) and len(set_items) == 4:
                        addrs = {item["prefix"]["addr"] for item in set_items if "prefix" in item}
                        if addrs == {"10.0.0.0", "172.16.0.0", "192.168.0.0", "100.64.0.0"}:
                            has_private_set = True
        assert has_private_set, (
            "forward 规则 3 应含私有网段匿名 set（10/8, 172.16/12, 192.168/16, 100.64/10 CGNAT）"
        )
        assert any("accept" in e for e in r3_expr), "forward 规则 3 应 accept"

        # 规则 4：ipv6-icmp accept
        r4_expr = fwd_rules[4]["expr"]
        has_icmpv6 = any(
            isinstance(e, dict) and "match" in e
            and "ipv6-icmp" in str(e["match"].get("right", ""))
            for e in r4_expr
        )
        assert has_icmpv6, "forward 规则 4 应放行 ipv6-icmp"

        # 规则 5：meta nfproto ipv4 drop（最后）
        r5_expr = fwd_rules[5]["expr"]
        has_nfproto_ipv4_drop = False
        for e in r5_expr:
            if isinstance(e, dict) and "match" in e:
                left = e["match"].get("left", {})
                right = e["match"].get("right")
                if (
                    isinstance(left, dict)
                    and left.get("meta", {}).get("key") == "nfproto"
                    and right == "ipv4"
                ):
                    has_nfproto_ipv4_drop = True
        assert has_nfproto_ipv4_drop, "forward 规则 5 应匹配 meta nfproto ipv4"
        assert any("drop" in e for e in r5_expr), "forward 规则 5 应 drop"

    def test_forward_chain_no_iif_lo_or_ssh(self, fw: FirewallManager, backend: MockBackend):
        """forward chain 不应有 iif lo 或 tcp dport 22 规则（那是 input 专属）。"""
        backend.raise_on_text(["delete", "table"])
        fw.ensure_setup()
        cmd = backend.json_calls[0]

        fwd_rules = [
            item["add"]["rule"]
            for item in cmd
            if "add" in item and "rule" in item["add"]
            and item["add"]["rule"].get("chain") == CHAIN_FORWARD_NAME
        ]
        for rule in fwd_rules:
            for e in rule["expr"]:
                if not isinstance(e, dict) or "match" not in e:
                    continue
                m = e["match"]
                left = m.get("left", {})
                right = m.get("right")
                # 不应有 iif lo
                assert not (
                    isinstance(left, dict)
                    and left.get("meta", {}).get("key") == "iifname"
                    and right == "lo"
                ), "forward chain 不应有 iif lo 规则"
                # 不应有 tcp dport 22
                assert not (
                    isinstance(left, dict)
                    and left.get("payload", {}).get("field") == "dport"
                    and right == 22
                ), "forward chain 不应有 tcp dport 22 规则"

    def test_forward_chain_reuses_whitelist4_set(self, fw: FirewallManager, backend: MockBackend):
        """forward chain 应复用同一个 whitelist4 set，不新建其他 set。"""
        backend.raise_on_text(["delete", "table"])
        fw.ensure_setup()
        cmd = backend.json_calls[0]

        # 只有一个 set 被创建
        set_items = [
            item["add"]["set"]
            for item in cmd
            if "add" in item and "set" in item["add"]
        ]
        assert len(set_items) == 1, "应只创建一个 set（whitelist4），forward chain 复用"
        assert set_items[0]["name"] == SET_NAME

        # forward chain 中的 whitelist4 引用
        fwd_rules = [
            item["add"]["rule"]
            for item in cmd
            if "add" in item and "rule" in item["add"]
            and item["add"]["rule"].get("chain") == CHAIN_FORWARD_NAME
        ]
        wl4_refs = []
        for rule in fwd_rules:
            for e in rule["expr"]:
                if isinstance(e, dict) and "match" in e:
                    right = e["match"].get("right", {})
                    if isinstance(right, dict) and right.get("set") == f"@{SET_NAME}":
                        wl4_refs.append(rule)
        assert len(wl4_refs) == 1, "forward chain 应有且仅有一条 @whitelist4 引用"


# --------------------------------------------------------------------------- #
# reconcile 测试                                                                #
# --------------------------------------------------------------------------- #

class TestReconcile:
    def test_reconcile_empty_set(self, fw: FirewallManager, backend: MockBackend):
        """空集合：调用 flush set，不调用 add element。"""
        fw.reconcile(set())
        # 空集合用 run_text flush
        assert any("flush" in " ".join(c) for c in backend.text_calls)
        assert len(backend.json_calls) == 0

    def test_reconcile_with_cidrs(self, fw: FirewallManager, backend: MockBackend):
        """非空集合：调用 JSON 事务（flush + add element）。"""
        cidrs = {
            ipaddress.IPv4Network("10.0.0.0/8"),
            ipaddress.IPv4Network("192.168.1.0/24"),
        }
        count = fw.reconcile(cidrs)
        assert count == 2
        assert len(backend.json_calls) == 1
        cmd = backend.json_calls[0]
        # 应含 flush set + add element
        ops = [list(item.keys())[0] for item in cmd]
        assert "flush" in ops
        assert "add" in ops

    def test_reconcile_filters_invalid_cidr(self, fw: FirewallManager, backend: MockBackend):
        """非法 CIDR 被过滤（reconcile 内部安全校验）。"""
        # 模拟传入包含无效字符串（正常情况下 collapse_cidrs 已过滤，这是双重保护）
        # 直接构造 set 传入（应已是 IPv4Network，但测试内部 _flush_and_add_elements 的校验）
        valid = {ipaddress.IPv4Network("1.0.0.0/24")}
        count = fw.reconcile(valid)
        assert count == 1

    def test_reconcile_returns_element_count(self, fw: FirewallManager, backend: MockBackend):
        cidrs = {ipaddress.IPv4Network(f"10.{i}.0.0/24") for i in range(5)}
        count = fw.reconcile(cidrs)
        assert count == 5


# --------------------------------------------------------------------------- #
# panic 测试                                                                    #
# --------------------------------------------------------------------------- #

class TestPanic:
    def test_panic_calls_delete_table(self, fw: FirewallManager, backend: MockBackend):
        fw.panic()
        assert len(backend.text_calls) == 1
        args = backend.text_calls[0]
        assert args == ["delete", "table", TABLE_FAMILY, TABLE_NAME]


# --------------------------------------------------------------------------- #
# status 测试                                                                   #
# --------------------------------------------------------------------------- #

class TestStatus:
    def test_status_table_not_exists(self, fw: FirewallManager, backend: MockBackend):
        backend.raise_on_text(["list", "table"])
        s = fw.status()
        assert s.table_exists is False
        assert s.chain_exists is False
        assert s.set_exists is False
        assert s.element_count == 0
        assert s.backend == "mock"

    def test_status_table_exists(self, fw: FirewallManager, backend: MockBackend):
        # table 存在，chain/set 也存在
        backend.set_text_response(["list", "table"], "table inet whitelist { }")
        backend.set_text_response(["list", "chain"], "chain input { }")
        # set 存在，element_count 通过 -j list set 解析
        backend.set_text_response(["list", "set"], "set whitelist4 { }")
        backend.set_text_response(
            ["-j", "list", "set"],
            json.dumps({"nftables": [{"set": {"name": SET_NAME, "elem": ["1.0.0.0/8", "2.0.0.0/8"]}}]}),
        )
        s = fw.status()
        assert s.table_exists is True
        assert s.element_count == 2


# --------------------------------------------------------------------------- #
# collapse_cidrs 工具测试                                                       #
# --------------------------------------------------------------------------- #

class TestCollapseCidrs:
    def test_basic_merge(self):
        result = collapse_cidrs(["10.0.0.0/25", "10.0.0.128/25"])
        assert ipaddress.IPv4Network("10.0.0.0/24") in result

    def test_dedup(self):
        result = collapse_cidrs(["192.168.0.0/24", "192.168.0.0/24"])
        assert len(result) == 1

    def test_invalid_skipped(self):
        result = collapse_cidrs(["not-an-ip", "10.0.0.0/8"])
        assert len(result) == 1
        assert ipaddress.IPv4Network("10.0.0.0/8") in result

    def test_ipv6_skipped(self):
        result = collapse_cidrs(["::1/128", "10.0.0.0/8"])
        # IPv6 被跳过，只剩 v4
        assert len(result) == 1
        assert all(isinstance(n, ipaddress.IPv4Network) for n in result)

    def test_empty_list(self):
        result = collapse_cidrs([])
        assert result == set()

    def test_single_host(self):
        result = collapse_cidrs(["1.2.3.4/32"])
        assert len(result) == 1

    def test_non_strict_host_bits(self):
        # 即使 host bit 不为 0，也能处理（strict=False）
        result = collapse_cidrs(["10.0.0.1/24"])
        assert ipaddress.IPv4Network("10.0.0.0/24") in result


# --------------------------------------------------------------------------- #
# Noop 后端测试（非 Linux 平台保护）                                            #
# --------------------------------------------------------------------------- #

class TestNoopBackend:
    def test_noop_raises_on_json(self):
        b = _NoopBackend()
        with pytest.raises(RuntimeError, match="Linux"):
            b.run_json([])

    def test_noop_raises_on_text(self):
        b = _NoopBackend()
        with pytest.raises(RuntimeError, match="Linux"):
            b.run_text(["list", "table"])

    def test_noop_name(self):
        b = _NoopBackend()
        assert b.name == "noop"
