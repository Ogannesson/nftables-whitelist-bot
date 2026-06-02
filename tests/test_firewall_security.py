"""
tests/test_firewall_security.py — firewall.py 安全对抗性补充测试

专项覆盖以下盲区：
1. ensure_setup 中 _create_table_and_rules 失败时系统处于"无表"危险状态
2. _delete_table_if_exists 对 FileNotFoundError（非 RuntimeError）的处理
3. reconcile 接受 IPv4Address 时的 /32 语义
4. _flush_and_add_elements 所有元素被过滤时的分支行为
5. panic 失败时异常正确传播
6. SSH 规则确实只匹配 TCP 协议字段（not UDP）
7. reconcile 后 JSON 事务中 elements 列表确实包含期望的 CIDR
"""

from __future__ import annotations

import ipaddress
import json
import pytest

from tgwl.firewall import (
    FirewallManager,
    _NftBackend,
    _NoopBackend,
    collapse_cidrs,
    TABLE_FAMILY,
    TABLE_NAME,
    SET_NAME,
    CHAIN_NAME,
)


# --------------------------------------------------------------------------- #
# Mock 后端（复用 test_firewall.py 的结构，这里独立定义避免跨文件依赖）
# --------------------------------------------------------------------------- #

class MockBackend(_NftBackend):
    """记录所有调用，可配置返回值和抛出行为。"""

    def __init__(self):
        self.json_calls: list = []
        self.text_calls: list = []
        self._text_responses: dict[tuple, str] = {}
        self._raise_on_text: set[tuple] = set()
        self._raise_on_json: bool = False
        self._json_raise_after: int | None = None  # 第几次 json 调用后抛出
        self._json_call_count: int = 0

    def set_text_response(self, args_prefix: list, response: str) -> None:
        self._text_responses[tuple(args_prefix)] = response

    def raise_on_text(self, args_prefix: list) -> None:
        self._raise_on_text.add(tuple(args_prefix))

    def raise_on_json_after(self, n: int) -> None:
        """在第 n 次（0-based）json 调用时抛出。"""
        self._json_raise_after = n

    def run_json(self, cmd_obj: list) -> dict:
        self.json_calls.append(cmd_obj)
        if self._json_raise_after is not None and self._json_call_count >= self._json_raise_after:
            self._json_call_count += 1
            raise RuntimeError("mock: json_cmd 失败（模拟 nft 错误）")
        self._json_call_count += 1
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
# 测试 1：ensure_setup 原子性缺口 — 创建失败时表已被删除
# --------------------------------------------------------------------------- #

class TestEnsureSetupFailureDanger:
    def test_ensure_setup_create_fails_table_already_deleted(
        self, fw: FirewallManager, backend: MockBackend
    ):
        """
        【高风险】ensure_setup 先删表成功，再建表失败时：
        系统处于"table 不存在"的暴露状态，所有防火墙规则消失。
        本测试验证该场景确实会抛出异常（调用方需要处理），
        而不会被静默吞掉。
        """
        # delete 不报错（表原本存在，成功删除）
        # json（建表）报错
        backend.raise_on_json_after(0)

        with pytest.raises(RuntimeError, match="mock: json_cmd 失败"):
            fw.ensure_setup()

        # 验证：delete 已被调用（表已删除），json 调用失败
        delete_calls = [c for c in backend.text_calls if c[:2] == ["delete", "table"]]
        assert len(delete_calls) == 1, "应当调用了 delete table（删除操作已执行）"
        assert len(backend.json_calls) == 1, "应当尝试了 json 创建（但失败了）"
        # 此时系统已处于无表状态——调用方必须处理此异常并告警

    def test_ensure_setup_idempotent_on_success(
        self, fw: FirewallManager, backend: MockBackend
    ):
        """ensure_setup 成功时幂等：可多次调用，均以干净状态结束。"""
        backend.raise_on_text(["delete", "table"])  # 模拟表不存在（delete 报 no such）
        fw.ensure_setup()
        fw.ensure_setup()
        # 每次都应有一次 json 创建
        assert len(backend.json_calls) == 2


# --------------------------------------------------------------------------- #
# 测试 2：_delete_table_if_exists 对 FileNotFoundError 的处理
# --------------------------------------------------------------------------- #

class TestDeleteTableFileNotFound:
    def test_file_not_found_propagates(self, fw: FirewallManager, backend: MockBackend):
        """
        【中风险】若 nft 二进制不在 PATH（底层抛 FileNotFoundError 而非
        RuntimeError），_delete_table_if_exists 当前只 catch RuntimeError，
        FileNotFoundError 会直接 bubble up 到 ensure_setup 调用方。
        本测试记录该行为（期望抛出，不被静默吞掉）。
        """
        # 替换 run_text 为抛出 FileNotFoundError 的实现
        original_run_text = backend.run_text

        def raise_fnf(args):
            if args[:2] == ["delete", "table"]:
                raise FileNotFoundError("nft: command not found")
            return original_run_text(args)

        backend.run_text = raise_fnf  # type: ignore[method-assign]

        with pytest.raises(FileNotFoundError):
            fw.ensure_setup()


# --------------------------------------------------------------------------- #
# 测试 3：reconcile 接受 IPv4Address（不带前缀长度）语义
# --------------------------------------------------------------------------- #

class TestReconcileIPv4Address:
    def test_ipv4_address_becomes_slash32(
        self, fw: FirewallManager, backend: MockBackend
    ):
        """
        IPv4Address 传入 reconcile 后，str() 为 "a.b.c.d"，
        _flush_and_add_elements 内 ip_network(..., strict=False) 会变为 a.b.c.d/32。
        本测试验证该语义转换是预期的（/32 单主机路由），而非意外行为。
        """
        addr = ipaddress.IPv4Address("10.0.0.1")
        count = fw.reconcile({addr})  # type: ignore[arg-type]
        assert count == 1

        # 验证 JSON 事务中 element 是 10.0.0.1/32（即 /32 单主机）
        assert len(backend.json_calls) == 1
        cmd = backend.json_calls[0]
        add_elem_ops = [
            item["add"]["element"]
            for item in cmd
            if "add" in item and "element" in item["add"]
        ]
        assert len(add_elem_ops) == 1
        elem_list = add_elem_ops[0]["elem"]
        assert len(elem_list) == 1
        # 元素应为 /32 形式（单主机）
        net = ipaddress.ip_network(elem_list[0], strict=False)
        assert net.prefixlen == 32, f"IPv4Address 应转为 /32，实际: {elem_list[0]}"
        assert str(net.network_address) == "10.0.0.1"


# --------------------------------------------------------------------------- #
# 测试 4：_flush_and_add_elements 所有元素均被过滤时走 flush 分支
# --------------------------------------------------------------------------- #

class TestReconcileAllFiltered:
    def test_all_ipv6_elements_filtered_falls_back_to_flush(
        self, fw: FirewallManager, backend: MockBackend
    ):
        """
        若 reconcile 收到全为 IPv6 的 Network 对象（理论上 collapse_cidrs 已过滤，
        但防御性测试 _flush_and_add_elements 内部的校验逻辑）。
        由于外层 reconcile 类型注解只允许 IPv4Network/IPv4Address，
        此处模拟非预期输入（IPv6 传入）验证内部会 flush 不 crash。
        """
        # 构造包含 IPv6Network 的集合（绕过类型检查传入）
        ipv6_net = ipaddress.IPv6Network("2001:db8::/32")
        # 直接调用内部方法，传入包含 IPv6 字符串的 list 模拟过滤场景
        fw._flush_and_add_elements(["2001:db8::/32", "::1/128"])

        # 所有元素应被过滤，走 _flush_set 分支，不调用 JSON 事务
        assert len(backend.json_calls) == 0, "全 IPv6 过滤后不应有 JSON 事务"
        assert any(
            c[:3] == ["flush", "set", TABLE_FAMILY]
            for c in backend.text_calls
        ), "应调用 flush set（text 方式）"

    def test_mixed_valid_invalid_only_valid_in_json(
        self, fw: FirewallManager, backend: MockBackend
    ):
        """混合输入中，只有合法 IPv4 CIDR 进入 JSON 事务。"""
        fw._flush_and_add_elements(["10.0.0.0/8", "not-an-ip", "::1/128", "192.168.1.0/24"])

        assert len(backend.json_calls) == 1
        cmd = backend.json_calls[0]
        add_elem_ops = [
            item["add"]["element"]
            for item in cmd
            if "add" in item and "element" in item["add"]
        ]
        assert len(add_elem_ops) == 1
        elems = add_elem_ops[0]["elem"]
        # 只有 2 个合法 IPv4 CIDR
        assert len(elems) == 2
        for e in elems:
            net = ipaddress.ip_network(e, strict=False)
            assert isinstance(net, ipaddress.IPv4Network)


# --------------------------------------------------------------------------- #
# 测试 5：panic 失败时异常正确传播
# --------------------------------------------------------------------------- #

class TestPanicFailure:
    def test_panic_failure_propagates(self, fw: FirewallManager, backend: MockBackend):
        """
        panic 若 nft 命令失败（如权限不足），异常应传播给调用方，
        不被静默吞掉——调用方需要知道解除失败，采取人工干预。
        """
        backend.raise_on_text(["delete", "table"])

        with pytest.raises(RuntimeError):
            fw.panic()


# --------------------------------------------------------------------------- #
# 测试 6：SSH 规则 JSON 结构验证 — 确认使用 TCP 协议字段
# --------------------------------------------------------------------------- #

class TestSSHRuleProtocol:
    def test_ssh_rule_matches_tcp_protocol_field(
        self, fw: FirewallManager, backend: MockBackend
    ):
        """
        规则 4（SSH 放行）应匹配 payload protocol=tcp, field=dport, right=22。
        验证 protocol 字段为 "tcp"，确保不会错配 UDP。
        """
        backend.raise_on_text(["delete", "table"])
        fw.ensure_setup()
        cmd = backend.json_calls[0]

        rules = [
            item["add"]["rule"]
            for item in cmd
            if "add" in item and "rule" in item["add"]
        ]

        # 规则 3（索引 3，第 4 条）：tcp dport 22
        ssh_rule = rules[3]
        ssh_expr = ssh_rule["expr"]

        tcp_dport_22_found = False
        for e in ssh_expr:
            if isinstance(e, dict) and "match" in e:
                m = e["match"]
                left = m.get("left", {})
                right = m.get("right")
                payload = left.get("payload", {})
                if (
                    payload.get("protocol") == "tcp"
                    and payload.get("field") == "dport"
                    and right == 22
                ):
                    tcp_dport_22_found = True

        assert tcp_dport_22_found, (
            "SSH 放行规则必须明确匹配 protocol=tcp + field=dport + right=22，"
            "确保不会误匹配 UDP 22"
        )

    def test_established_before_ssh_rule(
        self, fw: FirewallManager, backend: MockBackend
    ):
        """
        ct state established,related 必须在 tcp dport 22 之前（索引 1 < 索引 3）。
        回包通过 established 放行，不需要走 SSH 规则。
        """
        backend.raise_on_text(["delete", "table"])
        fw.ensure_setup()
        cmd = backend.json_calls[0]

        rules = [
            item["add"]["rule"]
            for item in cmd
            if "add" in item and "rule" in item["add"]
        ]

        established_index = None
        ssh_index = None
        final_drop_index = None

        for i, rule in enumerate(rules):
            expr = rule["expr"]
            for e in expr:
                if not isinstance(e, dict) or "match" not in e:
                    continue
                m = e["match"]
                left = m.get("left", {})
                right = m.get("right")

                # established 规则
                if (
                    "ct" in left
                    and isinstance(right, list)
                    and "established" in right
                ):
                    established_index = i

                # SSH 规则
                payload = left.get("payload", {})
                if payload.get("field") == "dport" and right == 22:
                    ssh_index = i

                # 最终 drop 规则
                if left.get("meta", {}).get("key") == "nfproto":
                    if any("drop" in ex for ex in expr if isinstance(ex, dict)):
                        final_drop_index = i

        assert established_index is not None, "找不到 established 规则"
        assert ssh_index is not None, "找不到 SSH 规则"
        assert final_drop_index is not None, "找不到最终 drop 规则"

        assert established_index < ssh_index < final_drop_index, (
            f"规则顺序错误: established({established_index}) "
            f"SSH({ssh_index}) drop({final_drop_index})"
        )


# --------------------------------------------------------------------------- #
# 测试 7：reconcile JSON 事务中元素内容验证
# --------------------------------------------------------------------------- #

class TestReconcileElementContent:
    def test_reconcile_json_contains_correct_cidrs(
        self, fw: FirewallManager, backend: MockBackend
    ):
        """
        reconcile 后 JSON 事务中的 element.elem 应包含且仅包含传入的 CIDR 字符串。
        """
        cidrs = {
            ipaddress.IPv4Network("10.0.0.0/8"),
            ipaddress.IPv4Network("172.16.0.0/12"),
            ipaddress.IPv4Network("192.168.0.0/16"),
        }
        fw.reconcile(cidrs)

        assert len(backend.json_calls) == 1
        cmd = backend.json_calls[0]

        # 找到 add element 操作
        add_elem_ops = [
            item["add"]["element"]
            for item in cmd
            if "add" in item and "element" in item["add"]
        ]
        assert len(add_elem_ops) == 1
        elem_list = set(add_elem_ops[0]["elem"])

        expected = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
        assert elem_list == expected, f"CIDR 不匹配: {elem_list} != {expected}"

    def test_reconcile_json_targets_correct_set_name(
        self, fw: FirewallManager, backend: MockBackend
    ):
        """add element 操作的目标 set 名称必须是 whitelist4，不能错误写入其他 set。"""
        cidrs = {ipaddress.IPv4Network("10.0.0.0/8")}
        fw.reconcile(cidrs)

        cmd = backend.json_calls[0]
        add_elem_ops = [
            item["add"]["element"]
            for item in cmd
            if "add" in item and "element" in item["add"]
        ]
        op = add_elem_ops[0]
        assert op["name"] == SET_NAME, f"目标 set 名应为 {SET_NAME}，实际: {op['name']}"
        assert op["table"] == TABLE_NAME
        assert op["family"] == TABLE_FAMILY

    def test_reconcile_flush_targets_correct_set(
        self, fw: FirewallManager, backend: MockBackend
    ):
        """flush set 操作必须针对 whitelist4，不能 flush 其他 set。"""
        cidrs = {ipaddress.IPv4Network("10.0.0.0/8")}
        fw.reconcile(cidrs)

        cmd = backend.json_calls[0]
        flush_ops = [
            item["flush"]["set"]
            for item in cmd
            if "flush" in item and "set" in item["flush"]
        ]
        assert len(flush_ops) == 1
        op = flush_ops[0]
        assert op["name"] == SET_NAME
        assert op["table"] == TABLE_NAME
        assert op["family"] == TABLE_FAMILY
