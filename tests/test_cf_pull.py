"""
tests/test_cf_pull.py — CFPullClient 单元测试

覆盖：
  - pull() 解析正常 JSON
  - process() 跳过私有/回环/IPv6，仅对有效公网 IPv4 调 add_entry
  - 成功路径：add_entry + reconcile_from_store 被调 + ack 被调（带正确 ids）
  - reconcile 抛异常时 ack 不被调用（不丢）
  - pull HTTP 错误异常消息不含 client_secret
  - headers 含 CF-Access-Client-Id / CF-Access-Client-Secret
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch, call

import httpx
import pytest

from tgwl.cf_pull import CFPullClient, mask_ip


# --------------------------------------------------------------------------- #
# 工具测试                                                                      #
# --------------------------------------------------------------------------- #


class TestMaskIp:
    def test_ipv4(self):
        assert mask_ip("1.2.3.4") == "1.2.3.***"

    def test_ipv4_single_octet_end(self):
        assert mask_ip("203.0.113.42") == "203.0.113.***"

    def test_ipv6(self):
        result = mask_ip("2001:db8::1")
        assert result.endswith(":***")
        assert "2001" in result

    def test_invalid_ip(self):
        # 非法 IP 原样返回，不抛异常
        assert mask_ip("not-an-ip") == "not-an-ip"


# --------------------------------------------------------------------------- #
# 辅助：伪造 httpx 响应                                                         #
# --------------------------------------------------------------------------- #


def _make_response(status_code: int, body: dict | None = None) -> MagicMock:
    """构造假 httpx.Response，支持 raise_for_status + json()。"""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    if body is not None:
        resp.json.return_value = body
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            message=f"HTTP {status_code}",
            request=MagicMock(),
            response=resp,
        )
    else:
        resp.raise_for_status.return_value = None
    return resp


# --------------------------------------------------------------------------- #
# 测试夹具                                                                      #
# --------------------------------------------------------------------------- #


CLIENT_ID = "test-client-id"
CLIENT_SECRET = "super-secret-value"
WORKER_URL = "https://worker.example.com"


def _make_client(**kwargs) -> CFPullClient:
    return CFPullClient(
        worker_url=WORKER_URL,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        **kwargs,
    )


def _make_store(add_entry_result=MagicMock()) -> MagicMock:
    store = MagicMock()
    store.add_entry.return_value = add_entry_result
    return store


# --------------------------------------------------------------------------- #
# pull() 测试                                                                   #
# --------------------------------------------------------------------------- #


class TestPull:
    def test_parse_normal_json(self):
        """pull() 正确解析 {"ips": [...]} 响应。"""
        items = [
            {"id": "id1", "ip": "203.0.113.1", "email": "a@b.com"},
            {"id": "id2", "ip": "198.51.100.2", "email": "c@d.com"},
        ]
        resp = _make_response(200, {"ips": items})

        client = _make_client()
        with patch.object(client, "_make_client") as mock_factory:
            mock_http = MagicMock()
            mock_factory.return_value.__enter__ = lambda s: mock_http
            mock_factory.return_value.__exit__ = MagicMock(return_value=False)
            mock_http.post.return_value = resp

            result = client.pull()

        assert result == items

    def test_empty_ips_key(self):
        """pull() 当响应没有 ips 键时返回空列表。"""
        resp = _make_response(200, {"other": "data"})

        client = _make_client()
        with patch.object(client, "_make_client") as mock_factory:
            mock_http = MagicMock()
            mock_factory.return_value.__enter__ = lambda s: mock_http
            mock_factory.return_value.__exit__ = MagicMock(return_value=False)
            mock_http.post.return_value = resp

            result = client.pull()

        assert result == []

    def test_http_error_raises_runtime_error(self):
        """pull() HTTP 错误抛 RuntimeError，消息不含 client_secret。"""
        resp = _make_response(403)

        client = _make_client()
        with patch.object(client, "_make_client") as mock_factory:
            mock_http = MagicMock()
            mock_factory.return_value.__enter__ = lambda s: mock_http
            mock_factory.return_value.__exit__ = MagicMock(return_value=False)
            mock_http.post.return_value = resp

            with pytest.raises(RuntimeError) as exc_info:
                client.pull()

        assert CLIENT_SECRET not in str(exc_info.value)
        assert "403" in str(exc_info.value)

    def test_network_error_raises_runtime_error(self):
        """pull() 网络错误抛 RuntimeError，消息不含 client_secret。"""
        client = _make_client()
        with patch.object(client, "_make_client") as mock_factory:
            mock_http = MagicMock()
            mock_factory.return_value.__enter__ = lambda s: mock_http
            mock_factory.return_value.__exit__ = MagicMock(return_value=False)
            mock_http.post.side_effect = httpx.ConnectError("connection refused")

            with pytest.raises(RuntimeError) as exc_info:
                client.pull()

        assert CLIENT_SECRET not in str(exc_info.value)

    def test_headers_contain_cf_access_tokens(self):
        """_headers() 返回正确的 CF Access 请求头键值。"""
        client = _make_client()
        headers = client._headers()
        assert headers["CF-Access-Client-Id"] == CLIENT_ID
        assert headers["CF-Access-Client-Secret"] == CLIENT_SECRET

    def test_pull_sends_correct_headers(self):
        """pull() 请求中携带正确的 CF Access 请求头。"""
        resp = _make_response(200, {"ips": []})

        client = _make_client()
        with patch.object(client, "_make_client") as mock_factory:
            mock_http = MagicMock()
            mock_factory.return_value.__enter__ = lambda s: mock_http
            mock_factory.return_value.__exit__ = MagicMock(return_value=False)
            mock_http.post.return_value = resp

            client.pull()

        _, kwargs = mock_http.post.call_args
        headers = kwargs.get("headers", {})
        assert headers.get("CF-Access-Client-Id") == CLIENT_ID
        assert headers.get("CF-Access-Client-Secret") == CLIENT_SECRET


# --------------------------------------------------------------------------- #
# process() 测试                                                                #
# --------------------------------------------------------------------------- #


def _mock_pull(client: CFPullClient, items: list[dict]) -> None:
    """在 client 上 patch pull() 返回指定 items。"""
    client.pull = MagicMock(return_value=items)


def _mock_ack(client: CFPullClient) -> MagicMock:
    """在 client 上 patch ack()，返回 mock。"""
    client.ack = MagicMock()
    return client.ack


class TestProcess:
    def test_skips_private_ip(self):
        """process() 跳过私有地址（192.168.x.x 等），不调 add_entry。"""
        client = _make_client()
        _mock_pull(client, [{"id": "id1", "ip": "192.168.1.1", "email": "a@b.com"}])
        mock_ack = _mock_ack(client)
        store = _make_store()

        with patch("tgwl.cf_pull.reconcile_from_store") as mock_reconcile:
            result = client.process(store, MagicMock(), MagicMock())

        store.add_entry.assert_not_called()
        mock_reconcile.assert_not_called()
        mock_ack.assert_not_called()
        assert result["skipped"] == 1
        assert result["added"] == 0

    def test_skips_loopback(self):
        """process() 跳过回环地址 127.0.0.1。"""
        client = _make_client()
        _mock_pull(client, [{"id": "id1", "ip": "127.0.0.1", "email": "x@y.com"}])
        mock_ack = _mock_ack(client)
        store = _make_store()

        with patch("tgwl.cf_pull.reconcile_from_store"):
            result = client.process(store, MagicMock(), MagicMock())

        store.add_entry.assert_not_called()
        mock_ack.assert_not_called()
        assert result["skipped"] == 1

    def test_skips_link_local(self):
        """process() 跳过链路本地地址 169.254.x.x。"""
        client = _make_client()
        _mock_pull(client, [{"id": "id1", "ip": "169.254.1.1", "email": "x@y.com"}])
        mock_ack = _mock_ack(client)
        store = _make_store()

        with patch("tgwl.cf_pull.reconcile_from_store"):
            result = client.process(store, MagicMock(), MagicMock())

        store.add_entry.assert_not_called()
        mock_ack.assert_not_called()
        assert result["skipped"] == 1

    def test_skips_ipv6(self):
        """process() 跳过 IPv6 地址（暂不支持）。"""
        client = _make_client()
        _mock_pull(client, [{"id": "id1", "ip": "2001:db8::1", "email": "x@y.com"}])
        mock_ack = _mock_ack(client)
        store = _make_store()

        with patch("tgwl.cf_pull.reconcile_from_store"):
            result = client.process(store, MagicMock(), MagicMock())

        store.add_entry.assert_not_called()
        mock_ack.assert_not_called()
        assert result["skipped"] == 1

    def test_skips_invalid_ip_string(self):
        """process() 跳过无法解析为 IP 的字符串。"""
        client = _make_client()
        _mock_pull(client, [{"id": "id1", "ip": "not-an-ip", "email": "x@y.com"}])
        mock_ack = _mock_ack(client)
        store = _make_store()

        with patch("tgwl.cf_pull.reconcile_from_store"):
            result = client.process(store, MagicMock(), MagicMock())

        store.add_entry.assert_not_called()
        mock_ack.assert_not_called()
        assert result["skipped"] == 1

    def test_success_path_add_reconcile_ack(self):
        """成功路径：公网 IPv4 → add_entry + reconcile + ack（带正确 ids）。"""
        client = _make_client()
        items = [
            {"id": "id-a", "ip": "8.8.8.8", "email": "alice@example.com"},
            {"id": "id-b", "ip": "1.1.1.1", "email": "bob@example.com"},
        ]
        _mock_pull(client, items)
        mock_ack = _mock_ack(client)
        # add_entry 返回非 None 表示新增
        store = MagicMock()
        store.add_entry.return_value = MagicMock()  # 新增成功
        store.get_setting.return_value = "normal"

        geo = MagicMock()
        fw = MagicMock()

        with patch("tgwl.cf_pull.reconcile_from_store") as mock_reconcile:
            result = client.process(store, geo, fw)

        # add_entry 被调两次
        assert store.add_entry.call_count == 2
        store.add_entry.assert_any_call(
            "ip", "8.8.8.8", label="CF-Access:alice@example.com", added_by=0
        )
        store.add_entry.assert_any_call(
            "ip", "1.1.1.1", label="CF-Access:bob@example.com", added_by=0
        )

        # reconcile 被调一次，传入 store/geo/fw
        mock_reconcile.assert_called_once_with(store, geo, fw)

        # ack 被调，携带两个 id
        mock_ack.assert_called_once_with(["id-a", "id-b"])

        assert result["pulled"] == 2
        assert result["added"] == 2
        assert result["skipped"] == 0

    def test_already_exists_still_acked(self):
        """add_entry 返回 None（已存在）也算成功处理，id 纳入 ack。"""
        client = _make_client()
        items = [{"id": "id-x", "ip": "9.9.9.9", "email": "u@v.com"}]
        _mock_pull(client, items)
        mock_ack = _mock_ack(client)
        store = MagicMock()
        store.add_entry.return_value = None  # 已存在
        store.get_setting.return_value = "normal"

        with patch("tgwl.cf_pull.reconcile_from_store"):
            result = client.process(store, MagicMock(), MagicMock())

        # 虽然 add_entry 返回 None，id 仍纳入 ack
        mock_ack.assert_called_once_with(["id-x"])
        # added 计数为 0（返回 None），但 skipped 也为 0（处理成功）
        assert result["added"] == 0

    def test_reconcile_error_no_ack(self):
        """reconcile 抛异常时 ack 不被调用（两段式保障，不丢数据）。"""
        client = _make_client()
        items = [{"id": "id-z", "ip": "208.67.222.222", "email": "fail@test.com"}]
        _mock_pull(client, items)
        mock_ack = _mock_ack(client)
        store = MagicMock()
        store.add_entry.return_value = MagicMock()
        store.get_setting.return_value = "normal"

        with patch(
            "tgwl.cf_pull.reconcile_from_store",
            side_effect=RuntimeError("nftables 故障"),
        ):
            with pytest.raises(RuntimeError, match="nftables 故障"):
                client.process(store, MagicMock(), MagicMock())

        # ack 绝对不能被调用
        mock_ack.assert_not_called()

    def test_empty_pull_no_reconcile_no_ack(self):
        """pull 返回空列表时，reconcile 和 ack 都不调用。"""
        client = _make_client()
        _mock_pull(client, [])
        mock_ack = _mock_ack(client)
        store = _make_store()

        with patch("tgwl.cf_pull.reconcile_from_store") as mock_reconcile:
            result = client.process(store, MagicMock(), MagicMock())

        mock_reconcile.assert_not_called()
        mock_ack.assert_not_called()
        assert result["pulled"] == 0

    def test_mixed_valid_and_invalid(self):
        """混合：有效 IP 加白，私有/IPv6 跳过，统计正确。"""
        client = _make_client()
        items = [
            {"id": "id-1", "ip": "8.8.4.4", "email": "a@a.com"},     # 有效
            {"id": "id-2", "ip": "10.0.0.1", "email": "b@b.com"},     # 私有，跳过
            {"id": "id-3", "ip": "::1", "email": "c@c.com"},          # IPv6 回环，跳过
            {"id": "id-4", "ip": "1.0.0.1", "email": "d@d.com"},      # 有效
        ]
        _mock_pull(client, items)
        mock_ack = _mock_ack(client)
        store = MagicMock()
        store.add_entry.return_value = MagicMock()
        store.get_setting.return_value = "normal"

        with patch("tgwl.cf_pull.reconcile_from_store") as mock_reconcile:
            result = client.process(store, MagicMock(), MagicMock())

        assert store.add_entry.call_count == 2
        mock_reconcile.assert_called_once()
        mock_ack.assert_called_once_with(["id-1", "id-4"])
        assert result["pulled"] == 4
        assert result["added"] == 2
        assert result["skipped"] == 2

    def test_pull_secret_not_in_http_error_message(self):
        """pull() HTTP 错误异常消息不包含 client_secret。"""
        client = _make_client()
        resp = _make_response(401)

        with patch.object(client, "_make_client") as mock_factory:
            mock_http = MagicMock()
            mock_factory.return_value.__enter__ = lambda s: mock_http
            mock_factory.return_value.__exit__ = MagicMock(return_value=False)
            mock_http.post.return_value = resp

            with pytest.raises(RuntimeError) as exc_info:
                client.pull()

        error_msg = str(exc_info.value)
        assert CLIENT_SECRET not in error_msg

    def test_process_label_uses_email(self):
        """add_entry 的 label 正确包含 CF-Access:email 前缀。"""
        client = _make_client()
        items = [{"id": "x", "ip": "94.140.14.14", "email": "user@corp.com"}]
        _mock_pull(client, items)
        _mock_ack(client)
        store = MagicMock()
        store.add_entry.return_value = MagicMock()
        store.get_setting.return_value = "normal"

        with patch("tgwl.cf_pull.reconcile_from_store"):
            client.process(store, MagicMock(), MagicMock())

        store.add_entry.assert_called_once_with(
            "ip",
            "94.140.14.14",
            label="CF-Access:user@corp.com",
            added_by=0,
        )

    def test_lockdown_mode_no_reconcile_no_ack(self):
        """firewall_mode=lockdown 时：add_entry 被调但 reconcile 和 ack 均不被调（保留 pending 待模式恢复）。"""
        client = _make_client()
        items = [{"id": "id-lock", "ip": "45.33.32.156", "email": "lock@test.com"}]
        _mock_pull(client, items)
        mock_ack = _mock_ack(client)
        store = MagicMock()
        store.add_entry.return_value = MagicMock()
        store.get_setting.return_value = "lockdown"

        with patch("tgwl.cf_pull.reconcile_from_store") as mock_reconcile:
            result = client.process(store, MagicMock(), MagicMock())

        # IP 已入库
        store.add_entry.assert_called_once_with(
            "ip", "45.33.32.156", label="CF-Access:lock@test.com", added_by=0
        )
        # lockdown 模式：不 reconcile、不 ack
        mock_reconcile.assert_not_called()
        mock_ack.assert_not_called()
        assert result["pulled"] == 1
        assert result["added"] == 1

    def test_normal_mode_reconcile_and_ack(self):
        """firewall_mode=normal 时：走标准 reconcile + ack 路径。"""
        client = _make_client()
        items = [{"id": "id-norm", "ip": "208.67.220.220", "email": "norm@test.com"}]
        _mock_pull(client, items)
        mock_ack = _mock_ack(client)
        store = MagicMock()
        store.add_entry.return_value = MagicMock()
        store.get_setting.return_value = "normal"

        geo = MagicMock()
        fw = MagicMock()

        with patch("tgwl.cf_pull.reconcile_from_store") as mock_reconcile:
            result = client.process(store, geo, fw)

        # normal 模式：reconcile 被调一次，ack 被调一次带正确 id
        mock_reconcile.assert_called_once_with(store, geo, fw)
        mock_ack.assert_called_once_with(["id-norm"])
        assert result["pulled"] == 1
        assert result["added"] == 1
