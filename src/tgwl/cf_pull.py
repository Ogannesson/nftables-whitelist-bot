"""
cf_pull.py — Cloudflare Access KV 待加白 IP 的服务器侧 pull 客户端

架构：CF Worker（边缘）认证后把 {id, ip, email, ts} 写入 KV；
本模块定期经 SOCKS5 代理 pull 一个 Worker 端点拿待加白 IP，
加白后 ack 删除（两段式，失败不丢）。

公共 API:
  CFPullClient(worker_url, client_id, client_secret, proxy_url, timeout)
  .pull()    -> list[dict]   拉取待加白条目
  .ack()     -> None         确认删除 KV 条目
  .process() -> dict         编排：pull → add_entry → reconcile → ack
"""

from __future__ import annotations

import ipaddress
import logging

import httpx

from tgwl.reconcile import reconcile_from_store

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# 工具：IP 末段打码                                                              #
# --------------------------------------------------------------------------- #


def mask_ip(ip: str) -> str:
    """将 IP 末段替换为 ***，用于日志脱敏。

    IPv4: 1.2.3.4   -> 1.2.3.***
    IPv6: 2001:db8::1 -> 2001:db8::***
    非法 IP 原样返回（不抛异常）。
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 4:
        parts = ip.rsplit(".", 1)
        return parts[0] + ".***"
    # IPv6: 替换最后一个段或 :: 后的部分
    parts = ip.rsplit(":", 1)
    return parts[0] + ":***"


# --------------------------------------------------------------------------- #
# CFPullClient                                                                  #
# --------------------------------------------------------------------------- #


class CFPullClient:
    """
    Cloudflare Access KV 白名单 pull 客户端。

    两段式可靠语义：
      - pull() 只读取，不删除（KV 保留）。
      - process() 在 reconcile 成功后才调用 ack()——
        若 reconcile 抛异常则不 ack，下次重拉（add_entry 幂等，不重复加白）。
    """

    def __init__(
        self,
        worker_url: str,
        client_id: str,
        client_secret: str,
        proxy_url: str = "",
        timeout: float = 10.0,
    ) -> None:
        self._worker_url = worker_url.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._proxy_url = proxy_url
        self._timeout = timeout

    # ---------------------------------------------------------------------- #
    # 内部辅助                                                                 #
    # ---------------------------------------------------------------------- #

    def _headers(self) -> dict[str, str]:
        """返回 CF Access Service Token 请求头。"""
        return {
            "CF-Access-Client-Id": self._client_id,
            "CF-Access-Client-Secret": self._client_secret,
        }

    def _make_client(self) -> httpx.Client:
        proxies = self._proxy_url or None
        return httpx.Client(
            proxy=proxies,
            timeout=self._timeout,
            follow_redirects=True,
        )

    # ---------------------------------------------------------------------- #
    # 公共 API                                                                 #
    # ---------------------------------------------------------------------- #

    def pull(self) -> list[dict]:
        """POST {worker_url}/pull，返回待加白条目列表。

        每项形如 {"id": "...", "ip": "...", "email": "..."}。
        HTTP / 网络错误抛 RuntimeError，消息不含 client_secret。
        """
        url = f"{self._worker_url}/pull"
        try:
            with self._make_client() as client:
                resp = client.post(url, headers=self._headers())
                resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            # 不把 headers（含 secret）外泄进异常消息
            raise RuntimeError(
                f"CF pull 请求失败: HTTP {e.response.status_code}"
            ) from None
        except httpx.RequestError as e:
            raise RuntimeError(
                f"CF pull 网络错误: {type(e).__name__}"
            ) from None

        try:
            return resp.json().get("ips", [])
        except Exception as e:
            raise RuntimeError(f"CF pull 响应解析失败: {e}") from None

    def ack(self, ids: list[str]) -> None:
        """POST {worker_url}/ack 确认删除 KV 条目。空列表直接返回。"""
        if not ids:
            return
        url = f"{self._worker_url}/ack"
        try:
            with self._make_client() as client:
                resp = client.post(url, json={"ids": ids}, headers=self._headers())
                resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise RuntimeError(
                f"CF ack 请求失败: HTTP {e.response.status_code}"
            ) from None
        except httpx.RequestError as e:
            raise RuntimeError(
                f"CF ack 网络错误: {type(e).__name__}"
            ) from None

    def process(self, store, geo, fw) -> dict:
        """编排：pull → 校验 → add_entry → reconcile → ack。

        两段式保证：reconcile 成功后才 ack，reconcile 抛异常则不 ack（下次重拉）。
        add_entry 幂等（同值已存在返回 None），保证重拉安全。

        Returns:
            {"pulled": int, "added": int, "skipped": int}
        """
        items = self.pull()
        pulled = len(items)
        added = 0
        skipped = 0
        successful_ids: list[str] = []

        for item in items:
            raw_ip = item.get("ip", "")
            item_id = item.get("id", "")
            email = item.get("email", "")

            # ---- IP 校验 -------------------------------------------------- #
            try:
                addr = ipaddress.ip_address(raw_ip)
            except ValueError:
                logger.debug("CF pull: 无效 IP %r，跳过", raw_ip)
                skipped += 1
                continue

            if addr.version != 4:
                logger.debug("CF pull: IPv6 %s 暂不支持，跳过", mask_ip(raw_ip))
                skipped += 1
                continue

            if (
                addr.is_private
                or addr.is_loopback
                or addr.is_link_local
                or addr.is_multicast
                or addr.is_reserved
                or addr.is_unspecified
            ):
                logger.debug(
                    "CF pull: 私有/保留地址 %s，跳过", mask_ip(raw_ip)
                )
                skipped += 1
                continue

            # ---- add_entry（幂等） ----------------------------------------- #
            label = f"CF-Access:{email}" if email else "CF-Access"
            result = store.add_entry("ip", raw_ip, label=label, added_by=0)
            # result is None 表示已存在 → 也算成功处理，纳入 ack
            if result is not None:
                added += 1
                logger.info(
                    "CF pull: 新增白名单 IP %s (email=%s)",
                    mask_ip(raw_ip),
                    email,
                )
            else:
                logger.debug(
                    "CF pull: IP %s 已存在，幂等跳过", mask_ip(raw_ip)
                )

            successful_ids.append(item_id)

        # ---- reconcile + ack（两段式） ------------------------------------ #
        if successful_ids:
            mode = store.get_setting("firewall_mode") or "normal"
            if mode != "normal":
                logger.warning(
                    "CF pull: firewall_mode=%r，已入库 %d 条但跳过 reconcile（保留 pending 待模式恢复）",
                    mode,
                    len(successful_ids),
                )
                return {"pulled": pulled, "added": added, "skipped": skipped}  # 不 reconcile、不 ack
            # reconcile 抛异常则不 ack，让异常向上传播，下次重拉
            reconcile_from_store(store, geo, fw)
            self.ack(successful_ids)

        return {"pulled": pulled, "added": added, "skipped": skipped}
