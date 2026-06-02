"""
config.py — 配置加载层

支持 TOML 配置文件 + 环境变量覆盖。
凭据（token、代理密码、API key）不打日志，不入 SQLite。

环境变量优先级高于配置文件，便于 systemd EnvironmentFile 注入：
  TGWL_TOKEN          → bot.token
  TGWL_PRIMARY_ADMIN  → bot.primary_admin
  TGWL_PROXY_URL      → proxy.url
  TGWL_DB_PATH        → database.path
  TGWL_DATA_DIR       → geo.data_dir
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Python 3.11+ 内置 tomllib；3.10 及以下用 tomli（requirements 中已列）
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError as exc:
        raise ImportError("Python < 3.11 需要安装 tomli: pip install tomli") from exc


# --------------------------------------------------------------------------- #
# 凭据脱敏工具函数                                                               #
# --------------------------------------------------------------------------- #

_CRED_PATTERN = re.compile(
    r"([a-zA-Z][a-zA-Z0-9+.\-]*://)[^/\s:@]+:[^/\s@]+@"
)


def redact_credentials(text: str) -> str:
    """
    将字符串中所有 "<scheme>://<user>:<pass>@" 形式的凭据替换为 "***@"。

    支持任意 scheme（socks5h、socks5、http、https 等）。
    适用于异常消息、日志行等含嵌入 URL 的任意字符串。
    对 None 或非 str 类型安全处理（直接返回原值转 str）。
    """
    if not isinstance(text, str):
        return str(text)
    return _CRED_PATTERN.sub(r"\1***@", text)


# --------------------------------------------------------------------------- #
# 数据类                                                                        #
# --------------------------------------------------------------------------- #

@dataclass
class BotConfig:
    token: str
    primary_admin: int


@dataclass
class ProxyConfig:
    url: str  # socks5h://[user:pass@]host:port 或空字符串（不走代理）


@dataclass
class GeoConfig:
    data_dir: Path
    online_provider: str = "ip-api"


@dataclass
class DatabaseConfig:
    path: Path


@dataclass
class Config:
    bot: BotConfig
    proxy: ProxyConfig
    geo: GeoConfig
    database: DatabaseConfig

    # 运行时派生字段（不来自配置文件）
    config_path: Path = field(default_factory=lambda: Path("config.toml"))

    # ------------------------------------------------------------------ #
    # 工厂方法                                                             #
    # ------------------------------------------------------------------ #

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Config":
        """
        加载配置。查找顺序：
        1. 显式传入的 path
        2. 环境变量 TGWL_CONFIG
        3. 当前目录的 config.toml
        4. 脚本所在目录的 config.toml

        环境变量可覆盖任意字段。
        """
        config_path = cls._resolve_config_path(path)

        raw: dict = {}
        if config_path and config_path.exists():
            with open(config_path, "rb") as f:
                raw = tomllib.load(f)

        # 构建各子配置，环境变量优先
        bot_raw = raw.get("bot", {})
        token = os.environ.get("TGWL_TOKEN") or bot_raw.get("token", "")
        primary_admin_str = os.environ.get("TGWL_PRIMARY_ADMIN") or str(
            bot_raw.get("primary_admin", 0)
        )
        try:
            primary_admin = int(primary_admin_str)
        except ValueError:
            primary_admin = 0

        proxy_raw = raw.get("proxy", {})
        proxy_url = os.environ.get("TGWL_PROXY_URL") or proxy_raw.get("url", "")

        geo_raw = raw.get("geo", {})
        data_dir_str = os.environ.get("TGWL_DATA_DIR") or geo_raw.get("data_dir", "data")

        # data_dir 相对于配置文件所在目录（若能确定），否则相对 cwd
        base_dir = config_path.parent if (config_path and config_path.exists()) else Path.cwd()
        data_dir = Path(data_dir_str)
        if not data_dir.is_absolute():
            data_dir = base_dir / data_dir

        db_raw = raw.get("database", {})
        db_path_str = os.environ.get("TGWL_DB_PATH") or db_raw.get("path", "whitelist.db")
        db_path = Path(db_path_str)
        if not db_path.is_absolute():
            db_path = base_dir / db_path

        cfg = cls(
            bot=BotConfig(token=token, primary_admin=primary_admin),
            proxy=ProxyConfig(url=proxy_url),
            geo=GeoConfig(
                data_dir=data_dir,
                online_provider=geo_raw.get("online_provider", "ip-api"),
            ),
            database=DatabaseConfig(path=db_path),
            config_path=config_path or Path("config.toml"),
        )
        cfg._validate()
        return cfg

    # ------------------------------------------------------------------ #
    # 内部方法                                                             #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _resolve_config_path(path: str | Path | None) -> Path | None:
        if path is not None:
            return Path(path)
        env_path = os.environ.get("TGWL_CONFIG")
        if env_path:
            return Path(env_path)
        candidates = [
            Path.cwd() / "config.toml",
            Path(__file__).parent.parent.parent / "config.toml",  # 项目根
        ]
        for c in candidates:
            if c.exists():
                return c
        return None  # 纯环境变量模式

    def _validate(self) -> None:
        """验证必填字段，不打印任何凭据内容。"""
        errors = []
        if not self.bot.token:
            errors.append("bot.token 未设置（环境变量 TGWL_TOKEN 或 config.toml [bot] token）")
        if not self.bot.primary_admin:
            errors.append(
                "bot.primary_admin 未设置（环境变量 TGWL_PRIMARY_ADMIN 或 config.toml [bot] primary_admin）"
            )
        if errors:
            raise ValueError("配置验证失败：\n  " + "\n  ".join(errors))

    def safe_repr(self) -> str:
        """返回隐藏凭据的可打印摘要，用于启动日志。不含 token、代理密码等敏感信息。"""
        token_hint = (
            f"***{self.bot.token[-6:]}" if len(self.bot.token) > 6 else "***"
        ) if self.bot.token else "(未设置)"
        proxy_hint = self._redact_proxy_url(self.proxy.url) if self.proxy.url else "(不走代理)"
        return (
            f"Config(primary_admin={self.bot.primary_admin}, "
            f"token={token_hint}, "
            f"proxy={proxy_hint}, "
            f"db={self.database.path}, "
            f"data_dir={self.geo.data_dir})"
        )

    @staticmethod
    def _redact_proxy_url(url: str) -> str:
        """
        脱敏代理 URL 中的 user:pass 部分，仅保留 scheme://host:port。
        例：socks5h://user:secret@proxy.example.com:1080
          → socks5h://***@proxy.example.com:1080

        若 URL 中无认证信息，则原样返回（不含凭据，无需脱敏）。
        """
        try:
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(url)
            if parsed.username or parsed.password:
                # 用 ***@host:port 替换 user:pass@host:port
                netloc = f"***@{parsed.hostname}"
                if parsed.port:
                    netloc += f":{parsed.port}"
                redacted = urlunparse((
                    parsed.scheme, netloc,
                    parsed.path, parsed.params,
                    parsed.query, parsed.fragment,
                ))
                return redacted
            # 无凭据，原样返回
            return url
        except Exception:
            # 畸形 URL 解析失败，用正则兜底脱敏；绝不返回可能含明文密码的原始串
            return redact_credentials(url)


# --------------------------------------------------------------------------- #
# 全局单例（延迟初始化，bot.py 调用 init_config() 后其他模块用 get_config()）     #
# --------------------------------------------------------------------------- #

_config: Config | None = None


def init_config(path: str | Path | None = None) -> Config:
    """初始化并缓存全局配置，返回 Config 实例。"""
    global _config
    _config = Config.load(path)
    return _config


def get_config() -> Config:
    """获取已初始化的全局配置。未初始化时抛 RuntimeError。"""
    if _config is None:
        raise RuntimeError(
            "配置未初始化，请先调用 init_config()。"
            "如在测试中使用，可直接调用 Config.load() 或 init_config()。"
        )
    return _config
