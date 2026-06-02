"""
tests/test_config.py — config.py 单元测试
"""

from __future__ import annotations

import os
import pytest
from pathlib import Path

from tgwl.config import Config, init_config, get_config, redact_credentials


# --------------------------------------------------------------------------- #
# 辅助                                                                          #
# --------------------------------------------------------------------------- #

def write_config(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


MINIMAL_TOML = """\
[bot]
token = "123:ABCtest"
primary_admin = 12345

[proxy]
url = "socks5h://127.0.0.1:1080"
"""


# --------------------------------------------------------------------------- #
# 测试                                                                          #
# --------------------------------------------------------------------------- #

class TestConfig:
    def test_load_from_toml(self, tmp_path):
        cfg_file = write_config(tmp_path / "config.toml", MINIMAL_TOML)
        cfg = Config.load(cfg_file)
        assert cfg.bot.token == "123:ABCtest"
        assert cfg.bot.primary_admin == 12345
        assert cfg.proxy.url == "socks5h://127.0.0.1:1080"

    def test_env_overrides_toml(self, tmp_path, monkeypatch):
        cfg_file = write_config(tmp_path / "config.toml", MINIMAL_TOML)
        monkeypatch.setenv("TGWL_TOKEN", "env_token:XXX")
        monkeypatch.setenv("TGWL_PRIMARY_ADMIN", "99999")
        cfg = Config.load(cfg_file)
        assert cfg.bot.token == "env_token:XXX"
        assert cfg.bot.primary_admin == 99999

    def test_env_only_no_file(self, monkeypatch, tmp_path):
        # 不存在配置文件时纯环境变量也能工作
        monkeypatch.setenv("TGWL_TOKEN", "env_only:TKN")
        monkeypatch.setenv("TGWL_PRIMARY_ADMIN", "11111")
        monkeypatch.setenv("TGWL_PROXY_URL", "socks5h://10.0.0.1:7070")
        monkeypatch.setenv("TGWL_DB_PATH", str(tmp_path / "test.db"))
        cfg = Config.load(None)
        assert cfg.bot.token == "env_only:TKN"
        assert cfg.bot.primary_admin == 11111

    def test_missing_token_raises(self, tmp_path):
        cfg_file = write_config(
            tmp_path / "config.toml",
            "[bot]\nprimary_admin = 12345\n"
        )
        with pytest.raises(ValueError, match="token"):
            Config.load(cfg_file)

    def test_missing_primary_admin_raises(self, tmp_path):
        cfg_file = write_config(
            tmp_path / "config.toml",
            '[bot]\ntoken = "abc:def"\n'
        )
        with pytest.raises(ValueError, match="primary_admin"):
            Config.load(cfg_file)

    def test_data_dir_relative_to_config(self, tmp_path):
        cfg_file = write_config(
            tmp_path / "config.toml",
            MINIMAL_TOML + '\n[geo]\ndata_dir = "mydata"\n'
        )
        cfg = Config.load(cfg_file)
        assert cfg.geo.data_dir == tmp_path / "mydata"

    def test_db_path_relative_to_config(self, tmp_path):
        cfg_file = write_config(
            tmp_path / "config.toml",
            MINIMAL_TOML + '\n[database]\npath = "my.db"\n'
        )
        cfg = Config.load(cfg_file)
        assert cfg.database.path == tmp_path / "my.db"

    def test_safe_repr_hides_token(self, tmp_path):
        cfg_file = write_config(tmp_path / "config.toml", MINIMAL_TOML)
        cfg = Config.load(cfg_file)
        rep = cfg.safe_repr()
        # token 不应完整出现
        assert "123:ABCtest" not in rep
        # 但末尾几位可见（用于核对）
        assert "ABCtest"[:3] not in rep or "***" in rep

    def test_get_config_without_init_raises(self, monkeypatch):
        # 重置全局单例
        import tgwl.config as cfg_mod
        original = cfg_mod._config
        cfg_mod._config = None
        try:
            with pytest.raises(RuntimeError, match="init_config"):
                get_config()
        finally:
            cfg_mod._config = original

    def test_init_config_and_get_config(self, tmp_path):
        import tgwl.config as cfg_mod
        original = cfg_mod._config
        cfg_mod._config = None
        try:
            cfg_file = write_config(tmp_path / "config.toml", MINIMAL_TOML)
            init_config(cfg_file)
            cfg = get_config()
            assert cfg.bot.primary_admin == 12345
        finally:
            cfg_mod._config = original

    def test_default_online_provider(self, tmp_path):
        cfg_file = write_config(tmp_path / "config.toml", MINIMAL_TOML)
        cfg = Config.load(cfg_file)
        assert cfg.geo.online_provider == "ip-api"


class TestRedactCredentials:
    """验证 redact_credentials 的脱敏行为。"""

    def test_socks5h_url_removes_secret(self):
        result = redact_credentials("socks5h://user:secret@host:1080")
        assert "secret" not in result
        assert "user" not in result
        assert "socks5h://***@host:1080" == result

    def test_socks5_scheme(self):
        result = redact_credentials("socks5://alice:p4ssw0rd@10.0.0.1:9050")
        assert "p4ssw0rd" not in result
        assert "alice" not in result

    def test_http_scheme(self):
        result = redact_credentials("http://proxyuser:proxypass@proxy.example.com:8080")
        assert "proxypass" not in result

    def test_https_scheme(self):
        result = redact_credentials("https://u:s3cr3t@proxy.example.com:443")
        assert "s3cr3t" not in result

    def test_no_credentials_unchanged(self):
        url = "socks5h://host:1080"
        assert redact_credentials(url) == url

    def test_embedded_in_exception_message(self):
        exc_msg = "ProxyError('Cannot connect to proxy', 'socks5h://user:secret@h:1080')"
        result = redact_credentials(exc_msg)
        assert "secret" not in result
        assert "***@h:1080" in result

    def test_none_input_safe(self):
        # None 应被转为字符串而不抛异常
        result = redact_credentials(None)  # type: ignore[arg-type]
        assert isinstance(result, str)

    def test_non_str_input_safe(self):
        result = redact_credentials(42)  # type: ignore[arg-type]
        assert result == "42"

    def test_multiple_urls_in_string(self):
        msg = "error: socks5h://a:b@h1:1 and http://c:d@h2:2"
        result = redact_credentials(msg)
        assert "b" not in result.split("h1")[0].split("://")[1] if "h1" in result else True
        assert ":b@" not in result
        assert ":d@" not in result

    def test_redact_proxy_url_malformed_falls_back_to_redact(self):
        """_redact_proxy_url 对畸形 URL 不应返回明文密码。"""
        # 构造一个 urlparse 无法正确解析用户名的畸形 URL，
        # 但字符串里含有 user:pass@ 模式——正则兜底也应脱敏它
        malformed = "socks5h://user:secret@[invalid-host"
        result = Config._redact_proxy_url(malformed)
        assert "secret" not in result

    def test_redact_proxy_url_with_credentials(self):
        result = Config._redact_proxy_url("socks5h://myuser:mypass@proxy.host:1080")
        assert "mypass" not in result
        assert "myuser" not in result
        assert "proxy.host:1080" in result

    def test_redact_proxy_url_no_credentials(self):
        url = "socks5h://proxy.host:1080"
        assert Config._redact_proxy_url(url) == url
