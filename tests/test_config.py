from pathlib import Path
from mercure.config import Config, load_config, _ConfigProxy


class TestConfig:
   def test_defaults(self):
      c = Config()
      assert c.dns_timeout == 5.0
      assert c.default_threads == 16
      assert c.smtp_relay_host == ""
      assert c.dns_cache_ttl == 300.0

   def test_custom_values(self):
      c = Config(dns_timeout=10.0, default_threads=32)
      assert c.dns_timeout == 10.0
      assert c.default_threads == 32


class TestConfigProxy:
   def test_lazy_load(self):
      proxy = _ConfigProxy()
      assert proxy._config is None
      _ = proxy.dns_timeout
      assert proxy._config is not None

   def test_reset(self):
      proxy = _ConfigProxy()
      custom = Config(dns_timeout=99.0)
      proxy.reset(custom)
      assert proxy.dns_timeout == 99.0

   def test_reset_none(self):
      proxy = _ConfigProxy()
      proxy.reset(Config(dns_timeout=99.0))
      proxy.reset(None)
      assert proxy._config is None


class TestLoadConfig:
   def test_returns_config(self):
      c = load_config()
      assert isinstance(c, Config)
