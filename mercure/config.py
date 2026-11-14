import os
from dataclasses import dataclass, field
from pathlib import Path

try:
   from dotenv import load_dotenv
   load_dotenv()
except ImportError:
   pass


def _env_int(key: str, default: str) -> int:
   return int(os.getenv(key, default))


def _env_float(key: str, default: str) -> float:
   return float(os.getenv(key, default))


@dataclass
class Config:
   log_retention_days: int = 30
   dns_timeout: float = 5.0
   default_threads: int = 16
   selector_threads: int = 16
   dkim_wordlist_path: str = "resources/dkim_selectors.txt"
   smtp_timeout: float = 10.0
   log_dir: Path = field(default_factory=lambda: Path("log"))
   smtp_relay_host: str = ""
   smtp_relay_port: int = 587
   smtp_relay_user: str = ""
   smtp_relay_pass: str = ""
   dns_cache_ttl: float = 300.0
   shodan_api_key: str = ""
   http_timeout: float = 10.0


def load_config() -> Config:
   return Config(
      log_retention_days=_env_int("LOG_RETENTION_DAYS", "30"),
      dns_timeout=_env_float("DNS_TIMEOUT", "5.0"),
      default_threads=_env_int("DEFAULT_THREADS", "16"),
      selector_threads=_env_int("SELECTOR_THREADS", "16"),
      dkim_wordlist_path=os.getenv("DKIM_WORDLIST_PATH", "resources/dkim_selectors.txt"),
      smtp_timeout=_env_float("SMTP_TIMEOUT", "10.0"),
      log_dir=Path(os.getenv("LOG_DIR", "log")),
      smtp_relay_host=os.getenv("SMTP_RELAY_HOST", ""),
      smtp_relay_port=_env_int("SMTP_RELAY_PORT", "587"),
      smtp_relay_user=os.getenv("SMTP_RELAY_USER", ""),
      smtp_relay_pass=os.getenv("SMTP_RELAY_PASS", ""),
      dns_cache_ttl=_env_float("DNS_CACHE_TTL", "300.0"),
      shodan_api_key=os.getenv("SHODAN_API_KEY", ""),
      http_timeout=_env_float("HTTP_TIMEOUT", "10.0"),
   )


class _ConfigProxy:
   def __init__(self):
      self._config = None

   def _ensure(self):
      if self._config is None:
         self._config = load_config()

   def __getattr__(self, name):
      if name.startswith("_"):
         return object.__getattribute__(self, name)
      self._ensure()
      return getattr(self._config, name)

   def reset(self, new_config: Config = None):
      self._config = new_config


config = _ConfigProxy()
