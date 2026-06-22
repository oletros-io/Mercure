import os
from dataclasses import dataclass, field
from pathlib import Path

try:
   from dotenv import load_dotenv
   load_dotenv()
except ImportError:
   pass


@dataclass
class Config:
   log_retention_days: int = int(os.getenv("LOG_RETENTION_DAYS", "30"))
   dns_timeout: float = float(os.getenv("DNS_TIMEOUT", "5.0"))
   default_threads: int = int(os.getenv("DEFAULT_THREADS", "16"))
   selector_threads: int = int(os.getenv("SELECTOR_THREADS", "16"))
   dkim_wordlist_path: str = os.getenv("DKIM_WORDLIST_PATH", "resources/dkim_selectors.txt")
   smtp_timeout: float = float(os.getenv("SMTP_TIMEOUT", "10.0"))
   log_dir: Path = field(default_factory=lambda: Path(os.getenv("LOG_DIR", "log")))
   smtp_relay_host: str = os.getenv("SMTP_RELAY_HOST", "")
   smtp_relay_port: int = int(os.getenv("SMTP_RELAY_PORT", "587"))
   smtp_relay_user: str = os.getenv("SMTP_RELAY_USER", "")
   smtp_relay_pass: str = os.getenv("SMTP_RELAY_PASS", "")


config = Config()
