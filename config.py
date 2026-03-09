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
   dkim_wordlist_path: str = os.getenv("DKIM_WORDLIST_PATH", "resources/selectors.txt")
   log_dir: Path = field(default_factory=lambda: Path(os.getenv("LOG_DIR", "log")))


config = Config()
