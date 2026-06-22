import threading
from datetime import datetime, timedelta
from pathlib import Path

from rich.console import Console
from rich.text import Text

from .config import config

console = Console()

LEVEL_STYLES = {
   "debug": "grey50",
   "info": "blue",
   "warning": "orange1",
   "error": "red",
   "success": "green",
}

LEVEL_VALUES = {
   "debug": 10,
   "info": 20,
   "success": 25,
   "warning": 30,
   "error": 40,
}

_lock = threading.Lock()
_min_level = LEVEL_VALUES["info"]


def set_level(level: str):
   global _min_level
   _min_level = LEVEL_VALUES.get(level.lower(), 20)


def _ensure_log_dir() -> Path:
   config.log_dir.mkdir(parents=True, exist_ok=True)
   return config.log_dir


def _log_file() -> Path:
   d = _ensure_log_dir()
   return d / f"{datetime.now().strftime('%Y-%m-%d')}.log"


def _prune():
   d = _ensure_log_dir()
   cutoff = datetime.now() - timedelta(days=config.log_retention_days)
   for f in d.glob("*.log"):
      try:
         ts = datetime.strptime(f.stem, "%Y-%m-%d")
         if ts < cutoff:
            f.unlink(missing_ok=True)
      except Exception:
         pass


def _write_disk(level: str, msg: str):
   ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
   line = f"{ts} {level} {msg}\n"
   with _lock:
      try:
         with _log_file().open("a", encoding="utf-8") as fh:
            fh.write(line)
      except Exception:
         pass


def _print_console(level: str, msg: str):
   ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
   style = LEVEL_STYLES.get(level, "white")
   console.print(Text(f"{ts} {level} {msg}", style=style))


def log(msg: str, level: str = "info"):
   lvl = level.lower()
   _write_disk(lvl, msg)
   if LEVEL_VALUES.get(lvl, 99) >= _min_level:
      _print_console(lvl, msg)


def debug(msg: str):
   log(msg, "debug")


def info(msg: str):
   log(msg, "info")


def warning(msg: str):
   log(msg, "warning")


def error(msg: str):
   log(msg, "error")


def success(msg: str):
   log(msg, "success")


_prune()
