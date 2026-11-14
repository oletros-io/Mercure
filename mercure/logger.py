import threading
from datetime import datetime, timedelta
from pathlib import Path

from rich.console import Console
from rich.text import Text

from .config import config

console = Console()

LEVEL_STYLES = {
   "debug": "grey50",
   "info": "dodger_blue1",
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
_pruned = False
_log_handle = None
_log_date = None


def set_level(level: str):
   global _min_level
   _min_level = LEVEL_VALUES.get(level.lower(), 20)


def _ensure_log_dir() -> Path:
   config.log_dir.mkdir(parents=True, exist_ok=True)
   return config.log_dir


def _prune():
   global _pruned
   if _pruned:
      return
   _pruned = True
   d = _ensure_log_dir()
   cutoff = datetime.now() - timedelta(days=config.log_retention_days)
   for f in d.glob("*.log"):
      try:
         ts = datetime.strptime(f.stem, "%Y-%m-%d")
         if ts < cutoff:
            f.unlink(missing_ok=True)
      except Exception:
         pass


def _get_handle():
   global _log_handle, _log_date
   today = datetime.now().strftime("%Y-%m-%d")
   if _log_handle is not None and _log_date == today:
      return _log_handle
   if _log_handle is not None:
      try:
         _log_handle.close()
      except Exception:
         pass
   d = _ensure_log_dir()
   _log_handle = (d / f"{today}.log").open("a", encoding="utf-8")
   _log_date = today
   return _log_handle


def _write_disk(level: str, msg: str):
   ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
   line = f"{ts} {level} {msg}\n"
   with _lock:
      try:
         _prune()
         fh = _get_handle()
         fh.write(line)
         fh.flush()
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
