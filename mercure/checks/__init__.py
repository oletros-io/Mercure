import importlib
import pkgutil
from pathlib import Path

from .base import BaseCheck

ALL_CHECKS = []
CHECK_MAP = {}


def _discover():
   pkg_dir = Path(__file__).parent
   for info in pkgutil.iter_modules([str(pkg_dir)]):
      if info.name == "base":
         continue
      mod = importlib.import_module(f".{info.name}", __package__)
      for attr_name in dir(mod):
         attr = getattr(mod, attr_name)
         if (isinstance(attr, type)
               and issubclass(attr, BaseCheck)
               and attr is not BaseCheck
               and attr.name):
            ALL_CHECKS.append(attr)
            CHECK_MAP[attr.name] = attr


_discover()


def get_check_by_name(name: str):
   return CHECK_MAP.get(name.lower())
