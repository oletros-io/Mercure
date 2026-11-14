from abc import ABC, abstractmethod
from ..scoring import CheckResult


class BaseCheck(ABC):
   name: str = ""
   label: str = ""
   intrusive: bool = False
   external: bool = False

   @abstractmethod
   def run(self, domain: str, **kwargs) -> CheckResult:
      ...
