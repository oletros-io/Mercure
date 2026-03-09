from abc import ABC, abstractmethod
from scoring import CheckResult


class BaseCheck(ABC):
   name: str = ""
   label: str = ""
   weight: float = 1.0

   @abstractmethod
   def run(self, domain: str, **kwargs) -> CheckResult:
      ...
