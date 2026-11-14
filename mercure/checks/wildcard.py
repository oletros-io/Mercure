from uuid import uuid4

from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_a


class WildcardCheck(BaseCheck):
   name = "wildcard"
   label = "WILDCARD"

   def run(self, domain: str, **kwargs) -> CheckResult:
      probe = f"{uuid4().hex[:16]}.{domain}"
      ips = query_a(probe)

      if ips:
         return CheckResult(
            name=self.name, label=self.label,
            score=0, reason="wildcard_enabled",
            value=ips[0],
            details={"probe": probe, "resolved_ips": ips},
         )

      return CheckResult(
         name=self.name, label=self.label,
         score=3, reason="no_wildcard",
         details={"probe": probe},
      )
