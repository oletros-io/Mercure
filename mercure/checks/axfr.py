from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_ns, attempt_axfr


class AXFRCheck(BaseCheck):
   name = "axfr"
   label = "AXFR"

   def run(self, domain: str, **kwargs) -> CheckResult:
      nameservers = query_ns(domain)
      if not nameservers:
         return CheckResult(
            name=self.name, label=self.label,
            score=1, reason="no_ns", details={},
         )

      vulnerable = {}
      for ns in nameservers:
         records = attempt_axfr(domain, ns)
         if records:
            vulnerable[ns] = len(records)

      if vulnerable:
         return CheckResult(
            name=self.name, label=self.label,
            score=0, reason="axfr_allowed",
            details={"vulnerable_ns": vulnerable},
         )

      return CheckResult(
         name=self.name, label=self.label,
         score=3, reason="axfr_denied",
         details={"tested_ns": nameservers},
      )
