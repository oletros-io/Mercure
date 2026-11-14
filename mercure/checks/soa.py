from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_soa


class SOACheck(BaseCheck):
   name = "soa"
   label = "SOA"

   def run(self, domain: str, **kwargs) -> CheckResult:
      soa = query_soa(domain)
      if not soa:
         return CheckResult(
            name=self.name, label=self.label,
            score=0, reason="no_soa", details={},
         )

      rname = soa.get("rname", "")
      if not rname or rname == ".":
         return CheckResult(
            name=self.name, label=self.label,
            score=1, reason="no_admin_contact", details=soa,
         )

      issues = []
      refresh = soa.get("refresh", 0)
      retry = soa.get("retry", 0)
      expire = soa.get("expire", 0)
      minimum = soa.get("minimum", 0)
      serial = soa.get("serial", 0)

      if serial <= 0:
         issues.append("serial_zero")
      if not (3600 <= refresh <= 86400):
         issues.append("refresh_out_of_range")
      if not (600 <= retry <= 3600):
         issues.append("retry_out_of_range")
      if not (604800 <= expire <= 2419200):
         issues.append("expire_out_of_range")
      if not (300 <= minimum <= 3600):
         issues.append("minimum_out_of_range")

      if issues:
         return CheckResult(
            name=self.name, label=self.label,
            score=2, reason="soa_weak_timers",
            details={**soa, "issues": issues},
         )

      return CheckResult(
         name=self.name, label=self.label,
         score=3, reason="soa_ok", details=soa,
      )
