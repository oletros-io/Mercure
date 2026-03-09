import re

from checks.base import BaseCheck
from scoring import CheckResult
from dns_utils import query_mx
import logger


class MXCheck(BaseCheck):
   name = "mx"
   label = "MX"
   weight = 1.5

   def run(self, domain: str, **kwargs) -> CheckResult:
      records = query_mx(domain)

      if not records:
         logger.warning(f"no MX record for {domain}")
         return CheckResult(
            name=self.name,
            label=self.label,
            score=3,
            reason="no_mx",
            details={"records": []},
         )

      exchanges = [r[1] for r in records]

      null_mx = any(ex in (".", "") for ex in exchanges)
      if null_mx:
         return CheckResult(
            name=self.name,
            label=self.label,
            score=2,
            reason="null_mx",
            details={"records": records},
         )

      ip_mx = any(re.match(r"^\d+\.\d+\.\d+\.\d+$", ex) for ex in exchanges)
      if ip_mx:
         return CheckResult(
            name=self.name,
            label=self.label,
            score=2,
            reason="ip_literal_mx",
            details={"records": records},
         )

      if len(records) == 1:
         return CheckResult(
            name=self.name,
            label=self.label,
            score=1,
            reason="single_mx",
            details={"records": records},
         )

      return CheckResult(
         name=self.name,
         label=self.label,
         score=0,
         reason="mx_ok",
         details={"records": records},
      )
