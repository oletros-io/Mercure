from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_aaaa
from .. import logger


class IPv6Check(BaseCheck):
   name = "ipv6"
   label = "IPv6"

   def run(self, domain: str, **kwargs) -> CheckResult:
      records = query_aaaa(domain)

      if records:
         return CheckResult(
            name=self.name,
            label=self.label,
            score=3,
            reason="ipv6_present",
            details={"addresses": records},
         )

      logger.info(f"no AAAA record for {domain}")
      return CheckResult(
         name=self.name,
         label=self.label,
         score=0,
         reason="no_ipv6",
         details={"addresses": []},
      )
