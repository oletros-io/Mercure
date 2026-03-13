from checks.base import BaseCheck
from scoring import CheckResult
from dns_utils import query_tlsa
import logger


class TLSACheck(BaseCheck):
   name = "tlsa"
   label = "TLSA"
   weight = 1.0

   def run(self, domain: str, **kwargs) -> CheckResult:
      fqdn = f"_25._tcp.{domain}"
      records = query_tlsa(fqdn)

      if records:
         return CheckResult(
            name=self.name,
            label=self.label,
            score=3,
            reason="tlsa_present",
            details={"fqdn": fqdn, "records": records},
         )

      logger.info(f"no TLSA record for {fqdn}")
      return CheckResult(
         name=self.name,
         label=self.label,
         score=0,
         reason="no_tlsa",
         details={"fqdn": fqdn, "records": []},
      )
