from checks.base import BaseCheck
from scoring import CheckResult
from dns_utils import query_srv
import logger


MAIL_SRV_NAMES = [
   "_submission._tcp",
   "_imaps._tcp",
   "_pop3s._tcp",
]


class SRVCheck(BaseCheck):
   name = "srv"
   label = "SRV"
   weight = 0.5

   def run(self, domain: str, **kwargs) -> CheckResult:
      found = {}

      for srv_name in MAIL_SRV_NAMES:
         fqdn = f"{srv_name}.{domain}"
         records = query_srv(fqdn)
         if records:
            found[srv_name] = records

      if not found:
         logger.info(f"no mail SRV records for {domain}")
         return CheckResult(
            name=self.name,
            label=self.label,
            score=3,
            reason="no_mail_srv",
            details={"srv_records": {}},
         )

      if len(found) < len(MAIL_SRV_NAMES):
         return CheckResult(
            name=self.name,
            label=self.label,
            score=1,
            reason="partial_mail_srv",
            details={"srv_records": found, "missing": [s for s in MAIL_SRV_NAMES if s not in found]},
         )

      return CheckResult(
         name=self.name,
         label=self.label,
         score=0,
         reason="mail_srv_ok",
         details={"srv_records": found},
      )
