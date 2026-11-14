import re

from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_mx, query_cname, query_srv
from ..http_utils import fetch
from .. import logger


def detect_mx_o365(domain: str) -> bool:
   records = query_mx(domain)
   for _, exchange in records:
      if "mail.protection.outlook.com" in exchange.lower():
         return True
   return False


def detect_autodiscover(domain: str) -> bool:
   cnames = query_cname(f"autodiscover.{domain}")
   for target in cnames:
      if "autodiscover.outlook.com" in target.lower():
         return True
   return False


def detect_sip_federation(domain: str) -> bool:
   records = query_srv(f"_sipfederationtls._tcp.{domain}")
   return len(records) > 0


def get_tenant_id(domain: str) -> str:
   resp = fetch(
      f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration",
      timeout=8.0,
   )
   if resp is None or resp.status_code != 200:
      return ""
   try:
      data = resp.json()
      token_endpoint = data.get("token_endpoint", "")
      match = re.search(r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/", token_endpoint)
      if match:
         return match.group(1)
   except Exception:
      pass
   return ""


class M365Check(BaseCheck):
   name = "m365"
   label = "M365"
   external = True

   def run(self, domain: str, **kwargs) -> CheckResult:
      mx_o365 = detect_mx_o365(domain)
      autodiscover = detect_autodiscover(domain)
      sip_fed = detect_sip_federation(domain)
      tenant_id = ""

      indicators = sum([mx_o365, autodiscover, sip_fed])

      if indicators > 0 or mx_o365:
         tenant_id = get_tenant_id(domain)

      details = {
         "tenant_id": tenant_id,
         "mx_o365": mx_o365,
         "autodiscover": autodiscover,
         "sip_federation": sip_fed,
      }

      if not mx_o365 and not autodiscover and not sip_fed and not tenant_id:
         return CheckResult(
            name=self.name, label=self.label, score=3,
            reason="no_m365", details=details,
         )

      if tenant_id:
         logger.info(f"M365 tenant detected for {domain}: {tenant_id}")
         return CheckResult(
            name=self.name, label=self.label, score=2,
            reason="m365_tenant_exposed", details=details,
         )

      return CheckResult(
         name=self.name, label=self.label, score=2,
         reason="m365_detected", details=details,
      )
