from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_a
from ..http_utils import fetch
from .. import logger


class RPKICheck(BaseCheck):
   name = "rpki"
   label = "RPKI"
   external = True

   def run(self, domain: str, **kwargs) -> CheckResult:
      ips = query_a(domain)
      if not ips:
         return CheckResult(
            name=self.name, label=self.label,
            score=2, reason="rpki_unknown",
            details={"ip": "", "state": "", "prefix": ""},
         )

      ip = ips[0]
      prefix = ".".join(ip.split(".")[:3]) + ".0/24"
      url = f"https://rpki.cloudflare.com/api/v1/validity/AS0/{prefix}"

      resp = fetch(url, timeout=10.0)
      if resp is None or resp.status_code != 200:
         return CheckResult(
            name=self.name, label=self.label,
            score=2, reason="rpki_unknown",
            details={"ip": ip, "state": "api_error", "prefix": prefix},
         )

      try:
         data = resp.json()
         state = data.get("validated_route", {}).get("validity", {}).get("state", "not-found")
      except Exception:
         state = "not-found"

      details = {"ip": ip, "state": state, "prefix": prefix}

      if state == "valid":
         return CheckResult(
            name=self.name, label=self.label,
            score=3, reason="rpki_valid",
            details=details,
         )

      if state == "invalid":
         logger.warning(f"RPKI invalid for {ip} ({prefix})")
         return CheckResult(
            name=self.name, label=self.label,
            score=0, reason="rpki_invalid",
            details=details,
         )

      return CheckResult(
         name=self.name, label=self.label,
         score=1, reason="rpki_not_found",
         details=details,
      )
