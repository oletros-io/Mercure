from .base import BaseCheck
from ..scoring import CheckResult
from ..http_utils import fetch_insecure
from .. import logger


class RedirectCheck(BaseCheck):
   name = "redirect"
   label = "REDIRECT"

   def run(self, domain: str, **kwargs) -> CheckResult:
      resp = fetch_insecure(f"http://{domain}", follow_redirects=False)

      details = {"status_code": 0, "location": "", "upgrades_to_tls": False}

      if resp is None:
         return CheckResult(
            name=self.name, label=self.label,
            score=2, reason="http_not_available", details=details,
         )

      details["status_code"] = resp.status_code
      location = resp.headers.get("location", "")
      details["location"] = location

      if resp.status_code in (301, 302, 303, 307, 308):
         loc_lower = location.lower()
         if loc_lower.startswith("https://"):
            details["upgrades_to_tls"] = True
            d_lower = domain.lower()
            if f"www.{d_lower}" in loc_lower:
               return CheckResult(
                  name=self.name, label=self.label,
                  score=3, reason="http_to_https_www", details=details,
               )
            if d_lower in loc_lower:
               return CheckResult(
                  name=self.name, label=self.label,
                  score=3, reason="http_to_https", details=details,
               )
            return CheckResult(
               name=self.name, label=self.label,
               score=3, reason="http_to_https", details=details,
            )
         return CheckResult(
            name=self.name, label=self.label,
            score=1, reason="redirect_no_tls", details=details,
         )

      if resp.status_code == 200:
         return CheckResult(
            name=self.name, label=self.label,
            score=0, reason="no_redirect_to_https", details=details,
         )

      return CheckResult(
         name=self.name, label=self.label,
         score=1, reason="http_unreachable", details=details,
      )
