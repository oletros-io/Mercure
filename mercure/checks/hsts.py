import re

from .base import BaseCheck
from ..scoring import CheckResult
from ..http_utils import fetch
from .. import logger


def _parse_hsts(header: str) -> dict:
   result = {"max_age": 0, "include_subdomains": False, "preload": False}
   ma = re.search(r"max-age\s*=\s*(\d+)", header, re.IGNORECASE)
   if ma:
      result["max_age"] = int(ma.group(1))
   if re.search(r"includeSubDomains", header, re.IGNORECASE):
      result["include_subdomains"] = True
   if re.search(r"preload", header, re.IGNORECASE):
      result["preload"] = True
   return result


class HSTSCheck(BaseCheck):
   name = "hsts"
   label = "HSTS"

   def run(self, domain: str, **kwargs) -> CheckResult:
      resp = fetch(f"https://{domain}")

      if resp is None:
         return CheckResult(
            name=self.name, label=self.label,
            score=0, reason="unreachable",
            details={"raw_header": ""},
         )

      raw = resp.headers.get("strict-transport-security", "")
      if not raw:
         return CheckResult(
            name=self.name, label=self.label,
            score=0, reason="no_hsts",
            details={"max_age": 0, "include_subdomains": False,
                     "preload": False, "raw_header": ""},
         )

      parsed = _parse_hsts(raw)
      parsed["raw_header"] = raw
      max_age = parsed["max_age"]
      incl_sub = parsed["include_subdomains"]
      preload = parsed["preload"]

      if max_age >= 31536000 and incl_sub and preload:
         score, reason = 3, "hsts_full"
      elif max_age >= 31536000 and incl_sub:
         score, reason = 3, "hsts_strong"
      elif max_age >= 15768000:
         score, reason = 2, "hsts_moderate"
      else:
         score, reason = 1, "hsts_weak"

      return CheckResult(
         name=self.name, label=self.label,
         score=score, reason=reason, details=parsed,
      )
