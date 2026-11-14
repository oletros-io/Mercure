from .base import BaseCheck
from ..scoring import CheckResult
from ..http_utils import fetch
from .. import logger

EXPECTED_HEADERS = [
   "content-security-policy",
   "x-frame-options",
   "x-content-type-options",
   "referrer-policy",
   "permissions-policy",
   "cross-origin-opener-policy",
]


class SecHeadersCheck(BaseCheck):
   name = "headers"
   label = "HEADERS"

   def run(self, domain: str, **kwargs) -> CheckResult:
      resp = fetch(f"https://{domain}")

      if resp is None:
         return CheckResult(
            name=self.name, label=self.label,
            score=0, reason="unreachable",
            details={"present": [], "missing": EXPECTED_HEADERS[:], "values": {}},
         )

      headers_lower = {k.lower(): v for k, v in resp.headers.items()}
      present = []
      missing = []
      values = {}

      for h in EXPECTED_HEADERS:
         val = headers_lower.get(h)
         if val:
            present.append(h)
            values[h] = val
         else:
            missing.append(h)

      details = {"present": present, "missing": missing, "values": values}
      count = len(present)

      if count >= 6:
         score, reason = 3, "all_headers"
      elif count >= 4:
         score, reason = 2, "most_headers"
      elif count >= 2:
         score, reason = 1, "some_headers"
      else:
         score, reason = 0, "missing_headers"

      return CheckResult(
         name=self.name, label=self.label,
         score=score, reason=reason, details=details,
      )
