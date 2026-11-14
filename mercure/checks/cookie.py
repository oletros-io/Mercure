from .base import BaseCheck
from ..scoring import CheckResult
from ..http_utils import fetch
from .. import logger


def _parse_set_cookie(header_value: str) -> dict:
   if not header_value or not header_value.strip():
      return {"name": "", "secure": False, "httponly": False, "samesite": ""}
   parts = [p.strip() for p in header_value.split(";")]
   name = parts[0].split("=")[0] if "=" in parts[0] else parts[0]
   flags_lower = [p.lower() for p in parts[1:]]
   samesite_raw = next(
      (p.split("=", 1)[1].strip() for p in parts[1:]
       if p.strip().lower().startswith("samesite=")), ""
   )
   return {
      "name": name,
      "secure": any("secure" == f for f in flags_lower),
      "httponly": any("httponly" == f for f in flags_lower),
      "samesite": samesite_raw,
   }


class CookieCheck(BaseCheck):
   name = "cookie"
   label = "COOKIE"

   def run(self, domain: str, **kwargs) -> CheckResult:
      resp = fetch(f"https://{domain}")

      if resp is None:
         return CheckResult(
            name=self.name, label=self.label,
            score=0, reason="unreachable",
            details={"cookies": [], "total": 0, "secured": 0},
         )

      if hasattr(resp.headers, "get_list"):
         raw_cookies = resp.headers.get_list("set-cookie")
      else:
         raw = resp.headers.get("set-cookie", "")
         raw_cookies = [raw] if raw and isinstance(raw, str) else []

      raw_cookies = [c for c in raw_cookies if isinstance(c, str) and c.strip()]
      if not raw_cookies:
         return CheckResult(
            name=self.name, label=self.label,
            score=3, reason="no_cookies",
            details={"cookies": [], "total": 0, "secured": 0},
         )

      cookies = [_parse_set_cookie(c) for c in raw_cookies]
      total = len(cookies)
      secured = sum(
         1 for c in cookies
         if c["secure"] and c["httponly"] and c["samesite"]
      )

      details = {"cookies": cookies, "total": total, "secured": secured}

      if secured == total:
         score, reason = 3, "cookies_secured"
      elif secured > 0:
         score, reason = 2, "cookies_partial"
      else:
         score, reason = 1, "cookies_insecure"

      return CheckResult(
         name=self.name, label=self.label,
         score=score, reason=reason, details=details,
      )
