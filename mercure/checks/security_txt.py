from .base import BaseCheck
from ..scoring import CheckResult
from ..http_utils import fetch
from .. import logger


def _parse_security_txt(body: str) -> dict:
   fields = {
      "contact": "",
      "expires": "",
      "encryption": "",
      "preferred_languages": "",
      "canonical": "",
   }
   for line in body.splitlines():
      line = line.strip()
      if line.startswith("#") or ":" not in line:
         continue
      key, _, value = line.partition(":")
      key = key.strip().lower().replace("-", "_")
      value = value.strip()
      if key in fields and not fields[key]:
         fields[key] = value
   return fields


class SecurityTxtCheck(BaseCheck):
   name = "security_txt"
   label = "SEC.TXT"

   def run(self, domain: str, **kwargs) -> CheckResult:
      resp = fetch(f"https://{domain}/.well-known/security.txt")

      if resp is None or resp.status_code != 200:
         return CheckResult(
            name=self.name, label=self.label,
            score=0, reason="no_security_txt",
            details={},
         )

      parsed = _parse_security_txt(resp.text)

      if parsed["contact"] and parsed["expires"]:
         score, reason = 3, "security_txt_valid"
      elif parsed["contact"]:
         score, reason = 2, "no_expires"
      else:
         score, reason = 1, "invalid_security_txt"

      return CheckResult(
         name=self.name, label=self.label,
         score=score, reason=reason, details=parsed,
      )
