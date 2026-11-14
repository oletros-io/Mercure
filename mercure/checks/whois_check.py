from datetime import datetime, timezone
from .base import BaseCheck
from ..scoring import CheckResult
from ..recon import rdap_lookup
from .. import logger


def _parse_expiry(rdap_data: dict) -> str:
   for event in rdap_data.get("events", []):
      if event.get("eventAction") == "expiration":
         return event.get("eventDate", "")
   return ""


def _parse_registrar(rdap_data: dict) -> str:
   for entity in rdap_data.get("entities", []):
      roles = entity.get("roles", [])
      if "registrar" in roles:
         vcard = entity.get("vcardArray", [None, []])
         if len(vcard) > 1:
            for item in vcard[1]:
               if item[0] == "fn":
                  return item[3]
         handle = entity.get("handle", "")
         if handle:
            return handle
   return ""


def _days_until(date_str: str) -> int:
   if not date_str:
      return -1
   try:
      dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
      now = datetime.now(timezone.utc)
      return (dt - now).days
   except Exception:
      return -1


class WhoisCheck(BaseCheck):
   name = "whois"
   label = "WHOIS"
   external = True

   def run(self, domain: str, **kwargs) -> CheckResult:
      rdap = rdap_lookup(domain)

      if not rdap:
         return CheckResult(
            name=self.name, label=self.label,
            score=2, reason="rdap_unavailable",
            details={"registrar": "", "expiry_date": "", "status": [], "days_until_expiry": -1},
         )

      expiry = _parse_expiry(rdap)
      registrar = _parse_registrar(rdap)
      status = rdap.get("status", [])
      days = _days_until(expiry)

      details = {
         "registrar": registrar,
         "expiry_date": expiry,
         "status": status,
         "days_until_expiry": days,
      }

      if 0 <= days <= 30:
         logger.warning(f"{domain} expires in {days} days")
         return CheckResult(
            name=self.name, label=self.label,
            score=0, reason="domain_expiring",
            details=details,
         )

      if 0 < days <= 90:
         logger.info(f"{domain} expires in {days} days")
         return CheckResult(
            name=self.name, label=self.label,
            score=1, reason="domain_renewal_soon",
            details=details,
         )

      has_lock = any("transferprohibited" in s.lower() for s in status)
      if not has_lock and status:
         return CheckResult(
            name=self.name, label=self.label,
            score=1, reason="no_transfer_lock",
            details=details,
         )

      return CheckResult(
         name=self.name, label=self.label,
         score=3, reason="whois_ok",
         details=details,
      )
