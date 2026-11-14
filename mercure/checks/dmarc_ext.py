import re
from typing import List, Tuple

from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_txt
from .. import logger


def _get_dmarc(domain: str) -> str:
   records = query_txt(f"_dmarc.{domain}")
   for r in records:
      if "v=dmarc1" in r.lower():
         return r.strip().strip('"')
   return ""


def _extract_uris(tag_value: str) -> List[str]:
   return [u.strip().split("!")[0] for u in tag_value.split(",") if u.strip()]


def _domain_from_mailto(uri: str) -> str:
   uri = uri.strip()
   if uri.lower().startswith("mailto:"):
      addr = uri[7:]
      if "@" in addr:
         return addr.split("@", 1)[1].lower()
   return ""


def _check_external_auth(source_domain: str, report_domain: str) -> bool:
   lookup = f"{source_domain}._report._dmarc.{report_domain}"
   records = query_txt(lookup)
   for r in records:
      if "v=dmarc1" in r.lower():
         return True
   return False


class DMARCExtCheck(BaseCheck):
   name = "dmarc_ext"
   label = "DMARC-EXT"

   def run(self, domain: str, **kwargs) -> CheckResult:
      dmarc = _get_dmarc(domain)
      if not dmarc:
         return CheckResult(
            name=self.name, label=self.label, score=0,
            reason="no_dmarc_reporting",
            details={"rua": [], "ruf": [], "external_checks": {}},
         )

      tags = {}
      for part in re.split(r";\s*", dmarc):
         if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()

      rua_raw = tags.get("rua", "")
      ruf_raw = tags.get("ruf", "")
      rua_uris = _extract_uris(rua_raw) if rua_raw else []
      ruf_uris = _extract_uris(ruf_raw) if ruf_raw else []

      all_uris = rua_uris + ruf_uris
      if not all_uris:
         return CheckResult(
            name=self.name, label=self.label, score=0,
            reason="no_dmarc_reporting",
            details={"rua": rua_uris, "ruf": ruf_uris, "external_checks": {}},
         )

      d_lower = domain.lower().rstrip(".")
      external_checks = {}
      has_external = False
      all_authorized = True

      for uri in all_uris:
         report_domain = _domain_from_mailto(uri)
         if not report_domain:
            continue
         if report_domain.rstrip(".") == d_lower:
            continue
         has_external = True
         authorized = _check_external_auth(d_lower, report_domain)
         external_checks[report_domain] = authorized
         if not authorized:
            all_authorized = False

      details = {
         "rua": rua_uris,
         "ruf": ruf_uris,
         "external_checks": external_checks,
      }

      if not has_external:
         return CheckResult(
            name=self.name, label=self.label, score=3,
            reason="internal_reports_only", details=details,
         )

      if all_authorized:
         return CheckResult(
            name=self.name, label=self.label, score=3,
            reason="external_reports_authorized", details=details,
         )

      logger.warning(f"unauthorized DMARC external report destinations for {domain}")
      return CheckResult(
         name=self.name, label=self.label, score=1,
         reason="unauthorized_external_report", details=details,
      )
