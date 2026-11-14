import re

from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_txt
from .. import logger


def get_tls_rpt_record(domain: str) -> str:
   records = query_txt(f"_smtp._tls.{domain}")
   for r in records:
      if r.strip().lower().startswith("v=tlsrptv1"):
         return r.strip()
   return ""


def parse_rua(record: str) -> str:
   for part in re.split(r";\s*", record):
      part = part.strip()
      if part.lower().startswith("rua="):
         return part.split("=", 1)[1].strip()
   return ""


class TLSRPTCheck(BaseCheck):
   name = "tls_rpt"
   label = "TLS-RPT"

   def run(self, domain: str, **kwargs) -> CheckResult:
      record = get_tls_rpt_record(domain)
      if not record:
         logger.info(f"no TLS-RPT record for {domain}")
         return CheckResult(
            name=self.name, label=self.label, score=0,
            reason="no_tls_rpt",
            details={"record": "", "rua": ""},
         )

      rua = parse_rua(record)
      details = {"record": record, "rua": rua}

      if rua:
         return CheckResult(
            name=self.name, label=self.label, score=3,
            reason="tls_rpt_configured", details=details,
         )

      return CheckResult(
         name=self.name, label=self.label, score=1,
         reason="no_reporting_address", details=details,
      )
