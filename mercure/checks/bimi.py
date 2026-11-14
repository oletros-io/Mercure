import re

from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_txt
from .. import logger


def get_bimi_record(domain: str) -> str:
   records = query_txt(f"default._bimi.{domain}")
   for r in records:
      if r.strip().lower().startswith("v=bimi1"):
         return r.strip()
   return ""


def parse_bimi(record: str) -> dict:
   result = {"logo_url": "", "authority_url": ""}
   for part in re.split(r";\s*", record):
      part = part.strip()
      kv = part.split("=", 1)
      if len(kv) != 2:
         continue
      key = kv[0].strip().lower()
      val = kv[1].strip()
      if key == "l":
         result["logo_url"] = val
      elif key == "a":
         result["authority_url"] = val
   return result


class BIMICheck(BaseCheck):
   name = "bimi"
   label = "BIMI"

   def run(self, domain: str, **kwargs) -> CheckResult:
      record = get_bimi_record(domain)
      if not record:
         logger.info(f"no BIMI record for {domain}")
         return CheckResult(
            name=self.name, label=self.label, score=0,
            reason="no_bimi",
            details={"record": "", "logo_url": "", "authority_url": ""},
         )

      parsed = parse_bimi(record)
      details = {"record": record, **parsed}

      if not parsed["logo_url"]:
         return CheckResult(
            name=self.name, label=self.label, score=1,
            reason="bimi_invalid", details=details,
         )

      if parsed["logo_url"] and parsed["authority_url"]:
         return CheckResult(
            name=self.name, label=self.label, score=3,
            reason="bimi_with_vmc", details=details,
         )

      return CheckResult(
         name=self.name, label=self.label, score=2,
         reason="bimi_no_vmc", details=details,
      )
