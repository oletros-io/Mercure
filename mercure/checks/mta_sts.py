import re

from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_txt
from ..http_utils import fetch
from .. import logger


def get_mta_sts_record(domain: str) -> str:
   records = query_txt(f"_mta-sts.{domain}")
   for r in records:
      if r.strip().lower().startswith("v=stsv1"):
         return r.strip()
   return ""


def parse_policy(text: str) -> dict:
   policy = {"mode": "", "mx_patterns": [], "max_age": 0}
   for line in text.splitlines():
      line = line.strip()
      if line.startswith("mode:"):
         policy["mode"] = line.split(":", 1)[1].strip().lower()
      elif line.startswith("mx:"):
         policy["mx_patterns"].append(line.split(":", 1)[1].strip())
      elif line.startswith("max_age:"):
         try:
            policy["max_age"] = int(line.split(":", 1)[1].strip())
         except ValueError:
            pass
   return policy


class MTASTSCheck(BaseCheck):
   name = "mta_sts"
   label = "MTA-STS"

   def run(self, domain: str, **kwargs) -> CheckResult:
      txt_record = get_mta_sts_record(domain)
      if not txt_record:
         logger.info(f"no MTA-STS record for {domain}")
         return CheckResult(
            name=self.name, label=self.label, score=0,
            reason="no_mta_sts",
            details={"txt_record": "", "mode": "", "mx_patterns": [], "max_age": 0},
         )

      resp = fetch(f"https://mta-sts.{domain}/.well-known/mta-sts.txt")
      if resp is None or resp.status_code != 200:
         return CheckResult(
            name=self.name, label=self.label, score=1,
            reason="none_or_invalid",
            details={"txt_record": txt_record, "mode": "", "mx_patterns": [], "max_age": 0},
         )

      policy = parse_policy(resp.text)
      details = {"txt_record": txt_record, **policy}

      if policy["mode"] == "enforce" and policy["max_age"] >= 86400:
         return CheckResult(
            name=self.name, label=self.label, score=3,
            reason="enforce", details=details,
         )

      if policy["mode"] == "testing":
         return CheckResult(
            name=self.name, label=self.label, score=2,
            reason="testing_mode", details=details,
         )

      return CheckResult(
         name=self.name, label=self.label, score=1,
         reason="none_or_invalid", details=details,
      )
