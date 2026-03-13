import re
from typing import Dict, Optional

from checks.base import BaseCheck
from scoring import CheckResult
from dns_utils import query_txt
import logger


def get_spf(domain: str) -> Optional[str]:
   txts = query_txt(domain)
   for t in txts:
      if "v=spf1" in t.lower():
         return t.strip().strip('"')
   logger.warning(f"no SPF record for {domain}")
   return None


def evaluate_spf(spf_txt: Optional[str]) -> Dict:
   if not spf_txt:
      return {"score": 0, "reason": "no_spf", "value": None}

   spf = spf_txt.lower()

   if "+all" in spf or " all +all" in spf:
      return {"score": 0, "reason": "allow_all_plus", "value": spf_txt}

   if "include:all" in spf:
      return {"score": 1, "reason": "include_all", "value": spf_txt}

   if re.search(r"(^|\s)-all\b", spf):
      return {"score": 3, "reason": "hard_fail", "value": spf_txt}

   if re.search(r"(^|\s)~all\b", spf):
      return {"score": 2, "reason": "soft_fail", "value": spf_txt}

   if re.search(r"(^|\s)\?all\b", spf):
      return {"score": 1, "reason": "neutral_all", "value": spf_txt}

   return {"score": 1, "reason": "unknown_policy", "value": spf_txt}


class SPFCheck(BaseCheck):
   name = "spf"
   label = "SPF"
   weight = 3.0

   def run(self, domain: str, **kwargs) -> CheckResult:
      spf_txt = get_spf(domain)
      result = evaluate_spf(spf_txt)
      return CheckResult(
         name=self.name,
         label=self.label,
         score=result["score"],
         reason=result["reason"],
         value=result.get("value"),
         details={"raw": spf_txt},
      )
