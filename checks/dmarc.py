import re
from typing import Dict, Optional

from checks.base import BaseCheck
from scoring import CheckResult
from dns_utils import query_txt
import logger


def get_dmarc(domain: str) -> Optional[str]:
   dname = f"_dmarc.{domain}"
   txts = query_txt(dname)
   for t in txts:
      if "v=dmarc1" in t.lower():
         return t.strip().strip('"')
   logger.warning(f"no DMARC record for {domain}")
   return None


def parse_dmarc(dmarc_txt: Optional[str]) -> Dict:
   if not dmarc_txt:
      return {"score": 3, "policy": "missing", "reason": "no_dmarc", "value": None}

   parts = {
      p.split("=")[0].strip(): "=".join(p.split("=")[1:]).strip()
      for p in re.split(r";\s*", dmarc_txt) if "=" in p
   }
   policy = parts.get("p", "").lower()
   pct = int(parts.get("pct", "100")) if parts.get("pct") and parts.get("pct").isdigit() else 100
   rua = parts.get("rua", "")
   ruf = parts.get("ruf", "")

   base = {"policy": policy, "pct": pct, "rua": rua, "ruf": ruf, "value": dmarc_txt}

   if policy == "reject":
      if pct < 100:
         return {"score": 1, "reason": "reject_partial_pct", **base}
      return {"score": 0, "reason": "reject_full", **base}

   if policy == "quarantine":
      return {"score": 1, "reason": "quarantine", **base}

   if policy == "none":
      return {"score": 2, "reason": "none_policy", **base}

   return {"score": 2, "reason": "unknown_policy", **base}


class DMARCCheck(BaseCheck):
   name = "dmarc"
   label = "DMARC"
   weight = 3.0

   def run(self, domain: str, **kwargs) -> CheckResult:
      dmarc_txt = get_dmarc(domain)
      result = parse_dmarc(dmarc_txt)
      return CheckResult(
         name=self.name,
         label=self.label,
         score=result["score"],
         reason=result["reason"],
         value=result.get("value"),
         details={
            "policy": result.get("policy"),
            "pct": result.get("pct"),
            "rua": result.get("rua"),
            "ruf": result.get("ruf"),
         },
      )
