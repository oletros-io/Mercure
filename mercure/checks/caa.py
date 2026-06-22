from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_caa
from .. import logger


class CAACheck(BaseCheck):
   name = "caa"
   label = "CAA"
   weight = 2.0

   def run(self, domain: str, **kwargs) -> CheckResult:
      records = query_caa(domain)

      if not records:
         logger.warning(f"no CAA record for {domain}")
         return CheckResult(
            name=self.name,
            label=self.label,
            score=0,
            reason="no_caa",
            details={"records": []},
         )

      tags = [r["tag"].lower() for r in records]

      has_issue = "issue" in tags
      has_issuewild = "issuewild" in tags
      has_iodef = "iodef" in tags

      if has_issue:
         issue_values = [r["value"] for r in records if r["tag"].lower() == "issue"]
         all_restricted = all(v.strip() and v.strip() != ";" for v in issue_values)

         if all_restricted:
            return CheckResult(
               name=self.name,
               label=self.label,
               score=3,
               reason="caa_restricted",
               details={"records": records, "has_issuewild": has_issuewild, "has_iodef": has_iodef},
            )

         return CheckResult(
            name=self.name,
            label=self.label,
            score=2,
            reason="caa_permissive_issue",
            details={"records": records},
         )

      return CheckResult(
         name=self.name,
         label=self.label,
         score=1,
         reason="caa_no_issue_tag",
         details={"records": records},
      )
