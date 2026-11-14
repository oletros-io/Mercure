from .base import BaseCheck
from ..scoring import CheckResult
from ..recon import crtsh_subdomains
from .. import logger


class CTCheck(BaseCheck):
   name = "ct"
   label = "CT"
   external = True

   def run(self, domain: str, **kwargs) -> CheckResult:
      subs = crtsh_subdomains(domain)

      wildcard_count = sum(1 for s in subs if s.startswith("*."))
      clean = [s.lstrip("*.") for s in subs]
      unique = sorted(set(clean))

      details = {
         "total_subdomains": len(unique),
         "sample": unique[:20],
         "wildcard_count": wildcard_count,
         "subdomains_discovered": unique,
      }

      if not unique:
         logger.warning(f"no CT records found for {domain}")
         return CheckResult(
            name=self.name, label=self.label,
            score=1, reason="no_ct_records", details=details,
         )

      logger.info(f"CT: {len(unique)} subdomains found for {domain}")
      return CheckResult(
         name=self.name, label=self.label,
         score=3, reason="ct_monitored", details=details,
      )
