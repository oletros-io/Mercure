from checks.base import BaseCheck
from scoring import CheckResult
from dns_utils import query_ns
import logger


def _extract_provider(ns: str) -> str:
   parts = ns.lower().rstrip(".").split(".")
   if len(parts) >= 2:
      return ".".join(parts[-2:])
   return ns.lower()


class NSCheck(BaseCheck):
   name = "ns"
   label = "NS"
   weight = 1.5

   def run(self, domain: str, **kwargs) -> CheckResult:
      records = query_ns(domain)

      if not records:
         logger.warning(f"no NS record for {domain}")
         return CheckResult(
            name=self.name,
            label=self.label,
            score=3,
            reason="no_ns",
            details={"nameservers": []},
         )

      if len(records) == 1:
         return CheckResult(
            name=self.name,
            label=self.label,
            score=2,
            reason="single_ns",
            details={"nameservers": records},
         )

      providers = set(_extract_provider(ns) for ns in records)

      if len(providers) == 1:
         return CheckResult(
            name=self.name,
            label=self.label,
            score=1,
            reason="same_provider_ns",
            details={"nameservers": records, "providers": list(providers)},
         )

      return CheckResult(
         name=self.name,
         label=self.label,
         score=0,
         reason="ns_ok",
         details={"nameservers": records, "providers": list(providers)},
      )
