from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_a, query_ptr
from .. import logger


def _domain_matches_ptr(domain: str, ptr: str) -> bool:
   d = domain.lower().rstrip(".")
   p = ptr.lower().rstrip(".")
   return p == d or p.endswith(f".{d}")


class PTRCheck(BaseCheck):
   name = "ptr"
   label = "PTR"

   def run(self, domain: str, **kwargs) -> CheckResult:
      a_records = query_a(domain)

      if not a_records:
         logger.warning(f"no A record for {domain}, skipping PTR check")
         return CheckResult(
            name=self.name,
            label=self.label,
            score=0,
            reason="no_a_record",
            details={"a_records": [], "ptr_results": {}},
         )

      ptr_results = {}
      for ip in a_records:
         ptrs = query_ptr(ip)
         ptr_results[ip] = ptrs

      ips_with_ptr = {ip: ptrs for ip, ptrs in ptr_results.items() if ptrs}
      ips_without_ptr = [ip for ip, ptrs in ptr_results.items() if not ptrs]

      if not ips_with_ptr:
         return CheckResult(
            name=self.name,
            label=self.label,
            score=0,
            reason="no_ptr",
            details={"a_records": a_records, "ptr_results": ptr_results},
         )

      if ips_without_ptr:
         return CheckResult(
            name=self.name,
            label=self.label,
            score=1,
            reason="partial_ptr",
            details={"a_records": a_records, "ptr_results": ptr_results, "missing": ips_without_ptr},
         )

      matching = any(
         any(_domain_matches_ptr(domain, ptr) for ptr in ptrs)
         for ptrs in ips_with_ptr.values()
      )

      if matching:
         return CheckResult(
            name=self.name,
            label=self.label,
            score=3,
            reason="ptr_match",
            details={"a_records": a_records, "ptr_results": ptr_results},
         )

      return CheckResult(
         name=self.name,
         label=self.label,
         score=2,
         reason="ptr_no_match",
         details={"a_records": a_records, "ptr_results": ptr_results},
      )
