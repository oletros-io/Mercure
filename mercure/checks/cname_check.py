from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import resolve_cname_chain, query_cname, query_mx


class CNAMECheck(BaseCheck):
   name = "cname"
   label = "CNAME"

   def run(self, domain: str, **kwargs) -> CheckResult:
      chain = resolve_cname_chain(domain)
      has_cname = len(chain) > 0
      has_mx = len(query_mx(domain)) > 0
      details = {"chain": chain, "chain_length": len(chain)}

      if has_cname and has_mx:
         return CheckResult(
            name=self.name, label=self.label,
            score=1, reason="cname_mx_coexistence",
            details=details,
         )

      if has_cname:
         if len(chain) > 3:
            return CheckResult(
               name=self.name, label=self.label,
               score=1, reason="cname_chain_too_long",
               details=details,
            )
         return CheckResult(
            name=self.name, label=self.label,
            score=1, reason="cname_on_apex",
            details=details,
         )

      return CheckResult(
         name=self.name, label=self.label,
         score=3, reason="cname_ok",
         details=details,
      )
