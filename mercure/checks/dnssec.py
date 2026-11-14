from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_ds, query_dnskey
from .. import logger


class DNSSECCheck(BaseCheck):
   name = "dnssec"
   label = "DNSSEC"

   def run(self, domain: str, **kwargs) -> CheckResult:
      ds_records = query_ds(domain)
      dnskey_records = query_dnskey(domain)

      has_ds = len(ds_records) > 0
      has_dnskey = len(dnskey_records) > 0

      if has_ds and has_dnskey:
         return CheckResult(
            name=self.name,
            label=self.label,
            score=3,
            reason="dnssec_valid",
            details={"ds": ds_records, "dnskey": dnskey_records},
         )

      if has_dnskey and not has_ds:
         logger.warning(f"DNSKEY present but no DS for {domain}")
         return CheckResult(
            name=self.name,
            label=self.label,
            score=2,
            reason="dnskey_no_ds",
            details={"ds": ds_records, "dnskey": dnskey_records},
         )

      if has_ds and not has_dnskey:
         logger.warning(f"DS present but no DNSKEY for {domain}")
         return CheckResult(
            name=self.name,
            label=self.label,
            score=1,
            reason="ds_no_dnskey",
            details={"ds": ds_records, "dnskey": dnskey_records},
         )

      return CheckResult(
         name=self.name,
         label=self.label,
         score=0,
         reason="no_dnssec",
         details={"ds": [], "dnskey": []},
      )
