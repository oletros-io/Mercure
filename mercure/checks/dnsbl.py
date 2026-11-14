from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_a, query_dnsbl

BLACKLISTS = [
   "zen.spamhaus.org",
   "bl.spamcop.net",
   "b.barracudacentral.org",
   "dnsbl.sorbs.net",
]


class DNSBLCheck(BaseCheck):
   name = "dnsbl"
   label = "DNSBL"

   def run(self, domain: str, **kwargs) -> CheckResult:
      ips = query_a(domain)
      if not ips:
         return CheckResult(
            name=self.name, label=self.label,
            score=2, reason="no_a_record",
            details={},
         )

      listed = {}
      for ip in ips:
         hits = []
         for bl in BLACKLISTS:
            if query_dnsbl(ip, bl):
               hits.append(bl)
         if hits:
            listed[ip] = hits

      details = {"checked_ips": ips, "listed": listed}

      if listed:
         return CheckResult(
            name=self.name, label=self.label,
            score=0, reason="blacklisted",
            details=details,
         )

      return CheckResult(
         name=self.name, label=self.label,
         score=3, reason="clean",
         details=details,
      )
