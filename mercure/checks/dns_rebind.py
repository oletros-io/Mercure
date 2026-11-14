import ipaddress

from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_a, query_aaaa
from .. import logger

PRIVATE_NETWORKS = [
   ipaddress.ip_network("10.0.0.0/8"),
   ipaddress.ip_network("172.16.0.0/12"),
   ipaddress.ip_network("192.168.0.0/16"),
   ipaddress.ip_network("127.0.0.0/8"),
   ipaddress.ip_network("169.254.0.0/16"),
   ipaddress.ip_network("100.64.0.0/10"),
   ipaddress.ip_network("0.0.0.0/8"),
   ipaddress.ip_network("::1/128"),
   ipaddress.ip_network("fc00::/7"),
   ipaddress.ip_network("fe80::/10"),
]

PROBE_PREFIXES = [
   "", "www", "mail", "ftp", "dev", "staging", "api",
   "vpn", "admin", "internal", "intranet", "test",
   "corp", "gateway", "proxy", "ns1", "ns2",
]


def _is_private(ip_str: str) -> str:
   try:
      addr = ipaddress.ip_address(ip_str)
   except ValueError:
      return ""
   for net in PRIVATE_NETWORKS:
      if addr in net:
         return str(net)
   return ""


class DNSRebindCheck(BaseCheck):
   name = "dns_rebind"
   label = "DNS-REBIND"

   def run(self, domain: str, **kwargs) -> CheckResult:
      private_records = []
      total_checked = 0
      domain_private = False

      for prefix in PROBE_PREFIXES:
         fqdn = f"{prefix}.{domain}" if prefix else domain
         ips = []
         try:
            ips.extend(query_a(fqdn))
         except Exception as exc:
            logger.debug(f"dns_rebind A query failed for {fqdn}: {exc}")
         try:
            ips.extend(query_aaaa(fqdn))
         except Exception as exc:
            logger.debug(f"dns_rebind AAAA query failed for {fqdn}: {exc}")

         if not ips:
            continue

         total_checked += 1

         for ip in ips:
            net = _is_private(ip)
            if net:
               private_records.append({"name": fqdn, "ip": ip, "network": net})
               if not prefix:
                  domain_private = True

      private_count = len(private_records)

      if domain_private:
         score = 0
         reason = "domain_private"
      elif private_count >= 3:
         score = 1
         reason = "many_private"
      elif private_count >= 1:
         score = 2
         reason = "some_private"
      else:
         score = 3
         reason = "all_public"

      return CheckResult(
         name=self.name,
         label=self.label,
         score=score,
         reason=reason,
         details={
            "private_records": private_records,
            "total_checked": total_checked,
            "private_count": private_count,
            "domain_private": domain_private,
         },
      )
