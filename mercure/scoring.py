from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional


@dataclass
class CheckResult:
   name: str
   label: str
   score: int
   reason: str
   details: Dict[str, Any] = field(default_factory=dict)
   value: Optional[str] = None


WEIGHTS = {
   "ghost": 4.0,
   "dmarc": 3.5,
   "dangling": 3.0,
   "spf": 3.0,
   "dkim": 2.5,
   "axfr": 2.0,
   "tls": 2.0,
   "smtp_sec": 2.0,
   "bounce": 2.0,
   "dnssec": 1.5,
   "caa": 1.5,
   "mta_sts": 1.5,
   "seg": 1.5,
   "subdomains": 1.5,
   "m365": 1.0,
   "ct": 1.0,
   "hsts": 1.0,
   "headers": 1.0,
   "dnsbl": 1.0,
   "open_ports": 1.0,
   "mx": 1.0,
   "ns": 1.0,
   "whois": 0.5,
   "soa": 0.5,
   "wildcard": 0.5,
   "tls_rpt": 0.5,
   "redirect": 0.5,
   "cookie": 0.5,
   "spf_depth": 0.5,
   "rpki": 0.5,
   "zone_consistency": 0.5,
   "tlsa": 0.5,
   "ptr": 0.5,
   "cname": 0.25,
   "bimi": 0.25,
   "security_txt": 0.25,
   "srv": 0.25,
   "ipv6": 0.25,
   "smtp_recon": 2.0,
   "smtp_enum": 1.5,
   "smtp_tls_strip": 1.5,
   "nsec_walk": 1.5,
   "dns_rebind": 1.0,
   "subdomain_brute": 1.0,
   "autodiscover": 1.0,
   "spf_recon": 0.5,
   "nuclei": 2.0,
   "katana": 0.5,
}


EXPLOIT_WEIGHTS = {
   "ghost": 5.0,
   "smtp_sec": 5.0,
   "nuclei": 5.0,
   "dmarc": 4.5,
   "dangling": 4.5,
   "spf": 4.0,
   "axfr": 4.0,
   "bounce": 4.0,
   "smtp_enum": 4.0,
   "dkim": 3.5,
   "smtp_recon": 3.0,
   "smtp_tls_strip": 3.0,
   "nsec_walk": 3.0,
   "dns_rebind": 3.0,
   "open_ports": 3.0,
   "mta_sts": 2.5,
   "tls": 2.5,
   "hsts": 2.5,
   "redirect": 2.5,
   "cookie": 2.5,
   "autodiscover": 2.5,
   "headers": 2.0,
   "subdomains": 2.0,
   "subdomain_brute": 2.0,
   "seg": 2.0,
   "m365": 2.0,
   "dnsbl": 2.0,
   "dmarc_ext": 1.5,
   "spf_depth": 2.0,
   "katana": 2.0,
   "spf_recon": 1.5,
   "dnssec": 1.5,
   "ct": 1.5,
   "mx": 1.5,
   "ns": 1.0,
   "wildcard": 1.0,
   "whois": 1.0,
   "rpki": 1.0,
   "soa": 0.5,
   "zone_consistency": 0.5,
   "tls_rpt": 0.5,
   "caa": 0.5,
   "tlsa": 0.5,
   "ptr": 0.5,
   "cname": 0.5,
   "bimi": 0.5,
   "srv": 0.5,
   "security_txt": 0.5,
   "ipv6": 0.25,
}


def score_to_ten(raw: int) -> int:
   return round(raw * 10 / 3)


def compute_global_score(results: List[CheckResult]) -> float:
   if not results:
      return 0.0
   total_weight = 0.0
   weighted_sum = 0.0
   for r in results:
      w = WEIGHTS.get(r.name, 1.0)
      weighted_sum += r.score * w
      total_weight += w
   if total_weight == 0:
      return 0.0
   raw = weighted_sum / total_weight
   return round(raw / 3.0 * 10.0, 1)


def compute_exploitability_score(results: List[CheckResult]) -> float:
   if not results:
      return 0.0
   total_weight = 0.0
   weighted_sum = 0.0
   for r in results:
      w = EXPLOIT_WEIGHTS.get(r.name, 1.0)
      weighted_sum += (3 - r.score) * w
      total_weight += w
   if total_weight == 0:
      return 0.0
   raw = weighted_sum / total_weight
   return round(raw / 3.0 * 10.0, 1)


def global_score_style(score: float) -> str:
   if score >= 7.0:
      return "green"
   if score >= 4.0:
      return "orange1"
   return "red"


def exploit_score_style(score: float) -> str:
   if score >= 7.0:
      return "red"
   if score >= 4.0:
      return "orange1"
   return "green"
