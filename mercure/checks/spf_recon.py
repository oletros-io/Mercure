import ipaddress
import re
from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_txt, query_a
from .. import logger

ESP_PATTERNS = {
   "sendgrid": "SendGrid",
   "mailchimp": "Mailchimp",
   "mailgun": "Mailgun",
   "amazonses": "Amazon SES",
   "sparkpost": "SparkPost",
   "postmark": "Postmark",
   "brevo": "Brevo",
   "sendinblue": "Brevo",
   "hubspot": "HubSpot",
   "salesforce": "Salesforce",
   "zendesk": "Zendesk",
   "freshdesk": "Freshdesk",
   "google": "Google Workspace",
   "outlook": "Microsoft 365",
   "protection.outlook": "Microsoft 365",
   "pphosted": "Proofpoint",
   "mimecast": "Mimecast",
   "fireeyecloud": "FireEye",
   "barracuda": "Barracuda",
   "spf.mandrillapp": "Mandrill",
   "msgfocus": "Adestra",
   "cust-spf.exacttarget": "Salesforce MC",
   "mktomail": "Marketo",
   "servers.mcsv": "Mailchimp",
}

BROAD_IPV4_THRESHOLD = 20
BROAD_IPV6_THRESHOLD = 48
MAX_DEPTH = 10
MAX_INCLUDES = 20


def _get_spf(domain: str) -> str:
   for txt in query_txt(domain):
      stripped = txt.strip().strip('"')
      if stripped.lower().startswith("v=spf1"):
         return stripped
   return ""


def _ip_count(cidr: str) -> int:
   try:
      net = ipaddress.ip_network(cidr, strict=False)
      count = int(net.num_addresses)
      return min(count, 1_000_000)
   except ValueError:
      return 0


def _identify_providers(include_domains: list) -> list:
   found = set()
   for domain in include_domains:
      domain_lower = domain.lower()
      for pattern, provider in ESP_PATTERNS.items():
         if pattern in domain_lower:
            found.add(provider)
   return sorted(found)


def _walk_spf(domain: str, visited: set, tree: list, depth: int,
              ip4_ranges: list, ip6_ranges: list, include_domains: list) -> None:
   if depth > MAX_DEPTH or domain in visited or len(tree) >= MAX_INCLUDES:
      return

   visited.add(domain)
   spf = _get_spf(domain)
   if not spf:
      return

   tree.append({"domain": domain, "depth": depth, "spf": spf})
   tokens = spf.split()[1:]

   for token in tokens:
      token_clean = token.lstrip("+-~?")
      token_lower = token_clean.lower()

      if token_lower.startswith("ip4:"):
         cidr = token_clean.split(":", 1)[1]
         if "/" not in cidr:
            cidr += "/32"
         ip4_ranges.append(cidr)

      elif token_lower.startswith("ip6:"):
         cidr = token_clean.split(":", 1)[1]
         if "/" not in cidr:
            cidr += "/128"
         ip6_ranges.append(cidr)

      elif token_lower.startswith("include:"):
         target = token_clean.split(":", 1)[1]
         include_domains.append(target)
         _walk_spf(target, visited, tree, depth + 1,
                   ip4_ranges, ip6_ranges, include_domains)

      elif token_lower.startswith("redirect="):
         target = token_clean.split("=", 1)[1]
         include_domains.append(target)
         _walk_spf(target, visited, tree, depth + 1,
                   ip4_ranges, ip6_ranges, include_domains)


class SPFReconCheck(BaseCheck):
   name = "spf_recon"
   label = "SPF-RECON"

   def run(self, domain: str, **kwargs) -> CheckResult:
      spf_record = _get_spf(domain)
      if not spf_record:
         return CheckResult(
            name=self.name, label=self.label,
            score=0, reason="no_spf",
            details={
               "spf_record": "",
               "include_tree": [],
               "total_includes": 0,
               "max_depth": 0,
               "ip4_ranges": [],
               "ip6_ranges": [],
               "total_authorized_ips": 0,
               "broad_ranges": [],
               "identified_providers": [],
               "esps_count": 0,
            },
         )

      visited = set()
      tree = []
      ip4_ranges = []
      ip6_ranges = []
      include_domains = []

      _walk_spf(domain, visited, tree, 0, ip4_ranges, ip6_ranges, include_domains)

      total_includes = len(include_domains)
      max_depth = max((e["depth"] for e in tree), default=0)
      providers = _identify_providers(include_domains)
      esps_count = len(providers)

      total_ips = sum(_ip_count(r) for r in ip4_ranges)
      total_ips += sum(_ip_count(r) for r in ip6_ranges)

      broad_ranges = []
      for cidr in ip4_ranges:
         try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.prefixlen < BROAD_IPV4_THRESHOLD:
               broad_ranges.append({
                  "range": cidr,
                  "prefix_len": net.prefixlen,
                  "ip_count": int(net.num_addresses),
               })
         except ValueError:
            pass
      for cidr in ip6_ranges:
         try:
            net = ipaddress.ip_network(cidr, strict=False)
            if net.prefixlen < BROAD_IPV6_THRESHOLD:
               broad_ranges.append({
                  "range": cidr,
                  "prefix_len": net.prefixlen,
                  "ip_count": min(int(net.num_addresses), 1_000_000),
               })
         except ValueError:
            pass

      has_very_broad = any(
         r["prefix_len"] < 16 for r in broad_ranges
         if ":" not in r["range"]
      )

      details = {
         "spf_record": spf_record,
         "include_tree": tree,
         "total_includes": total_includes,
         "max_depth": max_depth,
         "ip4_ranges": ip4_ranges,
         "ip6_ranges": ip6_ranges,
         "total_authorized_ips": total_ips,
         "broad_ranges": broad_ranges,
         "identified_providers": providers,
         "esps_count": esps_count,
      }

      if total_includes > 10 or has_very_broad or esps_count >= 5:
         return CheckResult(
            name=self.name, label=self.label,
            score=0, reason="extremely_broad_spf",
            details=details,
         )

      if 5 <= total_includes <= 10 or len(broad_ranges) > 0 or 3 <= esps_count <= 4:
         return CheckResult(
            name=self.name, label=self.label,
            score=1, reason="broad_spf",
            details=details,
         )

      if 2 <= total_includes <= 4:
         return CheckResult(
            name=self.name, label=self.label,
            score=2, reason="moderate_spf",
            details=details,
         )

      return CheckResult(
         name=self.name, label=self.label,
         score=3, reason="tight_spf",
         details=details,
      )
