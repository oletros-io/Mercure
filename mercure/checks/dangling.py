from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_a, resolve_cname_chain
from ..recon import crtsh_subdomains
from .. import logger

TAKEOVER_PATTERNS = {
   "s3.amazonaws.com": "aws_s3",
   "s3-website": "aws_s3",
   "elasticbeanstalk.com": "aws_eb",
   "cloudfront.net": "aws_cloudfront",
   "azurewebsites.net": "azure_app_service",
   "azurefd.net": "azure_front_door",
   "blob.core.windows.net": "azure_blob",
   "cloudapp.azure.com": "azure_vm",
   "trafficmanager.net": "azure_tm",
   "github.io": "github_pages",
   "herokuapp.com": "heroku",
   "herokudns.com": "heroku",
   "netlify.app": "netlify",
   "netlify.com": "netlify",
   "vercel-dns.com": "vercel",
   "now.sh": "vercel",
   "pantheonsite.io": "pantheon",
   "shopify.com": "shopify",
   "myshopify.com": "shopify",
   "zendesk.com": "zendesk",
   "ghost.io": "ghost",
   "surge.sh": "surge",
   "fly.dev": "fly",
   "fastly.net": "fastly",
   "tumblr.com": "tumblr",
   "cargocollective.com": "cargo",
   "unbouncepages.com": "unbounce",
   "helpjuice.com": "helpjuice",
   "helpscoutdocs.com": "helpscout",
   "freshdesk.com": "freshdesk",
   "bigcartel.com": "bigcartel",
}


def _match_takeover(cname_target: str) -> str:
   target_lower = cname_target.lower()
   for pattern, service in TAKEOVER_PATTERNS.items():
      if pattern in target_lower:
         return service
   return ""


class DanglingCheck(BaseCheck):
   name = "dangling"
   label = "DANGLING"
   external = True

   def run(self, domain: str, **kwargs) -> CheckResult:
      subs = crtsh_subdomains(domain)

      if not subs:
         return CheckResult(
            name=self.name, label=self.label,
            score=2, reason="enumeration_limited",
            details={"total_checked": 0, "dangling": []},
         )

      dangling = []
      takeover_found = False

      for sub in subs[:100]:
         chain = resolve_cname_chain(sub)
         if not chain:
            continue
         final_target = chain[-1]
         ips = query_a(final_target)
         if ips:
            continue

         service = _match_takeover(final_target)
         entry = {
            "subdomain": sub,
            "cname_target": final_target,
            "cname_chain": chain,
            "service": service,
            "takeover_risk": bool(service),
         }
         dangling.append(entry)
         if service:
            takeover_found = True
            logger.warning(f"dangling CNAME takeover risk: {sub} -> {final_target} ({service})")
         else:
            logger.info(f"dangling CNAME: {sub} -> {final_target}")

      details = {
         "total_checked": min(len(subs), 100),
         "dangling": dangling,
      }

      if takeover_found:
         return CheckResult(
            name=self.name, label=self.label,
            score=0, reason="subdomain_takeover_possible",
            details=details,
         )

      if dangling:
         return CheckResult(
            name=self.name, label=self.label,
            score=1, reason="dangling_cname_found",
            details=details,
         )

      return CheckResult(
         name=self.name, label=self.label,
         score=3, reason="no_dangling",
         details=details,
      )
