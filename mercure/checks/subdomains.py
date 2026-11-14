import shutil
import subprocess

from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_a
from ..recon import crtsh_subdomains
from .. import logger

SENSITIVE_KEYWORDS = ("dev", "staging", "test", "admin", "internal", "vpn", "api", "beta")


def _subfinder_subdomains(domain: str) -> list[str]:
   if not shutil.which("subfinder"):
      return []
   try:
      proc = subprocess.run(
         ["subfinder", "-d", domain, "-silent"],
         capture_output=True, text=True, timeout=120,
      )
      return [
         line.strip() for line in proc.stdout.strip().split("\n")
         if line.strip()
      ]
   except (subprocess.TimeoutExpired, OSError):
      return []


class SubdomainsCheck(BaseCheck):
   name = "subdomains"
   label = "SUBDOMAINS"
   external = True

   def run(self, domain: str, **kwargs) -> CheckResult:
      crt_subs = crtsh_subdomains(domain)
      sf_subs = _subfinder_subdomains(domain)

      if sf_subs:
         subs = sorted(set(crt_subs) | set(sf_subs))
         source = "subfinder+crtsh"
      else:
         subs = crt_subs
         source = "crtsh"

      if not subs:
         return CheckResult(
            name=self.name, label=self.label,
            score=2, reason="no_ct_data",
            details={"total_discovered": 0, "resolving": 0, "sensitive": [], "sample": [], "source": source},
         )

      resolving = []
      for sub in subs[:200]:
         ips = query_a(sub)
         if ips:
            resolving.append(sub)

      sensitive = [
         s for s in resolving
         if any(kw in s.split(".")[0] for kw in SENSITIVE_KEYWORDS)
      ]

      details = {
         "total_discovered": len(subs),
         "resolving": len(resolving),
         "sensitive": sensitive[:10],
         "sample": subs[:20],
         "source": source,
      }

      if len(sensitive) >= 3:
         logger.warning(f"{len(sensitive)} sensitive subdomains exposed on {domain}")
         return CheckResult(
            name=self.name, label=self.label,
            score=1, reason="sensitive_subdomains_exposed",
            details=details,
         )

      if len(subs) < 5:
         return CheckResult(
            name=self.name, label=self.label,
            score=3, reason="minimal_surface",
            details=details,
         )

      return CheckResult(
         name=self.name, label=self.label,
         score=2, reason="normal_surface",
         details=details,
      )
