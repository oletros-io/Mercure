import re
from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_txt
from .. import logger

LOOKUP_MECHS = re.compile(r"^(include|a|mx|ptr|exists|redirect)[:=]?", re.IGNORECASE)


def _get_spf(domain: str) -> str:
   for txt in query_txt(domain):
      stripped = txt.strip().strip('"')
      if stripped.lower().startswith("v=spf1"):
         return stripped
   return ""


def _count_lookups(domain: str, visited: set, chain: list, depth: int = 0) -> int:
   if depth > 10 or domain in visited:
      return 0
   visited.add(domain)

   spf = _get_spf(domain)
   if not spf:
      return 0

   total = 0
   tokens = spf.split()[1:]

   for token in tokens:
      token_lower = token.lower().lstrip("+-~?")

      if token_lower.startswith("ip4:") or token_lower.startswith("ip6:"):
         continue

      if token_lower.startswith("include:"):
         target = token.split(":", 1)[1]
         chain.append(target)
         total += 1 + _count_lookups(target, visited, chain, depth + 1)

      elif token_lower.startswith("redirect="):
         target = token.split("=", 1)[1]
         chain.append(target)
         total += 1 + _count_lookups(target, visited, chain, depth + 1)

      elif token_lower.startswith(("a:", "a/")):
         total += 1
      elif token_lower == "a":
         total += 1
      elif token_lower.startswith(("mx:", "mx/")):
         total += 1
      elif token_lower == "mx":
         total += 1
      elif token_lower.startswith("ptr"):
         total += 1
      elif token_lower.startswith("exists:"):
         total += 1

   return total


class SPFDepthCheck(BaseCheck):
   name = "spf_depth"
   label = "SPF-DEPTH"

   def run(self, domain: str, **kwargs) -> CheckResult:
      spf = _get_spf(domain)
      if not spf:
         return CheckResult(
            name=self.name, label=self.label,
            score=0, reason="no_spf",
            details={"total_lookups": 0, "include_chain": [], "depth_reached": 0},
         )

      visited = set()
      chain = []
      total = _count_lookups(domain, visited, chain)

      details = {
         "total_lookups": total,
         "include_chain": chain,
         "depth_reached": len(visited),
      }

      if total > 10:
         logger.warning(f"SPF permerror: {total} lookups for {domain}")
         return CheckResult(
            name=self.name, label=self.label,
            score=0, reason="spf_permerror",
            details=details,
         )

      if total >= 8:
         return CheckResult(
            name=self.name, label=self.label,
            score=1, reason="spf_near_limit",
            details=details,
         )

      return CheckResult(
         name=self.name, label=self.label,
         score=3, reason="spf_depth_ok",
         details=details,
      )
