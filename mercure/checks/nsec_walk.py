import secrets

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype

from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_ns, resolve_ipv4
from .. import logger


class NSECWalkCheck(BaseCheck):
   name = "nsec_walk"
   label = "NSEC-WALK"
   intrusive = True

   def run(self, domain: str, **kwargs) -> CheckResult:
      nameservers = query_ns(domain)
      if not nameservers:
         return CheckResult(
            name=self.name,
            label=self.label,
            score=2,
            reason="no_ns",
            details={"nsec_type": "none", "walkable": False, "discovered_names": [], "nsec3_params": None, "names_found": 0},
         )

      ns_ip = resolve_ipv4(nameservers[0])

      probe_name = f"{secrets.token_hex(8)}.{domain}"
      try:
         request = dns.message.make_query(probe_name, "A")
         request.flags |= dns.flags.AD
         request.use_edns(edns=0, ednsflags=dns.flags.DO)
         response = dns.query.udp(request, ns_ip, timeout=5)
      except Exception as exc:
         logger.debug(f"nsec_walk probe failed for {domain}: {exc}")
         return CheckResult(
            name=self.name,
            label=self.label,
            score=2,
            reason="probe_failed",
            details={"nsec_type": "none", "walkable": False, "discovered_names": [], "nsec3_params": None, "names_found": 0},
         )

      nsec_found = False
      nsec3_found = False
      nsec3_params = None

      for rrset in response.authority:
         if rrset.rdtype == dns.rdatatype.NSEC:
            nsec_found = True
         elif rrset.rdtype == dns.rdatatype.NSEC3:
            nsec3_found = True
            for rr in rrset:
               nsec3_params = {
                  "algorithm": rr.algorithm,
                  "iterations": rr.iterations,
                  "salt_length": len(rr.salt) if rr.salt else 0,
               }

      if nsec_found:
         discovered = self._walk_nsec(domain, ns_ip)
         walkable = len(discovered) > 0
         score = 0 if walkable else 1
         reason = "nsec_walkable" if walkable else "nsec_no_names"
         return CheckResult(
            name=self.name,
            label=self.label,
            score=score,
            reason=reason,
            details={
               "nsec_type": "nsec",
               "walkable": walkable,
               "discovered_names": discovered,
               "nsec3_params": None,
               "names_found": len(discovered),
            },
         )

      if nsec3_found and nsec3_params:
         score = self._score_nsec3(nsec3_params)
         return CheckResult(
            name=self.name,
            label=self.label,
            score=score,
            reason="nsec3",
            details={
               "nsec_type": "nsec3",
               "walkable": False,
               "discovered_names": [],
               "nsec3_params": nsec3_params,
               "names_found": 0,
            },
         )

      return CheckResult(
         name=self.name,
         label=self.label,
         score=2,
         reason="no_nsec",
         details={"nsec_type": "none", "walkable": False, "discovered_names": [], "nsec3_params": None, "names_found": 0},
      )

   def _walk_nsec(self, domain: str, ns_ip: str) -> list:
      discovered = []
      current = domain
      for _ in range(50):
         try:
            request = dns.message.make_query(current, "NSEC")
            request.use_edns(edns=0, ednsflags=dns.flags.DO)
            resp = dns.query.udp(request, ns_ip, timeout=5)
         except Exception:
            break
         found_nsec = False
         for rrset in resp.authority:
            if rrset.rdtype == dns.rdatatype.NSEC:
               for rr in rrset:
                  next_name = str(rr.next).rstrip(".")
                  if next_name not in discovered and next_name != domain:
                     discovered.append(next_name)
                     current = next_name
                     found_nsec = True
         if not found_nsec:
            break
      return discovered

   def _score_nsec3(self, params: dict) -> int:
      algo = params.get("algorithm", 0)
      iterations = params.get("iterations", 0)
      salt_len = params.get("salt_length", 0)

      if algo == 1 and iterations < 10 and salt_len == 0:
         return 1
      if iterations >= 100 and salt_len > 0:
         return 3
      return 2
