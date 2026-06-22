from typing import List

import dns.resolver
import dns.reversename

from .config import config
from . import logger


def _resolve(name: str, rdtype: str, timeout: float = None) -> list:
   timeout = timeout or config.dns_timeout
   try:
      return list(dns.resolver.resolve(name, rdtype, lifetime=timeout))
   except Exception as exc:
      logger.debug(f"dns query {rdtype} {name} failed: {exc}")
      return []


def query_txt(name: str) -> List[str]:
   answers = _resolve(name, "TXT")
   out = []
   for rr in answers:
      if hasattr(rr, "strings"):
         s = "".join(b.decode() if isinstance(b, bytes) else b for b in rr.strings)
      else:
         s = str(rr)
      out.append(s)
   return out


def query_a(name: str) -> List[str]:
   return [str(rr.address) for rr in _resolve(name, "A")]


def query_aaaa(name: str) -> List[str]:
   return [str(rr.address) for rr in _resolve(name, "AAAA")]


def query_mx(name: str) -> list:
   return [(rr.preference, str(rr.exchange).rstrip(".")) for rr in _resolve(name, "MX")]


def query_ns(name: str) -> List[str]:
   return [str(rr.target).rstrip(".") for rr in _resolve(name, "NS")]


def query_caa(name: str) -> list:
   results = []
   for rr in _resolve(name, "CAA"):
      results.append({
         "flags": rr.flags,
         "tag": rr.tag.decode() if isinstance(rr.tag, bytes) else str(rr.tag),
         "value": rr.value.decode() if isinstance(rr.value, bytes) else str(rr.value),
      })
   return results


def query_srv(name: str) -> list:
   results = []
   for rr in _resolve(name, "SRV"):
      results.append({
         "priority": rr.priority,
         "weight": rr.weight,
         "port": rr.port,
         "target": str(rr.target).rstrip("."),
      })
   return results


def query_ds(name: str) -> list:
   results = []
   for rr in _resolve(name, "DS"):
      results.append({
         "key_tag": rr.key_tag,
         "algorithm": rr.algorithm,
         "digest_type": rr.digest_type,
      })
   return results


def query_dnskey(name: str) -> list:
   results = []
   for rr in _resolve(name, "DNSKEY"):
      results.append({
         "flags": rr.flags,
         "protocol": rr.protocol,
         "algorithm": rr.algorithm,
      })
   return results


def query_tlsa(name: str) -> list:
   results = []
   for rr in _resolve(name, "TLSA"):
      results.append({
         "usage": rr.usage,
         "selector": rr.selector,
         "mtype": rr.mtype,
      })
   return results


def query_ptr(ip: str) -> List[str]:
   try:
      rev_name = dns.reversename.from_address(ip)
      answers = _resolve(str(rev_name), "PTR")
      return [str(rr.target).rstrip(".") for rr in answers]
   except Exception as exc:
      logger.debug(f"ptr lookup failed for {ip}: {exc}")
      return []


def query_cname(name: str) -> List[str]:
   return [str(rr.target).rstrip(".") for rr in _resolve(name, "CNAME")]
