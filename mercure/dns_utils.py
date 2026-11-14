import socket
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

import dns.query
import dns.resolver
import dns.reversename
import dns.zone

from .config import config
from . import logger


class DnsError(Enum):
   NONE = "none"
   NXDOMAIN = "nxdomain"
   NO_ANSWER = "no_answer"
   TIMEOUT = "timeout"
   SERVFAIL = "servfail"
   OTHER = "other"


@dataclass
class DnsResult:
   records: list = field(default_factory=list)
   error: DnsError = DnsError.NONE

   def __bool__(self):
      return len(self.records) > 0

   def __iter__(self):
      return iter(self.records)

   def __len__(self):
      return len(self.records)


class _DnsCache:
   def __init__(self):
      self._store = {}
      self._lock = threading.Lock()

   def get(self, key: str) -> Optional[list]:
      with self._lock:
         entry = self._store.get(key)
         if entry is None:
            return None
         records, ts = entry
         if time.monotonic() - ts > config.dns_cache_ttl:
            del self._store[key]
            return None
         return records

   def put(self, key: str, records: list):
      with self._lock:
         self._store[key] = (records, time.monotonic())

   def clear(self):
      with self._lock:
         self._store.clear()


_cache = _DnsCache()


def clear_cache():
   _cache.clear()


def _resolve(name: str, rdtype: str, timeout: float = None) -> DnsResult:
   timeout = timeout or config.dns_timeout
   cache_key = f"{name}|{rdtype}"

   cached = _cache.get(cache_key)
   if cached is not None:
      return DnsResult(records=cached)

   try:
      records = list(dns.resolver.resolve(name, rdtype, lifetime=timeout))
      _cache.put(cache_key, records)
      return DnsResult(records=records)
   except dns.resolver.NXDOMAIN:
      logger.debug(f"dns {rdtype} {name}: NXDOMAIN")
      _cache.put(cache_key, [])
      return DnsResult(error=DnsError.NXDOMAIN)
   except dns.resolver.NoAnswer:
      logger.debug(f"dns {rdtype} {name}: no answer")
      _cache.put(cache_key, [])
      return DnsResult(error=DnsError.NO_ANSWER)
   except dns.resolver.LifetimeTimeout:
      logger.debug(f"dns {rdtype} {name}: timeout")
      return DnsResult(error=DnsError.TIMEOUT)
   except dns.resolver.NoNameservers:
      logger.debug(f"dns {rdtype} {name}: SERVFAIL")
      return DnsResult(error=DnsError.SERVFAIL)
   except Exception as exc:
      logger.debug(f"dns {rdtype} {name}: {exc}")
      return DnsResult(error=DnsError.OTHER)


def query_txt(name: str) -> List[str]:
   result = _resolve(name, "TXT")
   out = []
   for rr in result:
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
      return [str(rr.target).rstrip(".") for rr in _resolve(str(rev_name), "PTR")]
   except Exception as exc:
      logger.debug(f"ptr lookup failed for {ip}: {exc}")
      return []


def query_cname(name: str) -> List[str]:
   return [str(rr.target).rstrip(".") for rr in _resolve(name, "CNAME")]


def query_soa(domain: str) -> dict:
   result = _resolve(domain, "SOA")
   if not result:
      return {}
   rr = result.records[0]
   return {
      "mname": str(rr.mname).rstrip("."),
      "rname": str(rr.rname).rstrip("."),
      "serial": rr.serial,
      "refresh": rr.refresh,
      "retry": rr.retry,
      "expire": rr.expire,
      "minimum": rr.minimum,
   }


def attempt_axfr(domain: str, nameserver: str) -> list:
   try:
      ip = resolve_ipv4(nameserver)
      xfr = dns.query.xfr(ip, domain, timeout=config.dns_timeout)
      zone = dns.zone.from_xfr(xfr)
      return sorted(str(name) for name in zone.nodes.keys())
   except Exception as exc:
      logger.debug(f"axfr {domain} @{nameserver}: {exc}")
      return []


def resolve_cname_chain(domain: str, max_depth: int = 10) -> list:
   chain = []
   current = domain
   for _ in range(max_depth):
      result = _resolve(current, "CNAME")
      if not result:
         break
      target = str(result.records[0].target).rstrip(".")
      chain.append(target)
      current = target
   return chain


def query_dnsbl(ip: str, blacklist: str = "zen.spamhaus.org") -> bool:
   parts = ip.split(".")
   if len(parts) != 4:
      return False
   reversed_ip = ".".join(reversed(parts))
   lookup = f"{reversed_ip}.{blacklist}"
   result = _resolve(lookup, "A")
   return bool(result)


def query_all_ns(domain: str, rdtype: str = "A") -> dict:
   nameservers = query_ns(domain)
   results = {}
   for ns in nameservers:
      try:
         ns_ip = resolve_ipv4(ns)
         resolver = dns.resolver.Resolver()
         resolver.nameservers = [ns_ip]
         resolver.lifetime = config.dns_timeout
         answer = list(resolver.resolve(domain, rdtype))
         results[ns] = sorted(str(rr) for rr in answer)
      except Exception as exc:
         results[ns] = f"error: {exc}"
   return results


def resolve_ipv4(hostname: str, port: int = 25) -> str:
   try:
      results = socket.getaddrinfo(hostname, port, socket.AF_INET, socket.SOCK_STREAM)
      if results:
         return results[0][4][0]
   except socket.gaierror:
      pass
   return hostname
