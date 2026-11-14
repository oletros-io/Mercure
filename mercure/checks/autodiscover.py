import re
from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_srv, query_cname
from ..http_utils import fetch, fetch_insecure
from .. import logger

ENDPOINTS = [
   ("https://autodiscover.{domain}/autodiscover/autodiscover.xml", "autodiscover_xml"),
   ("https://{domain}/autodiscover/autodiscover.xml", "root_autodiscover"),
   ("https://{domain}/.well-known/autoconfig/mail/config-v1.1.xml", "autoconfig_mozilla"),
   ("http://autoconfig.{domain}/mail/config-v1.1.xml", "autoconfig_http"),
]

SERVER_PATTERNS = ["exchange", "microsoft", "zimbra", "dovecot", "postfix"]

INTERNAL_PATTERNS = re.compile(
   r"(\b(?:\d{1,3}\.){3}\d{1,3}\b|\.local\b|\.internal\b|\.corp\b|\.lan\b)",
   re.IGNORECASE,
)


def _check_info_leak(text: str) -> list:
   leaked = []
   text_lower = text.lower()
   for pat in SERVER_PATTERNS:
      if pat in text_lower:
         leaked.append(f"server_type:{pat}")
   for match in INTERNAL_PATTERNS.finditer(text):
      leaked.append(f"internal:{match.group()}")
   return leaked


def _probe_endpoint(url: str, endpoint_type: str) -> dict:
   is_http = url.startswith("http://")
   resp = fetch_insecure(url, timeout=8.0) if is_http else fetch(url, timeout=8.0)

   entry = {
      "url": url,
      "type": endpoint_type,
      "status_code": 0,
      "accessible": False,
      "info_leak": False,
      "server_header": "",
      "leaked_info": [],
   }

   if resp is None:
      return entry

   entry["status_code"] = resp.status_code
   entry["server_header"] = resp.headers.get("Server", "")

   if resp.status_code == 200:
      entry["accessible"] = True
      leaked = _check_info_leak(resp.text)

      powered_by = resp.headers.get("X-Powered-By", "")
      if powered_by:
         leaked.append(f"x-powered-by:{powered_by}")

      server_hdr = entry["server_header"]
      if server_hdr:
         for pat in SERVER_PATTERNS:
            if pat in server_hdr.lower():
               leaked.append(f"server_header:{pat}")
               break

      if leaked:
         entry["info_leak"] = True
         entry["leaked_info"] = leaked

   elif resp.status_code in (301, 302):
      entry["accessible"] = False

   elif resp.status_code in (401, 403):
      entry["accessible"] = False

   return entry


class AutodiscoverCheck(BaseCheck):
   name = "autodiscover"
   label = "AUTODISCOVER"
   external = True

   def run(self, domain: str, **kwargs) -> CheckResult:
      endpoints = []
      for url_tpl, etype in ENDPOINTS:
         url = url_tpl.format(domain=domain)
         entry = _probe_endpoint(url, etype)
         endpoints.append(entry)

      srv_records = query_srv(f"_autodiscover._tcp.{domain}")
      srv_record = srv_records[0] if srv_records else None

      cname_records = query_cname(f"autodiscover.{domain}")
      autodiscover_cname = cname_records[0] if cname_records else None

      total_accessible = sum(1 for e in endpoints if e["accessible"])
      info_leaks = sum(1 for e in endpoints if e["info_leak"])

      http_accessible = any(
         e["accessible"] and e["url"].startswith("http://")
         for e in endpoints
      )

      details = {
         "endpoints": endpoints,
         "srv_record": srv_record,
         "autodiscover_cname": autodiscover_cname,
         "total_accessible": total_accessible,
         "info_leaks": info_leaks,
      }

      if info_leaks > 0:
         has_major_leak = any(
            e["info_leak"] and any(
               l.startswith("server_type:") or l.startswith("internal:")
               for l in e["leaked_info"]
            )
            for e in endpoints
         )
         if has_major_leak:
            return CheckResult(
               name=self.name, label=self.label,
               score=0, reason="autodiscover_info_leak",
               details=details,
            )
         return CheckResult(
            name=self.name, label=self.label,
            score=1, reason="autodiscover_limited_leak",
            details=details,
         )

      if total_accessible > 0 and http_accessible:
         return CheckResult(
            name=self.name, label=self.label,
            score=1, reason="autoconfig_http_unencrypted",
            details=details,
         )

      if total_accessible > 0:
         return CheckResult(
            name=self.name, label=self.label,
            score=1, reason="autodiscover_accessible",
            details=details,
         )

      secured_endpoints = any(
         e["status_code"] in (401, 403) for e in endpoints
      )

      if secured_endpoints or srv_record or autodiscover_cname:
         return CheckResult(
            name=self.name, label=self.label,
            score=2, reason="autodiscover_secured",
            details=details,
         )

      return CheckResult(
         name=self.name, label=self.label,
         score=3, reason="no_autodiscover",
         details=details,
      )
