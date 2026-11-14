from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_mx, query_txt
from .. import logger


SEG_MX_PATTERNS = {
   "pphosted.com": "proofpoint",
   "ppe-hosted.com": "proofpoint",
   "proofpoint.com": "proofpoint",
   "mimecast.com": "mimecast",
   "iphmx.com": "cisco_ironport",
   "barracudanetworks.com": "barracuda",
   "mail.protection.outlook.com": "microsoft_365",
   "messagelabs.com": "symantec",
   "mxrecord.io": "mxguarddog",
   "protection.gandi.net": "gandi",
   "ovh.net": "ovh",
   "in.mailjet.com": "mailjet",
   "secureserver.net": "godaddy",
   "emailsecurity.trendmicro.com": "trendmicro",
   "forcepoint.com": "forcepoint",
   "fireeyecloud.com": "fireeye",
   "sophos.com": "sophos",
   "hornetsecurity.com": "hornetsecurity",
   "vadesecure.com": "vadesecure",
}

GOOGLE_MX_PATTERNS = [
   "aspmx.l.google.com",
   "google.com",
   "googlemail.com",
]

SPF_FINGERPRINTS = {
   "_spf.google.com": "google_workspace",
   "spf.protection.outlook.com": "microsoft_365",
   "pphosted.com": "proofpoint",
   "spf.mimecast.com": "mimecast",
   "mktomail.com": "marketo",
   "sendgrid.net": "sendgrid",
   "amazonses.com": "amazon_ses",
   "mailgun.org": "mailgun",
}


def fingerprint_mx(exchange: str) -> str:
   ex = exchange.lower().rstrip(".")
   for pattern in GOOGLE_MX_PATTERNS:
      if ex == pattern or ex.endswith(f".{pattern}"):
         return "google_workspace"
   for suffix, provider in SEG_MX_PATTERNS.items():
      if ex == suffix or ex.endswith(f".{suffix}"):
         return provider
   return ""


def fingerprint_spf(txt_records: list) -> list:
   providers = []
   spf = ""
   for r in txt_records:
      if r.strip().lower().startswith("v=spf1"):
         spf = r.lower()
         break
   if not spf:
      return providers
   for pattern, provider in SPF_FINGERPRINTS.items():
      if pattern in spf:
         providers.append(provider)
   return providers


class SEGCheck(BaseCheck):
   name = "seg"
   label = "SEG"
   external = True

   def run(self, domain: str, **kwargs) -> CheckResult:
      mx_records = query_mx(domain)
      if not mx_records:
         return CheckResult(
            name=self.name, label=self.label, score=0,
            reason="no_mx",
            details={"gateways": [], "mx_records": [], "spf_includes": []},
         )

      gateways = set()
      mx_list = []
      for prio, exchange in mx_records:
         mx_list.append(f"{prio} {exchange}")
         provider = fingerprint_mx(exchange)
         if provider:
            gateways.add(provider)

      txt_records = query_txt(domain)
      spf_providers = fingerprint_spf(txt_records)
      for p in spf_providers:
         gateways.add(p)

      gw_list = sorted(gateways)
      details = {
         "gateways": gw_list,
         "mx_records": mx_list,
         "spf_includes": spf_providers,
      }

      if len(gw_list) >= 2:
         return CheckResult(
            name=self.name, label=self.label, score=3,
            reason="multi_layer_seg", details=details,
         )

      if len(gw_list) == 1:
         return CheckResult(
            name=self.name, label=self.label, score=2,
            reason="single_seg", details=details,
         )

      return CheckResult(
         name=self.name, label=self.label, score=1,
         reason="no_seg_detected", details=details,
      )
