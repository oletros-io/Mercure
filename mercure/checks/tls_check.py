from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_mx
from ..http_utils import get_tls_info, get_smtp_tls_info
from .. import logger


class TLSCheck(BaseCheck):
   name = "tls"
   label = "TLS"

   def run(self, domain: str, **kwargs) -> CheckResult:
      web = get_tls_info(domain, 443)

      mx_records = query_mx(domain)
      mx_tls = []
      for _, exchange in mx_records:
         info = get_smtp_tls_info(exchange, 25)
         mx_tls.append({
            "host": exchange,
            "starttls_offered": info.get("starttls_offered", False),
            "starttls_success": info.get("starttls_success", False),
            "protocol": info.get("protocol", ""),
            "cipher": info.get("cipher", ""),
         })

      details = {
         "web": web,
         "mx_tls": mx_tls,
         "deprecated_protocols_found": False,
      }

      if not web["connected"]:
         if "cert_invalid" in web.get("error", ""):
            score, reason = 1, "cert_invalid"
         else:
            score, reason = 0, "no_tls"
         return CheckResult(
            name=self.name, label=self.label,
            score=score, reason=reason, details=details,
         )

      if web.get("self_signed"):
         score, reason = 1, "self_signed"
      elif web.get("cipher_bits", 0) > 0 and web["cipher_bits"] < 128:
         score, reason = 1, "weak_cipher"
      elif web.get("protocol", "") in ("TLSv1", "TLSv1.1"):
         score, reason = 1, "deprecated_protocol"
         details["deprecated_protocols_found"] = True
      else:
         score, reason = 3, "tls_ok"

      if mx_tls:
         total_mx = len(mx_tls)
         starttls_count = sum(1 for m in mx_tls if m["starttls_offered"])
         if total_mx > 0 and starttls_count < total_mx:
            score = min(score, 2)
            if reason == "tls_ok":
               reason = "mx_missing_starttls"

      return CheckResult(
         name=self.name, label=self.label,
         score=score, reason=reason, details=details,
      )
