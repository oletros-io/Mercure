from email.mime.text import MIMEText
from uuid import uuid4

from .base import BaseCheck
from ..scoring import CheckResult
from ..smtp import relay_deliver, relay_configured
from ..config import config
from .. import logger


def _sender_domain_from_relay() -> str:
   user = config.smtp_relay_user
   if "@" in user:
      return user.split("@", 1)[1]
   return "mercure.local"


def _build_bounce_probe(sender: str, recipient: str) -> bytes:
   msg = MIMEText("Mercure bounce validation probe.", "plain", "utf-8")
   msg["From"] = sender
   msg["To"] = recipient
   msg["Subject"] = "Bounce Probe - Mercure"
   msg["Return-Path"] = f"<{sender}>"
   msg["X-Oletros-Tool"] = "https://oletros.io/"
   return msg.as_bytes()


class BounceCheck(BaseCheck):
   name = "bounce"
   label = "BOUNCE"
   intrusive = True

   def run(self, domain: str, **kwargs) -> CheckResult:
      if not relay_configured():
         return CheckResult(
            name=self.name, label=self.label, score=2,
            reason="relay_not_configured",
            details={"note": "SMTP relay credentials required for bounce analysis"},
         )

      timeout = kwargs.get("smtp_timeout", 10.0)
      tag = uuid4().hex[:8]
      test_addr = f"nxuser-{tag}@{domain}"
      sender_domain = _sender_domain_from_relay()
      envelope_from = f"mercure-bounce-test@{sender_domain}"

      msg_bytes = _build_bounce_probe(envelope_from, test_addr)

      logger.info(f"bounce probe: sending to {test_addr}")
      result = relay_deliver(envelope_from, [test_addr], msg_bytes, timeout=timeout)

      rcpt_code = result.get("rcpt_to_code", 0)
      mail_code = result.get("mail_from_code", 0)
      data_code = result.get("data_code", 0)
      delivered = result.get("delivered", False)
      connected = result.get("connected", False)

      details = {
         "test_address": test_addr,
         "delivery_result": result,
         "recipient_validation": "unknown",
         "ndr_risk": "unknown",
      }

      if not connected:
         details["ndr_risk"] = "unknown"
         return CheckResult(
            name=self.name, label=self.label, score=2,
            reason="delivery_error", details=details,
         )

      if mail_code >= 500:
         details["recipient_validation"] = "before_accept"
         details["ndr_risk"] = "none"
         return CheckResult(
            name=self.name, label=self.label, score=3,
            reason="sender_rejected", details=details,
         )

      if rcpt_code >= 500:
         details["recipient_validation"] = "before_accept"
         details["ndr_risk"] = "none"
         return CheckResult(
            name=self.name, label=self.label, score=3,
            reason="recipient_validated", details=details,
         )

      if rcpt_code >= 400:
         details["recipient_validation"] = "before_accept"
         details["ndr_risk"] = "none"
         return CheckResult(
            name=self.name, label=self.label, score=2,
            reason="recipient_temp_reject", details=details,
         )

      if delivered:
         details["recipient_validation"] = "after_accept"
         details["ndr_risk"] = "high"
         logger.warning(f"bounce risk: {domain} accepts mail for nonexistent users")
         return CheckResult(
            name=self.name, label=self.label, score=1,
            reason="accepts_invalid_recipients", details=details,
         )

      if data_code >= 500:
         details["recipient_validation"] = "after_accept"
         details["ndr_risk"] = "none"
         return CheckResult(
            name=self.name, label=self.label, score=2,
            reason="data_rejected", details=details,
         )

      details["ndr_risk"] = "unknown"
      return CheckResult(
         name=self.name, label=self.label, score=2,
         reason="inconclusive", details=details,
      )
