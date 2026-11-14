import smtplib

from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_mx, resolve_ipv4
from .. import logger


COMMON_USERS = [
   "postmaster", "admin", "abuse", "info", "contact", "support",
   "hr", "finance", "ceo", "cfo", "cto", "ciso", "it", "security",
   "helpdesk", "noreply", "no-reply", "billing", "sales", "marketing",
   "webmaster", "root", "test", "dev", "ops", "office", "reception",
   "accounting", "legal", "compliance",
]


class SMTPEnumCheck(BaseCheck):
   name = "smtp_enum"
   label = "SMTP-ENUM"
   intrusive = True

   def run(self, domain: str, **kwargs) -> CheckResult:
      timeout = kwargs.get("smtp_timeout", 10.0)
      records = query_mx(domain)
      if not records:
         return CheckResult(
            name=self.name, label=self.label, score=2,
            reason="no_mx", details={},
         )

      host = sorted(records)[0][1]
      details = {
         "host": host,
         "total_tested": 0,
         "valid": [],
         "invalid": [],
         "catch_all": False,
         "blocked": False,
         "rcpt_responses": {},
      }

      conn = None
      try:
         conn = smtplib.SMTP(timeout=timeout)
         ip = resolve_ipv4(host, 25)
         conn.connect(ip, 25)
         conn.ehlo()
         if conn.has_extn("STARTTLS"):
            try:
               conn.starttls()
               conn.ehlo()
            except Exception:
               pass

         code, _ = conn.mail("probe@test.local")
         if code not in (250, 251):
            details["blocked"] = True
            return CheckResult(
               name=self.name, label=self.label, score=3,
               reason="mail_from_rejected", details=details,
            )

         valid = []
         invalid = []
         responses = {}
         blocked = False

         for user in COMMON_USERS:
            addr = f"{user}@{domain}"
            try:
               code, msg = conn.rcpt(addr)
               responses[user] = code
               if code == 250:
                  valid.append(user)
               elif code == 550 or code == 553 or code == 551:
                  invalid.append(user)
               elif code in (503, 530):
                  blocked = True
                  break
            except smtplib.SMTPServerDisconnected:
               blocked = True
               break
            except Exception:
               pass

         try:
            conn.rset()
         except Exception:
            pass

         details["total_tested"] = len(responses)
         details["valid"] = valid
         details["invalid"] = invalid
         details["rcpt_responses"] = responses
         details["blocked"] = blocked

         if blocked:
            return CheckResult(
               name=self.name, label=self.label, score=3,
               reason="rcpt_blocked", details=details,
            )

         total_tested = len(responses)
         if total_tested == 0:
            return CheckResult(
               name=self.name, label=self.label, score=2,
               reason="no_responses", details=details,
            )

         if len(valid) == total_tested and total_tested > 0:
            details["catch_all"] = True
            return CheckResult(
               name=self.name, label=self.label, score=1,
               reason="catch_all", details=details,
            )

         diff_count = min(len(valid), len(invalid))
         if len(valid) > 0 and len(invalid) > 0 and diff_count > 2:
            return CheckResult(
               name=self.name, label=self.label, score=0,
               reason="user_enumeration", details=details,
            )

         if len(valid) > 0 and len(invalid) > 0:
            return CheckResult(
               name=self.name, label=self.label, score=2,
               reason="partial_enum", details=details,
            )

         if len(invalid) == total_tested:
            return CheckResult(
               name=self.name, label=self.label, score=3,
               reason="all_rejected", details=details,
            )

         return CheckResult(
            name=self.name, label=self.label, score=2,
            reason="inconclusive", details=details,
         )

      except Exception as exc:
         logger.debug(f"smtp enum {host}: {exc}")
         return CheckResult(
            name=self.name, label=self.label, score=2,
            reason="connection_error", details=details,
         )
      finally:
         if conn:
            try:
               conn.quit()
            except Exception:
               pass
