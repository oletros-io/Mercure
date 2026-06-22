import socket
import smtplib

from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_mx, query_a, resolve_ipv4
from .. import logger

EXO_SUFFIX = ".mail.protection.outlook.com"
PROBE_EHLO_TPL = "mail.{domain}"
PROBE_FROM_TPL = "postmaster@{domain}"
SMTP_TIMEOUT = 10.0


def derive_exo_endpoint(domain: str) -> str:
   return domain.rstrip(".").replace(".", "-") + EXO_SUFFIX


def mx_points_to_exo(domain: str) -> tuple:
   records = query_mx(domain)
   if not records:
      return False, [], []
   exo_mx = []
   third_party_mx = []
   for _, exchange in records:
      ex = exchange.lower().rstrip(".")
      if ex.endswith(EXO_SUFFIX.lstrip(".")):
         exo_mx.append(exchange)
      else:
         third_party_mx.append(exchange)
   direct = len(exo_mx) > 0 and len(third_party_mx) == 0
   return direct, exo_mx, third_party_mx


def exo_endpoint_resolves(endpoint: str) -> list:
   return query_a(endpoint)


def smtp_probe(endpoint: str, domain: str, timeout: float = SMTP_TIMEOUT) -> dict:
   probe = {
      "endpoint": endpoint,
      "connected": False,
      "banner": "",
      "ehlo_code": 0,
      "ehlo_msg": "",
      "mail_from_code": 0,
      "mail_from_msg": "",
      "rcpt_to_code": 0,
      "rcpt_to_msg": "",
      "mitigated_5751": False,
      "accepts_spoofed_rcpt": False,
      "error": "",
   }

   smtp = None
   try:
      smtp = smtplib.SMTP(timeout=timeout)
      ip = resolve_ipv4(endpoint, 25)
      code, msg = smtp.connect(ip, 25)
      probe["connected"] = True
      probe["banner"] = msg.decode(errors="replace")

      ehlo_host = PROBE_EHLO_TPL.format(domain=domain)
      probe_from = PROBE_FROM_TPL.format(domain=domain)

      code, msg = smtp.ehlo(ehlo_host)
      probe["ehlo_code"] = code
      probe["ehlo_msg"] = msg.decode(errors="replace")

      if code != 250:
         return probe

      code, msg = smtp.mail(probe_from)
      probe["mail_from_code"] = code
      probe["mail_from_msg"] = msg.decode(errors="replace")

      if code != 250:
         if "5.7.51" in probe["mail_from_msg"]:
            probe["mitigated_5751"] = True
         return probe

      target = f"postmaster@{domain}"
      code, msg = smtp.rcpt(target)
      probe["rcpt_to_code"] = code
      probe["rcpt_to_msg"] = msg.decode(errors="replace")

      if "5.7.51" in probe["rcpt_to_msg"]:
         probe["mitigated_5751"] = True
      elif code == 250:
         probe["accepts_spoofed_rcpt"] = True

      try:
         smtp.rset()
      except Exception:
         pass

   except smtplib.SMTPServerDisconnected as exc:
      probe["error"] = f"server disconnected: {exc}"
      logger.debug(f"ghost smtp probe {endpoint}: {exc}")
   except (smtplib.SMTPConnectError, socket.timeout, TimeoutError) as exc:
      probe["error"] = f"connection failed: {exc}"
      logger.debug(f"ghost smtp probe {endpoint}: {exc}")
   except OSError as exc:
      probe["error"] = f"network error: {exc}"
      logger.debug(f"ghost smtp probe {endpoint}: {exc}")
   finally:
      if smtp:
         try:
            smtp.quit()
         except Exception:
            pass

   return probe


class GhostSenderCheck(BaseCheck):
   name = "ghost"
   label = "GHOST"
   weight = 2.0

   def run(self, domain: str, **kwargs) -> CheckResult:
      endpoint = derive_exo_endpoint(domain)
      mx_direct, exo_mx, third_party_mx = mx_points_to_exo(domain)
      exo_ips = exo_endpoint_resolves(endpoint)

      base_details = {
         "endpoint": endpoint,
         "endpoint_ips": exo_ips,
         "mx_direct_to_exo": mx_direct,
         "exo_mx": exo_mx,
         "third_party_mx": third_party_mx,
      }

      if not exo_ips:
         logger.info(f"no EXO endpoint for {domain}")
         return CheckResult(
            name=self.name,
            label=self.label,
            score=3,
            reason="not_exchange_online",
            details=base_details,
         )

      if mx_direct:
         logger.info(f"MX direct to EXO for {domain}")
         return CheckResult(
            name=self.name,
            label=self.label,
            score=3,
            reason="mx_direct_to_exo",
            details=base_details,
         )

      timeout = kwargs.get("smtp_timeout", SMTP_TIMEOUT)
      logger.info(f"EXO endpoint found, MX via third-party, probing {endpoint}...")
      probe = smtp_probe(endpoint, domain, timeout=timeout)
      base_details["probe"] = probe

      if not probe["connected"]:
         return CheckResult(
            name=self.name,
            label=self.label,
            score=2,
            reason="exo_unreachable",
            details=base_details,
         )

      if probe["mitigated_5751"]:
         logger.success(f"partner connector mitigates ghost sender on {domain}")
         return CheckResult(
            name=self.name,
            label=self.label,
            score=3,
            reason="partner_connector_configured",
            details=base_details,
         )

      if probe["accepts_spoofed_rcpt"]:
         logger.warning(f"GHOST SENDER VULNERABLE: {domain}")
         return CheckResult(
            name=self.name,
            label=self.label,
            score=0,
            reason="ghost_sender_vulnerable",
            value=endpoint,
            details=base_details,
         )

      if probe["mail_from_code"] >= 500 or probe["rcpt_to_code"] >= 500:
         return CheckResult(
            name=self.name,
            label=self.label,
            score=2,
            reason="smtp_rejected",
            details=base_details,
         )

      if probe["mail_from_code"] >= 400 or probe["rcpt_to_code"] >= 400:
         return CheckResult(
            name=self.name,
            label=self.label,
            score=2,
            reason="smtp_temp_reject",
            details=base_details,
         )

      return CheckResult(
         name=self.name,
         label=self.label,
         score=1,
         reason="exo_exposed_inconclusive",
         details=base_details,
      )
