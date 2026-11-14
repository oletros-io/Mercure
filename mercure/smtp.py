import smtplib
import socket
from typing import Dict, List

from .config import config
from .dns_utils import resolve_ipv4


def _base_result(server: str) -> Dict:
   return {
      "server": server,
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


def _run_transaction(conn, envelope_from: str, recipients: List[str],
                     msg_bytes: bytes, result: Dict) -> Dict:
   code, resp = conn.mail(envelope_from)
   result["mail_from_code"] = code
   result["mail_from_msg"] = resp.decode(errors="replace")
   if code != 250:
      return result

   accepted = 0
   rejected = 0
   for rcpt in recipients:
      code, resp = conn.rcpt(rcpt)
      result["rcpt_to_code"] = code
      result["rcpt_to_msg"] = resp.decode(errors="replace")
      if code == 250:
         accepted += 1
      else:
         rejected += 1

   if "accepted_count" in result:
      result["accepted_count"] = accepted
      result["rejected_count"] = rejected

   if accepted == 0:
      return result

   code, resp = conn.data(msg_bytes)
   result["data_code"] = code
   result["data_msg"] = resp.decode(errors="replace")
   if 200 <= code < 300:
      result["delivered"] = True

   return result


def _safe_close(conn):
   if conn:
      try:
         conn.quit()
      except Exception:
         pass


def _handle_exception(exc: Exception, result: Dict) -> Dict:
   if isinstance(exc, smtplib.SMTPDataError):
      result["data_code"] = exc.smtp_code
      err = exc.smtp_error
      result["data_msg"] = err.decode(errors="replace") if isinstance(err, bytes) else str(err)
   elif isinstance(exc, smtplib.SMTPAuthenticationError):
      err = exc.smtp_error
      result["error"] = f"auth failed: {err.decode(errors='replace') if isinstance(err, bytes) else str(err)}"
   elif isinstance(exc, smtplib.SMTPServerDisconnected):
      result["error"] = f"disconnected: {exc}"
   elif isinstance(exc, (smtplib.SMTPConnectError, socket.timeout, TimeoutError)):
      result["error"] = f"connection timeout: {exc}"
   elif isinstance(exc, OSError):
      result["error"] = f"network error: {exc}"
   else:
      result["error"] = str(exc)
   return result


def direct_deliver(host: str, port: int, envelope_from: str,
                   recipients: List[str], msg_bytes: bytes,
                   ehlo_host: str, timeout: float = 10.0) -> Dict:
   result = _base_result(f"{host}:{port}")
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

      _run_transaction(conn, envelope_from, recipients, msg_bytes, result)

   except Exception as exc:
      _handle_exception(exc, result)
   finally:
      _safe_close(conn)

   return result


def relay_deliver(envelope_from: str, recipients: List[str],
                  msg_bytes: bytes, timeout: float = 10.0) -> Dict:
   host = config.smtp_relay_host
   port = config.smtp_relay_port
   result = _base_result(f"{host}:{port} (relay)")
   result["authenticated"] = False
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

      _run_transaction(conn, envelope_from, recipients, msg_bytes, result)

   except Exception as exc:
      _handle_exception(exc, result)
   finally:
      _safe_close(conn)

   return result


def amp_deliver(host: str, port: int, envelope_from: str,
                dead_recipients: List[str], msg_bytes: bytes,
                ehlo_host: str, timeout: float = 10.0) -> Dict:
   result = _base_result(f"{host}:{port}")
   result["accepted_count"] = 0
   result["rejected_count"] = 0
   result["total_recipients"] = len(dead_recipients)
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

      _run_transaction(conn, envelope_from, dead_recipients, msg_bytes, result)

   except Exception as exc:
      _handle_exception(exc, result)
   finally:
      _safe_close(conn)

   return result


def relay_configured() -> bool:
   return bool(config.smtp_relay_host and config.smtp_relay_user and config.smtp_relay_pass)
