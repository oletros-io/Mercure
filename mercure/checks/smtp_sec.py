import smtplib
import socket

from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_mx, resolve_ipv4
from .. import logger


SOFTWARE_SIGS = {
   "postfix": "Postfix",
   "exchange": "Exchange",
   "exim": "Exim",
   "sendmail": "Sendmail",
   "haraka": "Haraka",
   "hmail": "hMailServer",
   "zimbra": "Zimbra",
   "ironport": "IronPort",
   "barracuda": "Barracuda",
}


def _probe_banner(host: str, port: int = 25, timeout: float = 10.0) -> dict:
   result = {"banner": "", "version_disclosed": False, "software": ""}
   conn = None
   try:
      conn = smtplib.SMTP(timeout=timeout)
      ip = resolve_ipv4(host, port)
      code, banner_bytes = conn.connect(ip, port)
      banner = banner_bytes.decode(errors="replace")
      result["banner"] = banner
      banner_lower = banner.lower()
      for sig, name in SOFTWARE_SIGS.items():
         if sig in banner_lower:
            result["version_disclosed"] = True
            result["software"] = name
            break
   except Exception as exc:
      result["banner"] = f"error: {exc}"
   finally:
      if conn:
         try:
            conn.quit()
         except Exception:
            pass
   return result


def _probe_starttls(host: str, port: int = 25, timeout: float = 10.0) -> dict:
   result = {"offered": False, "success": False, "protocol": "", "cipher": ""}
   conn = None
   try:
      conn = smtplib.SMTP(timeout=timeout)
      ip = resolve_ipv4(host, port)
      conn.connect(ip, port)
      conn.ehlo()
      if conn.has_extn("STARTTLS"):
         result["offered"] = True
         try:
            conn.starttls()
            result["success"] = True
            ssock = conn.sock
            if hasattr(ssock, "version"):
               result["protocol"] = ssock.version()
            if hasattr(ssock, "cipher"):
               cipher = ssock.cipher()
               if cipher:
                  result["cipher"] = cipher[0]
         except Exception:
            pass
   except Exception:
      pass
   finally:
      if conn:
         try:
            conn.quit()
         except Exception:
            pass
   return result


def _probe_vrfy(host: str, port: int = 25, timeout: float = 10.0) -> dict:
   result = {"vrfy_enabled": False, "vrfy_code": 0, "expn_enabled": False, "expn_code": 0}
   conn = None
   try:
      conn = smtplib.SMTP(timeout=timeout)
      ip = resolve_ipv4(host, port)
      conn.connect(ip, port)
      conn.ehlo()
      try:
         code, _ = conn.vrfy("postmaster")
         result["vrfy_code"] = code
         if code in (250, 252):
            result["vrfy_enabled"] = True
      except smtplib.SMTPServerDisconnected:
         return result
      try:
         code, _ = conn.expn("postmaster")
         result["expn_code"] = code
         if code in (250, 252):
            result["expn_enabled"] = True
      except smtplib.SMTPServerDisconnected:
         pass
   except Exception:
      pass
   finally:
      if conn:
         try:
            conn.quit()
         except Exception:
            pass
   return result


def _probe_open_relay(host: str, port: int = 25, timeout: float = 10.0) -> dict:
   result = {"open_relay": False, "rcpt_code": 0}
   conn = None
   try:
      conn = smtplib.SMTP(timeout=timeout)
      ip = resolve_ipv4(host, port)
      conn.connect(ip, port)
      conn.ehlo()
      code, _ = conn.mail("test@example.org")
      if code != 250:
         return result
      code, _ = conn.rcpt("test@example.net")
      result["rcpt_code"] = code
      if code == 250:
         result["open_relay"] = True
      try:
         conn.rset()
      except Exception:
         pass
   except Exception:
      pass
   finally:
      if conn:
         try:
            conn.quit()
         except Exception:
            pass
   return result


def _probe_smuggling(host: str, domain: str, port: int = 25, timeout: float = 10.0) -> dict:
   result = {"vulnerable": False, "accepts_bare_lf": False}
   conn = None
   try:
      conn = smtplib.SMTP(timeout=timeout)
      ip = resolve_ipv4(host, port)
      conn.connect(ip, port)
      conn.ehlo()
      code, _ = conn.mail(f"test@{domain}")
      if code != 250:
         return result
      code, _ = conn.rcpt(f"test@{domain}")
      if code != 250:
         try:
            conn.rset()
         except Exception:
            pass
         return result
      conn.putcmd("DATA")
      code, _ = conn.getreply()
      if code != 354:
         return result
      raw_sock = conn.sock
      smuggle_payload = (
         b"Subject: smuggle test\r\n"
         b"\r\n"
         b"test body\n.\n"
         b"MAIL FROM:<smuggle@example.org>\r\n"
      )
      raw_sock.sendall(smuggle_payload)
      raw_sock.settimeout(5)
      try:
         resp = raw_sock.recv(1024).decode(errors="replace")
         if resp.startswith("250"):
            result["accepts_bare_lf"] = True
            result["vulnerable"] = True
      except (socket.timeout, TimeoutError):
         pass
      try:
         conn.rset()
      except Exception:
         pass
   except Exception:
      pass
   finally:
      if conn:
         try:
            conn.quit()
         except Exception:
            pass
   return result


class SMTPSecCheck(BaseCheck):
   name = "smtp_sec"
   label = "SMTP-SEC"
   intrusive = True

   def run(self, domain: str, **kwargs) -> CheckResult:
      timeout = kwargs.get("smtp_timeout", 10.0)
      records = query_mx(domain)
      if not records:
         return CheckResult(
            name=self.name, label=self.label, score=2,
            reason="no_mx", details={"mx_probes": []},
         )

      hosts = [exchange for _, exchange in sorted(records)[:3]]
      probes = []
      any_open_relay = False
      any_smuggling = False
      any_vrfy = False
      any_version_no_tls = False
      any_starttls = False
      all_secure = True

      for host in hosts:
         logger.info(f"probing SMTP security on {host}:25")
         banner_info = _probe_banner(host, timeout=timeout)
         starttls_info = _probe_starttls(host, timeout=timeout)
         vrfy_info = _probe_vrfy(host, timeout=timeout)
         relay_info = _probe_open_relay(host, timeout=timeout)
         smuggling_info = _probe_smuggling(host, domain, timeout=timeout)

         probe = {
            "host": host,
            "banner": banner_info,
            "starttls": starttls_info,
            "vrfy": vrfy_info,
            "relay": relay_info,
            "smuggling": smuggling_info,
         }
         probes.append(probe)

         if relay_info["open_relay"]:
            any_open_relay = True
            all_secure = False
         if smuggling_info["vulnerable"]:
            any_smuggling = True
            all_secure = False
         if vrfy_info["vrfy_enabled"] or vrfy_info["expn_enabled"]:
            any_vrfy = True
            all_secure = False
         if starttls_info["offered"]:
            any_starttls = True
         else:
            all_secure = False
         if banner_info["version_disclosed"]:
            if not starttls_info["offered"]:
               any_version_no_tls = True
            all_secure = False

      details = {"mx_probes": probes}

      if any_open_relay:
         return CheckResult(
            name=self.name, label=self.label, score=0,
            reason="open_relay", details=details,
         )

      if any_smuggling:
         return CheckResult(
            name=self.name, label=self.label, score=0,
            reason="smtp_smuggling", details=details,
         )

      if any_vrfy:
         return CheckResult(
            name=self.name, label=self.label, score=1,
            reason="user_enumeration", details=details,
         )

      if any_version_no_tls:
         return CheckResult(
            name=self.name, label=self.label, score=1,
            reason="banner_exposed_no_tls", details=details,
         )

      if any_starttls and not all_secure:
         return CheckResult(
            name=self.name, label=self.label, score=2,
            reason="smtp_partial", details=details,
         )

      if all_secure:
         return CheckResult(
            name=self.name, label=self.label, score=3,
            reason="smtp_hardened", details=details,
         )

      return CheckResult(
         name=self.name, label=self.label, score=2,
         reason="smtp_partial", details=details,
      )
