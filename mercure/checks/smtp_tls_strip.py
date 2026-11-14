import smtplib
import socket
import ssl

from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_mx, resolve_ipv4
from .. import logger


def _test_plaintext(host: str, domain: str, timeout: float = 10.0) -> dict:
   result = {"plaintext_accepted": False, "tls_required": False}
   conn = None
   try:
      conn = smtplib.SMTP(timeout=timeout)
      ip = resolve_ipv4(host, 25)
      conn.connect(ip, 25)
      conn.ehlo()
      code, _ = conn.mail(f"test@{domain}")
      if code == 250:
         result["plaintext_accepted"] = True
         try:
            conn.rset()
         except Exception:
            pass
      elif code == 530:
         result["tls_required"] = True
   except Exception as exc:
      logger.debug(f"plaintext test {host}: {exc}")
   finally:
      if conn:
         try:
            conn.quit()
         except Exception:
            pass
   return result


def _test_deprecated_tls(host: str, tls_version, timeout: float = 10.0) -> bool:
   conn = None
   try:
      conn = smtplib.SMTP(timeout=timeout)
      ip = resolve_ipv4(host, 25)
      conn.connect(ip, 25)
      conn.ehlo()
      if not conn.has_extn("STARTTLS"):
         return False
      ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
      ctx.check_hostname = False
      ctx.verify_mode = ssl.CERT_NONE
      ctx.minimum_version = tls_version
      ctx.maximum_version = tls_version
      conn.sock = ctx.wrap_socket(conn.sock, server_hostname=host)
      return True
   except (ssl.SSLError, OSError):
      return False
   except Exception as exc:
      logger.debug(f"deprecated tls test {host}: {exc}")
      return False
   finally:
      if conn:
         try:
            conn.quit()
         except Exception:
            pass


def _test_cert_match(host: str, domain: str, timeout: float = 10.0) -> dict:
   result = {"cert_match": False, "cert_names": []}
   conn = None
   try:
      conn = smtplib.SMTP(timeout=timeout)
      ip = resolve_ipv4(host, 25)
      conn.connect(ip, 25)
      conn.ehlo()
      if not conn.has_extn("STARTTLS"):
         return result
      ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
      ctx.check_hostname = False
      ctx.verify_mode = ssl.CERT_NONE
      conn.sock = ctx.wrap_socket(conn.sock, server_hostname=host)
      cert = conn.sock.getpeercert(binary_form=False)
      if not cert:
         der = conn.sock.getpeercert(binary_form=True)
         if der:
            result["cert_names"] = []
            return result
         return result
      names = []
      san = cert.get("subjectAltName", ())
      for typ, val in san:
         if typ.lower() == "dns":
            names.append(val.lower())
      subject = cert.get("subject", ())
      for rdn in subject:
         for attr_type, attr_value in rdn:
            if attr_type.lower() == "commonname":
               if attr_value.lower() not in names:
                  names.append(attr_value.lower())
      result["cert_names"] = names
      host_lower = host.lower()
      domain_lower = domain.lower()
      for name in names:
         if name == host_lower or name == domain_lower:
            result["cert_match"] = True
            break
         if name.startswith("*."):
            wildcard_base = name[2:]
            if host_lower.endswith(f".{wildcard_base}") or domain_lower.endswith(f".{wildcard_base}"):
               result["cert_match"] = True
               break
            if wildcard_base == host_lower or wildcard_base == domain_lower:
               result["cert_match"] = True
               break
   except Exception as exc:
      logger.debug(f"cert match test {host}: {exc}")
   finally:
      if conn:
         try:
            conn.quit()
         except Exception:
            pass
   return result


class SMTPTLSStripCheck(BaseCheck):
   name = "smtp_tls_strip"
   label = "SMTP-STRIP"
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
      any_plaintext = False
      any_deprecated = False
      any_cert_mismatch = False
      any_tls_required = False

      for host in hosts:
         logger.info(f"SMTP TLS strip test on {host}:25")

         plaintext_result = _test_plaintext(host, domain, timeout)
         tls10 = _test_deprecated_tls(host, ssl.TLSVersion.TLSv1, timeout)
         tls11 = _test_deprecated_tls(host, ssl.TLSVersion.TLSv1_1, timeout)
         cert_result = _test_cert_match(host, domain, timeout)

         probe = {
            "host": host,
            "plaintext_accepted": plaintext_result["plaintext_accepted"],
            "tls_required": plaintext_result["tls_required"],
            "tls10_supported": tls10,
            "tls11_supported": tls11,
            "cert_match": cert_result["cert_match"],
            "cert_names": cert_result["cert_names"],
         }
         probes.append(probe)

         if plaintext_result["plaintext_accepted"]:
            any_plaintext = True
         if plaintext_result["tls_required"]:
            any_tls_required = True
         if tls10 or tls11:
            any_deprecated = True
         if not cert_result["cert_match"] and cert_result["cert_names"]:
            any_cert_mismatch = True

      details = {"mx_probes": probes}

      if any_plaintext:
         return CheckResult(
            name=self.name, label=self.label, score=0,
            reason="plaintext_accepted", details=details,
         )

      if any_deprecated or any_cert_mismatch:
         return CheckResult(
            name=self.name, label=self.label, score=1,
            reason="deprecated_tls_or_cert_mismatch", details=details,
         )

      if not any_tls_required:
         return CheckResult(
            name=self.name, label=self.label, score=2,
            reason="opportunistic_tls", details=details,
         )

      return CheckResult(
         name=self.name, label=self.label, score=3,
         reason="tls_enforced", details=details,
      )
