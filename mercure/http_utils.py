import ssl
import socket
from typing import Dict, Any, Optional

import httpx

from . import logger

_TIMEOUT = 10.0
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"


def fetch(url: str, timeout: float = _TIMEOUT,
          follow_redirects: bool = True) -> Optional[httpx.Response]:
   try:
      with httpx.Client(
         timeout=timeout,
         follow_redirects=follow_redirects,
         verify=True,
         headers={"User-Agent": _UA},
      ) as client:
         return client.get(url)
   except Exception as exc:
      logger.debug(f"http fetch {url}: {exc}")
      return None


def fetch_insecure(url: str, timeout: float = _TIMEOUT,
                   follow_redirects: bool = False) -> Optional[httpx.Response]:
   try:
      with httpx.Client(
         timeout=timeout,
         follow_redirects=follow_redirects,
         verify=False,
         headers={"User-Agent": _UA},
      ) as client:
         return client.get(url)
   except Exception as exc:
      logger.debug(f"http fetch insecure {url}: {exc}")
      return None


def get_tls_info(host: str, port: int = 443,
                 timeout: float = _TIMEOUT) -> Dict[str, Any]:
   result = {
      "connected": False,
      "protocol": "",
      "cipher": "",
      "cipher_bits": 0,
      "cert_subject": {},
      "cert_issuer": {},
      "cert_san": [],
      "cert_not_before": "",
      "cert_not_after": "",
      "cert_serial": "",
      "self_signed": False,
      "error": "",
   }
   try:
      ctx = ssl.create_default_context()
      with socket.create_connection((host, port), timeout=timeout) as sock:
         with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            result["connected"] = True
            result["protocol"] = ssock.version()
            cipher = ssock.cipher()
            if cipher:
               result["cipher"] = cipher[0]
               result["cipher_bits"] = cipher[2]
            cert = ssock.getpeercert()
            if cert:
               result["cert_subject"] = dict(x[0] for x in cert.get("subject", ()))
               result["cert_issuer"] = dict(x[0] for x in cert.get("issuer", ()))
               san = cert.get("subjectAltName", ())
               result["cert_san"] = [v for _, v in san]
               result["cert_not_before"] = cert.get("notBefore", "")
               result["cert_not_after"] = cert.get("notAfter", "")
               result["cert_serial"] = cert.get("serialNumber", "")
               subj = result["cert_subject"]
               iss = result["cert_issuer"]
               if subj and iss and subj == iss:
                  result["self_signed"] = True
   except ssl.SSLCertVerificationError as exc:
      result["error"] = f"cert_invalid: {exc}"
      result["connected"] = True
   except ssl.SSLError as exc:
      result["error"] = f"ssl_error: {exc}"
   except (socket.timeout, TimeoutError):
      result["error"] = "timeout"
   except OSError as exc:
      result["error"] = f"connection_failed: {exc}"
   return result


def check_deprecated_tls(host: str, port: int = 443,
                         timeout: float = _TIMEOUT) -> Dict[str, bool]:
   supported = {}
   for name, min_v, max_v in [
      ("TLSv1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
      ("TLSv1.3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3),
   ]:
      try:
         ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
         ctx.check_hostname = False
         ctx.verify_mode = ssl.CERT_NONE
         ctx.minimum_version = min_v
         ctx.maximum_version = max_v
         with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
               supported[name] = True
      except Exception:
         supported[name] = False
   return supported


def get_smtp_tls_info(host: str, port: int = 25,
                      timeout: float = _TIMEOUT) -> Dict[str, Any]:
   import smtplib
   result = {
      "connected": False,
      "starttls_offered": False,
      "starttls_success": False,
      "protocol": "",
      "cipher": "",
      "cipher_bits": 0,
      "error": "",
   }
   conn = None
   try:
      conn = smtplib.SMTP(timeout=timeout)
      from .dns_utils import resolve_ipv4
      ip = resolve_ipv4(host, port)
      conn.connect(ip, port)
      result["connected"] = True
      code, _ = conn.ehlo()
      if code != 250:
         return result
      if conn.has_extn("STARTTLS"):
         result["starttls_offered"] = True
         try:
            conn.starttls()
            result["starttls_success"] = True
            ssock = conn.sock
            if hasattr(ssock, "version"):
               result["protocol"] = ssock.version()
            if hasattr(ssock, "cipher"):
               cipher = ssock.cipher()
               if cipher:
                  result["cipher"] = cipher[0]
                  result["cipher_bits"] = cipher[2]
         except Exception as exc:
            result["error"] = f"starttls_failed: {exc}"
   except Exception as exc:
      result["error"] = str(exc)
   finally:
      if conn:
         try:
            conn.quit()
         except Exception:
            pass
   return result
