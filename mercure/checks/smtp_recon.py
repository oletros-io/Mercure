import base64
import smtplib
import struct

from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_mx, resolve_ipv4
from .. import logger


AV_PAIR_TYPES = {
   0x0001: "netbios_computer",
   0x0002: "netbios_domain",
   0x0003: "dns_computer",
   0x0004: "dns_domain",
   0x0005: "dns_tree",
}


def _parse_ntlm_type2(data: bytes) -> dict:
   info = {}
   if len(data) < 56 or data[:7] != b"NTLMSSP":
      return info
   try:
      target_info_len = struct.unpack_from("<H", data, 40)[0]
      target_info_off = struct.unpack_from("<I", data, 44)[0]
   except struct.error:
      return info
   buf = data[target_info_off:target_info_off + target_info_len]
   pos = 0
   while pos + 4 <= len(buf):
      av_id = struct.unpack_from("<H", buf, pos)[0]
      av_len = struct.unpack_from("<H", buf, pos + 2)[0]
      pos += 4
      if av_id == 0x0000:
         break
      if pos + av_len > len(buf):
         break
      raw_value = buf[pos:pos + av_len]
      try:
         value = raw_value.decode("utf-16-le")
      except Exception:
         value = raw_value.hex()
      label = AV_PAIR_TYPES.get(av_id, f"0x{av_id:04x}")
      info[label] = value
      pos += av_len
   return info


def _build_ntlm_type1() -> bytes:
   return (
      b"NTLMSSP\x00"
      + struct.pack("<I", 1)
      + struct.pack("<I", 0x00088207)
      + b"\x00" * 16
   )


def _probe_ntlm(conn) -> dict:
   try:
      type1 = _build_ntlm_type1()
      code, _ = conn.docmd("AUTH", "NTLM")
      if code != 334:
         return {}
      code, resp = conn.docmd(base64.b64encode(type1).decode())
      if code != 334:
         return {}
      try:
         type2_data = base64.b64decode(resp)
      except Exception:
         type2_data = base64.b64decode(resp.decode(errors="replace").strip())
      info = _parse_ntlm_type2(type2_data)
      try:
         conn.docmd("*")
      except Exception:
         pass
      return info
   except Exception as exc:
      logger.debug(f"ntlm probe failed: {exc}")
      return {}


def _parse_ehlo(response: bytes) -> tuple:
   lines = response.decode(errors="replace").split("\n")
   hostname = lines[0].strip() if lines else ""
   extensions = []
   auth_methods = []
   for line in lines[1:]:
      ext = line.strip().upper()
      if ext:
         extensions.append(ext)
         if ext.startswith("AUTH "):
            auth_methods = ext.split()[1:]
   return hostname, extensions, auth_methods


def _probe_help(conn) -> str:
   try:
      code, resp = conn.docmd("HELP")
      if code in (211, 214):
         return resp.decode(errors="replace").strip()
   except Exception:
      pass
   return ""


def _probe_mx(host: str, domain: str, timeout: float = 10.0) -> dict:
   probe = {
      "host": host,
      "ehlo_hostname": "",
      "extensions": [],
      "auth_methods": [],
      "ntlm_info": None,
      "help_response": "",
   }
   conn = None
   try:
      conn = smtplib.SMTP(timeout=timeout)
      ip = resolve_ipv4(host, 25)
      conn.connect(ip, 25)
      code, ehlo_resp = conn.ehlo()
      if code != 250:
         return probe
      hostname, extensions, auth_methods = _parse_ehlo(ehlo_resp)
      probe["ehlo_hostname"] = hostname
      probe["extensions"] = extensions
      probe["auth_methods"] = auth_methods
      if "NTLM" in auth_methods:
         ntlm_info = _probe_ntlm(conn)
         if ntlm_info:
            probe["ntlm_info"] = ntlm_info
      probe["help_response"] = _probe_help(conn)
   except Exception as exc:
      logger.debug(f"smtp recon {host}: {exc}")
   finally:
      if conn:
         try:
            conn.quit()
         except Exception:
            pass
   return probe


def _has_internal_hostname(hostname: str, domain: str) -> bool:
   if not hostname:
      return False
   internal_indicators = [
      ".internal.", ".corp.", ".local.", ".lan.", ".ad.",
      ".priv.", ".intra.",
   ]
   hostname_lower = hostname.lower()
   for indicator in internal_indicators:
      if indicator in hostname_lower:
         return True
   if hostname_lower.endswith(".internal") or hostname_lower.endswith(".local"):
      return True
   return False


class SMTPReconCheck(BaseCheck):
   name = "smtp_recon"
   label = "SMTP-RECON"
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
      any_ntlm_leak = False
      any_auth_plain_no_tls = False
      any_internal_hostname = False
      any_exposure = False

      for host in hosts:
         logger.info(f"SMTP recon on {host}:25")
         probe = _probe_mx(host, domain, timeout=timeout)
         probes.append(probe)

         if probe["ntlm_info"]:
            any_ntlm_leak = True

         if _has_internal_hostname(probe["ehlo_hostname"], domain):
            any_internal_hostname = True

         auth_upper = [a.upper() for a in probe["auth_methods"]]
         if "PLAIN" in auth_upper or "LOGIN" in auth_upper:
            any_auth_plain_no_tls = True

         if probe["extensions"] or probe["help_response"]:
            any_exposure = True

      details = {"mx_probes": probes}

      if any_ntlm_leak:
         return CheckResult(
            name=self.name, label=self.label, score=0,
            reason="ntlm_info_leak", details=details,
         )

      if any_auth_plain_no_tls or any_internal_hostname:
         return CheckResult(
            name=self.name, label=self.label, score=1,
            reason="internal_info_leaked", details=details,
         )

      if any_exposure:
         return CheckResult(
            name=self.name, label=self.label, score=2,
            reason="extensions_exposed", details=details,
         )

      return CheckResult(
         name=self.name, label=self.label, score=3,
         reason="minimal_exposure", details=details,
      )
