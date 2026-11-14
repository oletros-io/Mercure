import base64
import struct

from unittest.mock import patch, MagicMock
from mercure.checks.smtp_recon import SMTPReconCheck, _parse_ntlm_type2, _has_internal_hostname


def _build_ntlm_type2(domain="CORP", computer="MAIL01", dns_domain="corp.contoso.com"):
   pairs = b""
   for av_id, value in [(2, domain), (1, computer), (4, dns_domain), (0, "")]:
      encoded = value.encode("utf-16-le")
      pairs += struct.pack("<HH", av_id, len(encoded)) + encoded

   sig = b"NTLMSSP\x00"
   msg_type = struct.pack("<I", 2)
   target_name = domain.encode("utf-16-le")
   header_len = 48
   target_name_fields = struct.pack("<HHI", len(target_name), len(target_name), header_len)
   flags = struct.pack("<I", 0x00028233)
   challenge = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
   reserved = b"\x00" * 8
   target_info_fields = struct.pack("<HHI", len(pairs), len(pairs), header_len + len(target_name))

   type2 = sig + msg_type + target_name_fields + flags + challenge + reserved + target_info_fields + target_name + pairs
   return base64.b64encode(type2).decode()


def _mock_conn(ehlo_resp=b"mail.example.com\nPIPELINING\n8BITMIME", ehlo_code=250):
   conn = MagicMock()
   conn.connect.return_value = (220, b"220 ESMTP ready")
   conn.ehlo.return_value = (ehlo_code, ehlo_resp)
   conn.quit.return_value = None
   return conn


class TestParseNtlmType2:
   def test_valid_type2(self):
      raw = base64.b64decode(_build_ntlm_type2())
      info = _parse_ntlm_type2(raw)
      assert info["netbios_domain"] == "CORP"
      assert info["netbios_computer"] == "MAIL01"
      assert info["dns_domain"] == "corp.contoso.com"

   def test_invalid_data(self):
      info = _parse_ntlm_type2(b"garbage")
      assert info == {}

   def test_too_short(self):
      info = _parse_ntlm_type2(b"NTLMSSP\x00" + b"\x00" * 10)
      assert info == {}


class TestInternalHostname:
   def test_internal_suffix(self):
      assert _has_internal_hostname("mail01.corp.internal.contoso.com", "contoso.com") is True

   def test_local_suffix(self):
      assert _has_internal_hostname("mail.office.local", "example.com") is True

   def test_normal_hostname(self):
      assert _has_internal_hostname("mail.example.com", "example.com") is False

   def test_empty_hostname(self):
      assert _has_internal_hostname("", "example.com") is False


class TestSMTPReconCheck:
   @patch("mercure.checks.smtp_recon.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.smtp_recon.smtplib")
   @patch("mercure.checks.smtp_recon.query_mx")
   def test_ntlm_info_leak(self, mock_mx, mock_smtp, mock_ipv4):
      mock_mx.return_value = [(10, "mx.example.com")]
      type2_b64 = _build_ntlm_type2()
      conn = _mock_conn(ehlo_resp=b"mail01.internal.corp\nAUTH NTLM LOGIN\nPIPELINING")
      docmd_calls = []

      def fake_docmd(cmd, arg=None):
         docmd_calls.append((cmd, arg))
         if cmd == "AUTH" and arg == "NTLM":
            return (334, b"")
         if cmd == "*":
            return (501, b"cancelled")
         return (334, type2_b64.encode())

      conn.docmd.side_effect = fake_docmd
      mock_smtp.SMTP.return_value = conn

      check = SMTPReconCheck()
      result = check.run("example.com")
      assert result.score == 0
      assert result.reason == "ntlm_info_leak"
      assert result.details["mx_probes"][0]["ntlm_info"]["netbios_domain"] == "CORP"

   @patch("mercure.checks.smtp_recon.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.smtp_recon.smtplib")
   @patch("mercure.checks.smtp_recon.query_mx")
   def test_internal_hostname_leak(self, mock_mx, mock_smtp, mock_ipv4):
      mock_mx.return_value = [(10, "mx.example.com")]
      conn = _mock_conn(ehlo_resp=b"mail01.corp.internal.local\nPIPELINING")
      conn.docmd.return_value = (502, b"not implemented")
      mock_smtp.SMTP.return_value = conn

      check = SMTPReconCheck()
      result = check.run("example.com")
      assert result.score == 1
      assert result.reason == "internal_info_leaked"

   @patch("mercure.checks.smtp_recon.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.smtp_recon.smtplib")
   @patch("mercure.checks.smtp_recon.query_mx")
   def test_auth_plain_exposed(self, mock_mx, mock_smtp, mock_ipv4):
      mock_mx.return_value = [(10, "mx.example.com")]
      conn = _mock_conn(ehlo_resp=b"mx.example.com\nAUTH PLAIN LOGIN\nPIPELINING")
      conn.docmd.return_value = (502, b"not implemented")
      mock_smtp.SMTP.return_value = conn

      check = SMTPReconCheck()
      result = check.run("example.com")
      assert result.score == 1
      assert result.reason == "internal_info_leaked"

   @patch("mercure.checks.smtp_recon.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.smtp_recon.smtplib")
   @patch("mercure.checks.smtp_recon.query_mx")
   def test_extensions_exposed(self, mock_mx, mock_smtp, mock_ipv4):
      mock_mx.return_value = [(10, "mx.example.com")]
      conn = _mock_conn(ehlo_resp=b"mx.example.com\nPIPELINING\n8BITMIME\nSIZE 52428800")
      conn.docmd.return_value = (502, b"not implemented")
      mock_smtp.SMTP.return_value = conn

      check = SMTPReconCheck()
      result = check.run("example.com")
      assert result.score == 2
      assert result.reason == "extensions_exposed"

   @patch("mercure.checks.smtp_recon.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.smtp_recon.smtplib")
   @patch("mercure.checks.smtp_recon.query_mx")
   def test_minimal_exposure(self, mock_mx, mock_smtp, mock_ipv4):
      mock_mx.return_value = [(10, "mx.example.com")]
      conn = _mock_conn(ehlo_resp=b"mx.example.com")
      conn.docmd.return_value = (502, b"not implemented")
      mock_smtp.SMTP.return_value = conn

      check = SMTPReconCheck()
      result = check.run("example.com")
      assert result.score == 3
      assert result.reason == "minimal_exposure"

   @patch("mercure.checks.smtp_recon.query_mx")
   def test_no_mx(self, mock_mx):
      mock_mx.return_value = []
      check = SMTPReconCheck()
      result = check.run("example.com")
      assert result.score == 2
      assert result.reason == "no_mx"

   @patch("mercure.checks.smtp_recon.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.smtp_recon.smtplib")
   @patch("mercure.checks.smtp_recon.query_mx")
   def test_multiple_mx(self, mock_mx, mock_smtp, mock_ipv4):
      mock_mx.return_value = [(10, "mx1.example.com"), (20, "mx2.example.com")]
      conn = _mock_conn(ehlo_resp=b"mx.example.com\nPIPELINING")
      conn.docmd.return_value = (502, b"not implemented")
      mock_smtp.SMTP.return_value = conn

      check = SMTPReconCheck()
      result = check.run("example.com")
      assert len(result.details["mx_probes"]) == 2

   @patch("mercure.checks.smtp_recon.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.smtp_recon.smtplib")
   @patch("mercure.checks.smtp_recon.query_mx")
   def test_connection_error(self, mock_mx, mock_smtp, mock_ipv4):
      mock_mx.return_value = [(10, "mx.example.com")]
      mock_smtp.SMTP.return_value = MagicMock(
         connect=MagicMock(side_effect=Exception("connection refused"))
      )

      check = SMTPReconCheck()
      result = check.run("example.com")
      assert result.score == 3
      assert result.reason == "minimal_exposure"
