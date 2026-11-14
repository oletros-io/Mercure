from unittest.mock import patch, MagicMock
from mercure.checks.smtp_sec import (
   SMTPSecCheck, _probe_banner, _probe_vrfy, _probe_open_relay,
)


def _mock_conn(banner=b"220 ESMTP ready", ehlo_code=250, has_starttls=True):
   conn = MagicMock()
   conn.connect.return_value = (220, banner)
   conn.ehlo.return_value = (ehlo_code, b"OK")
   conn.has_extn.side_effect = lambda ext: ext == "STARTTLS" and has_starttls
   conn.mail.return_value = (250, b"OK")
   conn.rcpt.return_value = (550, b"Relay denied")
   conn.vrfy.return_value = (502, b"Not implemented")
   conn.expn.return_value = (502, b"Not implemented")
   conn.rset.return_value = (250, b"OK")
   conn.starttls.return_value = None
   conn.sock = MagicMock()
   if has_starttls:
      conn.sock.version.return_value = "TLSv1.3"
      conn.sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
   return conn


class TestProbeBanner:
   @patch("mercure.checks.smtp_sec.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.smtp_sec.smtplib")
   def test_version_disclosed(self, mock_smtplib, mock_ipv4):
      mock_smtplib.SMTP.return_value = _mock_conn(banner=b"220 mail.example.com Postfix 3.8.1")
      result = _probe_banner("mx.example.com")
      assert result["version_disclosed"] is True
      assert result["software"] == "Postfix"

   @patch("mercure.checks.smtp_sec.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.smtp_sec.smtplib")
   def test_no_version(self, mock_smtplib, mock_ipv4):
      mock_smtplib.SMTP.return_value = _mock_conn(banner=b"220 ESMTP ready")
      result = _probe_banner("mx.example.com")
      assert result["version_disclosed"] is False
      assert result["software"] == ""


class TestProbeVrfy:
   @patch("mercure.checks.smtp_sec.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.smtp_sec.smtplib")
   def test_vrfy_enabled(self, mock_smtplib, mock_ipv4):
      conn = _mock_conn()
      conn.vrfy.return_value = (252, b"Cannot VRFY user")
      mock_smtplib.SMTP.return_value = conn
      result = _probe_vrfy("mx.example.com")
      assert result["vrfy_enabled"] is True
      assert result["vrfy_code"] == 252

   @patch("mercure.checks.smtp_sec.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.smtp_sec.smtplib")
   def test_vrfy_disabled(self, mock_smtplib, mock_ipv4):
      mock_smtplib.SMTP.return_value = _mock_conn()
      result = _probe_vrfy("mx.example.com")
      assert result["vrfy_enabled"] is False


class TestProbeOpenRelay:
   @patch("mercure.checks.smtp_sec.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.smtp_sec.smtplib")
   def test_open_relay_detected(self, mock_smtplib, mock_ipv4):
      conn = _mock_conn()
      conn.rcpt.return_value = (250, b"OK")
      mock_smtplib.SMTP.return_value = conn
      result = _probe_open_relay("mx.example.com")
      assert result["open_relay"] is True

   @patch("mercure.checks.smtp_sec.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.smtp_sec.smtplib")
   def test_relay_denied(self, mock_smtplib, mock_ipv4):
      mock_smtplib.SMTP.return_value = _mock_conn()
      result = _probe_open_relay("mx.example.com")
      assert result["open_relay"] is False


class TestSMTPSecCheck:
   @patch("mercure.checks.smtp_sec._probe_smuggling")
   @patch("mercure.checks.smtp_sec._probe_open_relay")
   @patch("mercure.checks.smtp_sec._probe_vrfy")
   @patch("mercure.checks.smtp_sec._probe_starttls")
   @patch("mercure.checks.smtp_sec._probe_banner")
   @patch("mercure.checks.smtp_sec.query_mx")
   def test_hardened(self, mock_mx, mock_banner, mock_tls, mock_vrfy, mock_relay, mock_smug):
      mock_mx.return_value = [(10, "mx.example.com")]
      mock_banner.return_value = {"banner": "220 ESMTP", "version_disclosed": False, "software": ""}
      mock_tls.return_value = {"offered": True, "success": True, "protocol": "TLSv1.3", "cipher": "AES256"}
      mock_vrfy.return_value = {"vrfy_enabled": False, "vrfy_code": 502, "expn_enabled": False, "expn_code": 502}
      mock_relay.return_value = {"open_relay": False, "rcpt_code": 550}
      mock_smug.return_value = {"vulnerable": False, "accepts_bare_lf": False}
      check = SMTPSecCheck()
      result = check.run("example.com")
      assert result.score == 3
      assert result.reason == "smtp_hardened"

   @patch("mercure.checks.smtp_sec._probe_smuggling")
   @patch("mercure.checks.smtp_sec._probe_open_relay")
   @patch("mercure.checks.smtp_sec._probe_vrfy")
   @patch("mercure.checks.smtp_sec._probe_starttls")
   @patch("mercure.checks.smtp_sec._probe_banner")
   @patch("mercure.checks.smtp_sec.query_mx")
   def test_open_relay(self, mock_mx, mock_banner, mock_tls, mock_vrfy, mock_relay, mock_smug):
      mock_mx.return_value = [(10, "mx.example.com")]
      mock_banner.return_value = {"banner": "220 ESMTP", "version_disclosed": False, "software": ""}
      mock_tls.return_value = {"offered": True, "success": True, "protocol": "TLSv1.3", "cipher": "AES256"}
      mock_vrfy.return_value = {"vrfy_enabled": False, "vrfy_code": 502, "expn_enabled": False, "expn_code": 502}
      mock_relay.return_value = {"open_relay": True, "rcpt_code": 250}
      mock_smug.return_value = {"vulnerable": False, "accepts_bare_lf": False}
      check = SMTPSecCheck()
      result = check.run("example.com")
      assert result.score == 0
      assert result.reason == "open_relay"

   @patch("mercure.checks.smtp_sec._probe_smuggling")
   @patch("mercure.checks.smtp_sec._probe_open_relay")
   @patch("mercure.checks.smtp_sec._probe_vrfy")
   @patch("mercure.checks.smtp_sec._probe_starttls")
   @patch("mercure.checks.smtp_sec._probe_banner")
   @patch("mercure.checks.smtp_sec.query_mx")
   def test_user_enumeration(self, mock_mx, mock_banner, mock_tls, mock_vrfy, mock_relay, mock_smug):
      mock_mx.return_value = [(10, "mx.example.com")]
      mock_banner.return_value = {"banner": "220 ESMTP", "version_disclosed": False, "software": ""}
      mock_tls.return_value = {"offered": True, "success": True, "protocol": "TLSv1.3", "cipher": "AES256"}
      mock_vrfy.return_value = {"vrfy_enabled": True, "vrfy_code": 250, "expn_enabled": False, "expn_code": 502}
      mock_relay.return_value = {"open_relay": False, "rcpt_code": 550}
      mock_smug.return_value = {"vulnerable": False, "accepts_bare_lf": False}
      check = SMTPSecCheck()
      result = check.run("example.com")
      assert result.score == 1
      assert result.reason == "user_enumeration"

   @patch("mercure.checks.smtp_sec.query_mx")
   def test_no_mx(self, mock_mx):
      mock_mx.return_value = []
      check = SMTPSecCheck()
      result = check.run("example.com")
      assert result.score == 2
      assert result.reason == "no_mx"
