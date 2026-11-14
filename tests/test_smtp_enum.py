import smtplib
from unittest.mock import patch, MagicMock
from mercure.checks.smtp_enum import SMTPEnumCheck, COMMON_USERS


def _mock_conn(has_starttls=False):
   conn = MagicMock()
   conn.connect.return_value = (220, b"220 ESMTP ready")
   conn.ehlo.return_value = (250, b"OK")
   conn.has_extn.side_effect = lambda ext: ext == "STARTTLS" and has_starttls
   conn.starttls.return_value = None
   conn.mail.return_value = (250, b"OK")
   conn.rset.return_value = (250, b"OK")
   conn.quit.return_value = None
   return conn


class TestSMTPEnumCheck:
   @patch("mercure.checks.smtp_enum.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.smtp_enum.smtplib")
   @patch("mercure.checks.smtp_enum.query_mx")
   def test_user_enumeration(self, mock_mx, mock_smtp, mock_ipv4):
      mock_mx.return_value = [(10, "mx.example.com")]
      conn = _mock_conn()
      valid_users = {"postmaster", "admin", "abuse", "info", "contact", "support"}

      def fake_rcpt(addr):
         user = addr.split("@")[0]
         if user in valid_users:
            return (250, b"OK")
         return (550, b"User unknown")

      conn.rcpt.side_effect = fake_rcpt
      mock_smtp.SMTP.return_value = conn

      check = SMTPEnumCheck()
      result = check.run("example.com")
      assert result.score == 0
      assert result.reason == "user_enumeration"
      assert len(result.details["valid"]) > 2
      assert len(result.details["invalid"]) > 2

   @patch("mercure.checks.smtp_enum.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.smtp_enum.smtplib")
   @patch("mercure.checks.smtp_enum.query_mx")
   def test_catch_all(self, mock_mx, mock_smtp, mock_ipv4):
      mock_mx.return_value = [(10, "mx.example.com")]
      conn = _mock_conn()
      conn.rcpt.return_value = (250, b"OK")
      mock_smtp.SMTP.return_value = conn

      check = SMTPEnumCheck()
      result = check.run("example.com")
      assert result.score == 1
      assert result.reason == "catch_all"
      assert result.details["catch_all"] is True

   @patch("mercure.checks.smtp_enum.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.smtp_enum.smtplib")
   @patch("mercure.checks.smtp_enum.query_mx")
   def test_all_rejected(self, mock_mx, mock_smtp, mock_ipv4):
      mock_mx.return_value = [(10, "mx.example.com")]
      conn = _mock_conn()
      conn.rcpt.return_value = (550, b"User unknown")
      mock_smtp.SMTP.return_value = conn

      check = SMTPEnumCheck()
      result = check.run("example.com")
      assert result.score == 3
      assert result.reason == "all_rejected"

   @patch("mercure.checks.smtp_enum.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.smtp_enum.smtplib")
   @patch("mercure.checks.smtp_enum.query_mx")
   def test_rcpt_blocked_530(self, mock_mx, mock_smtp, mock_ipv4):
      mock_mx.return_value = [(10, "mx.example.com")]
      conn = _mock_conn()
      conn.rcpt.return_value = (530, b"Authentication required")
      mock_smtp.SMTP.return_value = conn

      check = SMTPEnumCheck()
      result = check.run("example.com")
      assert result.score == 3
      assert result.reason == "rcpt_blocked"
      assert result.details["blocked"] is True

   @patch("mercure.checks.smtp_enum.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.smtp_enum.smtplib")
   @patch("mercure.checks.smtp_enum.query_mx")
   def test_mail_from_rejected(self, mock_mx, mock_smtp, mock_ipv4):
      mock_mx.return_value = [(10, "mx.example.com")]
      conn = _mock_conn()
      conn.mail.return_value = (550, b"Sender rejected")
      mock_smtp.SMTP.return_value = conn

      check = SMTPEnumCheck()
      result = check.run("example.com")
      assert result.score == 3
      assert result.reason == "mail_from_rejected"

   @patch("mercure.checks.smtp_enum.query_mx")
   def test_no_mx(self, mock_mx):
      mock_mx.return_value = []
      check = SMTPEnumCheck()
      result = check.run("example.com")
      assert result.score == 2
      assert result.reason == "no_mx"

   @patch("mercure.checks.smtp_enum.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.smtp_enum.smtplib")
   @patch("mercure.checks.smtp_enum.query_mx")
   def test_partial_enum(self, mock_mx, mock_smtp, mock_ipv4):
      mock_mx.return_value = [(10, "mx.example.com")]
      conn = _mock_conn()
      call_count = [0]

      def fake_rcpt(addr):
         call_count[0] += 1
         user = addr.split("@")[0]
         if user == "postmaster":
            return (250, b"OK")
         if user == "admin":
            return (550, b"Unknown")
         return (452, b"Try later")

      conn.rcpt.side_effect = fake_rcpt
      mock_smtp.SMTP.return_value = conn

      check = SMTPEnumCheck()
      result = check.run("example.com")
      assert result.score == 2

   @patch("mercure.checks.smtp_enum.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.smtp_enum.smtplib")
   @patch("mercure.checks.smtp_enum.query_mx")
   def test_disconnected_mid_enum(self, mock_mx, mock_smtp, mock_ipv4):
      mock_mx.return_value = [(10, "mx.example.com")]
      mock_smtp.SMTPServerDisconnected = smtplib.SMTPServerDisconnected
      conn = _mock_conn()
      conn.rcpt.side_effect = smtplib.SMTPServerDisconnected("gone")
      mock_smtp.SMTP.return_value = conn

      check = SMTPEnumCheck()
      result = check.run("example.com")
      assert result.score == 3
      assert result.details["blocked"] is True
