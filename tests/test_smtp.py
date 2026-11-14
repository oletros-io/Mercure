from unittest.mock import patch, MagicMock
from mercure.smtp import direct_deliver, relay_deliver, relay_configured, amp_deliver


class TestDirectDeliver:
   @patch("mercure.smtp.resolve_ipv4", return_value="1.2.3.4")
   def test_successful_delivery(self, mock_ipv4, mock_smtp):
      _, mock_conn = mock_smtp
      result = direct_deliver("mx.example.com", 25, "sender@test.com",
                              ["rcpt@test.com"], b"test", "ehlo.test", 10)
      assert result["delivered"] is True
      assert result["connected"] is True

   @patch("mercure.smtp.resolve_ipv4", return_value="1.2.3.4")
   def test_rejected_mail_from(self, mock_ipv4, mock_smtp):
      _, mock_conn = mock_smtp
      mock_conn.mail.return_value = (550, b"Rejected")
      result = direct_deliver("mx.example.com", 25, "sender@test.com",
                              ["rcpt@test.com"], b"test", "ehlo.test", 10)
      assert result["delivered"] is False
      assert result["mail_from_code"] == 550

   @patch("mercure.smtp.resolve_ipv4", return_value="1.2.3.4")
   def test_ehlo_rejected(self, mock_ipv4, mock_smtp):
      _, mock_conn = mock_smtp
      mock_conn.ehlo.return_value = (500, b"Bad")
      result = direct_deliver("mx.example.com", 25, "sender@test.com",
                              ["rcpt@test.com"], b"test", "ehlo.test", 10)
      assert result["delivered"] is False
      assert result["error"] == "EHLO rejected: 500"


class TestRelayDeliver:
   def test_successful_relay(self, mock_smtp):
      _, mock_conn = mock_smtp
      result = relay_deliver("sender@test.com", ["rcpt@test.com"], b"test", 10)
      assert result["delivered"] is True
      assert result["authenticated"] is True

   def test_auth_failure(self, mock_smtp):
      smtplib_mock, mock_conn = mock_smtp
      import smtplib
      mock_conn.login.side_effect = smtplib.SMTPAuthenticationError(535, b"Auth failed")
      result = relay_deliver("sender@test.com", ["rcpt@test.com"], b"test", 10)
      assert result["delivered"] is False
      assert "auth failed" in result["error"]


class TestRelayConfigured:
   def test_configured(self, reset_config):
      from mercure.config import Config
      from mercure import config as cfg
      cfg.config.reset(Config(
         smtp_relay_host="relay.test", smtp_relay_user="user",
         smtp_relay_pass="pass",
      ))
      assert relay_configured() is True

   def test_not_configured(self):
      assert relay_configured() is False


class TestAmpDeliver:
   @patch("mercure.smtp.resolve_ipv4", return_value="1.2.3.4")
   def test_multi_recipient(self, mock_ipv4, mock_smtp):
      _, mock_conn = mock_smtp
      recipients = ["dead1@test.com", "dead2@test.com", "dead3@test.com"]
      result = amp_deliver("mx.test.com", 25, "victim@test.com",
                           recipients, b"test", "ehlo.test", 10)
      assert result["delivered"] is True
      assert result["total_recipients"] == 3
