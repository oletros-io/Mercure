from unittest.mock import patch, MagicMock
from mercure.checks.ghost import (
   derive_exo_endpoint, mx_points_to_exo, GhostSenderCheck,
)


class TestDeriveExoEndpoint:
   def test_simple_domain(self):
      assert derive_exo_endpoint("example.com") == "example-com.mail.protection.outlook.com"

   def test_subdomain(self):
      assert derive_exo_endpoint("mail.example.com") == "mail-example-com.mail.protection.outlook.com"

   def test_trailing_dot(self):
      assert derive_exo_endpoint("example.com.") == "example-com.mail.protection.outlook.com"


class TestMxPointsToExo:
   def test_direct_exo(self, mock_query_mx):
      mock_query_mx.return_value = [(10, "example-com.mail.protection.outlook.com")]
      direct, exo, third = mx_points_to_exo("example.com")
      assert direct is True
      assert len(exo) == 1
      assert len(third) == 0

   def test_third_party_seg(self, mock_query_mx):
      mock_query_mx.return_value = [(10, "mx1.proofpoint.com")]
      direct, exo, third = mx_points_to_exo("example.com")
      assert direct is False
      assert len(exo) == 0
      assert len(third) == 1

   def test_mixed(self, mock_query_mx):
      mock_query_mx.return_value = [
         (10, "mx1.proofpoint.com"),
         (20, "example-com.mail.protection.outlook.com"),
      ]
      direct, exo, third = mx_points_to_exo("example.com")
      assert direct is False
      assert len(exo) == 1
      assert len(third) == 1

   def test_no_mx(self, mock_query_mx):
      mock_query_mx.return_value = []
      direct, exo, third = mx_points_to_exo("example.com")
      assert direct is False


class TestGhostSenderCheck:
   def test_not_exchange_online(self, mock_query_mx, mock_query_a):
      mock_query_mx.return_value = [(10, "mx.google.com")]
      mock_query_a.return_value = []
      check = GhostSenderCheck()
      result = check.run("example.com")
      assert result.score == 3
      assert result.reason == "not_exchange_online"

   def test_mx_direct_to_exo(self, mock_query_mx, mock_query_a):
      mock_query_mx.return_value = [(10, "example-com.mail.protection.outlook.com")]
      mock_query_a.return_value = ["1.2.3.4"]
      check = GhostSenderCheck()
      result = check.run("example.com")
      assert result.score == 3
      assert result.reason == "mx_direct_to_exo"

   @patch("mercure.checks.ghost.smtp_probe")
   def test_partner_connector(self, mock_probe, mock_query_mx, mock_query_a):
      mock_query_mx.return_value = [(10, "mx1.proofpoint.com")]
      mock_query_a.return_value = ["1.2.3.4"]
      mock_probe.return_value = {
         "connected": True, "mitigated_5751": True,
         "accepts_spoofed_rcpt": False, "mail_from_code": 550,
         "rcpt_to_code": 0, "error": "",
      }
      check = GhostSenderCheck()
      result = check.run("example.com")
      assert result.score == 3
      assert result.reason == "partner_connector_configured"

   @patch("mercure.checks.ghost.smtp_probe")
   def test_vulnerable(self, mock_probe, mock_query_mx, mock_query_a):
      mock_query_mx.return_value = [(10, "mx1.proofpoint.com")]
      mock_query_a.return_value = ["1.2.3.4"]
      mock_probe.return_value = {
         "connected": True, "mitigated_5751": False,
         "accepts_spoofed_rcpt": True, "mail_from_code": 250,
         "rcpt_to_code": 250, "error": "",
      }
      check = GhostSenderCheck()
      result = check.run("example.com")
      assert result.score == 0
      assert result.reason == "ghost_sender_vulnerable"

   @patch("mercure.checks.ghost.smtp_probe")
   def test_exo_unreachable(self, mock_probe, mock_query_mx, mock_query_a):
      mock_query_mx.return_value = [(10, "mx1.proofpoint.com")]
      mock_query_a.return_value = ["1.2.3.4"]
      mock_probe.return_value = {
         "connected": False, "mitigated_5751": False,
         "accepts_spoofed_rcpt": False, "mail_from_code": 0,
         "rcpt_to_code": 0, "error": "connection failed",
      }
      check = GhostSenderCheck()
      result = check.run("example.com")
      assert result.score == 2
      assert result.reason == "exo_unreachable"
