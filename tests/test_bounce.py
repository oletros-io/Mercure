from unittest.mock import patch
from mercure.checks.bounce import BounceCheck


class TestBounceCheck:
   @patch("mercure.checks.bounce.relay_configured", return_value=False)
   def test_relay_not_configured(self, mock_relay_cfg):
      check = BounceCheck()
      result = check.run("example.com")
      assert result.score == 2
      assert result.reason == "relay_not_configured"

   @patch("mercure.checks.bounce.relay_deliver")
   @patch("mercure.checks.bounce.relay_configured", return_value=True)
   def test_recipient_validated(self, mock_relay_cfg, mock_deliver):
      mock_deliver.return_value = {
         "connected": True, "delivered": False,
         "mail_from_code": 250, "mail_from_msg": "OK",
         "rcpt_to_code": 550, "rcpt_to_msg": "User unknown",
         "data_code": 0, "data_msg": "", "error": "",
      }
      check = BounceCheck()
      result = check.run("example.com")
      assert result.score == 3
      assert result.reason == "recipient_validated"
      assert result.details["recipient_validation"] == "before_accept"
      assert result.details["ndr_risk"] == "none"

   @patch("mercure.checks.bounce.relay_deliver")
   @patch("mercure.checks.bounce.relay_configured", return_value=True)
   def test_accepts_invalid_recipients(self, mock_relay_cfg, mock_deliver):
      mock_deliver.return_value = {
         "connected": True, "delivered": True,
         "mail_from_code": 250, "mail_from_msg": "OK",
         "rcpt_to_code": 250, "rcpt_to_msg": "OK",
         "data_code": 250, "data_msg": "Queued",
         "error": "",
      }
      check = BounceCheck()
      result = check.run("example.com")
      assert result.score == 1
      assert result.reason == "accepts_invalid_recipients"
      assert result.details["ndr_risk"] == "high"

   @patch("mercure.checks.bounce.relay_deliver")
   @patch("mercure.checks.bounce.relay_configured", return_value=True)
   def test_delivery_error(self, mock_relay_cfg, mock_deliver):
      mock_deliver.return_value = {
         "connected": False, "delivered": False,
         "mail_from_code": 0, "mail_from_msg": "",
         "rcpt_to_code": 0, "rcpt_to_msg": "",
         "data_code": 0, "data_msg": "",
         "error": "connection timeout",
      }
      check = BounceCheck()
      result = check.run("example.com")
      assert result.score == 2
      assert result.reason == "delivery_error"

   @patch("mercure.checks.bounce.relay_deliver")
   @patch("mercure.checks.bounce.relay_configured", return_value=True)
   def test_sender_rejected(self, mock_relay_cfg, mock_deliver):
      mock_deliver.return_value = {
         "connected": True, "delivered": False,
         "mail_from_code": 550, "mail_from_msg": "Sender rejected",
         "rcpt_to_code": 0, "rcpt_to_msg": "",
         "data_code": 0, "data_msg": "",
         "error": "",
      }
      check = BounceCheck()
      result = check.run("example.com")
      assert result.score == 3
      assert result.reason == "sender_rejected"
