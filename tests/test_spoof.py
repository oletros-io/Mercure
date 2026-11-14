from unittest.mock import patch, MagicMock
from mercure.spoof import (
   build_email, _sender_domain, _status_from_result,
   _format_reason, method_ghost, run_spoof,
)


class TestBuildEmail:
   def test_basic(self):
      msg = build_email("mercure@example.com", "victim@test.com", "direct")
      assert msg["From"] == "mercure@example.com"
      assert msg["To"] == "victim@test.com"
      assert "direct" in msg["Subject"]
      assert msg["X-Oletros-Tool"] == "https://oletros.io/"

   def test_from_override(self):
      msg = build_email("mercure@example.com", "victim@test.com", "display_name",
                        from_override='"CEO" <noreply@example.com>')
      assert msg["From"] == '"CEO" <noreply@example.com>'

   def test_message_id_format(self):
      msg = build_email("mercure@example.com", "victim@test.com")
      assert "@example.com>" in msg["Message-ID"]


class TestSenderDomain:
   def test_normal(self):
      assert _sender_domain("user@example.com") == "example.com"

   def test_no_at(self):
      assert _sender_domain("noatsign") == "mail.local"


class TestStatusFromResult:
   def test_delivered(self):
      assert _status_from_result({"delivered": True, "connected": True}) == "delivered"

   def test_rejected(self):
      assert _status_from_result({"delivered": False, "connected": True}) == "rejected"

   def test_error(self):
      assert _status_from_result({"delivered": False, "connected": False}) == "error"


class TestFormatReason:
   def test_error(self):
      assert _format_reason({"error": "timeout"}) == "timeout"

   def test_delivered(self):
      r = _format_reason({"delivered": True, "data_code": 250, "data_msg": "OK", "error": ""})
      assert "250" in r

   def test_mail_from_rejection(self):
      r = _format_reason({
         "error": "", "delivered": False, "mail_from_code": 550,
         "mail_from_msg": "Denied", "rcpt_to_code": 0, "data_code": 0,
      })
      assert "MAIL FROM" in r


class TestMethodGhost:
   @patch("mercure.spoof.exo_endpoint_resolves", return_value=[])
   @patch("mercure.spoof.derive_exo_endpoint", return_value="ep.test")
   def test_not_exo(self, mock_derive, mock_resolves):
      result = method_ghost("mercure@test.com", "victim@other.com", 5)
      assert result["status"] == "skip"

   @patch("mercure.spoof.direct_deliver")
   @patch("mercure.spoof.mx_points_to_exo", return_value=(False, [], ["mx.seg.com"]))
   @patch("mercure.spoof.exo_endpoint_resolves", return_value=["1.2.3.4"])
   @patch("mercure.spoof.derive_exo_endpoint", return_value="ep.test")
   def test_vulnerable(self, mock_derive, mock_resolves, mock_mx, mock_deliver):
      mock_deliver.return_value = {
         "server": "ep.test:25", "connected": True, "delivered": True,
         "data_code": 250, "data_msg": "OK", "error": "",
         "mail_from_code": 250, "mail_from_msg": "OK",
         "rcpt_to_code": 250, "rcpt_to_msg": "OK",
      }
      result = method_ghost("mercure@test.com", "victim@other.com", 5)
      assert result["status"] == "delivered"


class TestRunSpoof:
   @patch("mercure.spoof.method_bs_oob")
   @patch("mercure.spoof.method_bs_amp")
   @patch("mercure.spoof.method_bs_inject")
   @patch("mercure.spoof.method_backscatter")
   @patch("mercure.spoof.method_internal")
   @patch("mercure.spoof.method_display_name")
   @patch("mercure.spoof.method_mismatch")
   @patch("mercure.spoof.method_relay")
   @patch("mercure.spoof.method_subdomain")
   @patch("mercure.spoof.method_null_from")
   @patch("mercure.spoof.method_ghost")
   @patch("mercure.spoof.method_direct")
   def test_runs_all_methods_sequential(self, *mocks):
      for m in mocks:
         m.return_value = {"method": "test", "status": "rejected",
                           "server": "mx:25", "reason": "blocked"}
      results = run_spoof("target.com", "victim@test.com", parallel=False)
      assert len(results) == 12
      for m in mocks:
         m.assert_called_once()

   @patch("mercure.spoof.method_bs_oob")
   @patch("mercure.spoof.method_bs_amp")
   @patch("mercure.spoof.method_bs_inject")
   @patch("mercure.spoof.method_backscatter")
   @patch("mercure.spoof.method_internal")
   @patch("mercure.spoof.method_display_name")
   @patch("mercure.spoof.method_mismatch")
   @patch("mercure.spoof.method_relay")
   @patch("mercure.spoof.method_subdomain")
   @patch("mercure.spoof.method_null_from")
   @patch("mercure.spoof.method_ghost")
   @patch("mercure.spoof.method_direct")
   def test_runs_all_methods_parallel(self, *mocks):
      for m in mocks:
         m.return_value = {"method": "test", "status": "rejected",
                           "server": "mx:25", "reason": "blocked"}
      results = run_spoof("target.com", "victim@test.com", parallel=True)
      assert len(results) == 12
