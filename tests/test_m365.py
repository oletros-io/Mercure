from unittest.mock import patch, MagicMock
from mercure.checks.m365 import M365Check


class TestM365Check:
   @patch("mercure.checks.m365.get_tenant_id", return_value="")
   @patch("mercure.checks.m365.detect_sip_federation", return_value=False)
   @patch("mercure.checks.m365.detect_autodiscover", return_value=False)
   @patch("mercure.checks.m365.detect_mx_o365", return_value=False)
   def test_no_m365(self, mock_mx, mock_auto, mock_sip, mock_tenant):
      result = M365Check().run("example.com")
      assert result.score == 3
      assert result.reason == "no_m365"

   @patch("mercure.checks.m365.get_tenant_id", return_value="12345678-1234-1234-1234-123456789abc")
   @patch("mercure.checks.m365.detect_sip_federation", return_value=False)
   @patch("mercure.checks.m365.detect_autodiscover", return_value=True)
   @patch("mercure.checks.m365.detect_mx_o365", return_value=True)
   def test_tenant_exposed(self, mock_mx, mock_auto, mock_sip, mock_tenant):
      result = M365Check().run("example.com")
      assert result.score == 2
      assert result.reason == "m365_tenant_exposed"
      assert result.details["tenant_id"] == "12345678-1234-1234-1234-123456789abc"

   @patch("mercure.checks.m365.get_tenant_id", return_value="")
   @patch("mercure.checks.m365.detect_sip_federation", return_value=True)
   @patch("mercure.checks.m365.detect_autodiscover", return_value=False)
   @patch("mercure.checks.m365.detect_mx_o365", return_value=False)
   def test_detected_no_tenant(self, mock_mx, mock_auto, mock_sip, mock_tenant):
      result = M365Check().run("example.com")
      assert result.score == 2
      assert result.reason == "m365_detected"

   @patch("mercure.checks.m365.fetch")
   @patch("mercure.checks.m365.query_srv")
   @patch("mercure.checks.m365.query_cname")
   @patch("mercure.checks.m365.query_mx")
   def test_full_detection_path(self, mock_mx, mock_cname, mock_srv, mock_fetch):
      mock_mx.return_value = [(10, "example-com.mail.protection.outlook.com")]
      mock_cname.return_value = ["autodiscover.outlook.com"]
      mock_srv.return_value = [{"target": "sipfed.online.lync.com", "port": 5061, "priority": 100, "weight": 1}]
      resp = MagicMock()
      resp.status_code = 200
      resp.json.return_value = {"token_endpoint": "https://login.microsoftonline.com/abcdef01-2345-6789-abcd-ef0123456789/oauth2/token"}
      mock_fetch.return_value = resp
      result = M365Check().run("example.com")
      assert result.score == 2
      assert result.details["tenant_id"] == "abcdef01-2345-6789-abcd-ef0123456789"
