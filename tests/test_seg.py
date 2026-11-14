from unittest.mock import patch
from mercure.checks.seg import SEGCheck, fingerprint_mx, fingerprint_spf


class TestFingerprintMx:
   def test_proofpoint(self):
      assert fingerprint_mx("mx1.pphosted.com") == "proofpoint"

   def test_mimecast(self):
      assert fingerprint_mx("eu-smtp.mimecast.com") == "mimecast"

   def test_google(self):
      assert fingerprint_mx("aspmx.l.google.com") == "google_workspace"

   def test_microsoft(self):
      assert fingerprint_mx("example-com.mail.protection.outlook.com") == "microsoft_365"

   def test_unknown(self):
      assert fingerprint_mx("mx.random-host.com") == ""


class TestFingerprintSpf:
   def test_google_spf(self):
      records = ["v=spf1 include:_spf.google.com -all"]
      assert "google_workspace" in fingerprint_spf(records)

   def test_no_spf(self):
      assert fingerprint_spf(["random-txt"]) == []


class TestSEGCheck:
   @patch("mercure.checks.seg.query_txt")
   @patch("mercure.checks.seg.query_mx")
   def test_no_mx(self, mock_mx, mock_txt):
      mock_mx.return_value = []
      mock_txt.return_value = []
      result = SEGCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "no_mx"

   @patch("mercure.checks.seg.query_txt")
   @patch("mercure.checks.seg.query_mx")
   def test_single_seg(self, mock_mx, mock_txt):
      mock_mx.return_value = [(10, "mx1.pphosted.com")]
      mock_txt.return_value = ["v=spf1 -all"]
      result = SEGCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "single_seg"
      assert "proofpoint" in result.details["gateways"]

   @patch("mercure.checks.seg.query_txt")
   @patch("mercure.checks.seg.query_mx")
   def test_multi_layer(self, mock_mx, mock_txt):
      mock_mx.return_value = [(10, "mx1.pphosted.com")]
      mock_txt.return_value = ["v=spf1 include:spf.protection.outlook.com -all"]
      result = SEGCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "multi_layer_seg"

   @patch("mercure.checks.seg.query_txt")
   @patch("mercure.checks.seg.query_mx")
   def test_no_seg_detected(self, mock_mx, mock_txt):
      mock_mx.return_value = [(10, "mx.random-isp.com")]
      mock_txt.return_value = ["v=spf1 -all"]
      result = SEGCheck().run("example.com")
      assert result.score == 1
      assert result.reason == "no_seg_detected"
