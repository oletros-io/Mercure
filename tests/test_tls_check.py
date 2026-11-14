from unittest.mock import patch, MagicMock
from mercure.checks.tls_check import TLSCheck


def _web_info(**overrides):
   base = {
      "connected": True, "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
      "cipher_bits": 256, "self_signed": False, "error": "",
      "cert_subject": {}, "cert_issuer": {}, "cert_san": [],
      "cert_not_before": "", "cert_not_after": "", "cert_serial": "",
   }
   base.update(overrides)
   return base


def _mx_info(**overrides):
   base = {
      "connected": True, "starttls_offered": True, "starttls_success": True,
      "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384",
      "cipher_bits": 256, "error": "",
   }
   base.update(overrides)
   return base


class TestTLSCheck:
   @patch("mercure.checks.tls_check.get_smtp_tls_info")
   @patch("mercure.checks.tls_check.query_mx", return_value=[(10, "mx.example.com")])
   @patch("mercure.checks.tls_check.get_tls_info")
   def test_good_tls(self, mock_tls, mock_mx, mock_smtp_tls):
      mock_tls.return_value = _web_info()
      mock_smtp_tls.return_value = _mx_info()
      result = TLSCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "tls_ok"

   @patch("mercure.checks.tls_check.get_smtp_tls_info")
   @patch("mercure.checks.tls_check.query_mx", return_value=[])
   @patch("mercure.checks.tls_check.get_tls_info")
   def test_no_tls(self, mock_tls, mock_mx, mock_smtp_tls):
      mock_tls.return_value = _web_info(connected=False)
      result = TLSCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "no_tls"

   @patch("mercure.checks.tls_check.get_smtp_tls_info")
   @patch("mercure.checks.tls_check.query_mx", return_value=[])
   @patch("mercure.checks.tls_check.get_tls_info")
   def test_self_signed(self, mock_tls, mock_mx, mock_smtp_tls):
      mock_tls.return_value = _web_info(self_signed=True)
      result = TLSCheck().run("example.com")
      assert result.score == 1
      assert result.reason == "self_signed"

   @patch("mercure.checks.tls_check.get_smtp_tls_info")
   @patch("mercure.checks.tls_check.query_mx", return_value=[(10, "mx.example.com")])
   @patch("mercure.checks.tls_check.get_tls_info")
   def test_mx_missing_starttls(self, mock_tls, mock_mx, mock_smtp_tls):
      mock_tls.return_value = _web_info()
      mock_smtp_tls.return_value = _mx_info(starttls_offered=False)
      result = TLSCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "mx_missing_starttls"

   @patch("mercure.checks.tls_check.get_smtp_tls_info")
   @patch("mercure.checks.tls_check.query_mx", return_value=[])
   @patch("mercure.checks.tls_check.get_tls_info")
   def test_deprecated_protocol(self, mock_tls, mock_mx, mock_smtp_tls):
      mock_tls.return_value = _web_info(protocol="TLSv1")
      result = TLSCheck().run("example.com")
      assert result.score == 1
      assert result.reason == "deprecated_protocol"
