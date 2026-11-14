from unittest.mock import patch
from mercure.checks.tls_rpt import TLSRPTCheck, get_tls_rpt_record, parse_rua


class TestGetTlsRptRecord:
   @patch("mercure.checks.tls_rpt.query_txt")
   def test_found(self, mock_txt):
      mock_txt.return_value = ["v=TLSRPTv1; rua=mailto:tls@example.com"]
      assert "TLSRPTv1" in get_tls_rpt_record("example.com")

   @patch("mercure.checks.tls_rpt.query_txt")
   def test_not_found(self, mock_txt):
      mock_txt.return_value = []
      assert get_tls_rpt_record("example.com") == ""


class TestParseRua:
   def test_mailto(self):
      assert parse_rua("v=TLSRPTv1; rua=mailto:tls@example.com") == "mailto:tls@example.com"

   def test_no_rua(self):
      assert parse_rua("v=TLSRPTv1") == ""


class TestTLSRPTCheck:
   @patch("mercure.checks.tls_rpt.query_txt")
   def test_no_record(self, mock_txt):
      mock_txt.return_value = []
      result = TLSRPTCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "no_tls_rpt"

   @patch("mercure.checks.tls_rpt.query_txt")
   def test_configured(self, mock_txt):
      mock_txt.return_value = ["v=TLSRPTv1; rua=mailto:report@example.com"]
      result = TLSRPTCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "tls_rpt_configured"

   @patch("mercure.checks.tls_rpt.query_txt")
   def test_no_rua(self, mock_txt):
      mock_txt.return_value = ["v=TLSRPTv1"]
      result = TLSRPTCheck().run("example.com")
      assert result.score == 1
      assert result.reason == "no_reporting_address"
