from unittest.mock import patch
from mercure.checks.dmarc_ext import DMARCExtCheck


class TestDMARCExtCheck:
   @patch("mercure.checks.dmarc_ext.query_txt")
   def test_no_dmarc(self, mock_txt):
      mock_txt.return_value = []
      result = DMARCExtCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "no_dmarc_reporting"

   @patch("mercure.checks.dmarc_ext.query_txt")
   def test_internal_reports(self, mock_txt):
      def side_effect(name):
         if name == "_dmarc.example.com":
            return ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
         return []
      mock_txt.side_effect = side_effect
      result = DMARCExtCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "internal_reports_only"

   @patch("mercure.checks.dmarc_ext.query_txt")
   def test_authorized_external(self, mock_txt):
      def side_effect(name):
         if name == "_dmarc.example.com":
            return ["v=DMARC1; p=reject; rua=mailto:dmarc@external.com"]
         if name == "example.com._report._dmarc.external.com":
            return ["v=DMARC1"]
         return []
      mock_txt.side_effect = side_effect
      result = DMARCExtCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "external_reports_authorized"

   @patch("mercure.checks.dmarc_ext.query_txt")
   def test_unauthorized_external(self, mock_txt):
      def side_effect(name):
         if name == "_dmarc.example.com":
            return ["v=DMARC1; p=reject; rua=mailto:dmarc@external.com"]
         return []
      mock_txt.side_effect = side_effect
      result = DMARCExtCheck().run("example.com")
      assert result.score == 1
      assert result.reason == "unauthorized_external_report"

   @patch("mercure.checks.dmarc_ext.query_txt")
   def test_no_rua_ruf(self, mock_txt):
      def side_effect(name):
         if name == "_dmarc.example.com":
            return ["v=DMARC1; p=reject"]
         return []
      mock_txt.side_effect = side_effect
      result = DMARCExtCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "no_dmarc_reporting"
