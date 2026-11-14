from unittest.mock import patch
from mercure.checks.axfr import AXFRCheck


class TestAXFRCheck:
   @patch("mercure.checks.axfr.query_ns", return_value=[])
   def test_no_ns(self, mock_ns):
      result = AXFRCheck().run("example.com")
      assert result.score == 1
      assert result.reason == "no_ns"

   @patch("mercure.checks.axfr.attempt_axfr", return_value=[])
   @patch("mercure.checks.axfr.query_ns", return_value=["ns1.example.com", "ns2.example.com"])
   def test_axfr_denied(self, mock_ns, mock_axfr):
      result = AXFRCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "axfr_denied"

   @patch("mercure.checks.axfr.attempt_axfr")
   @patch("mercure.checks.axfr.query_ns", return_value=["ns1.example.com"])
   def test_axfr_allowed(self, mock_ns, mock_axfr):
      mock_axfr.return_value = ["@", "www", "mail", "ftp"]
      result = AXFRCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "axfr_allowed"
      assert "ns1.example.com" in result.details["vulnerable_ns"]
      assert result.details["vulnerable_ns"]["ns1.example.com"] == 4

   @patch("mercure.checks.axfr.attempt_axfr")
   @patch("mercure.checks.axfr.query_ns", return_value=["ns1.example.com", "ns2.example.com"])
   def test_partial_axfr(self, mock_ns, mock_axfr):
      mock_axfr.side_effect = [["@", "www"], []]
      result = AXFRCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "axfr_allowed"
