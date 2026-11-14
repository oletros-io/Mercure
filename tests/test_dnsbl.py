from unittest.mock import patch
from mercure.checks.dnsbl import DNSBLCheck


class TestDNSBLCheck:
   @patch("mercure.checks.dnsbl.query_a", return_value=[])
   def test_no_a_record(self, mock_a):
      result = DNSBLCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "no_a_record"

   @patch("mercure.checks.dnsbl.query_dnsbl", return_value=False)
   @patch("mercure.checks.dnsbl.query_a", return_value=["1.2.3.4"])
   def test_clean(self, mock_a, mock_dnsbl):
      result = DNSBLCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "clean"
      assert result.details["checked_ips"] == ["1.2.3.4"]

   @patch("mercure.checks.dnsbl.query_dnsbl")
   @patch("mercure.checks.dnsbl.query_a", return_value=["1.2.3.4"])
   def test_blacklisted(self, mock_a, mock_dnsbl):
      mock_dnsbl.side_effect = lambda ip, bl: bl == "zen.spamhaus.org"
      result = DNSBLCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "blacklisted"
      assert "zen.spamhaus.org" in result.details["listed"]["1.2.3.4"]

   @patch("mercure.checks.dnsbl.query_dnsbl", return_value=True)
   @patch("mercure.checks.dnsbl.query_a", return_value=["1.2.3.4", "5.6.7.8"])
   def test_multiple_ips_blacklisted(self, mock_a, mock_dnsbl):
      result = DNSBLCheck().run("example.com")
      assert result.score == 0
      assert "1.2.3.4" in result.details["listed"]
      assert "5.6.7.8" in result.details["listed"]
