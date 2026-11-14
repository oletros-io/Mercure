from unittest.mock import patch
from mercure.checks.spf_recon import SPFReconCheck


class TestSPFReconCheck:
   @patch("mercure.checks.spf_recon.query_txt", return_value=[])
   def test_no_spf(self, mock_txt):
      result = SPFReconCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "no_spf"
      assert result.details["total_includes"] == 0

   @patch("mercure.checks.spf_recon.query_txt")
   def test_tight_spf(self, mock_txt):
      mock_txt.return_value = ["v=spf1 ip4:203.0.113.0/28 -all"]
      result = SPFReconCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "tight_spf"
      assert result.details["total_includes"] == 0
      assert "203.0.113.0/28" in result.details["ip4_ranges"]

   @patch("mercure.checks.spf_recon.query_txt")
   def test_moderate_spf(self, mock_txt):
      def _txt(name):
         records = {
            "example.com": ["v=spf1 include:_spf.google.com include:spf.mailgun.org -all"],
            "_spf.google.com": ["v=spf1 ip4:35.190.247.0/24 ~all"],
            "spf.mailgun.org": ["v=spf1 ip4:209.61.151.0/24 ~all"],
         }
         return records.get(name, [])
      mock_txt.side_effect = _txt
      result = SPFReconCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "moderate_spf"
      assert result.details["total_includes"] == 2

   @patch("mercure.checks.spf_recon.query_txt")
   def test_broad_spf_many_includes(self, mock_txt):
      def _txt(name):
         records = {
            "example.com": ["v=spf1 include:_spf.google.com include:spf.protection.outlook.com include:sendgrid.net include:spf.mailgun.org include:mail.zendesk.com include:spf.mandrillapp.com -all"],
            "_spf.google.com": ["v=spf1 ip4:35.190.247.0/24 ~all"],
            "spf.protection.outlook.com": ["v=spf1 ip4:40.107.0.0/16 ~all"],
            "sendgrid.net": ["v=spf1 ip4:167.89.0.0/17 ~all"],
            "spf.mailgun.org": ["v=spf1 ip4:209.61.151.0/24 ~all"],
            "mail.zendesk.com": ["v=spf1 ip4:192.161.144.0/20 ~all"],
            "spf.mandrillapp.com": ["v=spf1 ip4:198.2.128.0/18 ~all"],
         }
         return records.get(name, [])
      mock_txt.side_effect = _txt
      result = SPFReconCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "extremely_broad_spf"
      assert result.details["esps_count"] >= 5

   @patch("mercure.checks.spf_recon.query_txt")
   def test_broad_range_detection(self, mock_txt):
      mock_txt.return_value = ["v=spf1 ip4:10.0.0.0/8 -all"]
      result = SPFReconCheck().run("example.com")
      assert result.score == 0
      assert len(result.details["broad_ranges"]) > 0
      assert result.details["broad_ranges"][0]["prefix_len"] == 8

   @patch("mercure.checks.spf_recon.query_txt")
   def test_redirect_followed(self, mock_txt):
      def _txt(name):
         records = {
            "example.com": ["v=spf1 redirect=_spf.example.net"],
            "_spf.example.net": ["v=spf1 ip4:203.0.113.0/28 -all"],
         }
         return records.get(name, [])
      mock_txt.side_effect = _txt
      result = SPFReconCheck().run("example.com")
      assert result.details["total_includes"] == 1
      assert len(result.details["ip4_ranges"]) == 1

   @patch("mercure.checks.spf_recon.query_txt")
   def test_circular_include_protection(self, mock_txt):
      def _txt(name):
         records = {
            "example.com": ["v=spf1 include:loop.example.com -all"],
            "loop.example.com": ["v=spf1 include:example.com -all"],
         }
         return records.get(name, [])
      mock_txt.side_effect = _txt
      result = SPFReconCheck().run("example.com")
      assert result.details["total_includes"] >= 1

   @patch("mercure.checks.spf_recon.query_txt")
   def test_missing_include_domain(self, mock_txt):
      def _txt(name):
         if name == "example.com":
            return ["v=spf1 include:nonexistent.example.com ip4:1.2.3.4/32 -all"]
         return []
      mock_txt.side_effect = _txt
      result = SPFReconCheck().run("example.com")
      assert result.score == 3
      assert "1.2.3.4/32" in result.details["ip4_ranges"]

   @patch("mercure.checks.spf_recon.query_txt")
   def test_ipv6_ranges(self, mock_txt):
      mock_txt.return_value = ["v=spf1 ip6:2001:db8::/32 -all"]
      result = SPFReconCheck().run("example.com")
      assert len(result.details["ip6_ranges"]) == 1
      assert result.details["ip6_ranges"][0] == "2001:db8::/32"
