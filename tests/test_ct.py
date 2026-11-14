from unittest.mock import patch
from mercure.checks.ct import CTCheck


class TestCTCheck:
   @patch("mercure.checks.ct.crtsh_subdomains")
   def test_ct_monitored(self, mock_crt):
      mock_crt.return_value = ["example.com", "www.example.com", "mail.example.com"]
      result = CTCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "ct_monitored"
      assert result.details["total_subdomains"] == 3

   @patch("mercure.checks.ct.crtsh_subdomains")
   def test_no_ct_records(self, mock_crt):
      mock_crt.return_value = []
      result = CTCheck().run("example.com")
      assert result.score == 1
      assert result.reason == "no_ct_records"

   @patch("mercure.checks.ct.crtsh_subdomains")
   def test_wildcard_counted(self, mock_crt):
      mock_crt.return_value = ["*.example.com", "example.com", "www.example.com"]
      result = CTCheck().run("example.com")
      assert result.details["wildcard_count"] == 1

   @patch("mercure.checks.ct.crtsh_subdomains")
   def test_sample_capped(self, mock_crt):
      mock_crt.return_value = [f"sub{i}.example.com" for i in range(50)]
      result = CTCheck().run("example.com")
      assert len(result.details["sample"]) == 20

   def test_external_flag(self):
      assert CTCheck.external is True
