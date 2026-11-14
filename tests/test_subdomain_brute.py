from unittest.mock import patch
from mercure.checks.subdomain_brute import SubdomainBruteCheck, SENSITIVE_PREFIXES


class TestSubdomainBruteCheck:
   @patch("mercure.checks.subdomain_brute.query_a")
   def test_no_subdomains(self, mock_a):
      mock_a.return_value = []
      result = SubdomainBruteCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "minimal_exposure"
      assert result.details["total_found"] == 0
      assert result.details["wildcard"] is False

   @patch("mercure.checks.subdomain_brute.query_a")
   def test_wildcard_detected(self, mock_a):
      def _resolve(name):
         return ["1.2.3.99"]
      mock_a.side_effect = _resolve
      result = SubdomainBruteCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "wildcard_active"
      assert result.details["wildcard"] is True
      assert result.details["wildcard_ip"] == "1.2.3.99"

   @patch("mercure.checks.subdomain_brute.query_a")
   def test_many_sensitive(self, mock_a):
      sensitive_subs = {
         "dev.example.com": ["1.2.3.1"],
         "staging.example.com": ["1.2.3.2"],
         "admin.example.com": ["1.2.3.3"],
         "jenkins.example.com": ["1.2.3.4"],
         "vpn.example.com": ["1.2.3.5"],
         "jira.example.com": ["1.2.3.6"],
      }
      def _resolve(name):
         if len(name) > 30:
            return []
         return sensitive_subs.get(name, [])
      mock_a.side_effect = _resolve
      result = SubdomainBruteCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "many_sensitive"
      assert result.details["sensitive_found"] == 6

   @patch("mercure.checks.subdomain_brute.query_a")
   def test_some_sensitive(self, mock_a):
      known = {
         "dev.example.com": ["1.2.3.1"],
         "www.example.com": ["1.2.3.2"],
         "mail.example.com": ["1.2.3.3"],
      }
      def _resolve(name):
         if len(name) > 30:
            return []
         return known.get(name, [])
      mock_a.side_effect = _resolve
      result = SubdomainBruteCheck().run("example.com")
      assert result.score == 1
      assert result.reason == "some_sensitive"
      assert result.details["sensitive_found"] == 1

   @patch("mercure.checks.subdomain_brute.query_a")
   def test_standard_only(self, mock_a):
      known = {
         "www.example.com": ["1.2.3.1"],
         "mail.example.com": ["1.2.3.2"],
         "ftp.example.com": ["1.2.3.3"],
      }
      def _resolve(name):
         if len(name) > 30:
            return []
         return known.get(name, [])
      mock_a.side_effect = _resolve
      result = SubdomainBruteCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "standard_only"
      assert result.details["sensitive_found"] == 0
      assert result.details["total_found"] == 3

   @patch("mercure.checks.subdomain_brute.query_a")
   def test_wildcard_filters_duplicates(self, mock_a):
      def _resolve(name):
         if len(name) > 30:
            return ["9.9.9.9"]
         if name == "dev.example.com":
            return ["1.2.3.4"]
         return ["9.9.9.9"]
      mock_a.side_effect = _resolve
      result = SubdomainBruteCheck().run("example.com")
      assert result.details["wildcard"] is True
      found_names = [f["name"] for f in result.details["found"]]
      assert "dev.example.com" in found_names

   @patch("mercure.checks.subdomain_brute.query_a")
   def test_minimal_exposure(self, mock_a):
      known = {
         "www.example.com": ["1.2.3.1"],
      }
      def _resolve(name):
         if len(name) > 30:
            return []
         return known.get(name, [])
      mock_a.side_effect = _resolve
      result = SubdomainBruteCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "minimal_exposure"
      assert result.details["total_found"] <= 2

   @patch("mercure.checks.subdomain_brute.query_a")
   def test_categorization(self, mock_a):
      known = {
         "dev.example.com": ["1.2.3.1"],
         "ns1.example.com": ["1.2.3.2"],
         "www.example.com": ["1.2.3.3"],
      }
      def _resolve(name):
         if len(name) > 30:
            return []
         return known.get(name, [])
      mock_a.side_effect = _resolve
      result = SubdomainBruteCheck().run("example.com")
      categories = {f["name"]: f["category"] for f in result.details["found"]}
      assert categories.get("dev.example.com") == "sensitive"
      assert categories.get("ns1.example.com") == "infrastructure"
      assert categories.get("www.example.com") == "standard"
