from unittest.mock import patch


class TestMatchTakeover:
   def test_known_service(self):
      from mercure.checks.dangling import _match_takeover
      assert _match_takeover("old.herokuapp.com") == "heroku"

   def test_unknown_target(self):
      from mercure.checks.dangling import _match_takeover
      assert _match_takeover("random.provider.net") == ""

   def test_azure(self):
      from mercure.checks.dangling import _match_takeover
      assert _match_takeover("myapp.azurewebsites.net") == "azure_app_service"


class TestDanglingCheck:
   @patch("mercure.checks.dangling.crtsh_subdomains", return_value=[])
   def test_enumeration_limited(self, mock_crt):
      from mercure.checks.dangling import DanglingCheck
      result = DanglingCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "enumeration_limited"

   @patch("mercure.checks.dangling.query_a", return_value=["1.2.3.4"])
   @patch("mercure.checks.dangling.resolve_cname_chain", return_value=[])
   @patch("mercure.checks.dangling.crtsh_subdomains", return_value=["www.example.com"])
   def test_no_dangling(self, mock_crt, mock_chain, mock_a):
      from mercure.checks.dangling import DanglingCheck
      result = DanglingCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "no_dangling"

   @patch("mercure.checks.dangling.query_a", return_value=[])
   @patch("mercure.checks.dangling.resolve_cname_chain", return_value=["old.herokuapp.com"])
   @patch("mercure.checks.dangling.crtsh_subdomains", return_value=["app.example.com"])
   def test_takeover_possible(self, mock_crt, mock_chain, mock_a):
      from mercure.checks.dangling import DanglingCheck
      result = DanglingCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "subdomain_takeover_possible"
      assert result.details["dangling"][0]["service"] == "heroku"

   @patch("mercure.checks.dangling.query_a", return_value=[])
   @patch("mercure.checks.dangling.resolve_cname_chain", return_value=["old.custom-host.net"])
   @patch("mercure.checks.dangling.crtsh_subdomains", return_value=["legacy.example.com"])
   def test_dangling_no_pattern(self, mock_crt, mock_chain, mock_a):
      from mercure.checks.dangling import DanglingCheck
      result = DanglingCheck().run("example.com")
      assert result.score == 1
      assert result.reason == "dangling_cname_found"
