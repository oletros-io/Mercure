from unittest.mock import patch
from mercure.checks.wildcard import WildcardCheck


class TestWildcardCheck:
   @patch("mercure.checks.wildcard.query_a", return_value=[])
   def test_no_wildcard(self, mock_a):
      result = WildcardCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "no_wildcard"

   @patch("mercure.checks.wildcard.query_a", return_value=["1.2.3.4"])
   def test_wildcard_enabled(self, mock_a):
      result = WildcardCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "wildcard_enabled"
      assert result.value == "1.2.3.4"

   @patch("mercure.checks.wildcard.query_a", return_value=["10.0.0.1", "10.0.0.2"])
   def test_wildcard_multiple_ips(self, mock_a):
      result = WildcardCheck().run("example.com")
      assert result.score == 0
      assert result.details["resolved_ips"] == ["10.0.0.1", "10.0.0.2"]
