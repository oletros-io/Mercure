from unittest.mock import patch
from mercure.checks.cname_check import CNAMECheck


class TestCNAMECheck:
   @patch("mercure.checks.cname_check.query_mx", return_value=[])
   @patch("mercure.checks.cname_check.resolve_cname_chain", return_value=[])
   def test_no_cname(self, mock_chain, mock_mx):
      result = CNAMECheck().run("example.com")
      assert result.score == 3
      assert result.reason == "cname_ok"

   @patch("mercure.checks.cname_check.query_mx", return_value=[])
   @patch("mercure.checks.cname_check.resolve_cname_chain", return_value=["other.com"])
   def test_cname_on_apex(self, mock_chain, mock_mx):
      result = CNAMECheck().run("example.com")
      assert result.score == 1
      assert result.reason == "cname_on_apex"

   @patch("mercure.checks.cname_check.query_mx", return_value=[(10, "mx.example.com")])
   @patch("mercure.checks.cname_check.resolve_cname_chain", return_value=["other.com"])
   def test_cname_mx_coexistence(self, mock_chain, mock_mx):
      result = CNAMECheck().run("example.com")
      assert result.score == 1
      assert result.reason == "cname_mx_coexistence"

   @patch("mercure.checks.cname_check.query_mx", return_value=[])
   @patch("mercure.checks.cname_check.resolve_cname_chain")
   def test_chain_too_long(self, mock_chain, mock_mx):
      mock_chain.return_value = ["a.com", "b.com", "c.com", "d.com"]
      result = CNAMECheck().run("example.com")
      assert result.score == 1
      assert result.reason == "cname_chain_too_long"
      assert result.details["chain_length"] == 4
