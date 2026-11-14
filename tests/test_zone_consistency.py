from unittest.mock import patch
from mercure.checks.zone_consistency import ZoneConsistencyCheck


class TestZoneConsistencyCheck:
   @patch("mercure.checks.zone_consistency.query_all_ns")
   def test_consistent(self, mock_all_ns):
      mock_all_ns.return_value = {
         "ns1.example.com": ["1.2.3.4"],
         "ns2.example.com": ["1.2.3.4"],
      }
      result = ZoneConsistencyCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "consistent"

   @patch("mercure.checks.zone_consistency.query_all_ns")
   def test_inconsistent(self, mock_all_ns):
      mock_all_ns.return_value = {
         "ns1.example.com": ["1.2.3.4"],
         "ns2.example.com": ["5.6.7.8"],
      }
      result = ZoneConsistencyCheck().run("example.com")
      assert result.score == 1
      assert result.reason == "inconsistent_answers"

   @patch("mercure.checks.zone_consistency.query_all_ns")
   def test_single_ns(self, mock_all_ns):
      mock_all_ns.return_value = {"ns1.example.com": ["1.2.3.4"]}
      result = ZoneConsistencyCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "single_ns_cannot_compare"

   @patch("mercure.checks.zone_consistency.query_all_ns")
   def test_ns_error(self, mock_all_ns):
      mock_all_ns.return_value = {
         "ns1.example.com": ["1.2.3.4"],
         "ns2.example.com": "error: timeout",
      }
      result = ZoneConsistencyCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "ns_query_error"
