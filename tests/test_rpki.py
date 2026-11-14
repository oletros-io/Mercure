from unittest.mock import patch, MagicMock


class TestRPKICheck:
   @patch("mercure.checks.rpki.query_a", return_value=[])
   def test_no_a_record(self, mock_a):
      from mercure.checks.rpki import RPKICheck
      result = RPKICheck().run("example.com")
      assert result.score == 2
      assert result.reason == "rpki_unknown"

   @patch("mercure.checks.rpki.fetch")
   @patch("mercure.checks.rpki.query_a", return_value=["1.2.3.4"])
   def test_rpki_valid(self, mock_a, mock_fetch):
      resp = MagicMock()
      resp.status_code = 200
      resp.json.return_value = {
         "validated_route": {"validity": {"state": "valid"}}
      }
      mock_fetch.return_value = resp
      from mercure.checks.rpki import RPKICheck
      result = RPKICheck().run("example.com")
      assert result.score == 3
      assert result.reason == "rpki_valid"

   @patch("mercure.checks.rpki.fetch")
   @patch("mercure.checks.rpki.query_a", return_value=["1.2.3.4"])
   def test_rpki_invalid(self, mock_a, mock_fetch):
      resp = MagicMock()
      resp.status_code = 200
      resp.json.return_value = {
         "validated_route": {"validity": {"state": "invalid"}}
      }
      mock_fetch.return_value = resp
      from mercure.checks.rpki import RPKICheck
      result = RPKICheck().run("example.com")
      assert result.score == 0
      assert result.reason == "rpki_invalid"

   @patch("mercure.checks.rpki.fetch", return_value=None)
   @patch("mercure.checks.rpki.query_a", return_value=["1.2.3.4"])
   def test_api_unavailable(self, mock_a, mock_fetch):
      from mercure.checks.rpki import RPKICheck
      result = RPKICheck().run("example.com")
      assert result.score == 2
      assert result.reason == "rpki_unknown"

   @patch("mercure.checks.rpki.fetch")
   @patch("mercure.checks.rpki.query_a", return_value=["1.2.3.4"])
   def test_rpki_not_found(self, mock_a, mock_fetch):
      resp = MagicMock()
      resp.status_code = 200
      resp.json.return_value = {
         "validated_route": {"validity": {"state": "not-found"}}
      }
      mock_fetch.return_value = resp
      from mercure.checks.rpki import RPKICheck
      result = RPKICheck().run("example.com")
      assert result.score == 1
      assert result.reason == "rpki_not_found"
