from unittest.mock import patch, MagicMock
from mercure.checks.hsts import HSTSCheck, _parse_hsts


class TestParseHsts:
   def test_full(self):
      r = _parse_hsts("max-age=31536000; includeSubDomains; preload")
      assert r["max_age"] == 31536000
      assert r["include_subdomains"] is True
      assert r["preload"] is True

   def test_simple(self):
      r = _parse_hsts("max-age=86400")
      assert r["max_age"] == 86400
      assert r["include_subdomains"] is False
      assert r["preload"] is False


def _mock_resp(hsts_value=None, status=200):
   resp = MagicMock()
   resp.status_code = status
   headers = {}
   if hsts_value:
      headers["strict-transport-security"] = hsts_value
   resp.headers = headers
   return resp


class TestHSTSCheck:
   @patch("mercure.checks.hsts.fetch")
   def test_no_hsts(self, mock_fetch):
      mock_fetch.return_value = _mock_resp()
      result = HSTSCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "no_hsts"

   @patch("mercure.checks.hsts.fetch")
   def test_hsts_full(self, mock_fetch):
      mock_fetch.return_value = _mock_resp("max-age=31536000; includeSubDomains; preload")
      result = HSTSCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "hsts_full"

   @patch("mercure.checks.hsts.fetch")
   def test_hsts_strong(self, mock_fetch):
      mock_fetch.return_value = _mock_resp("max-age=31536000; includeSubDomains")
      result = HSTSCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "hsts_strong"

   @patch("mercure.checks.hsts.fetch")
   def test_hsts_moderate(self, mock_fetch):
      mock_fetch.return_value = _mock_resp("max-age=15768000")
      result = HSTSCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "hsts_moderate"

   @patch("mercure.checks.hsts.fetch")
   def test_hsts_weak(self, mock_fetch):
      mock_fetch.return_value = _mock_resp("max-age=3600")
      result = HSTSCheck().run("example.com")
      assert result.score == 1
      assert result.reason == "hsts_weak"

   @patch("mercure.checks.hsts.fetch", return_value=None)
   def test_unreachable(self, mock_fetch):
      result = HSTSCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "unreachable"
