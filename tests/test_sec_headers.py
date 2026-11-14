from unittest.mock import patch, MagicMock
from mercure.checks.sec_headers import SecHeadersCheck


def _mock_resp(headers_dict):
   resp = MagicMock()
   resp.status_code = 200
   resp.headers = headers_dict
   return resp


ALL_HEADERS = {
   "content-security-policy": "default-src 'self'",
   "x-frame-options": "DENY",
   "x-content-type-options": "nosniff",
   "referrer-policy": "strict-origin-when-cross-origin",
   "permissions-policy": "geolocation=()",
   "cross-origin-opener-policy": "same-origin",
}


class TestSecHeadersCheck:
   @patch("mercure.checks.sec_headers.fetch")
   def test_all_headers(self, mock_fetch):
      mock_fetch.return_value = _mock_resp(ALL_HEADERS)
      result = SecHeadersCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "all_headers"

   @patch("mercure.checks.sec_headers.fetch")
   def test_most_headers(self, mock_fetch):
      h = dict(ALL_HEADERS)
      del h["permissions-policy"]
      del h["cross-origin-opener-policy"]
      mock_fetch.return_value = _mock_resp(h)
      result = SecHeadersCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "most_headers"

   @patch("mercure.checks.sec_headers.fetch")
   def test_some_headers(self, mock_fetch):
      h = {"content-security-policy": "default-src 'self'", "x-frame-options": "DENY"}
      mock_fetch.return_value = _mock_resp(h)
      result = SecHeadersCheck().run("example.com")
      assert result.score == 1
      assert result.reason == "some_headers"

   @patch("mercure.checks.sec_headers.fetch")
   def test_missing_headers(self, mock_fetch):
      mock_fetch.return_value = _mock_resp({})
      result = SecHeadersCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "missing_headers"

   @patch("mercure.checks.sec_headers.fetch", return_value=None)
   def test_unreachable(self, mock_fetch):
      result = SecHeadersCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "unreachable"
