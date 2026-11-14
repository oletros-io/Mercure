from unittest.mock import patch, MagicMock
from mercure.checks.redirect import RedirectCheck


def _mock_resp(status, location=""):
   resp = MagicMock()
   resp.status_code = status
   resp.headers = {"location": location} if location else {}
   return resp


class TestRedirectCheck:
   @patch("mercure.checks.redirect.fetch_insecure")
   def test_http_to_https(self, mock_fetch):
      mock_fetch.return_value = _mock_resp(301, "https://example.com/")
      result = RedirectCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "http_to_https"

   @patch("mercure.checks.redirect.fetch_insecure")
   def test_http_to_https_www(self, mock_fetch):
      mock_fetch.return_value = _mock_resp(302, "https://www.example.com/")
      result = RedirectCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "http_to_https_www"

   @patch("mercure.checks.redirect.fetch_insecure")
   def test_redirect_no_tls(self, mock_fetch):
      mock_fetch.return_value = _mock_resp(301, "http://example.com/new")
      result = RedirectCheck().run("example.com")
      assert result.score == 1
      assert result.reason == "redirect_no_tls"

   @patch("mercure.checks.redirect.fetch_insecure")
   def test_no_redirect(self, mock_fetch):
      mock_fetch.return_value = _mock_resp(200)
      result = RedirectCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "no_redirect_to_https"

   @patch("mercure.checks.redirect.fetch_insecure", return_value=None)
   def test_http_not_available(self, mock_fetch):
      result = RedirectCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "http_not_available"
