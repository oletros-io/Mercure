from unittest.mock import patch, MagicMock
from mercure.checks.cookie import CookieCheck, _parse_set_cookie


class TestParseSetCookie:
   def test_secure_httponly_samesite(self):
      c = _parse_set_cookie("session=abc123; Secure; HttpOnly; SameSite=Strict")
      assert c["name"] == "session"
      assert c["secure"] is True
      assert c["httponly"] is True
      assert c["samesite"] == "Strict"

   def test_no_flags(self):
      c = _parse_set_cookie("tracker=xyz; Path=/")
      assert c["secure"] is False
      assert c["httponly"] is False
      assert c["samesite"] == ""


def _mock_resp(cookie_headers):
   resp = MagicMock()
   resp.status_code = 200
   resp.headers = MagicMock()
   if hasattr(resp.headers, "get_list"):
      resp.headers.get_list = MagicMock(return_value=cookie_headers)
   else:
      delattr(resp.headers, "get_list")
      resp.headers.get = MagicMock(
         side_effect=lambda k, d="": cookie_headers[0] if cookie_headers else d
      )
   return resp


class TestCookieCheck:
   @patch("mercure.checks.cookie.fetch")
   def test_no_cookies(self, mock_fetch):
      resp = MagicMock()
      resp.status_code = 200
      resp.headers = MagicMock()
      resp.headers.get_list = MagicMock(return_value=[])
      mock_fetch.return_value = resp
      result = CookieCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "no_cookies"

   @patch("mercure.checks.cookie.fetch")
   def test_cookies_secured(self, mock_fetch):
      resp = MagicMock()
      resp.status_code = 200
      resp.headers = MagicMock()
      resp.headers.get_list = MagicMock(return_value=[
         "session=abc; Secure; HttpOnly; SameSite=Strict",
      ])
      mock_fetch.return_value = resp
      result = CookieCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "cookies_secured"

   @patch("mercure.checks.cookie.fetch")
   def test_cookies_insecure(self, mock_fetch):
      resp = MagicMock()
      resp.status_code = 200
      resp.headers = MagicMock()
      resp.headers.get_list = MagicMock(return_value=[
         "tracker=xyz; Path=/",
      ])
      mock_fetch.return_value = resp
      result = CookieCheck().run("example.com")
      assert result.score == 1
      assert result.reason == "cookies_insecure"

   @patch("mercure.checks.cookie.fetch", return_value=None)
   def test_unreachable(self, mock_fetch):
      result = CookieCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "unreachable"
