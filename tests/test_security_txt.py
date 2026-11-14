from unittest.mock import patch, MagicMock
from mercure.checks.security_txt import SecurityTxtCheck, _parse_security_txt


class TestParseSecurityTxt:
   def test_full(self):
      body = (
         "Contact: mailto:security@example.com\n"
         "Expires: 2027-01-01T00:00:00Z\n"
         "Encryption: https://example.com/pgp-key.txt\n"
      )
      r = _parse_security_txt(body)
      assert r["contact"] == "mailto:security@example.com"
      assert r["expires"] == "2027-01-01T00:00:00Z"
      assert r["encryption"] == "https://example.com/pgp-key.txt"

   def test_ignores_comments(self):
      body = "# This is a comment\nContact: mailto:a@b.com\n"
      r = _parse_security_txt(body)
      assert r["contact"] == "mailto:a@b.com"


def _mock_resp(body, status=200):
   resp = MagicMock()
   resp.status_code = status
   resp.text = body
   return resp


class TestSecurityTxtCheck:
   @patch("mercure.checks.security_txt.fetch")
   def test_valid(self, mock_fetch):
      mock_fetch.return_value = _mock_resp(
         "Contact: mailto:sec@example.com\nExpires: 2027-01-01T00:00:00Z\n"
      )
      result = SecurityTxtCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "security_txt_valid"

   @patch("mercure.checks.security_txt.fetch")
   def test_no_expires(self, mock_fetch):
      mock_fetch.return_value = _mock_resp("Contact: mailto:sec@example.com\n")
      result = SecurityTxtCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "no_expires"

   @patch("mercure.checks.security_txt.fetch")
   def test_invalid(self, mock_fetch):
      mock_fetch.return_value = _mock_resp("random text\n")
      result = SecurityTxtCheck().run("example.com")
      assert result.score == 1
      assert result.reason == "invalid_security_txt"

   @patch("mercure.checks.security_txt.fetch", return_value=None)
   def test_missing(self, mock_fetch):
      result = SecurityTxtCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "no_security_txt"

   @patch("mercure.checks.security_txt.fetch")
   def test_404(self, mock_fetch):
      mock_fetch.return_value = _mock_resp("", status=404)
      result = SecurityTxtCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "no_security_txt"
