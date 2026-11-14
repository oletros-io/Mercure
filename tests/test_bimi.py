from unittest.mock import patch
from mercure.checks.bimi import BIMICheck, get_bimi_record, parse_bimi


class TestGetBimiRecord:
   @patch("mercure.checks.bimi.query_txt")
   def test_found(self, mock_txt):
      mock_txt.return_value = ["v=BIMI1; l=https://example.com/logo.svg"]
      assert "BIMI1" in get_bimi_record("example.com")

   @patch("mercure.checks.bimi.query_txt")
   def test_not_found(self, mock_txt):
      mock_txt.return_value = []
      assert get_bimi_record("example.com") == ""


class TestParseBimi:
   def test_full(self):
      r = parse_bimi("v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem")
      assert r["logo_url"] == "https://example.com/logo.svg"
      assert r["authority_url"] == "https://example.com/vmc.pem"

   def test_logo_only(self):
      r = parse_bimi("v=BIMI1; l=https://example.com/logo.svg")
      assert r["logo_url"] == "https://example.com/logo.svg"
      assert r["authority_url"] == ""


class TestBIMICheck:
   @patch("mercure.checks.bimi.query_txt")
   def test_no_record(self, mock_txt):
      mock_txt.return_value = []
      result = BIMICheck().run("example.com")
      assert result.score == 0
      assert result.reason == "no_bimi"

   @patch("mercure.checks.bimi.query_txt")
   def test_with_vmc(self, mock_txt):
      mock_txt.return_value = ["v=BIMI1; l=https://x.com/logo.svg; a=https://x.com/vmc.pem"]
      result = BIMICheck().run("example.com")
      assert result.score == 3
      assert result.reason == "bimi_with_vmc"

   @patch("mercure.checks.bimi.query_txt")
   def test_no_vmc(self, mock_txt):
      mock_txt.return_value = ["v=BIMI1; l=https://x.com/logo.svg"]
      result = BIMICheck().run("example.com")
      assert result.score == 2
      assert result.reason == "bimi_no_vmc"

   @patch("mercure.checks.bimi.query_txt")
   def test_invalid(self, mock_txt):
      mock_txt.return_value = ["v=BIMI1"]
      result = BIMICheck().run("example.com")
      assert result.score == 1
      assert result.reason == "bimi_invalid"
