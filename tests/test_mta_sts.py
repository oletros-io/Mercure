from unittest.mock import patch, MagicMock
from mercure.checks.mta_sts import MTASTSCheck, get_mta_sts_record, parse_policy


class TestGetMtaStsRecord:
   @patch("mercure.checks.mta_sts.query_txt")
   def test_found(self, mock_txt):
      mock_txt.return_value = ["v=STSv1; id=20240101"]
      assert get_mta_sts_record("example.com") == "v=STSv1; id=20240101"

   @patch("mercure.checks.mta_sts.query_txt")
   def test_not_found(self, mock_txt):
      mock_txt.return_value = ["some-other-record"]
      assert get_mta_sts_record("example.com") == ""


class TestParsePolicy:
   def test_enforce(self):
      text = "version: STSv1\nmode: enforce\nmx: *.example.com\nmx: mail.example.com\nmax_age: 604800"
      p = parse_policy(text)
      assert p["mode"] == "enforce"
      assert len(p["mx_patterns"]) == 2
      assert p["max_age"] == 604800

   def test_testing(self):
      p = parse_policy("version: STSv1\nmode: testing\nmax_age: 86400")
      assert p["mode"] == "testing"


class TestMTASTSCheck:
   @patch("mercure.checks.mta_sts.fetch")
   @patch("mercure.checks.mta_sts.query_txt")
   def test_no_record(self, mock_txt, mock_fetch):
      mock_txt.return_value = []
      check = MTASTSCheck()
      result = check.run("example.com")
      assert result.score == 0
      assert result.reason == "no_mta_sts"

   @patch("mercure.checks.mta_sts.fetch")
   @patch("mercure.checks.mta_sts.query_txt")
   def test_enforce(self, mock_txt, mock_fetch):
      mock_txt.return_value = ["v=STSv1; id=123"]
      resp = MagicMock()
      resp.status_code = 200
      resp.text = "version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 604800"
      mock_fetch.return_value = resp
      check = MTASTSCheck()
      result = check.run("example.com")
      assert result.score == 3
      assert result.reason == "enforce"

   @patch("mercure.checks.mta_sts.fetch")
   @patch("mercure.checks.mta_sts.query_txt")
   def test_testing_mode(self, mock_txt, mock_fetch):
      mock_txt.return_value = ["v=STSv1; id=123"]
      resp = MagicMock()
      resp.status_code = 200
      resp.text = "version: STSv1\nmode: testing\nmax_age: 86400"
      mock_fetch.return_value = resp
      check = MTASTSCheck()
      result = check.run("example.com")
      assert result.score == 2
      assert result.reason == "testing_mode"

   @patch("mercure.checks.mta_sts.fetch")
   @patch("mercure.checks.mta_sts.query_txt")
   def test_policy_unreachable(self, mock_txt, mock_fetch):
      mock_txt.return_value = ["v=STSv1; id=123"]
      mock_fetch.return_value = None
      check = MTASTSCheck()
      result = check.run("example.com")
      assert result.score == 1
      assert result.reason == "none_or_invalid"
