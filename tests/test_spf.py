from mercure.checks.spf import get_spf, evaluate_spf, SPFCheck


class TestGetSpf:
   def test_finds_spf_record(self, mock_query_txt):
      mock_query_txt.return_value = ["v=spf1 include:_spf.google.com -all"]
      assert get_spf("example.com") == "v=spf1 include:_spf.google.com -all"

   def test_ignores_non_spf(self, mock_query_txt):
      mock_query_txt.return_value = [
         "google-site-verification=abc123",
         "v=spf1 -all",
      ]
      assert get_spf("example.com") == "v=spf1 -all"

   def test_no_spf(self, mock_query_txt):
      mock_query_txt.return_value = ["google-site-verification=abc123"]
      assert get_spf("example.com") is None

   def test_empty_records(self, mock_query_txt):
      mock_query_txt.return_value = []
      assert get_spf("example.com") is None

   def test_spf_must_start_with_v_spf1(self, mock_query_txt):
      mock_query_txt.return_value = ["some random text with v=spf1 inside"]
      assert get_spf("example.com") is None

   def test_case_insensitive(self, mock_query_txt):
      mock_query_txt.return_value = ["V=SPF1 -all"]
      assert get_spf("example.com") is not None


class TestEvaluateSpf:
   def test_no_spf(self):
      r = evaluate_spf(None)
      assert r["score"] == 0
      assert r["reason"] == "no_spf"

   def test_hard_fail(self):
      r = evaluate_spf("v=spf1 include:_spf.google.com -all")
      assert r["score"] == 3
      assert r["reason"] == "hard_fail"

   def test_soft_fail(self):
      r = evaluate_spf("v=spf1 include:_spf.google.com ~all")
      assert r["score"] == 2
      assert r["reason"] == "soft_fail"

   def test_neutral(self):
      r = evaluate_spf("v=spf1 ?all")
      assert r["score"] == 1
      assert r["reason"] == "neutral_all"

   def test_allow_all(self):
      r = evaluate_spf("v=spf1 +all")
      assert r["score"] == 0
      assert r["reason"] == "allow_all_plus"

   def test_redirect_no_all(self):
      r = evaluate_spf("v=spf1 redirect=_spf.example.com")
      assert r["score"] == 2
      assert r["reason"] == "redirect_no_all"

   def test_redirect_with_all(self):
      r = evaluate_spf("v=spf1 redirect=_spf.example.com -all")
      assert r["score"] == 3
      assert r["reason"] == "hard_fail"

   def test_unknown_policy(self):
      r = evaluate_spf("v=spf1 include:_spf.example.com")
      assert r["score"] == 1
      assert r["reason"] == "unknown_policy"


class TestSPFCheck:
   def test_run(self, mock_query_txt):
      mock_query_txt.return_value = ["v=spf1 -all"]
      check = SPFCheck()
      result = check.run("example.com")
      assert result.name == "spf"
      assert result.score == 3
      assert result.reason == "hard_fail"
