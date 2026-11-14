from mercure.scoring import (
   score_to_ten, compute_global_score, compute_exploitability_score,
   global_score_style, exploit_score_style, CheckResult, WEIGHTS, EXPLOIT_WEIGHTS,
)


class TestScoreToTen:
   def test_zero(self):
      assert score_to_ten(0) == 0

   def test_one(self):
      assert score_to_ten(1) == 3

   def test_two(self):
      assert score_to_ten(2) == 7

   def test_three(self):
      assert score_to_ten(3) == 10


class TestComputeGlobalScore:
   def test_empty(self):
      assert compute_global_score([]) == 0.0

   def test_all_max(self):
      results = [CheckResult(name=n, label=n.upper(), score=3, reason="ok")
                 for n in WEIGHTS]
      assert compute_global_score(results) == 10.0

   def test_all_zero(self):
      results = [CheckResult(name=n, label=n.upper(), score=0, reason="bad")
                 for n in WEIGHTS]
      assert compute_global_score(results) == 0.0

   def test_single_check(self):
      results = [CheckResult(name="spf", label="SPF", score=3, reason="hard_fail")]
      assert compute_global_score(results) == 10.0

   def test_mixed_scores(self):
      results = [
         CheckResult(name="spf", label="SPF", score=3, reason="hard_fail"),
         CheckResult(name="dmarc", label="DMARC", score=0, reason="no_dmarc"),
      ]
      score = compute_global_score(results)
      expected = round((3 * 3.0 + 0 * 3.5) / (3.0 + 3.5) / 3.0 * 10.0, 1)
      assert score == expected

   def test_unknown_check_uses_default_weight(self):
      results = [CheckResult(name="custom", label="CUSTOM", score=3, reason="ok")]
      assert compute_global_score(results) == 10.0

   def test_weights_sum(self):
      total = sum(WEIGHTS.values())
      assert total == 58.75


class TestExploitabilityScore:
   def test_empty(self):
      assert compute_exploitability_score([]) == 0.0

   def test_all_secure(self):
      results = [CheckResult(name=n, label=n.upper(), score=3, reason="ok")
                 for n in EXPLOIT_WEIGHTS]
      assert compute_exploitability_score(results) == 0.0

   def test_all_vulnerable(self):
      results = [CheckResult(name=n, label=n.upper(), score=0, reason="bad")
                 for n in EXPLOIT_WEIGHTS]
      assert compute_exploitability_score(results) == 10.0

   def test_high_exploit_weight_matters_more(self):
      r_ghost = [CheckResult(name="ghost", label="GHOST", score=0, reason="vuln")]
      r_bimi = [CheckResult(name="bimi", label="BIMI", score=0, reason="vuln")]
      assert compute_exploitability_score(r_ghost) == compute_exploitability_score(r_bimi)

   def test_mixed(self):
      results = [
         CheckResult(name="ghost", label="GHOST", score=0, reason="vuln"),
         CheckResult(name="dmarc", label="DMARC", score=3, reason="ok"),
      ]
      score = compute_exploitability_score(results)
      expected = round((3 * 5.0 + 0 * 4.5) / (5.0 + 4.5) / 3.0 * 10.0, 1)
      assert score == expected


class TestExploitScoreStyle:
   def test_red(self):
      assert exploit_score_style(7.0) == "red"
      assert exploit_score_style(10.0) == "red"

   def test_orange(self):
      assert exploit_score_style(4.0) == "orange1"
      assert exploit_score_style(6.9) == "orange1"

   def test_green(self):
      assert exploit_score_style(0.0) == "green"
      assert exploit_score_style(3.9) == "green"


class TestGlobalScoreStyle:
   def test_green(self):
      assert global_score_style(7.0) == "green"
      assert global_score_style(10.0) == "green"

   def test_orange(self):
      assert global_score_style(4.0) == "orange1"
      assert global_score_style(6.9) == "orange1"

   def test_red(self):
      assert global_score_style(0.0) == "red"
      assert global_score_style(3.9) == "red"
