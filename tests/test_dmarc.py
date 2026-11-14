from mercure.checks.dmarc import get_dmarc, parse_dmarc, DMARCCheck


class TestGetDmarc:
   def test_finds_dmarc(self, mock_query_txt):
      mock_query_txt.return_value = ["v=DMARC1; p=reject; pct=100"]
      assert get_dmarc("example.com") is not None

   def test_no_dmarc(self, mock_query_txt):
      mock_query_txt.return_value = []
      assert get_dmarc("example.com") is None


class TestParseDmarc:
   def test_no_dmarc(self):
      r = parse_dmarc(None)
      assert r["score"] == 0
      assert r["reason"] == "no_dmarc"

   def test_reject_full(self):
      r = parse_dmarc("v=DMARC1; p=reject; pct=100")
      assert r["score"] == 3
      assert r["reason"] == "reject_full"

   def test_reject_partial_pct(self):
      r = parse_dmarc("v=DMARC1; p=reject; pct=50")
      assert r["score"] == 2
      assert r["reason"] == "reject_partial_pct"

   def test_quarantine(self):
      r = parse_dmarc("v=DMARC1; p=quarantine")
      assert r["score"] == 2
      assert r["reason"] == "quarantine"

   def test_quarantine_partial(self):
      r = parse_dmarc("v=DMARC1; p=quarantine; pct=25")
      assert r["score"] == 1
      assert r["reason"] == "quarantine_partial_pct"

   def test_none_policy(self):
      r = parse_dmarc("v=DMARC1; p=none")
      assert r["score"] == 1
      assert r["reason"] == "none_policy"

   def test_parses_sp(self):
      r = parse_dmarc("v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com")
      assert r["sp"] == "none"
      assert r["rua"] == "mailto:d@example.com"

   def test_reject_implicit_pct100(self):
      r = parse_dmarc("v=DMARC1; p=reject")
      assert r["score"] == 3
      assert r["pct"] == 100


class TestDMARCCheck:
   def test_run(self, mock_query_txt):
      mock_query_txt.return_value = ["v=DMARC1; p=none"]
      check = DMARCCheck()
      result = check.run("example.com")
      assert result.name == "dmarc"
      assert result.score == 1
      assert result.reason == "none_policy"
