from mercure.checks.ns import NSCheck, _extract_provider


class TestExtractProvider:
   def test_standard(self):
      assert _extract_provider("ns1.cloudflare.com") == "cloudflare.com"

   def test_short(self):
      assert _extract_provider("localhost") == "localhost"


class TestNSCheck:
   def test_no_ns(self, mock_query_ns):
      mock_query_ns.return_value = []
      check = NSCheck()
      result = check.run("example.com")
      assert result.score == 0
      assert result.reason == "no_ns"

   def test_single_ns(self, mock_query_ns):
      mock_query_ns.return_value = ["ns1.example.com"]
      check = NSCheck()
      result = check.run("example.com")
      assert result.score == 1
      assert result.reason == "single_ns"

   def test_same_provider(self, mock_query_ns):
      mock_query_ns.return_value = ["ns1.cloudflare.com", "ns2.cloudflare.com"]
      check = NSCheck()
      result = check.run("example.com")
      assert result.score == 2
      assert result.reason == "same_provider_ns"

   def test_diverse_providers(self, mock_query_ns):
      mock_query_ns.return_value = ["ns1.cloudflare.com", "ns1.route53.com"]
      check = NSCheck()
      result = check.run("example.com")
      assert result.score == 3
      assert result.reason == "ns_ok"
