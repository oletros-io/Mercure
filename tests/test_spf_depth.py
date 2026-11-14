from unittest.mock import patch


class TestSPFDepthCheck:
   @patch("mercure.checks.spf_depth.query_txt", return_value=[])
   def test_no_spf(self, mock_txt):
      from mercure.checks.spf_depth import SPFDepthCheck
      result = SPFDepthCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "no_spf"

   @patch("mercure.checks.spf_depth.query_txt")
   def test_simple_spf_ok(self, mock_txt):
      mock_txt.return_value = ["v=spf1 ip4:1.2.3.0/24 -all"]
      from mercure.checks.spf_depth import SPFDepthCheck
      result = SPFDepthCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "spf_depth_ok"
      assert result.details["total_lookups"] == 0

   @patch("mercure.checks.spf_depth.query_txt")
   def test_moderate_lookups(self, mock_txt):
      def side_effect(domain):
         if domain == "example.com":
            return ["v=spf1 include:a.com include:b.com mx -all"]
         return []
      mock_txt.side_effect = side_effect
      from mercure.checks.spf_depth import SPFDepthCheck
      result = SPFDepthCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "spf_depth_ok"
      assert result.details["total_lookups"] == 3

   @patch("mercure.checks.spf_depth.query_txt")
   def test_near_limit(self, mock_txt):
      includes = " ".join(f"include:s{i}.example.com" for i in range(8))
      def side_effect(domain):
         if domain == "example.com":
            return [f"v=spf1 {includes} -all"]
         return []
      mock_txt.side_effect = side_effect
      from mercure.checks.spf_depth import SPFDepthCheck
      result = SPFDepthCheck().run("example.com")
      assert result.score == 1
      assert result.reason == "spf_near_limit"

   @patch("mercure.checks.spf_depth.query_txt")
   def test_permerror(self, mock_txt):
      includes = " ".join(f"include:s{i}.example.com" for i in range(11))
      def side_effect(domain):
         if domain == "example.com":
            return [f"v=spf1 {includes} -all"]
         return []
      mock_txt.side_effect = side_effect
      from mercure.checks.spf_depth import SPFDepthCheck
      result = SPFDepthCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "spf_permerror"
