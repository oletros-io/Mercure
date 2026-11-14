from mercure.checks.ptr import PTRCheck, _domain_matches_ptr


class TestDomainMatchesPtr:
   def test_exact_match(self):
      assert _domain_matches_ptr("example.com", "example.com") is True

   def test_subdomain_match(self):
      assert _domain_matches_ptr("example.com", "mail.example.com") is True

   def test_no_match(self):
      assert _domain_matches_ptr("example.com", "notexample.com") is False

   def test_partial_no_match(self):
      assert _domain_matches_ptr("example.com", "badexample.com") is False

   def test_trailing_dot(self):
      assert _domain_matches_ptr("example.com.", "mail.example.com.") is True


class TestPTRCheck:
   def test_no_a_record(self, mock_query_a, mock_query_ptr):
      mock_query_a.return_value = []
      check = PTRCheck()
      result = check.run("example.com")
      assert result.score == 0
      assert result.reason == "no_a_record"

   def test_no_ptr(self, mock_query_a, mock_query_ptr):
      mock_query_a.return_value = ["1.2.3.4"]
      mock_query_ptr.return_value = []
      check = PTRCheck()
      result = check.run("example.com")
      assert result.score == 0
      assert result.reason == "no_ptr"

   def test_ptr_match(self, mock_query_a, mock_query_ptr):
      mock_query_a.return_value = ["1.2.3.4"]
      mock_query_ptr.return_value = ["mail.example.com"]
      check = PTRCheck()
      result = check.run("example.com")
      assert result.score == 3
      assert result.reason == "ptr_match"

   def test_ptr_no_match(self, mock_query_a, mock_query_ptr):
      mock_query_a.return_value = ["1.2.3.4"]
      mock_query_ptr.return_value = ["server.hosting.com"]
      check = PTRCheck()
      result = check.run("example.com")
      assert result.score == 2
      assert result.reason == "ptr_no_match"

   def test_partial_ptr(self, mock_query_a, mock_query_ptr):
      mock_query_a.return_value = ["1.2.3.4", "5.6.7.8"]
      def ptr_side_effect(ip):
         return ["mail.example.com"] if ip == "1.2.3.4" else []
      mock_query_ptr.side_effect = ptr_side_effect
      check = PTRCheck()
      result = check.run("example.com")
      assert result.score == 1
      assert result.reason == "partial_ptr"
