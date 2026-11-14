from unittest.mock import patch, MagicMock


class TestSubdomainsCheck:
   @patch("mercure.checks.subdomains.shutil")
   @patch("mercure.checks.subdomains.query_a", return_value=[])
   @patch("mercure.checks.subdomains.crtsh_subdomains", return_value=[])
   def test_no_ct_data(self, mock_crt, mock_a, mock_shutil):
      mock_shutil.which.return_value = None
      from mercure.checks.subdomains import SubdomainsCheck
      result = SubdomainsCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "no_ct_data"
      assert result.details["source"] == "crtsh"

   @patch("mercure.checks.subdomains.shutil")
   @patch("mercure.checks.subdomains.query_a", return_value=["1.2.3.4"])
   @patch("mercure.checks.subdomains.crtsh_subdomains", return_value=["a.example.com", "b.example.com", "c.example.com"])
   def test_minimal_surface(self, mock_crt, mock_a, mock_shutil):
      mock_shutil.which.return_value = None
      from mercure.checks.subdomains import SubdomainsCheck
      result = SubdomainsCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "minimal_surface"

   @patch("mercure.checks.subdomains.shutil")
   @patch("mercure.checks.subdomains.query_a", return_value=["1.2.3.4"])
   @patch("mercure.checks.subdomains.crtsh_subdomains")
   def test_sensitive_exposed(self, mock_crt, mock_a, mock_shutil):
      mock_shutil.which.return_value = None
      subs = [f"{kw}.example.com" for kw in ("dev", "staging", "test", "admin", "www", "mail")]
      mock_crt.return_value = subs
      from mercure.checks.subdomains import SubdomainsCheck
      result = SubdomainsCheck().run("example.com")
      assert result.score == 1
      assert result.reason == "sensitive_subdomains_exposed"

   @patch("mercure.checks.subdomains.shutil")
   @patch("mercure.checks.subdomains.query_a", return_value=["1.2.3.4"])
   @patch("mercure.checks.subdomains.crtsh_subdomains")
   def test_normal_surface(self, mock_crt, mock_a, mock_shutil):
      mock_shutil.which.return_value = None
      subs = [f"host{i}.example.com" for i in range(10)]
      mock_crt.return_value = subs
      from mercure.checks.subdomains import SubdomainsCheck
      result = SubdomainsCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "normal_surface"

   @patch("mercure.checks.subdomains.subprocess")
   @patch("mercure.checks.subdomains.shutil")
   @patch("mercure.checks.subdomains.query_a", return_value=["1.2.3.4"])
   @patch("mercure.checks.subdomains.crtsh_subdomains")
   def test_subfinder_integration(self, mock_crt, mock_a, mock_shutil, mock_sub):
      mock_crt.return_value = ["www.example.com", "mail.example.com"]
      mock_shutil.which.return_value = "/usr/bin/subfinder"
      mock_proc = MagicMock()
      mock_proc.stdout = "api.example.com\nwww.example.com\ncdn.example.com\n"
      mock_sub.run.return_value = mock_proc
      mock_sub.TimeoutExpired = TimeoutError
      from mercure.checks.subdomains import SubdomainsCheck
      result = SubdomainsCheck().run("example.com")
      assert result.details["source"] == "subfinder+crtsh"
      assert result.details["total_discovered"] == 4

   @patch("mercure.checks.subdomains.subprocess")
   @patch("mercure.checks.subdomains.shutil")
   @patch("mercure.checks.subdomains.query_a", return_value=["1.2.3.4"])
   @patch("mercure.checks.subdomains.crtsh_subdomains", return_value=["a.example.com"])
   def test_subfinder_not_available_fallback(self, mock_crt, mock_a, mock_shutil, mock_sub):
      mock_shutil.which.return_value = None
      from mercure.checks.subdomains import SubdomainsCheck
      result = SubdomainsCheck().run("example.com")
      assert result.details["source"] == "crtsh"
      mock_sub.run.assert_not_called()
