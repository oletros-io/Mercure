import subprocess
import json
from unittest.mock import patch, MagicMock


class TestKatanaScanCheck:
   def test_tool_not_installed(self):
      with patch("mercure.checks.katana_scan.shutil") as mock_shutil:
         mock_shutil.which.return_value = None
         from mercure.checks.katana_scan import KatanaScanCheck
         result = KatanaScanCheck().run("example.com")
         assert result.score == 2
         assert result.reason == "tool_not_installed"
         assert "katana not found" in result.details["note"]

   def test_many_sensitive_paths(self):
      urls = [
         "https://example.com/admin",
         "https://example.com/login",
         "https://example.com/.env",
         "https://example.com/.git/config",
         "https://example.com/phpmyadmin",
         "https://example.com/about",
      ]
      lines = "\n".join(
         json.dumps({"request": {"endpoint": u, "method": "GET"}}) for u in urls
      )
      with patch("mercure.checks.katana_scan.shutil") as mock_shutil, \
           patch("mercure.checks.katana_scan.subprocess") as mock_sub:
         mock_shutil.which.return_value = "/usr/bin/katana"
         mock_proc = MagicMock()
         mock_proc.stdout = lines
         mock_sub.run.return_value = mock_proc
         mock_sub.TimeoutExpired = subprocess.TimeoutExpired
         from mercure.checks.katana_scan import KatanaScanCheck
         result = KatanaScanCheck().run("example.com")
         assert result.score == 0
         assert result.reason == "many_sensitive_paths"
         assert result.details["sensitive_count"] >= 5

   def test_some_sensitive_paths(self):
      urls = [
         "https://example.com/admin",
         "https://example.com/about",
         "https://example.com/contact",
      ]
      lines = "\n".join(
         json.dumps({"request": {"endpoint": u, "method": "GET"}}) for u in urls
      )
      with patch("mercure.checks.katana_scan.shutil") as mock_shutil, \
           patch("mercure.checks.katana_scan.subprocess") as mock_sub:
         mock_shutil.which.return_value = "/usr/bin/katana"
         mock_proc = MagicMock()
         mock_proc.stdout = lines
         mock_sub.run.return_value = mock_proc
         mock_sub.TimeoutExpired = subprocess.TimeoutExpired
         from mercure.checks.katana_scan import KatanaScanCheck
         result = KatanaScanCheck().run("example.com")
         assert result.score == 1
         assert result.reason == "sensitive_paths_found"

   def test_surface_mapped_no_sensitive(self):
      urls = [
         "https://example.com/about",
         "https://example.com/contact",
         "https://example.com/products",
      ]
      lines = "\n".join(
         json.dumps({"request": {"endpoint": u, "method": "GET"}}) for u in urls
      )
      with patch("mercure.checks.katana_scan.shutil") as mock_shutil, \
           patch("mercure.checks.katana_scan.subprocess") as mock_sub:
         mock_shutil.which.return_value = "/usr/bin/katana"
         mock_proc = MagicMock()
         mock_proc.stdout = lines
         mock_sub.run.return_value = mock_proc
         mock_sub.TimeoutExpired = subprocess.TimeoutExpired
         from mercure.checks.katana_scan import KatanaScanCheck
         result = KatanaScanCheck().run("example.com")
         assert result.score == 2
         assert result.reason == "surface_mapped"
         assert result.details["total_urls"] == 3

   def test_minimal_surface(self):
      with patch("mercure.checks.katana_scan.shutil") as mock_shutil, \
           patch("mercure.checks.katana_scan.subprocess") as mock_sub:
         mock_shutil.which.return_value = "/usr/bin/katana"
         mock_proc = MagicMock()
         mock_proc.stdout = ""
         mock_sub.run.return_value = mock_proc
         mock_sub.TimeoutExpired = subprocess.TimeoutExpired
         from mercure.checks.katana_scan import KatanaScanCheck
         result = KatanaScanCheck().run("example.com")
         assert result.score == 3
         assert result.reason == "minimal_surface"

   def test_crawl_timeout(self):
      with patch("mercure.checks.katana_scan.shutil") as mock_shutil, \
           patch("mercure.checks.katana_scan.subprocess") as mock_sub:
         mock_shutil.which.return_value = "/usr/bin/katana"
         mock_sub.run.side_effect = subprocess.TimeoutExpired(cmd="katana", timeout=180)
         mock_sub.TimeoutExpired = subprocess.TimeoutExpired
         from mercure.checks.katana_scan import KatanaScanCheck
         result = KatanaScanCheck().run("example.com")
         assert result.score == 2
         assert result.reason == "crawl_timeout"

   def test_forms_and_js_detected(self):
      lines = "\n".join([
         json.dumps({"request": {"endpoint": "https://example.com/contact", "method": "POST"}}),
         json.dumps({"request": {"endpoint": "https://example.com/assets/app.js", "method": "GET"}}),
         json.dumps({"request": {"endpoint": "https://example.com/home", "method": "GET"}}),
      ])
      with patch("mercure.checks.katana_scan.shutil") as mock_shutil, \
           patch("mercure.checks.katana_scan.subprocess") as mock_sub:
         mock_shutil.which.return_value = "/usr/bin/katana"
         mock_proc = MagicMock()
         mock_proc.stdout = lines
         mock_sub.run.return_value = mock_proc
         mock_sub.TimeoutExpired = subprocess.TimeoutExpired
         from mercure.checks.katana_scan import KatanaScanCheck
         result = KatanaScanCheck().run("example.com")
         assert len(result.details["forms"]) == 1
         assert len(result.details["js_files"]) == 1

   def test_plain_url_fallback(self):
      lines = "https://example.com/page1\nhttps://example.com/page2\n"
      with patch("mercure.checks.katana_scan.shutil") as mock_shutil, \
           patch("mercure.checks.katana_scan.subprocess") as mock_sub:
         mock_shutil.which.return_value = "/usr/bin/katana"
         mock_proc = MagicMock()
         mock_proc.stdout = lines
         mock_sub.run.return_value = mock_proc
         mock_sub.TimeoutExpired = subprocess.TimeoutExpired
         from mercure.checks.katana_scan import KatanaScanCheck
         result = KatanaScanCheck().run("example.com")
         assert result.details["total_urls"] == 2
         assert result.reason == "surface_mapped"
