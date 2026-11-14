import subprocess
from unittest.mock import patch, MagicMock


class TestNucleiScanCheck:
   def test_tool_not_installed(self):
      with patch("mercure.checks.nuclei_scan.shutil") as mock_shutil:
         mock_shutil.which.return_value = None
         from mercure.checks.nuclei_scan import NucleiScanCheck
         result = NucleiScanCheck().run("example.com")
         assert result.score == 2
         assert result.reason == "tool_not_installed"
         assert "nuclei not found" in result.details["note"]

   def test_critical_findings(self):
      json_line = '{"template-id":"cve-2021-44228","info":{"name":"Log4Shell","severity":"critical"},"matched-at":"https://example.com","type":"http"}'
      with patch("mercure.checks.nuclei_scan.shutil") as mock_shutil, \
           patch("mercure.checks.nuclei_scan.subprocess") as mock_sub:
         mock_shutil.which.return_value = "/usr/bin/nuclei"
         mock_proc = MagicMock()
         mock_proc.stdout = json_line
         mock_sub.run.return_value = mock_proc
         mock_sub.TimeoutExpired = subprocess.TimeoutExpired
         from mercure.checks.nuclei_scan import NucleiScanCheck
         result = NucleiScanCheck().run("example.com")
         assert result.score == 0
         assert result.reason == "critical_vulnerabilities"
         assert result.details["critical"] == 1

   def test_high_findings(self):
      json_line = '{"template-id":"cve-2023-1234","info":{"name":"SQLi","severity":"high"},"matched-at":"https://example.com/login","type":"http"}'
      with patch("mercure.checks.nuclei_scan.shutil") as mock_shutil, \
           patch("mercure.checks.nuclei_scan.subprocess") as mock_sub:
         mock_shutil.which.return_value = "/usr/bin/nuclei"
         mock_proc = MagicMock()
         mock_proc.stdout = json_line
         mock_sub.run.return_value = mock_proc
         mock_sub.TimeoutExpired = subprocess.TimeoutExpired
         from mercure.checks.nuclei_scan import NucleiScanCheck
         result = NucleiScanCheck().run("example.com")
         assert result.score == 1
         assert result.reason == "high_vulnerabilities"
         assert result.details["high"] == 1

   def test_medium_findings(self):
      json_line = '{"template-id":"misconfig-001","info":{"name":"Directory Listing","severity":"medium"},"matched-at":"https://example.com/images/","type":"http"}'
      with patch("mercure.checks.nuclei_scan.shutil") as mock_shutil, \
           patch("mercure.checks.nuclei_scan.subprocess") as mock_sub:
         mock_shutil.which.return_value = "/usr/bin/nuclei"
         mock_proc = MagicMock()
         mock_proc.stdout = json_line
         mock_sub.run.return_value = mock_proc
         mock_sub.TimeoutExpired = subprocess.TimeoutExpired
         from mercure.checks.nuclei_scan import NucleiScanCheck
         result = NucleiScanCheck().run("example.com")
         assert result.score == 2
         assert result.reason == "medium_vulnerabilities"
         assert result.details["medium"] == 1

   def test_no_findings(self):
      with patch("mercure.checks.nuclei_scan.shutil") as mock_shutil, \
           patch("mercure.checks.nuclei_scan.subprocess") as mock_sub:
         mock_shutil.which.return_value = "/usr/bin/nuclei"
         mock_proc = MagicMock()
         mock_proc.stdout = ""
         mock_sub.run.return_value = mock_proc
         mock_sub.TimeoutExpired = subprocess.TimeoutExpired
         from mercure.checks.nuclei_scan import NucleiScanCheck
         result = NucleiScanCheck().run("example.com")
         assert result.score == 3
         assert result.reason == "no_significant_findings"
         assert result.details["total"] == 0

   def test_scan_timeout(self):
      with patch("mercure.checks.nuclei_scan.shutil") as mock_shutil, \
           patch("mercure.checks.nuclei_scan.subprocess") as mock_sub:
         mock_shutil.which.return_value = "/usr/bin/nuclei"
         mock_sub.run.side_effect = subprocess.TimeoutExpired(cmd="nuclei", timeout=300)
         mock_sub.TimeoutExpired = subprocess.TimeoutExpired
         from mercure.checks.nuclei_scan import NucleiScanCheck
         result = NucleiScanCheck().run("example.com")
         assert result.score == 2
         assert result.reason == "scan_timeout"

   def test_mixed_severities(self):
      lines = "\n".join([
         '{"template-id":"cve-high","info":{"name":"XSS","severity":"high"},"matched-at":"https://example.com","type":"http"}',
         '{"template-id":"cve-med","info":{"name":"Info Disclosure","severity":"medium"},"matched-at":"https://example.com","type":"http"}',
         '{"template-id":"cve-low","info":{"name":"Cookie","severity":"low"},"matched-at":"https://example.com","type":"http"}',
      ])
      with patch("mercure.checks.nuclei_scan.shutil") as mock_shutil, \
           patch("mercure.checks.nuclei_scan.subprocess") as mock_sub:
         mock_shutil.which.return_value = "/usr/bin/nuclei"
         mock_proc = MagicMock()
         mock_proc.stdout = lines
         mock_sub.run.return_value = mock_proc
         mock_sub.TimeoutExpired = subprocess.TimeoutExpired
         from mercure.checks.nuclei_scan import NucleiScanCheck
         result = NucleiScanCheck().run("example.com")
         assert result.score == 1
         assert result.reason == "high_vulnerabilities"
         assert result.details["total"] == 3

   def test_malformed_json_lines_skipped(self):
      lines = "not json\n" + '{"template-id":"t1","info":{"name":"Test","severity":"low"},"matched-at":"https://example.com","type":"http"}'
      with patch("mercure.checks.nuclei_scan.shutil") as mock_shutil, \
           patch("mercure.checks.nuclei_scan.subprocess") as mock_sub:
         mock_shutil.which.return_value = "/usr/bin/nuclei"
         mock_proc = MagicMock()
         mock_proc.stdout = lines
         mock_sub.run.return_value = mock_proc
         mock_sub.TimeoutExpired = subprocess.TimeoutExpired
         from mercure.checks.nuclei_scan import NucleiScanCheck
         result = NucleiScanCheck().run("example.com")
         assert result.score == 3
         assert result.details["total"] == 1
