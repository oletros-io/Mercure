import shutil
import subprocess
import json

from .base import BaseCheck
from ..scoring import CheckResult


class NucleiScanCheck(BaseCheck):
   name = "nuclei"
   label = "NUCLEI"
   intrusive = True

   def run(self, domain: str, **kwargs) -> CheckResult:
      if not shutil.which("nuclei"):
         return CheckResult(
            name=self.name, label=self.label, score=2,
            reason="tool_not_installed",
            details={"note": "nuclei not found in PATH"},
         )

      try:
         proc = subprocess.run(
            ["nuclei", "-u", f"https://{domain}", "-u", f"http://{domain}",
             "-silent", "-jsonl", "-severity", "critical,high,medium,low"],
            capture_output=True, text=True, timeout=300,
         )
      except subprocess.TimeoutExpired:
         return CheckResult(
            name=self.name, label=self.label, score=2,
            reason="scan_timeout",
            details={"note": "nuclei scan timed out after 300s"},
         )

      findings = []
      for line in proc.stdout.strip().split("\n"):
         if not line.strip():
            continue
         try:
            data = json.loads(line)
            findings.append({
               "template_id": data.get("template-id", ""),
               "severity": data.get("info", {}).get("severity", "unknown"),
               "name": data.get("info", {}).get("name", ""),
               "matched_at": data.get("matched-at", ""),
               "type": data.get("type", ""),
            })
         except (json.JSONDecodeError, KeyError):
            pass

      critical = sum(1 for f in findings if f["severity"] == "critical")
      high = sum(1 for f in findings if f["severity"] == "high")
      medium = sum(1 for f in findings if f["severity"] == "medium")

      details = {
         "findings": findings[:50],
         "total": len(findings),
         "critical": critical,
         "high": high,
         "medium": medium,
      }

      if critical > 0:
         return CheckResult(name=self.name, label=self.label, score=0,
            reason="critical_vulnerabilities", details=details)
      if high > 0:
         return CheckResult(name=self.name, label=self.label, score=1,
            reason="high_vulnerabilities", details=details)
      if medium > 0:
         return CheckResult(name=self.name, label=self.label, score=2,
            reason="medium_vulnerabilities", details=details)
      return CheckResult(name=self.name, label=self.label, score=3,
         reason="no_significant_findings", details=details)
