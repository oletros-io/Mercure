import shutil
import subprocess
import json
from urllib.parse import urlparse

from .base import BaseCheck
from ..scoring import CheckResult

SENSITIVE_PATHS = {
   "/admin", "/login", "/wp-admin", "/wp-login", "/phpmyadmin",
   "/debug", "/.env", "/.git", "/api/", "/graphql", "/swagger",
   "/backup", "/.DS_Store", "/server-status", "/server-info",
   "/actuator", "/health", "/metrics", "/trace", "/console",
   "/elmah.axd", "/web.config", "/crossdomain.xml",
   "/robots.txt", "/sitemap.xml", "/.well-known",
}


class KatanaScanCheck(BaseCheck):
   name = "katana"
   label = "KATANA"
   intrusive = True

   def run(self, domain: str, **kwargs) -> CheckResult:
      if not shutil.which("katana"):
         return CheckResult(
            name=self.name, label=self.label, score=2,
            reason="tool_not_installed",
            details={"note": "katana not found in PATH"},
         )

      try:
         proc = subprocess.run(
            ["katana", "-u", f"https://{domain}", "-silent", "-jsonl",
             "-depth", "3", "-concurrency", "10", "-timeout", "10",
             "-no-color"],
            capture_output=True, text=True, timeout=180,
         )
      except subprocess.TimeoutExpired:
         return CheckResult(
            name=self.name, label=self.label, score=2,
            reason="crawl_timeout",
            details={"note": "katana crawl timed out after 180s"},
         )

      urls = set()
      forms = []
      js_files = []
      for line in proc.stdout.strip().split("\n"):
         if not line.strip():
            continue
         try:
            data = json.loads(line)
            url = data.get("request", {}).get("endpoint", line.strip())
            urls.add(url)
            if data.get("request", {}).get("method") == "POST":
               forms.append(url)
            if url.endswith(".js"):
               js_files.append(url)
         except (json.JSONDecodeError, KeyError):
            if line.startswith("http"):
               urls.add(line.strip())

      sensitive = []
      for url in urls:
         path = urlparse(url).path.lower()
         for sp in SENSITIVE_PATHS:
            if sp in path:
               sensitive.append(url)
               break

      details = {
         "total_urls": len(urls),
         "forms": forms[:20],
         "js_files": js_files[:20],
         "sensitive_paths": sensitive[:20],
         "sensitive_count": len(sensitive),
         "sample_urls": sorted(urls)[:50],
      }

      if len(sensitive) >= 5:
         return CheckResult(name=self.name, label=self.label, score=0,
            reason="many_sensitive_paths", details=details)
      if len(sensitive) >= 1:
         return CheckResult(name=self.name, label=self.label, score=1,
            reason="sensitive_paths_found", details=details)
      if len(urls) > 0:
         return CheckResult(name=self.name, label=self.label, score=2,
            reason="surface_mapped", details=details)
      return CheckResult(name=self.name, label=self.label, score=3,
         reason="minimal_surface", details=details)
