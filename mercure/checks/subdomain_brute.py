import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_a
from .. import logger

WORDLIST = [
   "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "email",
   "ns1", "ns2", "ns3", "dns", "dns1", "dns2",
   "dev", "development", "staging", "stage", "test", "testing", "qa", "uat",
   "admin", "administrator", "panel", "dashboard", "manage", "management",
   "api", "api2", "api-v2", "graphql", "rest", "ws", "websocket",
   "app", "apps", "application", "mobile", "m",
   "vpn", "remote", "gateway", "gw", "proxy", "socks",
   "git", "gitlab", "github", "bitbucket", "svn", "repo",
   "jenkins", "ci", "cd", "build", "deploy", "drone", "travis", "circleci",
   "jira", "confluence", "wiki", "docs", "documentation",
   "monitor", "monitoring", "grafana", "prometheus", "kibana", "elastic",
   "log", "logs", "logging", "syslog", "splunk",
   "db", "database", "mysql", "postgres", "postgresql", "mongo", "redis", "memcached",
   "ldap", "ad", "dc", "exchange", "owa", "autodiscover",
   "backup", "bak", "archive", "old", "legacy", "v1", "v2",
   "cdn", "static", "assets", "media", "images", "img", "files",
   "s3", "storage", "blob", "bucket",
   "shop", "store", "commerce", "pay", "payment", "billing",
   "sso", "auth", "login", "signin", "oauth", "cas", "saml", "idp",
   "corp", "corporate", "internal", "intranet", "extranet", "portal",
   "hr", "finance", "legal", "sales", "marketing",
   "support", "help", "helpdesk", "ticket", "service", "servicedesk",
   "crm", "erp", "sap",
   "web", "www2", "www3", "web1", "web2",
   "mx", "mx1", "mx2", "mx3", "relay", "outbound", "inbound",
   "vpn1", "vpn2", "ssl", "secure", "wss",
   "status", "health", "uptime",
   "sandbox", "demo", "preview", "beta", "alpha", "canary",
   "docker", "k8s", "kubernetes", "swarm", "rancher", "openshift",
   "aws", "azure", "gcp", "cloud", "paas",
   "nagios", "zabbix", "cacti", "netbox", "prtg",
   "ftp2", "sftp", "ftps", "nfs", "smb", "cifs",
   "chat", "slack", "teams", "meet", "zoom", "video",
   "blog", "news", "press", "forum", "community",
   "analytics", "stats", "tracking", "pixel",
   "mx-backup", "mail2", "smtp2",
]

SENSITIVE_PREFIXES = {
   "dev", "development", "staging", "stage", "test", "testing", "qa", "uat",
   "admin", "administrator", "panel", "dashboard", "manage",
   "vpn", "remote", "gateway",
   "git", "gitlab", "jenkins", "ci", "cd", "build", "deploy",
   "jira", "confluence", "wiki",
   "monitor", "grafana", "prometheus", "kibana", "elastic", "splunk",
   "db", "database", "mysql", "postgres", "mongo", "redis",
   "ldap", "ad", "dc", "exchange", "owa",
   "backup", "bak", "old", "legacy",
   "sso", "auth", "login", "oauth",
   "internal", "intranet", "corp",
   "sandbox", "demo",
   "docker", "k8s", "kubernetes",
}


def _categorize(prefix: str) -> str:
   if prefix in SENSITIVE_PREFIXES:
      return "sensitive"
   infra = {"ns1", "ns2", "ns3", "dns", "dns1", "dns2", "mx", "mx1", "mx2", "mx3",
            "relay", "cdn", "static", "assets", "media", "images", "img", "files",
            "s3", "storage", "blob", "bucket", "outbound", "inbound", "mx-backup"}
   if prefix in infra:
      return "infrastructure"
   return "standard"


class SubdomainBruteCheck(BaseCheck):
   name = "subdomain_brute"
   label = "SUB-BRUTE"
   intrusive = True

   def run(self, domain: str, **kwargs) -> CheckResult:
      wildcard_ip = self._detect_wildcard(domain)
      wildcard = wildcard_ip is not None

      found = []
      sensitive_count = 0

      def _probe(prefix):
         fqdn = f"{prefix}.{domain}"
         try:
            ips = query_a(fqdn)
         except Exception:
            return None
         if not ips:
            return None
         if wildcard_ip and all(ip == wildcard_ip for ip in ips):
            return None
         is_sensitive = prefix in SENSITIVE_PREFIXES
         return {
            "name": fqdn,
            "ip": ips[0],
            "sensitive": is_sensitive,
            "category": _categorize(prefix),
         }

      with ThreadPoolExecutor(max_workers=20) as pool:
         futures = {pool.submit(_probe, w): w for w in WORDLIST}
         for future in as_completed(futures):
            try:
               result = future.result()
            except Exception as exc:
               logger.debug(f"subdomain_brute probe error: {exc}")
               continue
            if result:
               found.append(result)
               if result["sensitive"]:
                  sensitive_count += 1

      found.sort(key=lambda x: x["name"])
      total_found = len(found)

      if wildcard:
         score = 2
         reason = "wildcard_active"
      elif sensitive_count > 5:
         score = 0
         reason = "many_sensitive"
      elif sensitive_count >= 1:
         score = 1
         reason = "some_sensitive"
      elif total_found <= 2:
         score = 3
         reason = "minimal_exposure"
      else:
         score = 2
         reason = "standard_only"

      return CheckResult(
         name=self.name,
         label=self.label,
         score=score,
         reason=reason,
         details={
            "wildcard": wildcard,
            "wildcard_ip": wildcard_ip,
            "total_found": total_found,
            "sensitive_found": sensitive_count,
            "found": found,
         },
      )

   def _detect_wildcard(self, domain: str) -> str | None:
      random_sub = f"{secrets.token_hex(10)}.{domain}"
      try:
         ips = query_a(random_sub)
      except Exception:
         return None
      if ips:
         logger.debug(f"wildcard detected for {domain}: {ips[0]}")
         return ips[0]
      return None
