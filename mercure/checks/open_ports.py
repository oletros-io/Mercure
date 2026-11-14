import socket
from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_a
from ..recon import shodan_internetdb
from .. import logger

PORTS = {
   21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
   80: "http", 110: "pop3", 143: "imap", 443: "https",
   445: "smb", 465: "smtps", 587: "submission",
   993: "imaps", 995: "pop3s", 3306: "mysql",
   3389: "rdp", 5432: "postgres", 8080: "http_alt", 8443: "https_alt",
}

DANGEROUS = {21, 23, 445, 3306, 3389, 5432}
EXPECTED = {25, 80, 443, 465, 587, 993, 995}


def _scan_port(ip: str, port: int, timeout: float = 2.0) -> bool:
   sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   sock.settimeout(timeout)
   try:
      return sock.connect_ex((ip, port)) == 0
   except Exception:
      return False
   finally:
      sock.close()


class OpenPortsCheck(BaseCheck):
   name = "open_ports"
   label = "PORTS"
   intrusive = True

   def run(self, domain: str, **kwargs) -> CheckResult:
      ips = query_a(domain)
      if not ips:
         return CheckResult(
            name=self.name, label=self.label,
            score=2, reason="no_a_record",
            details={"ip": "", "open_ports": [], "shodan": {}},
         )

      ip = ips[0]
      open_list = []
      for port, service in sorted(PORTS.items()):
         if _scan_port(ip, port):
            open_list.append({
               "port": port,
               "service": service,
               "dangerous": port in DANGEROUS,
            })

      shodan = shodan_internetdb(ip)

      details = {
         "ip": ip,
         "open_ports": open_list,
         "shodan": shodan,
      }

      dangerous_open = [p for p in open_list if p["dangerous"]]
      if dangerous_open:
         names = ", ".join(f"{p['port']}/{p['service']}" for p in dangerous_open)
         logger.warning(f"dangerous ports open on {ip}: {names}")
         return CheckResult(
            name=self.name, label=self.label,
            score=0, reason="dangerous_ports_open",
            details=details,
         )

      unexpected = [p for p in open_list if p["port"] not in EXPECTED]
      if unexpected:
         return CheckResult(
            name=self.name, label=self.label,
            score=2, reason="unexpected_ports",
            details=details,
         )

      return CheckResult(
         name=self.name, label=self.label,
         score=3, reason="expected_ports_only",
         details=details,
      )
