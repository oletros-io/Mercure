from unittest.mock import patch
from mercure.checks.dns_rebind import DNSRebindCheck


class TestDNSRebindCheck:
   def test_domain_private_ip(self):
      check = DNSRebindCheck()
      with patch("mercure.checks.dns_rebind.query_a") as mock_a, \
           patch("mercure.checks.dns_rebind.query_aaaa") as mock_aaaa:
         mock_a.side_effect = lambda name: ["10.0.0.1"] if name == "example.com" else []
         mock_aaaa.return_value = []
         result = check.run("example.com")
         assert result.score == 0
         assert result.reason == "domain_private"
         assert result.details["domain_private"] is True

   def test_all_public(self):
      check = DNSRebindCheck()
      with patch("mercure.checks.dns_rebind.query_a") as mock_a, \
           patch("mercure.checks.dns_rebind.query_aaaa") as mock_aaaa:
         def resolve_a(name):
            known = {
               "example.com": ["93.184.216.34"],
               "www.example.com": ["93.184.216.34"],
               "mail.example.com": ["93.184.216.35"],
            }
            return known.get(name, [])
         mock_a.side_effect = resolve_a
         mock_aaaa.return_value = []
         result = check.run("example.com")
         assert result.score == 3
         assert result.reason == "all_public"
         assert result.details["private_count"] == 0

   def test_some_private_subdomains(self):
      check = DNSRebindCheck()
      with patch("mercure.checks.dns_rebind.query_a") as mock_a, \
           patch("mercure.checks.dns_rebind.query_aaaa") as mock_aaaa:
         def resolve_a(name):
            known = {
               "example.com": ["93.184.216.34"],
               "vpn.example.com": ["192.168.1.1"],
               "admin.example.com": ["172.16.0.5"],
            }
            return known.get(name, [])
         mock_a.side_effect = resolve_a
         mock_aaaa.return_value = []
         result = check.run("example.com")
         assert result.score == 2
         assert result.reason == "some_private"
         assert result.details["private_count"] == 2

   def test_many_private_subdomains(self):
      check = DNSRebindCheck()
      with patch("mercure.checks.dns_rebind.query_a") as mock_a, \
           patch("mercure.checks.dns_rebind.query_aaaa") as mock_aaaa:
         def resolve_a(name):
            known = {
               "example.com": ["93.184.216.34"],
               "dev.example.com": ["10.0.0.1"],
               "staging.example.com": ["10.0.0.2"],
               "internal.example.com": ["192.168.0.1"],
            }
            return known.get(name, [])
         mock_a.side_effect = resolve_a
         mock_aaaa.return_value = []
         result = check.run("example.com")
         assert result.score == 1
         assert result.reason == "many_private"
         assert result.details["private_count"] == 3

   def test_ipv6_private(self):
      check = DNSRebindCheck()
      with patch("mercure.checks.dns_rebind.query_a") as mock_a, \
           patch("mercure.checks.dns_rebind.query_aaaa") as mock_aaaa:
         mock_a.return_value = []
         mock_aaaa.side_effect = lambda name: ["::1"] if name == "example.com" else []
         result = check.run("example.com")
         assert result.score == 0
         assert result.details["domain_private"] is True
         assert any(r["ip"] == "::1" for r in result.details["private_records"])

   def test_loopback_detected(self):
      check = DNSRebindCheck()
      with patch("mercure.checks.dns_rebind.query_a") as mock_a, \
           patch("mercure.checks.dns_rebind.query_aaaa") as mock_aaaa:
         mock_a.side_effect = lambda name: ["127.0.0.1"] if name == "example.com" else []
         mock_aaaa.return_value = []
         result = check.run("example.com")
         assert result.score == 0
         assert result.details["domain_private"] is True
         assert result.details["private_records"][0]["network"] == "127.0.0.0/8"

   def test_no_records(self):
      check = DNSRebindCheck()
      with patch("mercure.checks.dns_rebind.query_a") as mock_a, \
           patch("mercure.checks.dns_rebind.query_aaaa") as mock_aaaa:
         mock_a.return_value = []
         mock_aaaa.return_value = []
         result = check.run("example.com")
         assert result.score == 3
         assert result.reason == "all_public"
         assert result.details["total_checked"] == 0

   def test_link_local_detected(self):
      check = DNSRebindCheck()
      with patch("mercure.checks.dns_rebind.query_a") as mock_a, \
           patch("mercure.checks.dns_rebind.query_aaaa") as mock_aaaa:
         mock_a.side_effect = lambda name: ["169.254.1.1"] if name == "test.example.com" else []
         mock_aaaa.return_value = []
         result = check.run("example.com")
         assert result.details["private_count"] == 1
         assert result.details["private_records"][0]["network"] == "169.254.0.0/16"
