from unittest.mock import patch
from datetime import datetime, timezone, timedelta


class TestWhoisCheck:
   @patch("mercure.checks.whois_check.rdap_lookup", return_value={})
   def test_rdap_unavailable(self, mock_rdap):
      from mercure.checks.whois_check import WhoisCheck
      result = WhoisCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "rdap_unavailable"

   @patch("mercure.checks.whois_check.rdap_lookup")
   def test_expiring_soon(self, mock_rdap):
      expiry = (datetime.now(timezone.utc) + timedelta(days=15)).isoformat()
      mock_rdap.return_value = {
         "events": [{"eventAction": "expiration", "eventDate": expiry}],
         "status": ["clientTransferProhibited"],
         "entities": [],
      }
      from mercure.checks.whois_check import WhoisCheck
      result = WhoisCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "domain_expiring"

   @patch("mercure.checks.whois_check.rdap_lookup")
   def test_no_transfer_lock(self, mock_rdap):
      expiry = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
      mock_rdap.return_value = {
         "events": [{"eventAction": "expiration", "eventDate": expiry}],
         "status": ["active"],
         "entities": [],
      }
      from mercure.checks.whois_check import WhoisCheck
      result = WhoisCheck().run("example.com")
      assert result.score == 1
      assert result.reason == "no_transfer_lock"

   @patch("mercure.checks.whois_check.rdap_lookup")
   def test_whois_ok(self, mock_rdap):
      expiry = (datetime.now(timezone.utc) + timedelta(days=365)).isoformat()
      mock_rdap.return_value = {
         "events": [{"eventAction": "expiration", "eventDate": expiry}],
         "status": ["clientTransferProhibited", "active"],
         "entities": [],
      }
      from mercure.checks.whois_check import WhoisCheck
      result = WhoisCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "whois_ok"

   @patch("mercure.checks.whois_check.rdap_lookup")
   def test_renewal_soon(self, mock_rdap):
      expiry = (datetime.now(timezone.utc) + timedelta(days=60)).isoformat()
      mock_rdap.return_value = {
         "events": [{"eventAction": "expiration", "eventDate": expiry}],
         "status": ["clientTransferProhibited"],
         "entities": [],
      }
      from mercure.checks.whois_check import WhoisCheck
      result = WhoisCheck().run("example.com")
      assert result.score == 1
      assert result.reason == "domain_renewal_soon"
