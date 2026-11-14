import time
from unittest.mock import patch, MagicMock
from mercure.dns_utils import (
   _resolve, DnsResult, DnsError, _cache, query_txt, clear_cache,
)
import dns.resolver


class TestDnsCache:
   def test_cache_hit(self):
      _cache.clear()
      _cache.put("example.com|A", ["1.2.3.4"])
      assert _cache.get("example.com|A") == ["1.2.3.4"]

   def test_cache_miss(self):
      _cache.clear()
      assert _cache.get("missing.com|A") is None

   def test_cache_expiry(self):
      _cache.clear()
      _cache.put("old.com|A", ["1.2.3.4"])
      _cache._store["old.com|A"] = (["1.2.3.4"], time.monotonic() - 9999)
      assert _cache.get("old.com|A") is None

   def test_cache_clear(self):
      _cache.put("test.com|A", ["1.2.3.4"])
      _cache.clear()
      assert _cache.get("test.com|A") is None


class TestResolve:
   @patch("mercure.dns_utils.dns.resolver.resolve")
   def test_nxdomain(self, mock_dns):
      mock_dns.side_effect = dns.resolver.NXDOMAIN()
      result = _resolve("nonexistent.com", "A")
      assert result.error == DnsError.NXDOMAIN
      assert len(result) == 0

   @patch("mercure.dns_utils.dns.resolver.resolve")
   def test_timeout(self, mock_dns):
      mock_dns.side_effect = dns.resolver.LifetimeTimeout()
      result = _resolve("slow.com", "A")
      assert result.error == DnsError.TIMEOUT

   @patch("mercure.dns_utils.dns.resolver.resolve")
   def test_no_answer(self, mock_dns):
      mock_dns.side_effect = dns.resolver.NoAnswer()
      result = _resolve("example.com", "AAAA")
      assert result.error == DnsError.NO_ANSWER

   @patch("mercure.dns_utils.dns.resolver.resolve")
   def test_success(self, mock_dns):
      mock_rr = MagicMock()
      mock_rr.address = "1.2.3.4"
      mock_dns.return_value = [mock_rr]
      result = _resolve("example.com", "A")
      assert result.error == DnsError.NONE
      assert len(result) == 1

   @patch("mercure.dns_utils.dns.resolver.resolve")
   def test_caches_result(self, mock_dns):
      _cache.clear()
      mock_rr = MagicMock()
      mock_dns.return_value = [mock_rr]
      _resolve("cached.com", "A")
      _resolve("cached.com", "A")
      assert mock_dns.call_count == 1

   @patch("mercure.dns_utils.dns.resolver.resolve")
   def test_caches_nxdomain(self, mock_dns):
      _cache.clear()
      mock_dns.side_effect = dns.resolver.NXDOMAIN()
      _resolve("nx.com", "A")
      mock_dns.side_effect = None
      mock_dns.return_value = []
      result = _resolve("nx.com", "A")
      assert mock_dns.call_count == 1


class TestDnsResult:
   def test_bool_empty(self):
      assert not DnsResult()

   def test_bool_with_records(self):
      assert DnsResult(records=["a"])

   def test_iter(self):
      r = DnsResult(records=[1, 2, 3])
      assert list(r) == [1, 2, 3]

   def test_len(self):
      assert len(DnsResult(records=[1, 2])) == 2
