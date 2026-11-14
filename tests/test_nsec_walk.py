from unittest.mock import patch, MagicMock
from mercure.checks.nsec_walk import NSECWalkCheck

import dns.rdatatype


def _make_nsec_response(nsec_type=None, nsec3_params=None, next_name=None):
   response = MagicMock()
   rrsets = []

   if nsec_type == "nsec":
      rrset = MagicMock()
      rrset.rdtype = dns.rdatatype.NSEC
      rr = MagicMock()
      rr.next = dns.name.from_text(next_name) if next_name else dns.name.from_text("example.com.")
      rrset.__iter__ = lambda self: iter([rr])
      rrsets.append(rrset)

   elif nsec_type == "nsec3":
      rrset = MagicMock()
      rrset.rdtype = dns.rdatatype.NSEC3
      rr = MagicMock()
      rr.algorithm = nsec3_params.get("algorithm", 1)
      rr.iterations = nsec3_params.get("iterations", 10)
      rr.salt = nsec3_params.get("salt", b"")
      rrset.__iter__ = lambda self: iter([rr])
      rrsets.append(rrset)

   response.authority = rrsets
   return response


import dns.name


class TestNSECWalkCheck:
   @patch("mercure.checks.nsec_walk.query_ns", return_value=[])
   def test_no_nameservers(self, mock_ns):
      result = NSECWalkCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "no_ns"
      assert result.details["nsec_type"] == "none"

   @patch("mercure.checks.nsec_walk.dns.query.udp", side_effect=Exception("timeout"))
   @patch("mercure.checks.nsec_walk.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.nsec_walk.query_ns", return_value=["ns1.example.com"])
   def test_probe_failure(self, mock_ns, mock_ip, mock_udp):
      result = NSECWalkCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "probe_failed"

   @patch("mercure.checks.nsec_walk.dns.query.udp")
   @patch("mercure.checks.nsec_walk.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.nsec_walk.query_ns", return_value=["ns1.example.com"])
   def test_no_nsec_records(self, mock_ns, mock_ip, mock_udp):
      mock_udp.return_value = _make_nsec_response()
      result = NSECWalkCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "no_nsec"
      assert result.details["nsec_type"] == "none"

   @patch("mercure.checks.nsec_walk.dns.query.udp")
   @patch("mercure.checks.nsec_walk.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.nsec_walk.query_ns", return_value=["ns1.example.com"])
   def test_nsec_walkable(self, mock_ns, mock_ip, mock_udp):
      probe_resp = _make_nsec_response(nsec_type="nsec", next_name="www.example.com.")

      walk_resp1 = _make_nsec_response(nsec_type="nsec", next_name="mail.example.com.")
      walk_resp2 = _make_nsec_response(nsec_type="nsec", next_name="ftp.example.com.")
      walk_resp3 = _make_nsec_response()

      mock_udp.side_effect = [probe_resp, walk_resp1, walk_resp2, walk_resp3]
      result = NSECWalkCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "nsec_walkable"
      assert result.details["nsec_type"] == "nsec"
      assert result.details["walkable"] is True
      assert len(result.details["discovered_names"]) >= 1

   @patch("mercure.checks.nsec_walk.dns.query.udp")
   @patch("mercure.checks.nsec_walk.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.nsec_walk.query_ns", return_value=["ns1.example.com"])
   def test_nsec_no_names_discovered(self, mock_ns, mock_ip, mock_udp):
      probe_resp = _make_nsec_response(nsec_type="nsec", next_name="example.com.")
      walk_resp = _make_nsec_response()
      mock_udp.side_effect = [probe_resp, walk_resp]
      result = NSECWalkCheck().run("example.com")
      assert result.score == 1
      assert result.reason == "nsec_no_names"
      assert result.details["walkable"] is False

   @patch("mercure.checks.nsec_walk.dns.query.udp")
   @patch("mercure.checks.nsec_walk.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.nsec_walk.query_ns", return_value=["ns1.example.com"])
   def test_nsec3_weak(self, mock_ns, mock_ip, mock_udp):
      mock_udp.return_value = _make_nsec_response(
         nsec_type="nsec3",
         nsec3_params={"algorithm": 1, "iterations": 5, "salt": b""},
      )
      result = NSECWalkCheck().run("example.com")
      assert result.score == 1
      assert result.reason == "nsec3"
      assert result.details["nsec_type"] == "nsec3"
      assert result.details["nsec3_params"]["algorithm"] == 1
      assert result.details["nsec3_params"]["iterations"] == 5
      assert result.details["nsec3_params"]["salt_length"] == 0

   @patch("mercure.checks.nsec_walk.dns.query.udp")
   @patch("mercure.checks.nsec_walk.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.nsec_walk.query_ns", return_value=["ns1.example.com"])
   def test_nsec3_strong(self, mock_ns, mock_ip, mock_udp):
      mock_udp.return_value = _make_nsec_response(
         nsec_type="nsec3",
         nsec3_params={"algorithm": 1, "iterations": 150, "salt": b"\xab\xcd"},
      )
      result = NSECWalkCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "nsec3"
      assert result.details["nsec3_params"]["iterations"] == 150
      assert result.details["nsec3_params"]["salt_length"] == 2

   @patch("mercure.checks.nsec_walk.dns.query.udp")
   @patch("mercure.checks.nsec_walk.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.nsec_walk.query_ns", return_value=["ns1.example.com"])
   def test_nsec3_moderate(self, mock_ns, mock_ip, mock_udp):
      mock_udp.return_value = _make_nsec_response(
         nsec_type="nsec3",
         nsec3_params={"algorithm": 1, "iterations": 50, "salt": b"\x01"},
      )
      result = NSECWalkCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "nsec3"
