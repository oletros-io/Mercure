from unittest.mock import patch
from mercure.checks.soa import SOACheck


class TestSOACheck:
   @patch("mercure.checks.soa.query_soa", return_value={})
   def test_no_soa(self, mock):
      result = SOACheck().run("example.com")
      assert result.score == 0
      assert result.reason == "no_soa"

   @patch("mercure.checks.soa.query_soa")
   def test_no_admin_contact(self, mock):
      mock.return_value = {
         "mname": "ns1.example.com", "rname": ".",
         "serial": 1, "refresh": 7200, "retry": 900,
         "expire": 1209600, "minimum": 300,
      }
      result = SOACheck().run("example.com")
      assert result.score == 1
      assert result.reason == "no_admin_contact"

   @patch("mercure.checks.soa.query_soa")
   def test_weak_timers(self, mock):
      mock.return_value = {
         "mname": "ns1.example.com", "rname": "admin.example.com",
         "serial": 1, "refresh": 60, "retry": 10,
         "expire": 100, "minimum": 10,
      }
      result = SOACheck().run("example.com")
      assert result.score == 2
      assert result.reason == "soa_weak_timers"
      assert len(result.details["issues"]) > 0

   @patch("mercure.checks.soa.query_soa")
   def test_soa_ok(self, mock):
      mock.return_value = {
         "mname": "ns1.example.com", "rname": "admin.example.com",
         "serial": 2024010101, "refresh": 7200, "retry": 900,
         "expire": 1209600, "minimum": 300,
      }
      result = SOACheck().run("example.com")
      assert result.score == 3
      assert result.reason == "soa_ok"

   @patch("mercure.checks.soa.query_soa")
   def test_serial_zero(self, mock):
      mock.return_value = {
         "mname": "ns1.example.com", "rname": "admin.example.com",
         "serial": 0, "refresh": 7200, "retry": 900,
         "expire": 1209600, "minimum": 300,
      }
      result = SOACheck().run("example.com")
      assert result.score == 2
      assert "serial_zero" in result.details["issues"]
