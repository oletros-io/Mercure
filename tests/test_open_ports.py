from unittest.mock import patch, MagicMock


class TestOpenPortsCheck:
   @patch("mercure.checks.open_ports.query_a", return_value=[])
   def test_no_a_record(self, mock_a):
      from mercure.checks.open_ports import OpenPortsCheck
      result = OpenPortsCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "no_a_record"

   @patch("mercure.checks.open_ports.shodan_internetdb", return_value={})
   @patch("mercure.checks.open_ports._scan_port")
   @patch("mercure.checks.open_ports.query_a", return_value=["1.2.3.4"])
   def test_expected_ports_only(self, mock_a, mock_scan, mock_shodan):
      expected = {80, 443}
      mock_scan.side_effect = lambda ip, port: port in expected
      from mercure.checks.open_ports import OpenPortsCheck
      result = OpenPortsCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "expected_ports_only"

   @patch("mercure.checks.open_ports.shodan_internetdb", return_value={})
   @patch("mercure.checks.open_ports._scan_port")
   @patch("mercure.checks.open_ports.query_a", return_value=["1.2.3.4"])
   def test_dangerous_ports(self, mock_a, mock_scan, mock_shodan):
      dangerous = {80, 443, 3306}
      mock_scan.side_effect = lambda ip, port: port in dangerous
      from mercure.checks.open_ports import OpenPortsCheck
      result = OpenPortsCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "dangerous_ports_open"

   @patch("mercure.checks.open_ports.shodan_internetdb", return_value={})
   @patch("mercure.checks.open_ports._scan_port")
   @patch("mercure.checks.open_ports.query_a", return_value=["1.2.3.4"])
   def test_unexpected_ports(self, mock_a, mock_scan, mock_shodan):
      unexpected = {80, 443, 8080}
      mock_scan.side_effect = lambda ip, port: port in unexpected
      from mercure.checks.open_ports import OpenPortsCheck
      result = OpenPortsCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "unexpected_ports"
