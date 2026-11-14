from unittest.mock import patch, MagicMock
from mercure.checks.autodiscover import AutodiscoverCheck


def _mock_resp(status_code=200, text="", headers=None):
   resp = MagicMock()
   resp.status_code = status_code
   resp.text = text
   resp.headers = headers or {}
   return resp


class TestAutodiscoverCheck:
   @patch("mercure.checks.autodiscover.query_cname", return_value=[])
   @patch("mercure.checks.autodiscover.query_srv", return_value=[])
   @patch("mercure.checks.autodiscover.fetch_insecure", return_value=None)
   @patch("mercure.checks.autodiscover.fetch", return_value=None)
   def test_no_endpoints(self, mock_f, mock_fi, mock_srv, mock_cname):
      result = AutodiscoverCheck().run("example.com")
      assert result.score == 3
      assert result.reason == "no_autodiscover"
      assert result.details["total_accessible"] == 0
      assert result.details["info_leaks"] == 0

   @patch("mercure.checks.autodiscover.query_cname", return_value=[])
   @patch("mercure.checks.autodiscover.query_srv", return_value=[])
   @patch("mercure.checks.autodiscover.fetch_insecure", return_value=None)
   @patch("mercure.checks.autodiscover.fetch")
   def test_info_leak_exchange(self, mock_f, mock_fi, mock_srv, mock_cname):
      resp = _mock_resp(
         status_code=200,
         text='<Autodiscover><Response><Account><Protocol><Type>EXPR</Type><Server>mail.exchange.corp.local</Server></Protocol></Account></Response></Autodiscover>',
         headers={"Server": "Microsoft-IIS/10.0"},
      )
      mock_f.return_value = resp
      result = AutodiscoverCheck().run("example.com")
      assert result.score == 0
      assert result.reason == "autodiscover_info_leak"
      assert result.details["info_leaks"] > 0

   @patch("mercure.checks.autodiscover.query_cname", return_value=[])
   @patch("mercure.checks.autodiscover.query_srv", return_value=[])
   @patch("mercure.checks.autodiscover.fetch_insecure", return_value=None)
   @patch("mercure.checks.autodiscover.fetch")
   def test_accessible_no_major_leak(self, mock_f, mock_fi, mock_srv, mock_cname):
      resp = _mock_resp(
         status_code=200,
         text='<config><emailProvider></emailProvider></config>',
         headers={"X-Powered-By": "Express"},
      )
      mock_f.return_value = resp
      result = AutodiscoverCheck().run("example.com")
      assert result.score == 1
      assert result.reason == "autodiscover_limited_leak"

   @patch("mercure.checks.autodiscover.query_cname", return_value=[])
   @patch("mercure.checks.autodiscover.query_srv", return_value=[])
   @patch("mercure.checks.autodiscover.fetch_insecure")
   @patch("mercure.checks.autodiscover.fetch", return_value=None)
   def test_http_autoconfig_unencrypted(self, mock_f, mock_fi, mock_srv, mock_cname):
      resp = _mock_resp(
         status_code=200,
         text='<clientConfig><emailProvider id="example.com"></emailProvider></clientConfig>',
         headers={},
      )
      mock_fi.return_value = resp
      result = AutodiscoverCheck().run("example.com")
      assert result.score == 1

   @patch("mercure.checks.autodiscover.query_cname", return_value=[])
   @patch("mercure.checks.autodiscover.query_srv", return_value=[])
   @patch("mercure.checks.autodiscover.fetch_insecure", return_value=None)
   @patch("mercure.checks.autodiscover.fetch")
   def test_secured_401(self, mock_f, mock_fi, mock_srv, mock_cname):
      resp = _mock_resp(status_code=401, text="", headers={})
      mock_f.return_value = resp
      result = AutodiscoverCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "autodiscover_secured"

   @patch("mercure.checks.autodiscover.query_cname", return_value=[])
   @patch("mercure.checks.autodiscover.query_srv")
   @patch("mercure.checks.autodiscover.fetch_insecure", return_value=None)
   @patch("mercure.checks.autodiscover.fetch", return_value=None)
   def test_srv_record_only(self, mock_f, mock_fi, mock_srv, mock_cname):
      mock_srv.return_value = [{"priority": 0, "weight": 0, "port": 443, "target": "autodiscover.outlook.com"}]
      result = AutodiscoverCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "autodiscover_secured"
      assert result.details["srv_record"] is not None

   @patch("mercure.checks.autodiscover.query_cname")
   @patch("mercure.checks.autodiscover.query_srv", return_value=[])
   @patch("mercure.checks.autodiscover.fetch_insecure", return_value=None)
   @patch("mercure.checks.autodiscover.fetch", return_value=None)
   def test_cname_only(self, mock_f, mock_fi, mock_srv, mock_cname):
      mock_cname.return_value = ["autodiscover.outlook.com"]
      result = AutodiscoverCheck().run("example.com")
      assert result.score == 2
      assert result.reason == "autodiscover_secured"
      assert result.details["autodiscover_cname"] == "autodiscover.outlook.com"

   @patch("mercure.checks.autodiscover.query_cname", return_value=[])
   @patch("mercure.checks.autodiscover.query_srv", return_value=[])
   @patch("mercure.checks.autodiscover.fetch_insecure", return_value=None)
   @patch("mercure.checks.autodiscover.fetch")
   def test_redirect_not_accessible(self, mock_f, mock_fi, mock_srv, mock_cname):
      resp = _mock_resp(status_code=302, text="", headers={})
      mock_f.return_value = resp
      result = AutodiscoverCheck().run("example.com")
      assert result.score == 3
      assert result.details["total_accessible"] == 0
