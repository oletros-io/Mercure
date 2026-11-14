import pytest
from contextlib import ExitStack
from unittest.mock import MagicMock, patch
from mercure.config import Config, _ConfigProxy
from mercure.dns_utils import DnsResult, DnsError, _cache


@pytest.fixture(autouse=True)
def reset_config():
   from mercure import config as cfg_module
   cfg_module.config.reset(Config(
      log_dir=__import__("pathlib").Path("/tmp/mercure-test-logs"),
      dns_cache_ttl=300.0,
   ))
   yield
   cfg_module.config.reset(None)


@pytest.fixture(autouse=True)
def clear_dns_cache():
   _cache.clear()
   yield
   _cache.clear()


def _multi_patch(base_target, extra_targets):
   def _fixture(request):
      stack = ExitStack()
      m = stack.enter_context(patch(base_target))
      for t in extra_targets:
         try:
            stack.enter_context(patch(t, m))
         except AttributeError:
            pass
      request.addfinalizer(stack.close)
      return m
   return _fixture


mock_query_txt = pytest.fixture(name="mock_query_txt")(
   _multi_patch("mercure.dns_utils.query_txt", [
      "mercure.checks.spf.query_txt",
      "mercure.checks.dkim.query_txt",
      "mercure.checks.dmarc.query_txt",
   ])
)

mock_query_mx = pytest.fixture(name="mock_query_mx")(
   _multi_patch("mercure.dns_utils.query_mx", [
      "mercure.checks.ghost.query_mx",
      "mercure.checks.mx.query_mx",
      "mercure.spoof.query_mx",
   ])
)

mock_query_a = pytest.fixture(name="mock_query_a")(
   _multi_patch("mercure.dns_utils.query_a", [
      "mercure.checks.ghost.query_a",
      "mercure.checks.ptr.query_a",
   ])
)

mock_query_ns = pytest.fixture(name="mock_query_ns")(
   _multi_patch("mercure.dns_utils.query_ns", [
      "mercure.checks.ns.query_ns",
   ])
)

mock_query_ptr = pytest.fixture(name="mock_query_ptr")(
   _multi_patch("mercure.dns_utils.query_ptr", [
      "mercure.checks.ptr.query_ptr",
   ])
)

mock_query_cname = pytest.fixture(name="mock_query_cname")(
   _multi_patch("mercure.dns_utils.query_cname", [
      "mercure.checks.dkim.query_cname",
   ])
)


@pytest.fixture
def mock_smtp():
   with patch("mercure.smtp.smtplib") as m:
      mock_conn = MagicMock()
      mock_conn.ehlo.return_value = (250, b"OK")
      mock_conn.has_extn.return_value = False
      mock_conn.mail.return_value = (250, b"OK")
      mock_conn.rcpt.return_value = (250, b"OK")
      mock_conn.data.return_value = (250, b"OK")
      mock_conn.connect.return_value = (220, b"ESMTP ready")
      m.SMTP.return_value = mock_conn
      m.SMTP_SSL.return_value = mock_conn
      m.SMTPDataError = __import__("smtplib").SMTPDataError
      m.SMTPServerDisconnected = __import__("smtplib").SMTPServerDisconnected
      m.SMTPConnectError = __import__("smtplib").SMTPConnectError
      m.SMTPAuthenticationError = __import__("smtplib").SMTPAuthenticationError
      yield m, mock_conn
