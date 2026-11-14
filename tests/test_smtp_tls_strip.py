import ssl
from unittest.mock import patch, MagicMock, PropertyMock
from mercure.checks.smtp_tls_strip import SMTPTLSStripCheck, _test_plaintext, _test_deprecated_tls, _test_cert_match


def _mock_conn(has_starttls=True):
   conn = MagicMock()
   conn.connect.return_value = (220, b"220 ESMTP ready")
   conn.ehlo.return_value = (250, b"OK")
   conn.has_extn.side_effect = lambda ext: ext == "STARTTLS" and has_starttls
   conn.mail.return_value = (250, b"OK")
   conn.rset.return_value = (250, b"OK")
   conn.quit.return_value = None
   conn.sock = MagicMock()
   return conn


class TestPlaintext:
   @patch("mercure.checks.smtp_tls_strip.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.smtp_tls_strip.smtplib")
   def test_plaintext_accepted(self, mock_smtp, mock_ipv4):
      conn = _mock_conn()
      conn.mail.return_value = (250, b"OK")
      mock_smtp.SMTP.return_value = conn
      result = _test_plaintext("mx.example.com", "example.com")
      assert result["plaintext_accepted"] is True
      assert result["tls_required"] is False

   @patch("mercure.checks.smtp_tls_strip.resolve_ipv4", return_value="1.2.3.4")
   @patch("mercure.checks.smtp_tls_strip.smtplib")
   def test_tls_required(self, mock_smtp, mock_ipv4):
      conn = _mock_conn()
      conn.mail.return_value = (530, b"Must issue STARTTLS first")
      mock_smtp.SMTP.return_value = conn
      result = _test_plaintext("mx.example.com", "example.com")
      assert result["plaintext_accepted"] is False
      assert result["tls_required"] is True


class TestSMTPTLSStripCheck:
   @patch("mercure.checks.smtp_tls_strip._test_cert_match")
   @patch("mercure.checks.smtp_tls_strip._test_deprecated_tls")
   @patch("mercure.checks.smtp_tls_strip._test_plaintext")
   @patch("mercure.checks.smtp_tls_strip.query_mx")
   def test_plaintext_accepted_score0(self, mock_mx, mock_plain, mock_dep, mock_cert):
      mock_mx.return_value = [(10, "mx.example.com")]
      mock_plain.return_value = {"plaintext_accepted": True, "tls_required": False}
      mock_dep.return_value = False
      mock_cert.return_value = {"cert_match": True, "cert_names": ["mx.example.com"]}

      check = SMTPTLSStripCheck()
      result = check.run("example.com")
      assert result.score == 0
      assert result.reason == "plaintext_accepted"

   @patch("mercure.checks.smtp_tls_strip._test_cert_match")
   @patch("mercure.checks.smtp_tls_strip._test_deprecated_tls")
   @patch("mercure.checks.smtp_tls_strip._test_plaintext")
   @patch("mercure.checks.smtp_tls_strip.query_mx")
   def test_deprecated_tls_score1(self, mock_mx, mock_plain, mock_dep, mock_cert):
      mock_mx.return_value = [(10, "mx.example.com")]
      mock_plain.return_value = {"plaintext_accepted": False, "tls_required": True}
      mock_dep.side_effect = [True, False]
      mock_cert.return_value = {"cert_match": True, "cert_names": ["mx.example.com"]}

      check = SMTPTLSStripCheck()
      result = check.run("example.com")
      assert result.score == 1
      assert result.reason == "deprecated_tls_or_cert_mismatch"

   @patch("mercure.checks.smtp_tls_strip._test_cert_match")
   @patch("mercure.checks.smtp_tls_strip._test_deprecated_tls")
   @patch("mercure.checks.smtp_tls_strip._test_plaintext")
   @patch("mercure.checks.smtp_tls_strip.query_mx")
   def test_cert_mismatch_score1(self, mock_mx, mock_plain, mock_dep, mock_cert):
      mock_mx.return_value = [(10, "mx.example.com")]
      mock_plain.return_value = {"plaintext_accepted": False, "tls_required": True}
      mock_dep.return_value = False
      mock_cert.return_value = {"cert_match": False, "cert_names": ["other.example.com"]}

      check = SMTPTLSStripCheck()
      result = check.run("example.com")
      assert result.score == 1
      assert result.reason == "deprecated_tls_or_cert_mismatch"

   @patch("mercure.checks.smtp_tls_strip._test_cert_match")
   @patch("mercure.checks.smtp_tls_strip._test_deprecated_tls")
   @patch("mercure.checks.smtp_tls_strip._test_plaintext")
   @patch("mercure.checks.smtp_tls_strip.query_mx")
   def test_opportunistic_tls_score2(self, mock_mx, mock_plain, mock_dep, mock_cert):
      mock_mx.return_value = [(10, "mx.example.com")]
      mock_plain.return_value = {"plaintext_accepted": False, "tls_required": False}
      mock_dep.return_value = False
      mock_cert.return_value = {"cert_match": True, "cert_names": ["mx.example.com"]}

      check = SMTPTLSStripCheck()
      result = check.run("example.com")
      assert result.score == 2
      assert result.reason == "opportunistic_tls"

   @patch("mercure.checks.smtp_tls_strip._test_cert_match")
   @patch("mercure.checks.smtp_tls_strip._test_deprecated_tls")
   @patch("mercure.checks.smtp_tls_strip._test_plaintext")
   @patch("mercure.checks.smtp_tls_strip.query_mx")
   def test_tls_enforced_score3(self, mock_mx, mock_plain, mock_dep, mock_cert):
      mock_mx.return_value = [(10, "mx.example.com")]
      mock_plain.return_value = {"plaintext_accepted": False, "tls_required": True}
      mock_dep.return_value = False
      mock_cert.return_value = {"cert_match": True, "cert_names": ["mx.example.com"]}

      check = SMTPTLSStripCheck()
      result = check.run("example.com")
      assert result.score == 3
      assert result.reason == "tls_enforced"

   @patch("mercure.checks.smtp_tls_strip.query_mx")
   def test_no_mx(self, mock_mx):
      mock_mx.return_value = []
      check = SMTPTLSStripCheck()
      result = check.run("example.com")
      assert result.score == 2
      assert result.reason == "no_mx"

   @patch("mercure.checks.smtp_tls_strip._test_cert_match")
   @patch("mercure.checks.smtp_tls_strip._test_deprecated_tls")
   @patch("mercure.checks.smtp_tls_strip._test_plaintext")
   @patch("mercure.checks.smtp_tls_strip.query_mx")
   def test_multiple_mx(self, mock_mx, mock_plain, mock_dep, mock_cert):
      mock_mx.return_value = [(10, "mx1.example.com"), (20, "mx2.example.com")]
      mock_plain.return_value = {"plaintext_accepted": False, "tls_required": True}
      mock_dep.return_value = False
      mock_cert.return_value = {"cert_match": True, "cert_names": ["*.example.com"]}

      check = SMTPTLSStripCheck()
      result = check.run("example.com")
      assert result.score == 3
      assert len(result.details["mx_probes"]) == 2

   @patch("mercure.checks.smtp_tls_strip._test_cert_match")
   @patch("mercure.checks.smtp_tls_strip._test_deprecated_tls")
   @patch("mercure.checks.smtp_tls_strip._test_plaintext")
   @patch("mercure.checks.smtp_tls_strip.query_mx")
   def test_one_bad_mx_fails_all(self, mock_mx, mock_plain, mock_dep, mock_cert):
      mock_mx.return_value = [(10, "mx1.example.com"), (20, "mx2.example.com")]
      mock_plain.side_effect = [
         {"plaintext_accepted": False, "tls_required": True},
         {"plaintext_accepted": True, "tls_required": False},
      ]
      mock_dep.return_value = False
      mock_cert.return_value = {"cert_match": True, "cert_names": ["*.example.com"]}

      check = SMTPTLSStripCheck()
      result = check.run("example.com")
      assert result.score == 0
      assert result.reason == "plaintext_accepted"
