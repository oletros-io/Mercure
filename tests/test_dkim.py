import base64
from unittest.mock import patch
from mercure.checks.dkim import (
   parse_rsa_key_bits, evaluate_dkim, is_guessable, expand_inline_patterns,
   parse_dkim_record, DKIMCheck, brute_selectors,
)


RSA_2048_DER = (
   b"\x30\x82\x01\x22\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01"
   b"\x01\x05\x00\x03\x82\x01\x0f\x00\x30\x82\x01\x0a\x02\x82\x01\x01"
   b"\x00" + b"\xab" * 256 + b"\x02\x03\x01\x00\x01"
)

RSA_1024_DER = (
   b"\x30\x81\x9f\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"
   b"\x05\x00\x03\x81\x8d\x00\x30\x81\x89\x02\x81\x81\x00"
   + b"\xab" * 128 + b"\x02\x03\x01\x00\x01"
)


class TestParseRsaKeyBits:
   def test_2048_bit_key(self):
      p_value = base64.b64encode(RSA_2048_DER).decode()
      bits = parse_rsa_key_bits(p_value)
      assert bits == 2048

   def test_1024_bit_key(self):
      p_value = base64.b64encode(RSA_1024_DER).decode()
      bits = parse_rsa_key_bits(p_value)
      assert bits == 1024

   def test_empty_value(self):
      assert parse_rsa_key_bits("") == 0

   def test_invalid_base64(self):
      assert parse_rsa_key_bits("!!!invalid!!!") == 0

   def test_too_short(self):
      p_value = base64.b64encode(b"\x30\x01\x00").decode()
      assert parse_rsa_key_bits(p_value) == 0


class TestEvaluateDkim:
   def test_no_dkim(self):
      r = evaluate_dkim([])
      assert r["score"] == 0
      assert r["reason"] == "no_dkim"

   def test_strong_dkim(self):
      r = evaluate_dkim([{
         "present": True, "key_bits": 2048, "weak_key": False,
         "risky_tags": [], "guessable_selector": False,
      }])
      assert r["score"] == 3
      assert r["reason"] == "strong_dkim"

   def test_weak_key(self):
      r = evaluate_dkim([{
         "present": True, "key_bits": 1024, "weak_key": True,
         "risky_tags": [], "guessable_selector": False,
      }])
      assert r["score"] == 1
      assert r["reason"] == "weak_key"

   def test_l_tag(self):
      r = evaluate_dkim([{
         "present": True, "key_bits": 2048, "weak_key": False,
         "risky_tags": ["l"], "guessable_selector": False,
      }])
      assert r["score"] == 1
      assert r["reason"] == "dangerous_l_tag"

   def test_test_mode(self):
      r = evaluate_dkim([{
         "present": True, "key_bits": 2048, "weak_key": False,
         "risky_tags": ["t"], "guessable_selector": False,
      }])
      assert r["score"] == 2
      assert r["reason"] == "test_mode"

   def test_all_guessable(self):
      r = evaluate_dkim([{
         "present": True, "key_bits": 2048, "weak_key": False,
         "risky_tags": [], "guessable_selector": True,
      }])
      assert r["score"] == 2
      assert r["reason"] == "all_selectors_guessable"

   def test_not_present_ignored(self):
      r = evaluate_dkim([{"present": False}])
      assert r["score"] == 0


class TestIsGuessable:
   def test_base_selectors(self):
      assert is_guessable("default") is True
      assert is_guessable("selector1") is True

   def test_short_selector(self):
      assert is_guessable("ab") is True

   def test_long_random(self):
      assert is_guessable("x7k9m2p4q8w1") is False


class TestExpandInlinePatterns:
   def test_literal(self):
      assert expand_inline_patterns(["default"]) == ["default"]

   def test_numeric_range(self):
      result = expand_inline_patterns(["key%N1,3%"])
      assert result == ["key1", "key2", "key3"]

   def test_list_pattern(self):
      result = expand_inline_patterns(["s%L512,1024%"])
      assert result == ["s512", "s1024"]


class TestParseDkimRecord:
   def test_basic(self):
      r = parse_dkim_record("v=DKIM1; k=rsa; p=ABCD")
      assert r["v"] == "DKIM1"
      assert r["k"] == "rsa"
      assert r["p"] == "ABCD"


class TestBruteSelectors:
   def test_enriches(self):
      result = brute_selectors(["custom"])
      assert "default" in result
      assert "custom" in result
      assert "custom1" in result
      assert "custom2" in result

   def test_deduplicates(self):
      result = brute_selectors(["default"])
      assert result.count("default") == 1
