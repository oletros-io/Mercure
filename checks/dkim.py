import base64
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Iterable

from checks.base import BaseCheck
from scoring import CheckResult
from dns_utils import query_txt, query_cname
import logger

BASE_SELECTORS = [
   "default", "dkim", "dkim1", "dkim2", "selector", "selector1", "selector2", "s1", "s2", "s3", "s4", "smtp", "smtp1", "smtp2", "smtp3",
   "mail", "mail1", "mail2", "mail3", "api", "transactional", "transactional1", "transactional2", "marketing", "news", "bulk", "mx", "mx1",
   "send", "send1", "sendgrid", "sparkpost", "postmark", "amazonses", "mailgun", "brevo", "mandrill", "google", "google1", "ms", "o365", "office",
   "noreply", "no-reply", "newsletter", "key1", "key2", "key3", "selector3", "s5", "trans", "sales", "shop", "magento", "shopify", "notify",
   "smtpapi", "bfi", "spop", "spop1024", "beta", "domk", "dk", "ei", "smtpout", "sm", "authsmtp", "alpha", "mesmtp", "cm", "prod", "pm", "gamma",
   "dkrnt", "dkimrnt", "private", "gmmailerd", "pmta", "x", "qcdkim", "postfix", "mikd", "main", "m", "dk20050327", "delta", "yibm", "wesmail",
   "test", "stigmate", "squaremail", "sitemail", "sasl", "sailthru", "responsys", "publickey", "proddkim", "mail-in", "key", "ED-DKIM",
   "ebmailerd", "Corporate", "care", "0xdeadbeef", "yousendit", "www", "tilprivate", "testdk", "smtpcomcustomers", "smtpauth",
   "sharedpool", "ses", "server", "scooby", "scarlet", "safe", "s", "pvt", "primus", "primary", "postfix.private", "outbound", "originating",
   "one", "neomailout", "msa", "monkey", "mkt", "mimi", "mdaemon", "mailrelay", "mailjet", "mail-dkim", "mailo", "lists",
   "iweb", "iport", "id", "hubris", "googleapps", "global", "gears", "exim4u", "exim", "et", "dyn", "duh", "dksel", "dkimmail", "corp",
   "centralsmtp", "ca", "auth", "allselector", "zendesk1", "class",
]

INLINE_PATTERNS = [
   "default", "google", "mail", "class",
   "s%L384,512,768,1024,2048%", "m%L384,512,768,1024,2048%", "smtpapi", "dkim", "bfi", "spop", "spop1024", "beta", "domk",
   "key%N1,20%", "dk", "ei", "yesmail%N1,20%", "smtpout", "sm", "selector%N1,20%", "authsmtp", "alpha", "v%N1,5%", "mesmtp", "cm",
   "prod", "pm", "gamma", "dkrnt", "dkimrnt", "private", "gmmailerd", "pmta", "m%N1,20%", "x", "selector", "qcdkim", "postfix", "mikd",
   "main", "m", "dk20050327", "delta", "yibm", "wesmail", "test", "stigmate", "squaremail", "sitemail", "sel%N1,20%", "sasl", "sailthru",
   "rsa%N1,20%", "responsys", "publickey", "proddkim", "my%N1,20%", "mail-in", "ls%N1,20%", "key", "ED-DKIM", "ebmailerd", "eb%N1,20%",
   "dk%N1,20%", "Corporate", "care", "0xdeadbeef", "yousendit", "www", "tilprivate", "testdk", "smtpcomcustomers", "smtpauth", "smtp",
   "sl%N1,20%", "sl", "sharedpool", "ses", "server", "scooby", "scarlet", "safe", "s", "s%N1,20%", "pvt", "primus", "primary", "postfix.private",
   "outbound", "originating", "one", "neomailout", "mx", "msa", "monkey", "mkt", "mimi", "mdaemon", "mailrelay", "mailjet", "mail-dkim",
   "mailo", "mandrill", "lists", "iweb", "iport", "id", "hubris", "googleapps", "global", "gears", "exim4u", "exim", "et", "dyn", "duh",
   "dksel", "dkimmail", "corp", "centralsmtp", "ca", "bfi", "auth", "allselector", "zendesk1",
]

GUESSABLE_PATTERNS = [
   r"^default$", r"^selector\d*$", r"^selector$", r"^s\d+$", r"^key\d+$", r"^dkim\d*$", r"^mail\d*$", r"^api$",
   r"^(marketing|transactional|newsletter|bulk|news)$", r"^(smtp|mx|send)$",
]


def expand_inline_patterns(patterns: Iterable[str]) -> List[str]:
   out = []
   for p in patterns:
      if "%L" in p and p.endswith("%"):
         prefix, rest = p.split("%L", 1)
         vals = rest.rstrip("%")
         for v in vals.split(","):
            v = v.strip()
            if v:
               out.append(f"{prefix}{v}")
      elif "%N" in p and p.endswith("%"):
         prefix, rest = p.split("%N", 1)
         rng = rest.rstrip("%")
         parts = [x.strip() for x in rng.split(",") if x.strip()]
         if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            a, b = int(parts[0]), int(parts[1])
            step = 1 if a <= b else -1
            for n in range(a, b + step, step):
               out.append(f"{prefix}{n}")
      else:
         out.append(p)
   return list(dict.fromkeys(out))


def load_selectors_wordlist(path: str) -> List[str]:
   if not path:
      return []
   try:
      with open(path, "r", encoding="utf-8") as f:
         return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
   except Exception as e:
      logger.warning(f"wordlist load failed path={path} error={e}")
      return []


def is_guessable(selector: str) -> bool:
   sel = selector.lower()
   if sel in BASE_SELECTORS:
      return True
   for pat in GUESSABLE_PATTERNS:
      if re.match(pat, sel):
         return True
   if len(sel) < 4:
      return True
   if re.match(r"^[a-z0-9\-]{1,8}$", sel):
      return True
   return False


def parse_dkim_record(txt: str) -> Dict[str, str]:
   parts = [p.strip() for p in re.split(r";\s*", txt) if p.strip()]
   d = {}
   for p in parts:
      if "=" in p:
         k, v = p.split("=", 1)
         d[k.strip().lower()] = v.strip()
   return d


def approx_key_bits(p_value: str) -> int:
   try:
      raw = base64.b64decode(p_value + "===")
      return len(raw) * 8
   except Exception:
      return 0


def scan_selector(domain: str, selector: str) -> Dict:
   fqdn = f"{selector}._domainkey.{domain}".strip(".")
   txts = query_txt(fqdn)

   for rec in txts:
      low = rec.lower()
      if "v=dkim1" not in low or "p=" not in low:
         continue

      tags = parse_dkim_record(rec)
      p = tags.get("p", "")
      k = tags.get("k", "rsa")
      t = tags.get("t", "")
      n = tags.get("n", "")
      s = tags.get("s", "")
      bits = approx_key_bits(p) if p else 0

      risky = []
      if "l=" in rec:
         risky.append("l")
      if t == "y":
         risky.append("t")

      vendor = ""
      cnames = query_cname(fqdn)
      if cnames:
         vendor = cnames[0]

      return {
         "selector": selector,
         "fqdn": fqdn,
         "present": True,
         "key_bits_approx": bits,
         "weak_key": bool(bits and bits < 2048),
         "algo": k,
         "risky_tags": risky,
         "guessable_selector": bool(is_guessable(selector)),
         "vendor_cname": vendor,
         "notes_tag_present": bool(n != ""),
         "services_tag": s,
         "raw": rec,
      }

   return {"selector": selector, "fqdn": fqdn, "present": False}


def brute_selectors(domain: str, extra: List[str]) -> List[str]:
   base = list(dict.fromkeys(BASE_SELECTORS + extra))
   enriched = []
   for b in base:
      enriched.append(b)
      enriched.append(f"{b}1")
      enriched.append(f"{b}2")
   return list(dict.fromkeys(enriched))


def evaluate_dkim(results: List[Dict]) -> Dict:
   present = [r for r in results if r.get("present")]
   if not present:
      return {"score": 3, "reason": "no_dkim", "details": []}

   weak = sum(1 for r in present if r.get("weak_key"))
   risky = sum(1 for r in present if r.get("risky_tags"))
   guess = sum(1 for r in present if r.get("guessable_selector"))
   details = present

   if weak and (weak >= 1) and (weak < len(present) + 1):
      return {"score": 1, "reason": "weak_key_present", "details": details}

   if risky or guess:
      return {"score": 2, "reason": "risky_or_guessable_selector", "details": details}

   return {"score": 0, "reason": "strong_dkim", "details": details}


class DKIMCheck(BaseCheck):
   name = "dkim"
   label = "DKIM"
   weight = 2.5

   def run(self, domain: str, **kwargs) -> CheckResult:
      bruteforce = kwargs.get("dkim_bruteforce", True)
      aggressive = kwargs.get("dkim_aggressive", False)
      wordlist = kwargs.get("dkim_wordlist", None)
      selector_threads = kwargs.get("selector_threads", 16)

      candidates: List[str] = []
      if bruteforce:
         wl = []
         if aggressive:
            wl_expanded = expand_inline_patterns(INLINE_PATTERNS)
            file_sels = load_selectors_wordlist(wordlist) if wordlist else []
            wl = list(dict.fromkeys(file_sels + wl_expanded))
            logger.info(f"Aggressive selectors count={len(wl)}")
         candidates = brute_selectors(domain, wl)

      dkim_results: List[Dict] = []
      if candidates:
         seen = set()
         uniq = [c for c in candidates if not (c in seen or seen.add(c))]
         with ThreadPoolExecutor(max_workers=max(2, selector_threads)) as executor:
            futures = {executor.submit(scan_selector, domain, s): s for s in uniq}
            for fut in as_completed(futures):
               r = fut.result()
               if r.get("present"):
                  dkim_results.append(r)

      dkim_eval = evaluate_dkim(dkim_results)
      return CheckResult(
         name=self.name,
         label=self.label,
         score=dkim_eval["score"],
         reason=dkim_eval["reason"],
         details={
            "selectors_found": len(dkim_results),
            "selectors": dkim_eval.get("details", []),
         },
      )
