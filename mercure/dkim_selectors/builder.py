import concurrent.futures as cf
import datetime as dt
import itertools
import os
import re
import string
import secrets
import pathlib
from typing import List, Set, Iterable

from .. import logger

VALID_CHARS = set(string.ascii_lowercase + string.digits + "-")
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")

L_PAT = re.compile(r"%L([^%]+)%")
N_PAT = re.compile(r"%N(\d+),(\d+)%")

MONTHS = [
   ("jan", "01"), ("feb", "02"), ("mar", "03"), ("apr", "04"), ("may", "05"), ("jun", "06"),
   ("jul", "07"), ("aug", "08"), ("sep", "09"), ("oct", "10"), ("nov", "11"), ("dec", "12"),
]


def sanitize(s: str) -> str:
   s = s.strip().lower()
   s = re.sub(r"[^a-z0-9\-]+", "-", s)
   s = re.sub(r"-{2,}", "-", s).strip("-")
   return s


def valid_selector(s: str) -> bool:
   if not s:
      return False
   if len(s) > 63:
      return False
   return bool(LABEL_RE.match(s))


def expand_placeholders(token: str) -> Iterable[str]:
   queue = [token]
   out = set()
   while queue:
      cur = queue.pop()
      m_l = L_PAT.search(cur)
      m_n = N_PAT.search(cur)
      if m_l:
         items = [x.strip() for x in m_l.group(1).split(",") if x.strip()]
         for it in items:
            queue.append(cur[:m_l.start()] + it + cur[m_l.end():])
         continue
      if m_n:
         start = int(m_n.group(1))
         end = int(m_n.group(2))
         for n in range(start, end + 1):
            queue.append(cur[:m_n.start()] + str(n) + cur[m_n.end():])
         continue
      out.add(cur)
   return out


def read_base_lines(path: pathlib.Path) -> List[str]:
   raw = []
   with open(path, "r", encoding="utf-8", errors="ignore") as fh:
      for line in fh:
         line = line.strip()
         if not line or line.startswith("#") or line.startswith(";"):
            continue
         raw.append(line)
   return raw


def expand_tokens_multithread(tokens: List[str], threads: int) -> Set[str]:
   results = set()
   with cf.ThreadPoolExecutor(max_workers=threads) as ex:
      futs = [ex.submit(expand_placeholders, t) for t in tokens]
      for f in cf.as_completed(futs):
         for v in f.result():
            results.add(v)
   return results


def curated_vendor_prefixes() -> List[str]:
   return [
      "default", "selector", "selector1", "selector2", "dkim", "dkim1", "dkim2", "s", "m", "mail", "smtp", "postfix",
      "key", "alpha", "beta", "gamma", "prod", "stage", "staging", "dev", "test",
      "google", "googlemail", "gmmailerd",
      "amazonses", "ses",
      "sendgrid", "smtpapi",
      "sparkpost", "sp", "spop", "spop1024",
      "mailgun", "mg", "mesmtp",
      "postmark", "pm", "pmta",
      "mailchimp", "mandrill", "mc",
      "proofpoint", "pp", "emaildefense",
      "mimecast", "mcx",
      "yesmail", "ym",
      "mailjet", "mj",
      "brevo", "sendinblue", "sib",
      "outlook", "microsoft", "ms", "exchange",
      "cm", "private", "x", "main", "authsmtp", "smtpout", "sm", "dk", "ei", "dk20050327",
      "dkrnt", "dkimrnt", "qcdkim", "mikd", "domk", "bfi", "dkimr", "class",
   ]


def year_patterns(start_year: int, end_year: int) -> Set[str]:
   prefixes = ["", "dkim", "dk", "s", "m", "selector", "key", "prod", "stage", "beta"]
   seps = ["", "-", "_"]
   out = set()
   for y in range(start_year, end_year + 1):
      ys = str(y)
      for p, sep in itertools.product(prefixes, seps):
         base = f"{p}{sep}{ys}" if p else ys
         out.add(base)
      for q in ("q1", "q2", "q3", "q4"):
         out.add(f"dkim-{ys}-{q}")
         out.add(f"{ys}-{q}")
   return out


def month_patterns(start_year: int, end_year: int) -> Set[str]:
   prefixes = ["", "dkim", "dk", "s", "selector"]
   seps = ["", "-", "_"]
   out = set()
   for y in range(start_year, end_year + 1):
      ys = str(y)
      for mn, mm in MONTHS:
         for p, sep in itertools.product(prefixes, seps):
            out.add(f"{p}{sep}{ys}{mm}")
            out.add(f"{p}{sep}{mn}{ys}")
            out.add(f"{p}{sep}{ys}-{mm}")
   return out


def numeric_suffix_patterns(prefixes: List[str], start: int, end: int) -> Set[str]:
   out = set()
   for p in prefixes:
      for n in range(start, end + 1):
         out.add(f"{p}{n}")
   return out


def aggressive_bruteforce() -> Set[str]:
   base = [
      "selector", "dkim", "s", "m", "mail", "key", "prod", "stage", "beta", "gamma",
      "pm", "pmta", "sp", "spop", "mg", "mc", "ms", "cm", "authsmtp", "smtp", "smtpout",
      "main", "private", "x",
   ]
   out = set()
   out |= numeric_suffix_patterns(base, 1, 50)
   out |= {f"s{b}" for b in ("256", "384", "512", "768", "1024", "2048")}
   out |= {f"m{b}" for b in ("256", "384", "512", "768", "1024", "2048")}
   return out


def dedupe_and_validate(candidates: Iterable[str]) -> List[str]:
   seen = set()
   out = []
   for c in candidates:
      s = sanitize(c)
      if not s:
         continue
      if s in seen:
         continue
      if not valid_selector(s):
         continue
      seen.add(s)
      out.append(s)
   return out


def random_suffix(n: int = 16) -> str:
   alphabet = string.ascii_uppercase + string.digits
   return "".join(secrets.choice(alphabet) for _ in range(n))


def safe_write_output(path: pathlib.Path, lines: List[str]):
   path.parent.mkdir(parents=True, exist_ok=True)
   if path.exists():
      new_name = path.parent / f"selectors_{random_suffix(16)}.bak"
      path.replace(new_name)
      logger.warning(f"Existing output renamed to {new_name.name}")
   tmp = path.with_suffix(path.suffix + ".tmp")
   with open(tmp, "w", encoding="utf-8") as fh:
      for s in lines:
         fh.write(s + "\n")
   tmp.replace(path)


def generate_selectors(
   base_path: pathlib.Path = None,
   aggressive: bool = False,
   years: str = None,
   threads: int = None,
) -> List[str]:

   current_year = dt.date.today().year
   years = years or f"2008:{current_year}"

   m = re.match(r"^\s*(\d{4})\s*:\s*(\d{4}|CURRENT)\s*$", years, flags=re.I)
   if not m:
      raise ValueError("Invalid years span. Use START:END or START:CURRENT")
   ystart = int(m.group(1))
   yend = current_year if m.group(2).upper() == "CURRENT" else int(m.group(2))
   if ystart > yend:
      ystart, yend = yend, ystart

   if not threads or threads <= 0:
      try:
         cpu = os.cpu_count() or 4
      except Exception:
         cpu = 4
      threads = min(cpu * 4, 32)

   expanded = set()
   if base_path and base_path.exists():
      logger.info(f"Loading base tokens from {base_path}")
      tokens = read_base_lines(base_path)
      if tokens:
         expanded = expand_tokens_multithread(tokens, threads)

   curated = set(curated_vendor_prefixes())
   curated |= year_patterns(ystart, yend)
   curated |= month_patterns(ystart, yend)
   curated |= {"v1", "v2", "v3", "v4", "v5"}
   curated |= {"dk", "dkimr", "dkimrnt"}

   if aggressive:
      logger.warning("Aggressive bruteforce enabled")
      curated |= aggressive_bruteforce()

   merged = expanded | curated
   sanitized = dedupe_and_validate(merged)

   logger.info(f"Final unique valid selectors: {len(sanitized)}")
   return sorted(sanitized)
