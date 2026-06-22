#!/usr/bin/env python3
import argparse
import csv
import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.box import DOUBLE

from . import logger
from .config import config
from .checks import ALL_CHECKS, get_check_by_name
from .scoring import CheckResult, compute_global_score, global_score_style, SCORE_STYLES, score_to_ten
from .spoof import run_spoof

console = Console()

BANNER = r"""
███╗   ███╗███████╗██████╗  ██████╗██╗   ██╗██████╗ ███████╗
████╗ ████║██╔════╝██╔══██╗██╔════╝██║   ██║██╔══██╗██╔════╝
██╔████╔██║█████╗  ██████╔╝██║     ██║   ██║██████╔╝█████╗
██║╚██╔╝██║██╔══╝  ██╔══██╗██║     ██║   ██║██╔══██╗██╔══╝
██║ ╚═╝ ██║███████╗██║  ██║╚██████╗╚██████╔╝██║  ██║███████╗
╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
""".strip("\n")

SPOOF_STATUS_STYLES = {
   "delivered": "bold red",
   "rejected": "green",
   "skip": "grey50",
   "error": "yellow",
}


def get_banner_panel():
   meta = "[bold cyan]Company:[/] Oletros.io  |  [italic green]Mercure - Domain Security Auditor[/]"
   return Panel(f"{BANNER}\n\n{meta}", box=DOUBLE, style="bold magenta", expand=False)


def rich_help():
   console.print(get_banner_panel())
   panel = Panel.fit(
      "[bold yellow]Modes:[/bold yellow]\n"
      "  score              Run security checks and score the domain (default)\n"
      "  spoof              Attempt email spoofing with multiple methods\n\n"
      "[bold yellow]Score usage:[/bold yellow]\n"
      "  python mercure.py score -d example.com\n"
      "  python mercure.py score -f domains.txt --format json --output results.json\n"
      "  python mercure.py -d example.com                      [dim](implicit score)[/dim]\n\n"
      "[bold yellow]Score arguments:[/bold yellow]\n"
      "  -d, --domain              Domain to analyze\n"
      "  -f, --file                File with domains (one per line)\n"
      "  --checks NAMES            Comma-separated checks (default: all)\n"
      "                            Available: spf,dkim,dmarc,caa,mx,ns,dnssec,ipv6,srv,ptr,tlsa,ghost\n"
      "  --dkim-wordlist PATH      Custom DKIM selector wordlist path\n"
      "  --no-bruteforce           Disable DKIM selector bruteforce\n"
      "  --aggressive              Enable aggressive DKIM selector bruteforce\n"
      "  --threads N               Worker threads for file mode (default 16)\n"
      "  --selector-threads N      Worker threads for DKIM selector bruteforce (default 16)\n"
      "  --format FMT              Output format: text|json|csv (default text)\n"
      "  --output PATH             Output file path (default stdout)\n\n"
      "[bold yellow]Spoof usage:[/bold yellow]\n"
      "  python mercure.py spoof -d target.com -r victim@example.com\n\n"
      "[bold yellow]Spoof arguments:[/bold yellow]\n"
      "  -d, --domain              Domain to spoof as (sender = mercure@domain)\n"
      "  -r, --recipient           Recipient email address\n"
      "  --format FMT              Output format: text|json (default text)\n"
      "  --output PATH             Output file path\n\n"
      "[bold yellow]Common arguments:[/bold yellow]\n"
      "  --log-level LEVEL         Log verbosity: debug|info|warning|error|success (default info)\n"
      "  -h, --help                Show this help\n\n"
      "[bold yellow]Scoring:[/bold yellow]\n"
      "  10/10 = maximum security   0/10 = no security\n\n"
      "[bold yellow]Spoof methods (12):[/bold yellow]\n"
      "  direct       Spoofed mail via recipient's MX (tests SPF/DKIM/DMARC)\n"
      "  ghost        Bypass SEG via EXO direct endpoint (tests partner connector)\n"
      "  null_from    Empty envelope sender, spoofed From header (bounce-style)\n"
      "  subdomain    From nonexistent.<domain> (tests DMARC sp= policy)\n"
      "  relay        Route through target's own MX (tests open relay)\n"
      "  mismatch     Envelope domain != header From domain (tests DMARC alignment)\n"
      "  display_name Neutral sender, spoofed display name (BEC-style)\n"
      "  internal     Intra-domain spoof via target's MX (tests internal filtering)\n"
      "  backscatter  Bounce to victim via nonexistent@target (tests recipient validation)\n"
      "  bs_inject    NDR content injection: phishing body in bounce (tests NDR body inclusion)\n"
      "  bs_amp       NDR amplification: 5 dead recipients per session (tests per-rcpt NDR)\n"
      "  bs_oob       Auto-reply abuse: functional addresses (tests OOO sender validation)\n",
      title="Mercure - Domain Security Auditor",
      border_style="cyan",
   )
   console.print(panel)


def analyze_domain(domain: str, checks: list, **kwargs) -> Dict:
   logger.info(f"analyzing {domain}")
   results: List[CheckResult] = []

   for check_cls in checks:
      check = check_cls()
      try:
         result = check.run(domain, **kwargs)
         results.append(result)
         displayed = score_to_ten(result.score)
         logger.info(f"  {result.label}: {displayed}/10 ({result.reason})")
      except Exception as exc:
         logger.error(f"  {check.label} check failed: {exc}")

   global_score = compute_global_score(results)

   return {
      "domain": domain,
      "timestamp": datetime.now().isoformat(),
      "checks": {
         r.name: {
            "score": score_to_ten(r.score),
            "reason": r.reason,
            "value": r.value,
            "details": r.details,
         }
         for r in results
      },
      "global_score": global_score,
   }


def analyze_file(file_path: str, checks: list, threads: int, **kwargs) -> List[Dict]:
   try:
      with open(file_path, "r", encoding="utf-8") as f:
         domains = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
   except Exception as exc:
      logger.error(f"could not read file {file_path}: {exc}")
      return []

   results: List[Dict] = []
   lock = threading.Lock()

   def task(d: str):
      r = analyze_domain(d, checks, **kwargs)
      with lock:
         results.append(r)

   with ThreadPoolExecutor(max_workers=max(2, threads)) as executor:
      futures = [executor.submit(task, d) for d in domains]
      for _ in as_completed(futures):
         pass

   return results


def print_scores_table(results: List[Dict]):
   if not results:
      return

   all_check_names = []
   for r in results:
      for name in r.get("checks", {}):
         if name not in all_check_names:
            all_check_names.append(name)

   table = Table(show_header=True, header_style="bold white")
   table.add_column("Domain", style="bold")

   for name in all_check_names:
      table.add_column(name.upper(), justify="center")

   table.add_column("Score", justify="center", style="bold")

   for r in results:
      row = [r["domain"]]

      for name in all_check_names:
         check_data = r.get("checks", {}).get(name)
         if check_data:
            s10 = check_data["score"]
            if s10 == 10:
               style = "green"
            elif s10 >= 7:
               style = "yellow"
            elif s10 >= 3:
               style = "orange1"
            else:
               style = "red"
            row.append(f"[{style}]{s10}[/{style}]")
         else:
            row.append("[grey50]-[/grey50]")

      gs = r["global_score"]
      gs_style = global_score_style(gs)
      row.append(f"[{gs_style}]{gs}/10[/{gs_style}]")

      table.add_row(*row)

   console.print()
   console.print(Panel(table, title="Domain Security Scores (10 = max security, 0 = none)", border_style="cyan"))


def print_spoof_table(results: List[Dict], domain: str, recipient: str):
   if not results:
      return

   header_text = (
      f"[bold cyan]Sender:[/] mercure@{domain}\n"
      f"[bold cyan]Recipient:[/] {recipient}\n"
      f"[bold cyan]Subject:[/] Security Test"
   )

   table = Table(show_header=True, header_style="bold white")
   table.add_column("Method", style="bold", min_width=10)
   table.add_column("Server", min_width=15)
   table.add_column("Status", justify="center", min_width=10)
   table.add_column("Details", max_width=60)

   for r in results:
      method = r.get("method", "?")
      server = r.get("server", "-")
      status = r.get("status", "error").upper()
      reason = r.get("reason", "")
      style = SPOOF_STATUS_STYLES.get(r.get("status", ""), "white")
      table.add_row(method, server, f"[{style}]{status}[/{style}]", reason)

   console.print()
   console.print(Panel(header_text, title="Spoof Test Parameters", border_style="cyan"))
   console.print(Panel(table, title="Spoof Results", border_style="cyan"))

   delivered = sum(1 for r in results if r.get("status") == "delivered")
   rejected = sum(1 for r in results if r.get("status") == "rejected")
   skipped = sum(1 for r in results if r.get("status") == "skip")
   errors = sum(1 for r in results if r.get("status") == "error")

   summary = f"[green]Rejected: {rejected}[/]  [red]Delivered: {delivered}[/]  [grey50]Skipped: {skipped}[/]  [yellow]Errors: {errors}[/]"
   console.print(Panel(summary, title="Summary", border_style="cyan"))


def save_json(results, path: str):
   with open(path, "w", encoding="utf-8") as f:
      json.dump(results, f, indent=2, default=str)
   logger.success(f"JSON results saved to {path}")


def save_csv(results: List[Dict], path: str):
   if not results:
      return

   all_check_names = []
   for r in results:
      for name in r.get("checks", {}):
         if name not in all_check_names:
            all_check_names.append(name)

   with open(path, "w", newline="", encoding="utf-8") as f:
      writer = csv.writer(f)
      header = ["domain"] + [n.upper() for n in all_check_names] + ["global_score"]
      writer.writerow(header)

      for r in results:
         row = [r["domain"]]
         for name in all_check_names:
            check_data = r.get("checks", {}).get(name)
            row.append(check_data["score"] if check_data else "")
         row.append(r["global_score"])
         writer.writerow(row)

   logger.success(f"CSV results saved to {path}")


def resolve_checks(names_str: str) -> list:
   if not names_str:
      return list(ALL_CHECKS)

   names = [n.strip().lower() for n in names_str.split(",") if n.strip()]
   selected = []

   for name in names:
      cls = get_check_by_name(name)
      if cls:
         selected.append(cls)
      else:
         logger.warning(f"unknown check: {name}")

   return selected


def main_score(argv: list):
   ap = argparse.ArgumentParser(add_help=False)
   ap.add_argument("-d", "--domain")
   ap.add_argument("-f", "--file")
   ap.add_argument("--checks", default=None)
   ap.add_argument("--dkim-wordlist", default=None)
   ap.add_argument("--no-bruteforce", action="store_true")
   ap.add_argument("--aggressive", action="store_true")
   ap.add_argument("--threads", type=int, default=config.default_threads)
   ap.add_argument("--selector-threads", type=int, default=config.selector_threads)
   ap.add_argument("--log-level", default="info")
   ap.add_argument("--format", choices=["text", "json", "csv"], default="text")
   ap.add_argument("--output", default=None)
   ap.add_argument("-h", "--help", action="store_true")
   args = ap.parse_args(argv)

   if args.help or (not args.domain and not args.file):
      rich_help()
      if not args.help:
         sys.exit(1)
      return

   console.print(get_banner_panel())
   logger.set_level(args.log_level)

   checks = resolve_checks(args.checks)
   if not checks:
      logger.error("no valid checks selected")
      sys.exit(1)

   kwargs = {
      "dkim_bruteforce": not args.no_bruteforce,
      "dkim_aggressive": args.aggressive,
      "dkim_wordlist": args.dkim_wordlist or config.dkim_wordlist_path,
      "selector_threads": args.selector_threads,
      "smtp_timeout": config.smtp_timeout,
   }

   results: List[Dict] = []

   if args.domain:
      result = analyze_domain(args.domain, checks, **kwargs)
      results.append(result)

   if args.file:
      file_results = analyze_file(args.file, checks, args.threads, **kwargs)
      results.extend(file_results)

   if args.format == "text" or args.format == "json":
      print_scores_table(results)

   if args.format == "json":
      if args.output:
         save_json(results, args.output)
      else:
         console.print()
         print(json.dumps(results, indent=2))

   elif args.format == "csv":
      if args.output:
         save_csv(results, args.output)
      else:
         print_scores_table(results)

   logger.success("analysis complete")


def main_spoof(argv: list):
   ap = argparse.ArgumentParser(add_help=False)
   ap.add_argument("-d", "--domain")
   ap.add_argument("-r", "--recipient")
   ap.add_argument("--log-level", default="info")
   ap.add_argument("--format", choices=["text", "json"], default="text")
   ap.add_argument("--output", default=None)
   ap.add_argument("-h", "--help", action="store_true")
   args = ap.parse_args(argv)

   if args.help or not args.domain or not args.recipient:
      rich_help()
      if not args.help:
         logger.error("spoof mode requires -d DOMAIN and -r RECIPIENT")
         sys.exit(1)
      return

   console.print(get_banner_panel())
   logger.set_level(args.log_level)

   logger.info(f"spoofing as mercure@{args.domain} -> {args.recipient}")
   results = run_spoof(args.domain, args.recipient, timeout=config.smtp_timeout)

   if args.format == "text":
      print_spoof_table(results, args.domain, args.recipient)

   if args.format == "json":
      data = {
         "mode": "spoof",
         "domain": args.domain,
         "sender": f"mercure@{args.domain}",
         "recipient": args.recipient,
         "timestamp": datetime.now().isoformat(),
         "methods": results,
      }
      if args.output:
         save_json(data, args.output)
      else:
         if args.format == "json":
            print_spoof_table(results, args.domain, args.recipient)
         console.print()
         print(json.dumps(data, indent=2, default=str))

   if args.output and args.format == "text":
      data = {
         "mode": "spoof",
         "domain": args.domain,
         "sender": f"mercure@{args.domain}",
         "recipient": args.recipient,
         "timestamp": datetime.now().isoformat(),
         "methods": results,
      }
      save_json(data, args.output)

   delivered = sum(1 for r in results if r.get("status") == "delivered")
   if delivered:
      logger.warning(f"{delivered} method(s) delivered successfully - domain is vulnerable to spoofing")
   else:
      logger.success("all methods blocked or failed - domain defenses held")


def main():
   raw_args = sys.argv[1:]

   if not raw_args or (len(raw_args) == 1 and raw_args[0] in ("-h", "--help")):
      rich_help()
      if not raw_args:
         sys.exit(1)
      return

   if raw_args[0] in ("score", "spoof"):
      mode = raw_args[0]
      mode_args = raw_args[1:]
   else:
      mode = "score"
      mode_args = raw_args

   if mode == "score":
      main_score(mode_args)
   elif mode == "spoof":
      main_spoof(mode_args)


if __name__ == "__main__":
   try:
      main()
   except KeyboardInterrupt:
      logger.error("interrupted by user")
      sys.exit(130)
   except Exception as exc:
      logger.error(f"unhandled error: {exc}")
      sys.exit(1)
