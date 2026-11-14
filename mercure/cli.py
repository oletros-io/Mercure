#!/usr/bin/env python3
import argparse
import json
import sys
from datetime import datetime
from typing import List, Dict

from . import logger
from .config import config
from .output import (
   console, get_banner_panel, print_scores_table,
   print_spoof_table, save_json, save_csv,
)
from .runner import resolve_checks, analyze_domain, analyze_file, run_spoof_test, auto_save_results


def rich_help():
   from rich.panel import Panel
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
      "  --checks NAMES            Comma-separated checks (default: all passive)\n"
      "                            DNS: spf,dkim,dmarc,caa,mx,ns,dnssec,ipv6,srv,ptr,tlsa,soa,axfr,wildcard,cname,dnsbl,zone_consistency\n"
      "                            Email: ghost,mta_sts,tls_rpt,bimi,seg,m365,spf_depth\n"
      "                            Web: tls,ct,hsts,headers,security_txt,redirect,cookie\n"
      "                            Recon: subdomains,dangling,whois,open_ports,rpki,autodiscover,spf_recon\n"
      "                            Intrusive (--intrusive): smtp_sec,smtp_recon,smtp_enum,smtp_tls_strip,bounce,nsec_walk,subdomain_brute,nuclei,katana\n"
      "  --intrusive               Enable intrusive checks (SMTP probing, bounce analysis)\n"
      "  --skip-external           Skip checks that call external APIs (crt.sh, Shodan, RDAP)\n"
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
      "  --no-parallel             Run spoof methods sequentially\n"
      "  --format FMT              Output format: text|json (default text)\n"
      "  --output PATH             Output file path\n\n"
      "[bold yellow]Common arguments:[/bold yellow]\n"
      "  --log-level LEVEL         Log verbosity: debug|info|warning|error|success (default info)\n"
      "  -h, --help                Show this help\n\n"
      "[bold yellow]Scoring:[/bold yellow]\n"
      "  Security:       10/10 = hardened, 0/10 = exposed\n"
      "  Exploitability: 10/10 = trivially exploitable, 0/10 = impractical\n"
      "  Results auto-saved to results/YYYYMMDD_XXXXX.txt\n\n"
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


def main_score(argv: list):
   ap = argparse.ArgumentParser(add_help=False)
   ap.add_argument("-d", "--domain")
   ap.add_argument("-f", "--file")
   ap.add_argument("--checks", default=None)
   ap.add_argument("--dkim-wordlist", default=None)
   ap.add_argument("--no-bruteforce", action="store_true")
   ap.add_argument("--aggressive", action="store_true")
   ap.add_argument("--intrusive", action="store_true")
   ap.add_argument("--skip-external", action="store_true")
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

   checks = resolve_checks(
      args.checks,
      intrusive=args.intrusive,
      skip_external=args.skip_external,
   )
   if not checks:
      logger.error("no valid checks selected")
      sys.exit(1)

   kwargs = {
      "dkim_bruteforce": not args.no_bruteforce,
      "dkim_aggressive": args.aggressive,
      "dkim_wordlist": args.dkim_wordlist or config.dkim_wordlist_path,
      "selector_threads": args.selector_threads,
      "smtp_timeout": config.smtp_timeout,
      "intrusive": args.intrusive,
      "skip_external": args.skip_external,
   }

   results: List[Dict] = []

   if args.domain:
      result = analyze_domain(args.domain, checks, **kwargs)
      results.append(result)

   if args.file:
      file_results = analyze_file(args.file, checks, args.threads, **kwargs)
      results.extend(file_results)

   print_scores_table(results)

   result_path = auto_save_results(results)
   logger.success(f"results saved to {result_path}")

   if args.format == "json" and args.output:
      save_json(results, args.output)
   elif args.format == "csv" and args.output:
      save_csv(results, args.output)

   logger.success("analysis complete")


def main_spoof(argv: list):
   ap = argparse.ArgumentParser(add_help=False)
   ap.add_argument("-d", "--domain")
   ap.add_argument("-r", "--recipient")
   ap.add_argument("--no-parallel", action="store_true")
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
   results = run_spoof_test(
      args.domain, args.recipient,
      timeout=config.smtp_timeout,
      parallel=not args.no_parallel,
   )

   print_spoof_table(results, args.domain, args.recipient)

   if args.format == "json" or args.output:
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
      elif args.format == "json":
         console.print()
         print(json.dumps(data, indent=2, default=str))

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
