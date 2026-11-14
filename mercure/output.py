import csv
import json
from typing import Dict, List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.box import DOUBLE

from . import logger
from .scoring import global_score_style, exploit_score_style

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


def print_scores_table(results: List[Dict]):
   if not results:
      return

   table = Table(show_header=True, header_style="bold white")
   table.add_column("Domain", style="bold")
   table.add_column("Security", justify="center", style="bold")
   table.add_column("Exploitability", justify="center", style="bold")
   table.add_column("Checks", justify="center")

   for r in results:
      gs = r["global_score"]
      es = r.get("exploit_score", 0.0)
      gs_style = global_score_style(gs)
      es_style = exploit_score_style(es)
      checks_run = r.get("checks_run", len(r.get("checks", {})))
      table.add_row(
         r["domain"],
         f"[{gs_style}]{gs}/10[/{gs_style}]",
         f"[{es_style}]{es}/10[/{es_style}]",
         str(checks_run),
      )

   console.print()
   legend = "[dim]Security: 10 = hardened, 0 = exposed  |  Exploitability: 10 = trivial, 0 = impractical[/dim]"
   console.print(Panel(table, title="Domain Security Audit", subtitle=legend, border_style="cyan"))


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


def save_json(data, path: str):
   with open(path, "w", encoding="utf-8") as f:
      json.dump(data, f, indent=2, default=str)
   logger.success(f"JSON results saved to {path}")


def save_csv(results: List[Dict], path: str):
   if not results:
      return

   all_check_names = _collect_check_names(results)

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
