import os
import random
import string
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Dict, List

from . import logger
from .checks import ALL_CHECKS, get_check_by_name
from .scoring import (
   CheckResult, compute_global_score, compute_exploitability_score, score_to_ten,
)
from .spoof import run_spoof
from .dns_utils import clear_cache


def resolve_checks(names_str: str, intrusive: bool = False,
                   skip_external: bool = False) -> list:
   if names_str:
      names = [n.strip().lower() for n in names_str.split(",") if n.strip()]
      selected = []
      for name in names:
         cls = get_check_by_name(name)
         if cls:
            selected.append(cls)
         else:
            logger.warning(f"unknown check: {name}")
      return selected

   checks = list(ALL_CHECKS)
   if not intrusive:
      checks = [c for c in checks if not c.intrusive]
   if skip_external:
      checks = [c for c in checks if not c.external]
   return checks


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
   exploit_score = compute_exploitability_score(results)

   return {
      "domain": domain,
      "timestamp": datetime.now().isoformat(),
      "scores": {
         "security": global_score,
         "exploitability": exploit_score,
      },
      "checks_run": len(results),
      "checks": {
         r.name: {
            "label": r.label,
            "score": score_to_ten(r.score),
            "reason": r.reason,
            "value": r.value,
            "details": r.details,
         }
         for r in results
      },
      "global_score": global_score,
      "exploit_score": exploit_score,
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


def _generate_result_path() -> str:
   chars = string.ascii_uppercase + string.digits
   tag = "".join(random.choices(chars, k=5))
   datestamp = datetime.now().strftime("%Y%m%d")
   return os.path.join("results", f"{datestamp}_{tag}.txt")


def auto_save_results(results: List[Dict]) -> str:
   import json
   os.makedirs("results", exist_ok=True)
   path = _generate_result_path()
   with open(path, "w", encoding="utf-8") as f:
      json.dump(results, f, indent=2, default=str)
   return path


def run_spoof_test(domain: str, recipient: str, timeout: float,
                   parallel: bool = True) -> List[Dict]:
   return run_spoof(domain, recipient, timeout=timeout, parallel=parallel)
