from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional


@dataclass
class CheckResult:
   name: str
   label: str
   score: int
   reason: str
   details: Dict[str, Any] = field(default_factory=dict)
   value: Optional[str] = None


WEIGHTS = {
   "spf": 3.0,
   "dkim": 2.5,
   "dmarc": 3.0,
   "dnssec": 2.0,
   "caa": 1.5,
   "mx": 1.5,
   "ns": 1.5,
   "ptr": 1.0,
   "ipv6": 0.5,
   "srv": 0.5,
   "tlsa": 1.0,
}

SCORE_STYLES = {
   0: "green",
   1: "yellow",
   2: "orange1",
   3: "red",
}


def compute_global_score(results: List[CheckResult]) -> float:
   if not results:
      return 0.0
   total_weight = 0.0
   weighted_sum = 0.0
   for r in results:
      w = WEIGHTS.get(r.name, 1.0)
      weighted_sum += r.score * w
      total_weight += w
   if total_weight == 0:
      return 0.0
   raw = weighted_sum / total_weight
   return round(raw / 3.0 * 10.0, 1)


def global_score_style(score: float) -> str:
   if score <= 2.0:
      return "green"
   if score <= 5.0:
      return "yellow"
   if score <= 7.0:
      return "orange1"
   return "red"
