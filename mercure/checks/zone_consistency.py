from .base import BaseCheck
from ..scoring import CheckResult
from ..dns_utils import query_all_ns


class ZoneConsistencyCheck(BaseCheck):
   name = "zone_consistency"
   label = "ZONE"

   def run(self, domain: str, **kwargs) -> CheckResult:
      ns_answers = query_all_ns(domain, "A")
      details = {"ns_answers": ns_answers}

      if len(ns_answers) < 2:
         return CheckResult(
            name=self.name, label=self.label,
            score=2, reason="single_ns_cannot_compare",
            details=details,
         )

      answer_sets = []
      has_error = False
      for ns, answer in ns_answers.items():
         if isinstance(answer, str) and answer.startswith("error:"):
            has_error = True
         else:
            answer_sets.append(tuple(sorted(answer)))

      if has_error:
         return CheckResult(
            name=self.name, label=self.label,
            score=2, reason="ns_query_error",
            details=details,
         )

      if len(set(answer_sets)) > 1:
         return CheckResult(
            name=self.name, label=self.label,
            score=1, reason="inconsistent_answers",
            details=details,
         )

      return CheckResult(
         name=self.name, label=self.label,
         score=3, reason="consistent",
         details=details,
      )
