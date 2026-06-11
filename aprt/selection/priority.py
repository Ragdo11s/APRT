"""
Priority = "how worth-it is this next test", NOT the finding's severity.

This is the axis the selector owns and the evaluator deliberately does not.
- pivot_value: new attack surface this action opens (from the rule's weight).
  A 0.0-severity fingerprint can have a high pivot value -- that's the point.
- followup_value: for actions triggered by *confirmed* findings, the severity
  worth deepening (final_score), nudged by real-world exposure_score.

For a fingerprint (final_score 0) pivot dominates. For a confirmed Medium that
still has something to test, followup dominates. Weights are tunable and live
here, not scattered as magic numbers.
"""
from __future__ import annotations

from normalizers.base import Finding

_EXPOSURE_NUDGE = 0.1   # exposure adds at most ~1.0


def priority(pivot_weight: float, triggering: list[Finding]) -> float:
    final_scores = [t.risk.final_score for t in triggering] or [0.0]
    exposures = [t.risk.exposure_score for t in triggering] or [0.0]
    followup = max(final_scores)
    exposure = max(exposures)
    base = max(pivot_weight, followup)          # pivot for leads, severity for confirmed
    return round(min(base + _EXPOSURE_NUDGE * exposure, 10.0), 1)
