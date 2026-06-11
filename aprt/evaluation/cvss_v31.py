"""
Thin wrapper over the `cvss` library (validated CVSS v3.1 implementation).

The evaluator never hand-rolls the CVSS formula; it delegates to this module so
every score is reproducible from its vector string. We expose:

  - base_score          : official 0-10 CVSS base score (this drives final_score)
  - impact_0_10         : impact subscore, linearly normalized to 0-10
  - exploitability_0_10 : exploitability subscore, linearly normalized to 0-10

The two subscores are presentation values: the report can say "8.1 because high
impact (9.7) but moderate exploitability (5.0)". The normalization constants are
the theoretical maxima of the v3.1 subscores, so the transform is documented and
deterministic (not an arbitrary weight).
"""
from cvss import CVSS3

# Theoretical maxima of the v3.1 subscores (used only to rescale to 0-10).
_ISC_MAX = 6.04   # impact subscore, scope-changed upper bound
_ESC_MAX = 3.89   # exploitability subscore upper bound


def _clamp(x, lo=0.0, hi=10.0):
    return max(lo, min(hi, x))


def score_vector(vector: str) -> dict:
    """Parse a CVSS:3.1 vector and return base + normalized subscores."""
    c = CVSS3(vector)
    return {
        "vector": c.clean_vector(),
        "version": "3.1",
        "base_score": float(c.base_score),
        "severity": c.severities()[0],
        "impact_0_10": round(_clamp(float(c.isc) / _ISC_MAX * 10.0), 1),
        "exploitability_0_10": round(_clamp(float(c.esc) / _ESC_MAX * 10.0), 1),
    }


def is_valid(vector: str) -> bool:
    try:
        CVSS3(vector)
        return True
    except Exception:
        return False
