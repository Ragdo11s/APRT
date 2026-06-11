"""
APRT Evaluator
==============
Consumes a Finding and populates its `risk` block with CVSS-grounded scores.
Pure scoring: NO test execution, NO network calls against the target. Optional
EPSS/NVD data is read off the finding's `cvss` block (the normalizer puts it
there); the evaluator never fetches it.

Layer contract:
  normalizer -> writes everything EXCEPT risk.*
  evaluator  -> writes finding.risk only; never touches tool-provided fields
  selector   -> reads risk.* + exposure to choose the next progressive action

Sourcing chain (priority):
  1. AUTHORITATIVE : finding.cvss.source_vector present -> use it as-is, no clamp.
  2. DERIVED       : no vector but a mapped CWE -> representative vector, base
                     score CLAMPED into the tool's severity band.
  3. HEURISTIC     : no vector/CWE -> midpoint of severity band. info/none -> 0.0.

final_score = (possibly clamped) CVSS base score, reproducible from risk.cvss_vector.
exposure_score = separate real-world-threat signal (reachability + EPSS), kept
OUT of final so final stays a clean citeable CVSS number. The selector combines them.
"""
from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlparse

from normalizers.base import Finding, Risk

from . import cvss_v31
from . import cwe_map

# ---- exposure model (documented, tunable) -------------------------------
_REACH_WEIGHT = 5.0
_EPSS_WEIGHT = 5.0


def _host_is_private(host: str) -> bool:
    if not host:
        return True
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        return ipaddress.ip_address(host).is_private
    except ValueError:
        return False  # public domain name


def _parse_host(url: str) -> str:
    if not url:
        return ""
    raw = url if "://" in url else "//" + url   # tolerate "can-fly.shop:22"
    netloc = urlparse(raw).netloc or url
    return netloc.split("@")[-1].split(":")[0].strip().lower()


def _exposure_score(url: str, epss: float | None) -> float:
    reachability = 0.3 if _host_is_private(_parse_host(url)) else 1.0
    return round(max(0.0, min(10.0, reachability * _REACH_WEIGHT + (epss or 0.0) * _EPSS_WEIGHT)), 1)


def _clamp_band(score: float, band: tuple[float, float]) -> float:
    lo, hi = band
    return max(lo, min(hi, score))


class Evaluator:
    def __init__(self, cwe_table=None):
        self._vector_for_cwe = (cwe_table or cwe_map).vector_for_cwe
        self._band_for_severity = cwe_map.band_for_severity

    def evaluate(self, finding: Finding) -> Finding:
        """Populate finding.risk in place and return the finding."""
        severity = (finding.severity or "").lower()
        cwe_ids = finding.mappings.cwe
        cve_ids = finding.mappings.cve
        preserved_vector = finding.cvss.source_vector
        epss = finding.cvss.epss_score

        provenance, rationale = "heuristic", ""
        scored = None
        final = 0.0

        # 1. AUTHORITATIVE
        if preserved_vector and cvss_v31.is_valid(preserved_vector):
            scored = cvss_v31.score_vector(preserved_vector)
            final = scored["base_score"]
            provenance = "authoritative" if cve_ids else "tool"
            src = f"NVD/{cve_ids[0]}" if cve_ids else "tool template"
            rationale = f"CVSS from {src}; used as-is ({scored['severity']})"

        # severity gate: info/none are not vulnerabilities
        elif severity in ("info", "none"):
            rationale = "informational finding; recon signal only, no severity"

        # 2. DERIVED from CWE, clamped into the tool's severity band
        elif cwe_ids and self._vector_for_cwe(cwe_ids)[2] is not None:
            vec, why, matched = self._vector_for_cwe(cwe_ids)
            scored = cvss_v31.score_vector(vec)
            band = self._band_for_severity(severity)
            final = _clamp_band(scored["base_score"], band)
            provenance = "derived"
            rationale = (f"derived from {matched} ({why}); base {scored['base_score']} "
                         f"clamped to '{severity}' band {band}")

        # 3. HEURISTIC: no vector, no mapped CWE -> midpoint of band
        else:
            band = self._band_for_severity(severity)
            final = round((band[0] + band[1]) / 2, 1)
            rationale = f"no vector/CWE; midpoint of '{severity}' band {band}"

        if scored and final > 0:
            impact = scored["impact_0_10"]
            exploitability = scored["exploitability_0_10"]
            used_vector = scored["vector"]
        else:
            impact = exploitability = 0.0
            used_vector = scored["vector"] if scored else None

        finding.risk = Risk(
            impact_score=impact,
            exploitability_score=exploitability,
            exposure_score=_exposure_score(finding.url, epss),
            final_score=round(final, 1),
            cvss_vector=used_vector,
            cvss_version="3.1",
            provenance=provenance,
            rationale=rationale,
            scored_at=datetime.now(timezone.utc).isoformat(),
        )
        return finding

    def evaluate_all(self, findings: list[Finding]) -> list[Finding]:
        return [self.evaluate(f) for f in findings]
