"""Tests for the APRT evaluator. Run: pytest tests/test_evaluator.py"""
from normalizers.base import Finding, Mappings, Cvss
from evaluation import Evaluator


def _finding(severity, url, cwe=None, cve=None, cvss=None):
    return Finding(
        finding_id="f", run_id="r", tool="nuclei", target_id="t",
        title="t", description="", category="unknown",
        severity=severity, confidence="medium", reproducibility="not_tested",
        url=url, method="GET",
        mappings=Mappings(cwe=cwe or [], cve=cve or []),
        cvss=cvss or Cvss(),
    )


def test_info_finding_scores_zero():
    f = Evaluator().evaluate(_finding("info", "https://can-fly.shop", cwe=["CWE-200"]))
    assert f.risk.final_score == 0.0
    assert f.risk.provenance == "heuristic"
    # but exposure is still computed (recon signal for the selector)
    assert f.risk.exposure_score > 0


def test_derived_cwe_is_clamped_to_tool_severity():
    # CWE-89 alone implies ~9.8, but the tool said 'high' -> clamp to band ceiling
    f = Evaluator().evaluate(_finding("high", "https://can-fly.shop/x", cwe=["CWE-89"]))
    assert f.risk.provenance == "derived"
    assert 7.0 <= f.risk.final_score <= 8.9
    assert f.risk.cvss_vector is not None  # reproducible


def test_authoritative_vector_used_as_is_no_clamp():
    cvss = Cvss(source_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                source_score=9.8, epss_score=0.97)
    f = Evaluator().evaluate(_finding("critical", "https://can-fly.shop/", cve=["CVE-2022-22965"], cvss=cvss))
    assert f.risk.provenance == "authoritative"
    assert f.risk.final_score == 9.8
    # EPSS feeds exposure, NOT final_score
    assert f.risk.exposure_score >= 9.0
    assert f.risk.final_score == 9.8


def test_exposure_separates_reachability_from_severity():
    pub = Evaluator().evaluate(_finding("high", "https://can-fly.shop/x", cwe=["CWE-89"]))
    intern = Evaluator().evaluate(_finding("high", "https://10.0.0.5/x", cwe=["CWE-89"]))
    # same severity/final, but internal host is less exposed
    assert pub.risk.final_score == intern.risk.final_score
    assert pub.risk.exposure_score > intern.risk.exposure_score


def test_evaluator_does_not_touch_tool_fields():
    f = _finding("high", "https://can-fly.shop/x", cwe=["CWE-89"])
    before = (f.severity, f.confidence, f.title)
    Evaluator().evaluate(f)
    assert (f.severity, f.confidence, f.title) == before
