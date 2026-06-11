"""
Tactic rules (the "Skill/Tactic Rules" box).

A rule maps an observation (a Finding, or a manifest capability) to candidate
next actions. This is where "progressive" lives: a 0.0-severity fingerprint can
still unlock a high-value next test, and a real vuln found mid-loop can be
deepened.

A rule is `rule(finding, manifest) -> list[Candidate]` (per finding) or
`rule(manifest, target) -> list[Candidate]` (manifest level). Knowledge lives in
the two tables below (TECH_TAGS, VULN_FOLLOWUP) so adding coverage = adding a row,
not writing code. These could later move to a YAML file in the Knowledge Layer.

Candidates carry a `profile_override` shaped like `scan_profiles.<adapter>` so the
orchestrator merges it into the manifest and calls the adapter unchanged. Rules
do NOT execute, scope-check, or rank -- the selector does.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse

from normalizers.base import Finding


@dataclass
class Candidate:
    adapter: str
    profile_override: dict
    risk_level: str                    # "safe" | "active" | "intrusive"
    pivot_weight: float                # 0-10: new surface this opens
    rationale: str
    source_finding_ids: list[str] = field(default_factory=list)
    target_origin: str | None = None   # action targets a non-manifest host (scope-checked)
    needs_capability: str | None = None


def _text(f: Finding) -> str:
    resp = f.evidence.response_sample or ""
    return " ".join([f.title or "", f.evidence.matched_text or "", resp[:500]]).lower()


# === KNOWLEDGE TABLE 1: technology fingerprint -> targeted nuclei tags =========
# alias substrings (matched against the finding text) -> nuclei -tags, pivot, why.
# Higher pivot = richer attack surface (RCE-prone stacks score higher).
TECH_TAGS: list[dict] = [
    {"aliases": ("spring",),            "tags": ["spring", "java", "exposure"], "pivot": 8.5,
     "why": "Spring detected -> actuator exposure + Spring CVE templates"},
    {"aliases": ("tomcat",),            "tags": ["tomcat", "java"],             "pivot": 8.0,
     "why": "Tomcat detected -> manager/CVE templates"},
    {"aliases": ("jenkins",),           "tags": ["jenkins"],                    "pivot": 8.5,
     "why": "Jenkins detected -> known RCE/exposure templates"},
    {"aliases": ("gitlab",),            "tags": ["gitlab"],                     "pivot": 8.0,
     "why": "GitLab detected -> GitLab CVE templates"},
    {"aliases": ("wordpress", "wp-"),   "tags": ["wordpress", "wp-plugin"],     "pivot": 7.5,
     "why": "WordPress detected -> core/plugin templates"},
    {"aliases": ("jboss", "wildfly"),   "tags": ["jboss"],                      "pivot": 8.0,
     "why": "JBoss/WildFly detected -> deserialization/CVE templates"},
    {"aliases": ("weblogic",),          "tags": ["weblogic"],                   "pivot": 8.5,
     "why": "WebLogic detected -> known RCE templates"},
    {"aliases": ("nginx",),             "tags": ["nginx"],                      "pivot": 6.0,
     "why": "nginx detected -> version/misconfig templates"},
    {"aliases": ("apache", "httpd"),    "tags": ["apache"],                     "pivot": 6.0,
     "why": "Apache detected -> version/misconfig templates"},
    {"aliases": ("iis",),               "tags": ["iis"],                        "pivot": 6.0,
     "why": "IIS detected -> IIS templates"},
    {"aliases": ("php",),               "tags": ["php"],                        "pivot": 6.0,
     "why": "PHP detected -> PHP-specific templates"},
    {"aliases": ("node", "express"),    "tags": ["nodejs"],                     "pivot": 6.0,
     "why": "Node/Express detected -> Node templates"},
    {"aliases": ("openssh", "ssh-2.0"), "tags": ["ssh", "network"],            "pivot": 6.0,
     "why": "OpenSSH banner -> SSH version/CVE network templates"},
]


# === KNOWLEDGE TABLE 2: vuln class (CWE) -> how to deepen a REAL finding ========
# Fires only on findings the scanner already rated low+ (not info fingerprints).
# "active" risk surfaces as blocked under a safe-only scope -- by design.
VULN_FOLLOWUP: dict[str, dict] = {
    "CWE-89":  {"tags": ["sqli"],                "risk": "safe",   "pivot": 8.0,
                "why": "SQLi class -> SQLi detection templates on the same surface"},
    "CWE-79":  {"tags": ["xss"],                 "risk": "safe",   "pivot": 7.0,
                "why": "XSS class -> broaden XSS templates"},
    "CWE-22":  {"tags": ["lfi", "traversal"],    "risk": "safe",   "pivot": 7.5,
                "why": "Path traversal -> LFI/traversal templates"},
    "CWE-918": {"tags": ["ssrf"],                "risk": "safe",   "pivot": 8.0,
                "why": "SSRF class -> SSRF templates"},
    "CWE-200": {"tags": ["exposure", "disclosure"], "risk": "safe", "pivot": 5.5,
                "why": "Info exposure -> probe related disclosure templates"},
    "CWE-94":  {"tags": ["rce"],                 "risk": "active", "pivot": 9.5,
                "why": "Code injection -> active confirmation (needs active scope)"},
    "CWE-78":  {"tags": ["rce"],                 "risk": "active", "pivot": 9.5,
                "why": "OS command injection -> active confirmation (needs active scope)"},
}

_REAL_SEVERITIES = {"low", "medium", "high", "critical"}


# === RULES ====================================================================

def rule_tech_fingerprint(f: Finding, manifest: dict) -> list[Candidate]:
    text = _text(f)
    out = []
    for entry in TECH_TAGS:
        if any(alias in text for alias in entry["aliases"]):
            out.append(Candidate(
                adapter="nuclei",
                profile_override={"tags": entry["tags"]},
                risk_level="safe", pivot_weight=entry["pivot"],
                rationale=entry["why"], source_finding_ids=[f.finding_id],
            ))
    return out


def rule_vuln_followup(f: Finding, manifest: dict) -> list[Candidate]:
    if (f.severity or "").lower() not in _REAL_SEVERITIES:
        return []   # only deepen confirmed findings, not info fingerprints
    out = []
    for cwe in f.mappings.cwe:
        entry = VULN_FOLLOWUP.get(str(cwe).upper())
        if not entry:
            continue
        out.append(Candidate(
            adapter="nuclei",
            profile_override={"tags": entry["tags"]},
            risk_level=entry["risk"], pivot_weight=entry["pivot"],
            rationale=entry["why"], source_finding_ids=[f.finding_id],
        ))
    return out


def rule_actuator(f: Finding, manifest: dict) -> list[Candidate]:
    """Spring Boot actuator is a high-value, specific pivot once spotted."""
    if "actuator" not in _text(f):
        return []
    return [Candidate(
        adapter="nuclei",
        profile_override={"tags": ["springboot", "exposure"]},
        risk_level="safe", pivot_weight=8.0,
        rationale="Actuator surface seen -> Spring Boot actuator templates (env, mappings, heapdump)",
        source_finding_ids=[f.finding_id],
    )]


def rule_extra_san_host(f: Finding, manifest: dict) -> list[Candidate]:
    """SSL SAN often reveals sibling hosts. Surface any that aren't the target itself."""
    if "ssl dns names" not in (f.title or "").lower():
        return []
    target = (manifest.get("targets") or [{}])[0]
    base = target.get("base_url") or ""
    base_host = urlparse(base if "://" in base else "//" + base).netloc.lower()
    out = []
    for h in [x.strip() for x in (f.evidence.matched_text or "").split(",") if x.strip()]:
        if h.lower() == base_host:
            continue
        out.append(Candidate(
            adapter="nuclei",
            profile_override={"severity": ["low", "medium", "high", "critical"]},
            risk_level="safe", pivot_weight=5.0,
            rationale=f"SAN host {h} on the cert; candidate to scan if added to scope",
            source_finding_ids=[f.finding_id],
            target_origin=f"https://{h}",
        ))
    return out


def manifest_openapi(manifest: dict, target: dict) -> list[Candidate]:
    if not (target.get("openapi_url") or target.get("swagger_url")):
        return []
    return [Candidate(
        adapter="zap",
        profile_override={"openapi_import": target.get("openapi_url") or target.get("swagger_url")},
        risk_level="safe", pivot_weight=9.0,
        rationale=("OpenAPI spec available -> import the sanitized surface (denied paths + "
                   "state-changing methods stripped) and scan the API endpoints"),
        source_finding_ids=[],
    )]


FINDING_RULES = [rule_tech_fingerprint, rule_vuln_followup, rule_actuator, rule_extra_san_host]
MANIFEST_RULES = [manifest_openapi]
