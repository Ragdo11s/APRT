"""
CWE -> representative CVSS v3.1 base vector.

WHY THIS EXISTS
---------------
Most findings this harness ingests are detection/enumeration results that carry
a CWE + a tool-assigned severity, but NO authoritative CVSS vector (the nuclei
`classification.cvss-metrics` field is only present on real-vuln templates).
For those, the evaluator must derive a score. To keep that derivation
*non-arbitrary*, we map each weakness class to a representative base vector that
reflects what that class of weakness actually does, and we record provenance so
a derived score never masquerades as an authoritative (NVD/vendor) one.

These vectors are REASONED DEFAULTS, not law:
  - CWE-89 (SQLi): remote, no auth, no UI, full CIA loss -> critical-ish.
  - CWE-200 (info exposure): confidentiality-only, low.
  - CWE-693 (missing protection mechanism): no direct impact on its own.
They are tunable, and can later be calibrated against NVD's per-CWE CVSS
distribution. The mechanism (documented table + provenance + severity clamp)
is the point, not these exact strings.

The derived score is ALWAYS clamped into the band implied by the tool's own
severity (see SEVERITY_BANDS) so we never over/under-score relative to what the
scanner already asserted. The bands are the official CVSS v3.1 qualitative
rating scale, so the clamp is itself standards-based.
"""

# Official CVSS v3.1 qualitative severity rating scale (spec section 5).
# (low, high) inclusive-ish bounds on the 0-10 base score.
SEVERITY_BANDS = {
    "info":     (0.0, 0.0),   # informational: not a vulnerability -> no score
    "none":     (0.0, 0.0),
    "low":      (0.1, 3.9),
    "medium":   (4.0, 6.9),
    "high":     (7.0, 8.9),
    "critical": (9.0, 10.0),
}

# CWE id -> (representative CVSS:3.1 vector, one-line rationale)
CWE_VECTORS = {
    # --- Injection / RCE family ---
    "CWE-89":  ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "SQL injection: remote, unauth, full CIA loss"),
    "CWE-94":  ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Code injection / RCE"),
    "CWE-78":  ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "OS command injection"),
    "CWE-77":  ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Command injection"),
    "CWE-502": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "Unsafe deserialization -> RCE"),
    "CWE-611": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "XXE: file read / SSRF"),
    "CWE-918": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", "SSRF: internal access, confidentiality"),

    # --- Web app logic / access control ---
    "CWE-79":  ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Reflected/stored XSS: needs UI, scope change"),
    "CWE-352": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:H/A:N", "CSRF: integrity via victim action"),
    "CWE-639": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", "IDOR/BOLA: auth'd, cross-object access"),
    "CWE-862": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "Missing authorization"),
    "CWE-287": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "Improper authentication / auth bypass"),
    "CWE-22":  ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "Path traversal: arbitrary file read"),
    "CWE-434": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "Unrestricted upload -> webshell"),

    # --- Information exposure / config ---
    "CWE-200": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Information exposure: confidentiality only, low"),
    "CWE-16":  ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Configuration weakness"),
    "CWE-693": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "Protection-mechanism failure: enabler, not direct impact"),
    "CWE-326": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "Weak crypto strength"),
    "CWE-327": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", "Broken/risky crypto algorithm (e.g. SHA-1 HMAC)"),

    # --- ZAP-common passive alert classes (calibrated from real runs) ---
    "CWE-497": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Sensitive system info exposure (e.g. Server version header)"),
    "CWE-319": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "Cleartext transmission / missing HSTS"),
    "CWE-1021": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N", "UI redress / clickjacking (missing X-Frame-Options)"),
    "CWE-614": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "Sensitive cookie without Secure flag"),
    "CWE-1004": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "Sensitive cookie without HttpOnly"),
    "CWE-522": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "Insufficiently protected credentials"),
    "CWE-538": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "File/directory information exposure"),
    "CWE-548": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "Directory listing exposure"),
}

# Fallback when a CWE is present but not in the table: lean on severity band only.
DEFAULT_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"


def vector_for_cwe(cwe_ids):
    """Return (vector, rationale, matched_cwe) for the first known CWE, else default."""
    for cwe in cwe_ids or []:
        key = cwe.strip().upper()
        if key in CWE_VECTORS:
            vec, why = CWE_VECTORS[key]
            return vec, why, key
    return DEFAULT_VECTOR, "no mapped CWE; severity-band default", None


def band_for_severity(severity):
    return SEVERITY_BANDS.get((severity or "").lower(), (0.0, 10.0))
