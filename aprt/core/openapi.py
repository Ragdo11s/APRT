"""
OpenAPI spec -> SAFE, scope-filtered import (for ZAP) + endpoint enumeration.

WHY THIS IS NOT just "add an openapi job"
-----------------------------------------
ZAP's native OpenAPI import actively REQUESTS every operation in the spec,
including POST/PUT/DELETE. Importing the raw live spec would send requests to
destructive, denied endpoints (/api/payment, /api/users/delete, ...). Under a
`max_risk_level: safe` scope that must never happen.

So we never import the raw spec. We:
  1. drop any path matching scope.denied_paths   (never even enumerated for attack)
  2. drop state-changing methods unless active scanning is explicitly allowed
  3. import only the SANITIZED spec (read-only, in-scope operations)
State-changing / out-of-policy operations are still ENUMERATED (returned for the
selector / report) but flagged active-tier -- surfaced, never auto-requested.
"""
from __future__ import annotations

import copy
import json
from urllib.request import Request, urlopen

SAFE_METHODS = ("get", "head", "options")
_HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")


def _path_denied(path: str, denied_paths) -> bool:
    p = path or "/"
    for d in denied_paths or []:
        if not isinstance(d, str) or not d:
            continue
        nd = d if d.startswith("/") else "/" + d
        if p == nd or p.startswith(nd.rstrip("/") + "/"):
            return True
    return False


def enumerate_and_sanitize(spec: dict, denied_paths=None, allow_active: bool = False) -> dict:
    """Return {sanitized spec, safe_endpoints, denied, active_only}."""
    denied_paths = denied_paths or []
    sanitized = copy.deepcopy(spec)
    paths = sanitized.get("paths")
    if not isinstance(paths, dict):
        return {"sanitized": sanitized, "safe_endpoints": [], "denied": [], "active_only": []}

    allowed = _HTTP_METHODS if allow_active else SAFE_METHODS
    safe_endpoints, denied, active_only = [], [], []

    for path in list(paths.keys()):
        item = paths.get(path)
        if not isinstance(item, dict):
            paths.pop(path, None)
            continue
        if _path_denied(path, denied_paths):
            denied.append(path)
            paths.pop(path, None)                 # never import a denied path
            continue
        for method in list(item.keys()):
            m = method.lower()
            if m not in _HTTP_METHODS:
                continue                          # keep $ref/parameters/summary
            if m in allowed:
                safe_endpoints.append(f"{m.upper()} {path}")
            else:
                active_only.append(f"{m.upper()} {path}")
                item.pop(method, None)            # drop state-changing op from import
        if not any(k.lower() in _HTTP_METHODS for k in item.keys()):
            paths.pop(path, None)                 # nothing left to import here

    return {"sanitized": sanitized, "safe_endpoints": safe_endpoints,
            "denied": denied, "active_only": active_only}


def fetch_spec(url: str, timeout: int = 20, token: str | None = None) -> dict:
    """GET an OpenAPI/Swagger definition (JSON or YAML). Caller must ensure `url`
    is in scope (adapter validates against allowed_hosts before calling).

    `token`: optional bearer token. The spec endpoint is often behind the same
    auth as the API, so without it the fetch 401s and the whole import dies."""
    headers = {"Accept": "application/json, application/yaml, */*"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(url, headers=headers)
    with urlopen(req, timeout=timeout) as resp:        # noqa: S310 (scope-validated upstream)
        raw = resp.read().decode("utf-8", errors="replace")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        import yaml
        return yaml.safe_load(raw)
