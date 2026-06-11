"""
External API-endpoint discovery: find /api paths from OUTSIDE -- no spec, no
insider access. The app ships its own front-end, and that client code calls its
own API, so the endpoint paths are sitting right there in the HTML + JS bundles.
We fetch what a browser would, pull endpoint-looking paths out, and feed the list
into the SAME sanitize -> import -> auth -> scan pipeline the OpenAPI path uses
(by synthesizing a minimal spec). Safe tier: only fetches, no payloads.

Brute-force (wordlist) discovery is a separate, active-tier source that can feed
the same machinery later.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

# endpoint-ish path references inside HTML/JS string literals
_PATH_RE = re.compile(r"""['"`](/(?:api|rest|graphql|v\d+)/[A-Za-z0-9_\-/{}.]*)""")
_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)


def script_urls(base_url: str, html: str) -> list[str]:
    """Absolute URLs of <script src=...> referenced by the page."""
    return [urljoin(base_url, src) for src in _SCRIPT_SRC_RE.findall(html or "")]


def extract_endpoints(texts: list[str]) -> list[str]:
    """Distinct /api-style paths found across the given HTML/JS blobs."""
    found = set()
    for t in texts:
        for path in _PATH_RE.findall(t or ""):
            found.add(path.split("?")[0].rstrip("/") or "/")
    return sorted(found)


def endpoints_to_spec(endpoints: list[str]) -> dict:
    """Synthesize a minimal OpenAPI 3 spec (GET ops) from a discovered endpoint
    list, so it flows straight through enumerate_and_sanitize -> ZAP import."""
    paths = {p: {"get": {"responses": {"200": {"description": "discovered"}}}}
             for p in endpoints}
    return {"openapi": "3.0.0",
            "info": {"title": "discovered-surface", "version": "0"},
            "paths": paths}


def discover(base_url: str, fetch) -> list[str]:
    """Crawl one level: fetch the page, then its scripts, extract endpoints.
    `fetch(url) -> str` is injected (real HTTP in prod, fake in tests)."""
    html = fetch(base_url) or ""
    blobs = [html]
    for js_url in script_urls(base_url, html):
        try:
            blobs.append(fetch(js_url) or "")
        except Exception:
            continue   # a missing/blocked bundle shouldn't kill discovery
    return extract_endpoints(blobs)


# ---- production crawl fetch + prepass -------------------------------------
import json
from pathlib import Path
from urllib.request import Request, urlopen

# WAFs 403 the default "Python-urllib" UA (we hit exactly this on can-fly.shop),
# so the crawl pretends to be a browser.
_BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")


def http_get_text(url: str, token: str | None = None, timeout: int = 20) -> str:
    """GET a page/JS bundle as text. Browser UA + optional bearer. Returns '' on
    any error so one blocked/missing bundle can't kill the whole crawl."""
    headers = {"User-Agent": _BROWSER_UA, "Accept": "*/*"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urlopen(Request(url, headers=headers), timeout=timeout) as resp:  # noqa: S310
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return ""


def run_discovery_prepass(base_url: str, out_path: str, token: str | None = None):
    """Crawl base_url externally, discover /api endpoints, synthesize a spec and
    write it to out_path. Returns (out_path, endpoints) if anything was found,
    else None. Feeds the ZAP openapi import via scan_profiles.zap.openapi_file."""
    endpoints = discover(base_url, lambda u: http_get_text(u, token=token))
    if not endpoints:
        return None
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_path).write_text(json.dumps(endpoints_to_spec(endpoints)), encoding="utf-8")
    return out_path, endpoints
