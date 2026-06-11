"""Tests for external endpoint discovery. Run: pytest tests/test_discovery.py"""
from core.discovery import extract_endpoints, script_urls, endpoints_to_spec, discover
from core.openapi import enumerate_and_sanitize

HTML = """<html><head>
<script src="/static/app.abc123.js"></script>
<script src="https://cdn.example.com/vendor.js"></script>
</head><body>fetch('/api/health')</body></html>"""

JS = """
const u = "/api/users/{id}"; axios.get(`/api/orders`);
fetch('/api/search?q=1'); const p='/api/payment';
const css='/static/x.css';  // not an endpoint
"""


def test_extracts_api_paths_from_html_and_js():
    eps = extract_endpoints([HTML, JS])
    assert "/api/health" in eps
    assert "/api/users/{id}" in eps
    assert "/api/orders" in eps
    assert "/api/search" in eps           # query stripped
    assert "/static/x.css" not in eps     # non-api ignored


def test_script_urls_resolved_absolute():
    urls = script_urls("https://can-fly.shop", HTML)
    assert "https://can-fly.shop/static/app.abc123.js" in urls
    assert "https://cdn.example.com/vendor.js" in urls


def test_discover_uses_injected_fetch():
    pages = {"https://can-fly.shop": HTML,
             "https://can-fly.shop/static/app.abc123.js": JS,
             "https://cdn.example.com/vendor.js": ""}
    eps = discover("https://can-fly.shop", lambda u: pages.get(u, ""))
    assert "/api/orders" in eps and "/api/payment" in eps


def test_synth_spec_feeds_sanitizer_and_denied_still_dropped():
    eps = extract_endpoints([HTML, JS])
    spec = endpoints_to_spec(eps)
    # the discovered surface flows through the SAME sanitizer; denied still dropped
    r = enumerate_and_sanitize(spec, ["/api/payment"], allow_active=False)
    assert "/api/payment" not in r["sanitized"]["paths"]
    assert "GET /api/orders" in r["safe_endpoints"]


def test_prepass_writes_spec_from_crawl(tmp_path, monkeypatch):
    import core.discovery as disc
    pages = {"https://can-fly.shop": HTML,
             "https://can-fly.shop/static/app.abc123.js": JS}
    monkeypatch.setattr(disc, "http_get_text", lambda u, token=None, timeout=20: pages.get(u, ""))
    out = tmp_path / "spec.json"
    res = disc.run_discovery_prepass("https://can-fly.shop", str(out), token="t")
    assert res is not None
    path, eps = res
    assert "/api/orders" in eps
    import json as J
    spec = J.loads(out.read_text())
    assert "/api/orders" in spec["paths"]


def test_prepass_returns_none_when_nothing_found(tmp_path, monkeypatch):
    import core.discovery as disc
    monkeypatch.setattr(disc, "http_get_text", lambda u, token=None, timeout=20: "<html>nothing</html>")
    res = disc.run_discovery_prepass("https://can-fly.shop", str(tmp_path / "s.json"))
    assert res is None
