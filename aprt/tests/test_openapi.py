"""Tests for the OpenAPI sanitizer. Run: pytest tests/test_openapi.py"""
from core.openapi import enumerate_and_sanitize

SPEC = {"openapi": "3.0.0", "info": {"title": "x", "version": "1"}, "paths": {
    "/api/search": {"get": {}},
    "/api/users/{id}": {"get": {}, "delete": {}},
    "/api/payment": {"post": {}},
    "/api/orders/checkout": {"post": {}},
    "/api/orders": {"get": {}, "post": {}},
    "/health": {"get": {}},
}}
DENIED = ["/api/payment", "/api/orders/checkout", "/api/users/delete", "/api/admin"]


def test_denied_paths_are_dropped_entirely():
    r = enumerate_and_sanitize(SPEC, DENIED, allow_active=False)
    assert "/api/payment" not in r["sanitized"]["paths"]
    assert "/api/orders/checkout" not in r["sanitized"]["paths"]
    assert set(r["denied"]) == {"/api/payment", "/api/orders/checkout"}


def test_state_changing_methods_stripped_but_enumerated():
    r = enumerate_and_sanitize(SPEC, DENIED, allow_active=False)
    assert "delete" not in r["sanitized"]["paths"]["/api/users/{id}"]
    assert "post" not in r["sanitized"]["paths"]["/api/orders"]
    assert "DELETE /api/users/{id}" in r["active_only"]
    assert "POST /api/orders" in r["active_only"]


def test_safe_get_endpoints_kept():
    r = enumerate_and_sanitize(SPEC, DENIED, allow_active=False)
    assert "GET /api/search" in r["safe_endpoints"]
    assert "GET /health" in r["safe_endpoints"]
    assert r["sanitized"]["info"]["title"] == "x"   # rest of spec preserved


def test_active_scope_keeps_state_changing():
    r = enumerate_and_sanitize(SPEC, DENIED, allow_active=True)
    # with active allowed, non-denied POST/DELETE stay in the import...
    assert "delete" in r["sanitized"]["paths"]["/api/users/{id}"]
    # ...but denied paths are STILL dropped regardless of risk level
    assert "/api/payment" not in r["sanitized"]["paths"]
