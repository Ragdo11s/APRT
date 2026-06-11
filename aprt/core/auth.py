"""
Bearer-token injection for ZAP via the automation-framework `replacer` job.

The manifest never holds the token -- only the NAME of the env var
(auth_profile.token_env). We resolve the token from the environment at
plan-build time and add a replacer rule that sets `Authorization: Bearer <token>`
on every request ZAP makes (replacer runs FIRST, so the OpenAPI import, spider,
and passive scan are all authenticated -- otherwise the API import just bounces
off 401 and you see nothing).

Safety: the replacer only affects requests ZAP is already allowed to make. Scope
(allowed_hosts include + denied_paths excludePaths) and the sanitized GET-only
OpenAPI surface still bound WHAT is requested. Auth only makes those in-scope
requests authenticate instead of 401-ing.

Secret hygiene: the literal token ends up in the generated plan file under the
run dir (ZAP needs it to send the header). That dir is local only -- keep runs/
out of version control. The token is never logged or written to the manifest.
"""
from __future__ import annotations

import os


def resolve_auth_profile(manifest: dict, target: dict) -> dict | None:
    pid = target.get("auth_profile")
    if not pid:
        return None
    for prof in manifest.get("auth_profiles", []) or []:
        if isinstance(prof, dict) and prof.get("id") == pid:
            return prof
    return None


def bearer_token(manifest: dict, target: dict) -> tuple[str | None, str | None]:
    """Return (token, note). token is None when auth isn't configured/available.
    `note` is a human log string -- the token itself is NEVER put in it."""
    prof = resolve_auth_profile(manifest, target)
    if not prof:
        return None, None                       # no auth profile -> unauthenticated, silently
    if (prof.get("type") or "").lower() != "bearer":
        return None, f"auth_profile '{prof.get('id')}' is not bearer; skipping injection"
    env_name = prof.get("token_env")
    if not env_name:
        return None, f"auth_profile '{prof.get('id')}' has no token_env; skipping"
    token = os.environ.get(env_name)
    if not token:
        return None, f"env var {env_name} is not set; running UNAUTHENTICATED"
    return token, f"bearer auth via {env_name} (token masked)"


def replacer_job(token: str) -> dict:
    """ZAP automation 'replacer' job that sets Authorization: Bearer <token>
    on every request. REQ_HEADER adds the header when absent, replaces when present."""
    return {
        "type": "replacer",
        "parameters": {"deleteAllRules": False},
        "rules": [{
            "description": "aprt-bearer-auth",
            "matchType": "REQ_HEADER",
            "matchString": "Authorization",
            "matchRegex": False,
            "replacementString": f"Bearer {token}",
            "tokenProcessing": False,
            "initiators": [],                    # empty = all initiators
        }],
    }
