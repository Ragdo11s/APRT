"""
Selector — the progressive decision core (behind the Test Planner Agent).

Reads Findings (with risk), the manifest, and tactic rules; emits a ranked list
of candidate NEXT ACTIONS. It does NOT execute: the orchestrator takes the
proposals, runs them through the Scope Guard + Approval Gate, and dispatches to
the adapters.

Output is split:
  ready   -> executable under the current manifest (scope ok, risk <= max, etc.)
  blocked -> surfaced with a reason (out of scope, risk too high, missing
             capability). The harness shows these so the operator can decide
             whether to widen scope / build the capability -- they are never
             silently run.

Safety note: scope is enforced for real inside each adapter (_validate_scope,
exclude_paths, the hard active-scan gate). This pre-filter just avoids proposing
things the adapter would reject, and tags intrusiveness for the Approval Gate.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from urllib.parse import urlparse

from normalizers.base import Finding

from . import rules as rules_mod
from .priority import priority

_RISK_RANK = {"safe": 0, "active": 1, "intrusive": 2}


@dataclass
class NextAction:
    action_id: str
    adapter: str
    target_id: str
    profile_override: dict
    risk_level: str
    priority: float
    rationale: str
    source_finding_ids: list[str] = field(default_factory=list)
    status: str = "ready"               # ready | blocked
    blocked_reason: str | None = None


def _origin(url: str) -> str:
    p = urlparse(url if "://" in url else "//" + url)
    return f"{p.scheme}://{p.netloc}".lower() if p.scheme else p.netloc.lower()


def _signature(adapter: str, target_id: str, override: dict, origin: str | None = None) -> str:
    key = f"{adapter}|{target_id}|{origin or ''}|{sorted(override.items(), key=str)}"
    return hashlib.sha1(key.encode()).hexdigest()[:12]


class Selector:
    def __init__(self, finding_rules=None, manifest_rules=None):
        self._finding_rules = finding_rules if finding_rules is not None else rules_mod.FINDING_RULES
        self._manifest_rules = manifest_rules if manifest_rules is not None else rules_mod.MANIFEST_RULES

    def select(self, findings: list[Finding], manifest: dict, done: set[str] | None = None,
               max_ready: int = 10) -> dict:
        done = done or set()
        scope = manifest.get("scope", {}) or {}
        target = (manifest.get("targets") or [{}])[0]
        target_id = str(target.get("id", "unknown"))
        max_rank = _RISK_RANK.get((scope.get("max_risk_level") or "safe").lower(), 0)
        active_allowed = bool(scope.get("active_scan_allowed", False))
        allowed_origins = {_origin(h) for h in scope.get("allowed_hosts", []) if isinstance(h, str)}

        by_finding = {f.finding_id: f for f in findings}

        # 1) gather candidates from rules
        cands = []
        for f in findings:
            for rule in self._finding_rules:
                cands.extend(rule(f, manifest))
        for rule in self._manifest_rules:
            cands.extend(rule(manifest, target))

        # 2) dedup by signature (and against already-executed history)
        seen, unique = set(), []
        for c in cands:
            sig = _signature(c.adapter, target_id, c.profile_override, c.target_origin)
            if sig in seen or sig in done:
                continue
            seen.add(sig)
            unique.append((sig, c))

        ready, blocked = [], []
        for sig, c in unique:
            trig = [by_finding[i] for i in c.source_finding_ids if i in by_finding]
            prio = priority(c.pivot_weight, trig)
            action = NextAction(
                action_id=sig, adapter=c.adapter, target_id=target_id,
                profile_override=c.profile_override, risk_level=c.risk_level,
                priority=prio, rationale=c.rationale, source_finding_ids=c.source_finding_ids,
            )

            reason = self._block_reason(c, max_rank, active_allowed, allowed_origins)
            if reason:
                action.status, action.blocked_reason = "blocked", reason
                blocked.append(action)
            else:
                ready.append(action)

        ready.sort(key=lambda a: a.priority, reverse=True)
        blocked.sort(key=lambda a: a.priority, reverse=True)
        return {"ready": ready[:max_ready], "blocked": blocked}

    @staticmethod
    def _block_reason(c, max_rank, active_allowed, allowed_origins) -> str | None:
        if c.needs_capability:
            return f"capability gap: {c.needs_capability}"
        if c.target_origin and c.target_origin not in allowed_origins:
            return f"out of scope: {c.target_origin} not in allowed_hosts"
        if _RISK_RANK.get(c.risk_level, 9) > max_rank:
            return f"risk '{c.risk_level}' exceeds scope max_risk_level"
        if c.adapter == "zap" and c.profile_override.get("active_scan") and not active_allowed:
            return "active scan not allowed by scope"
        return None
