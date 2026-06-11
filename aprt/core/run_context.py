# aprt/core/run_context.py
"""
RunContext: progressive 루프의 단일 상태 저장소.

이 모듈의 책임:
1. 실행 이력 추적 (dedup, max_once_per_url / max_once_per_target 강제)
2. follow-up 깊이 제어 (max_followup_depth)
3. approval 상태머신 (pending -> approved/rejected) 및 재개 진입점
4. finding score 누적 및 추세
5. runs/<run_id>/context.json 으로 영속화 (중단/재개 지원)

이 모듈이 하지 않는 것:
- 실제 스캔 실행 (Adapter 책임)
- 정책 검증 (PolicyGuard 책임) -- RunContext는 "이미 했는지/깊이 초과인지"만 본다
- rule 매칭 자체 (NextActionSelector 책임)
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


class RunStatus(str, Enum):
    INITIALIZED = "initialized"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class RunContextError(Exception):
    """RunContext 상태 위반 또는 영속화 오류."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_url(url: str) -> str:
    """
    dedup 핑거프린트용 URL 정규화.
    query/fragment 제거, origin+path 소문자화, trailing slash 정리.
    """
    parsed = urlparse(url.strip())
    scheme = (parsed.scheme or "").lower()
    netloc = (parsed.netloc or "").lower()
    path = parsed.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    if scheme and netloc:
        return f"{scheme}://{netloc}{path}"
    return path


def _fingerprint(action: str, url: str, method: str) -> str:
    """(action, url, method) 안정적 핑거프린트."""
    key = f"{action.strip().lower()}|{_normalize_url(url)}|{method.strip().upper()}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


@dataclass
class ExecutedAction:
    action: str
    url: str
    method: str
    target_id: str
    depth: int
    status: str  # success | failed | skipped
    finding_id: str | None = None
    rule_id: str | None = None
    executed_at: str = field(default_factory=_utc_now)

    @property
    def fingerprint(self) -> str:
        return _fingerprint(self.action, self.url, self.method)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "url": self.url,
            "method": self.method,
            "target_id": self.target_id,
            "depth": self.depth,
            "status": self.status,
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "executed_at": self.executed_at,
            "fingerprint": self.fingerprint,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExecutedAction":
        return cls(
            action=data["action"],
            url=data["url"],
            method=data.get("method", "UNKNOWN"),
            target_id=data["target_id"],
            depth=data.get("depth", 0),
            status=data.get("status", "success"),
            finding_id=data.get("finding_id"),
            rule_id=data.get("rule_id"),
            executed_at=data.get("executed_at", _utc_now()),
        )


@dataclass
class PendingApproval:
    approval_id: str
    action: str
    url: str
    method: str
    rule_id: str | None
    finding_id: str | None
    reason: str
    depth: int
    status: str = ApprovalStatus.PENDING.value
    created_at: str = field(default_factory=_utc_now)
    resolved_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "action": self.action,
            "url": self.url,
            "method": self.method,
            "rule_id": self.rule_id,
            "finding_id": self.finding_id,
            "reason": self.reason,
            "depth": self.depth,
            "status": self.status,
            "created_at": self.created_at,
            "resolved_at": self.resolved_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PendingApproval":
        return cls(
            approval_id=data["approval_id"],
            action=data["action"],
            url=data["url"],
            method=data.get("method", "UNKNOWN"),
            rule_id=data.get("rule_id"),
            finding_id=data.get("finding_id"),
            reason=data.get("reason", ""),
            depth=data.get("depth", 0),
            status=data.get("status", ApprovalStatus.PENDING.value),
            created_at=data.get("created_at", _utc_now()),
            resolved_at=data.get("resolved_at"),
        )


class RunContext:
    """
    하나의 run에 대한 progressive 상태.

    사용 흐름:
        ctx = RunContext.create(run_id, target_id, scope_hash, runs_dir, max_followup_depth)
        ...
        if ctx.can_run(action, url, method, rule):
            # adapter 실행
            ctx.record_execution(action, url, method, target_id, status, finding_id, rule_id)
        ...
        ctx.save()
    """

    def __init__(
        self,
        run_id: str,
        target_id: str,
        scope_hash: str,
        runs_dir: str | Path = "runs",
        max_followup_depth: int = 3,
        status: str = RunStatus.INITIALIZED.value,
        current_depth: int = 0,
    ) -> None:
        self.run_id = run_id
        self.target_id = target_id
        self.scope_hash = scope_hash
        self.runs_dir = Path(runs_dir)
        self.max_followup_depth = max_followup_depth
        self.status = status
        self.current_depth = current_depth
        self.created_at = _utc_now()
        self.updated_at = self.created_at

        self._executed: list[ExecutedAction] = []
        self._executed_fingerprints: set[str] = set()

        # rule 제한 카운터
        # key: (rule_id, normalized_url) -> count
        self._action_count_per_url: dict[str, int] = {}
        # key: (rule_id, target_id) -> count
        self._action_count_per_target: dict[str, int] = {}

        self._pending_approvals: dict[str, PendingApproval] = {}
        self._score_history: list[float] = []

    # ---------- 생성 / 영속화 ----------

    @classmethod
    def create(
        cls,
        run_id: str,
        target_id: str,
        scope_hash: str,
        runs_dir: str | Path = "runs",
        max_followup_depth: int = 3,
    ) -> "RunContext":
        ctx = cls(
            run_id=run_id,
            target_id=target_id,
            scope_hash=scope_hash,
            runs_dir=runs_dir,
            max_followup_depth=max_followup_depth,
            status=RunStatus.RUNNING.value,
        )
        ctx.save()
        return ctx

    @property
    def context_path(self) -> Path:
        return self.runs_dir / self.run_id / "context.json"

    def save(self) -> None:
        self.updated_at = _utc_now()
        self.context_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.context_path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(self.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        tmp.replace(self.context_path)  # atomic write

    @classmethod
    def load(cls, run_id: str, runs_dir: str | Path = "runs") -> "RunContext":
        path = Path(runs_dir) / run_id / "context.json"
        if not path.exists():
            raise RunContextError(f"context not found: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls.from_dict(data, runs_dir=runs_dir)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "target_id": self.target_id,
            "scope_hash": self.scope_hash,
            "max_followup_depth": self.max_followup_depth,
            "status": self.status,
            "current_depth": self.current_depth,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "executed_actions": [e.to_dict() for e in self._executed],
            "action_count_per_url": self._action_count_per_url,
            "action_count_per_target": self._action_count_per_target,
            "pending_approvals": [a.to_dict() for a in self._pending_approvals.values()],
            "score_history": self._score_history,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], runs_dir: str | Path = "runs") -> "RunContext":
        ctx = cls(
            run_id=data["run_id"],
            target_id=data["target_id"],
            scope_hash=data["scope_hash"],
            runs_dir=runs_dir,
            max_followup_depth=data.get("max_followup_depth", 3),
            status=data.get("status", RunStatus.RUNNING.value),
            current_depth=data.get("current_depth", 0),
        )
        ctx.created_at = data.get("created_at", ctx.created_at)
        ctx.updated_at = data.get("updated_at", ctx.updated_at)

        for item in data.get("executed_actions", []):
            ea = ExecutedAction.from_dict(item)
            ctx._executed.append(ea)
            ctx._executed_fingerprints.add(ea.fingerprint)

        ctx._action_count_per_url = dict(data.get("action_count_per_url", {}))
        ctx._action_count_per_target = dict(data.get("action_count_per_target", {}))

        for item in data.get("pending_approvals", []):
            pa = PendingApproval.from_dict(item)
            ctx._pending_approvals[pa.approval_id] = pa

        ctx._score_history = list(data.get("score_history", []))
        return ctx

    # ---------- dedup / 깊이 / rule 제한 판단 ----------

    def has_executed(self, action: str, url: str, method: str) -> bool:
        return _fingerprint(action, url, method) in self._executed_fingerprints

    def depth_exceeded(self) -> bool:
        return self.current_depth >= self.max_followup_depth

    def can_run(
        self,
        action: str,
        url: str,
        method: str = "GET",
        rule_id: str | None = None,
        max_once_per_url: bool = False,
        max_once_per_target: bool = False,
    ) -> tuple[bool, str | None]:
        """
        실행 가능 여부 + 거부 사유 반환.
        주의: 이것은 안전성(scope/policy) 검증이 아니다. 그건 PolicyGuard 책임.
        여기서는 오직 '중복/깊이/rule 제한'만 본다.
        """
        if self.depth_exceeded():
            return False, f"max_followup_depth reached ({self.max_followup_depth})"

        if self.has_executed(action, url, method):
            return False, "already executed (dedup)"

        if max_once_per_url and rule_id is not None:
            key = self._url_key(rule_id, url)
            if self._action_count_per_url.get(key, 0) >= 1:
                return False, f"max_once_per_url reached for rule {rule_id}"

        if max_once_per_target and rule_id is not None:
            key = self._target_key(rule_id)
            if self._action_count_per_target.get(key, 0) >= 1:
                return False, f"max_once_per_target reached for rule {rule_id}"

        return True, None

    # ---------- 상태 변경 ----------

    def record_execution(
        self,
        action: str,
        url: str,
        method: str,
        status: str,
        finding_id: str | None = None,
        rule_id: str | None = None,
    ) -> ExecutedAction:
        ea = ExecutedAction(
            action=action,
            url=url,
            method=method,
            target_id=self.target_id,
            depth=self.current_depth,
            status=status,
            finding_id=finding_id,
            rule_id=rule_id,
        )
        self._executed.append(ea)
        self._executed_fingerprints.add(ea.fingerprint)

        if rule_id is not None:
            url_key = self._url_key(rule_id, url)
            self._action_count_per_url[url_key] = self._action_count_per_url.get(url_key, 0) + 1
            tgt_key = self._target_key(rule_id)
            self._action_count_per_target[tgt_key] = self._action_count_per_target.get(tgt_key, 0) + 1

        return ea

    def advance_depth(self) -> int:
        """follow-up 한 wave 끝날 때마다 호출. 새 depth 반환."""
        self.current_depth += 1
        return self.current_depth

    def record_score(self, final_score: float) -> None:
        self._score_history.append(float(final_score))

    def set_status(self, status: RunStatus | str) -> None:
        self.status = status.value if isinstance(status, RunStatus) else status

    # ---------- approval 상태머신 ----------

    def enqueue_approval(
        self,
        action: str,
        url: str,
        method: str,
        reason: str,
        rule_id: str | None = None,
        finding_id: str | None = None,
    ) -> PendingApproval:
        approval_id = _fingerprint(action, url, method) + f"-d{self.current_depth}"
        pa = PendingApproval(
            approval_id=approval_id,
            action=action,
            url=url,
            method=method,
            rule_id=rule_id,
            finding_id=finding_id,
            reason=reason,
            depth=self.current_depth,
        )
        self._pending_approvals[approval_id] = pa
        self.set_status(RunStatus.WAITING_APPROVAL)
        return pa

    def list_pending_approvals(self) -> list[PendingApproval]:
        return [
            a for a in self._pending_approvals.values()
            if a.status == ApprovalStatus.PENDING.value
        ]

    def approve(self, approval_id: str) -> PendingApproval:
        return self._resolve_approval(approval_id, ApprovalStatus.APPROVED)

    def reject(self, approval_id: str) -> PendingApproval:
        return self._resolve_approval(approval_id, ApprovalStatus.REJECTED)

    def _resolve_approval(self, approval_id: str, status: ApprovalStatus) -> PendingApproval:
        pa = self._pending_approvals.get(approval_id)
        if pa is None:
            raise RunContextError(f"approval not found: {approval_id}")
        if pa.status != ApprovalStatus.PENDING.value:
            raise RunContextError(f"approval already resolved: {approval_id} ({pa.status})")
        pa.status = status.value
        pa.resolved_at = _utc_now()
        # 대기 중인 승인이 더 없으면 다시 RUNNING 으로
        if not self.list_pending_approvals():
            self.set_status(RunStatus.RUNNING)
        return pa

    def get_approved_actions(self) -> list[PendingApproval]:
        """승인됐지만 아직 실행 큐로 안 넘어간 액션들. Planner가 소비."""
        return [
            a for a in self._pending_approvals.values()
            if a.status == ApprovalStatus.APPROVED.value
        ]

    # ---------- 조회 헬퍼 ----------

    @property
    def executed_actions(self) -> list[ExecutedAction]:
        return list(self._executed)

    @property
    def score_trend(self) -> str:
        """누적 score 추세 요약 (LLM 컨텍스트나 리포트용)."""
        if len(self._score_history) < 2:
            return "insufficient_data"
        delta = self._score_history[-1] - self._score_history[0]
        if delta > 5:
            return "increasing"
        if delta < -5:
            return "decreasing"
        return "stable"

    def _url_key(self, rule_id: str, url: str) -> str:
        return f"{rule_id}::{_normalize_url(url)}"

    def _target_key(self, rule_id: str) -> str:
        return f"{rule_id}::{self.target_id}"
