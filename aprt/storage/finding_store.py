# storage/finding_store.py
"""
Finding 영속화 저장소.

저장 위치: runs/<run_id>/normalized/findings.json

핵심 설계:
- finding_id 기준 upsert (중복 저장 금지). normalizer 가 finding_id 를
  template-id+url+matcher 로 안정적으로 만들기 때문에, 1차 스캔과 follow-up
  스캔에서 같은 취약점이 나와도 한 건으로 합쳐진다.
- 읽기 -> 수정 -> 저장 가능. Evaluator 가 나중에 risk 점수를 채워 넣고
  다시 저장하는 흐름을 지원.
- atomic write (.tmp -> replace) 로 중간 크래시에도 파일이 깨지지 않음.

하지 않는 것:
- 점수 계산 (Evaluator)
- 마스킹 (Normalizer 가 이미 끝냄) -> 단, 안전망으로 저장 직전 재검증은 함
"""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from normalizers.base import Finding


class FindingStoreError(Exception):
    """Finding store 영속화 오류."""


class FindingStore:
    def __init__(self, run_id: str, runs_dir: str | Path = "runs") -> None:
        self.run_id = run_id
        self.runs_dir = Path(runs_dir)
        self._findings: dict[str, dict[str, Any]] = {}  # finding_id -> finding dict
        self._loaded = False

    @property
    def path(self) -> Path:
        return self.runs_dir / self.run_id / "normalized" / "findings.json"

    # ---------- 로드/저장 ----------

    def load(self) -> "FindingStore":
        """기존 findings.json 이 있으면 읽어들인다. 없으면 빈 상태."""
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise FindingStoreError(f"corrupt findings file: {self.path}: {exc}")
            items = data.get("findings", []) if isinstance(data, dict) else data
            for item in items:
                fid = item.get("finding_id")
                if fid:
                    self._findings[fid] = item
        self._loaded = True
        return self

    def save(self) -> Path:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "run_id": self.run_id,
            "count": len(self._findings),
            "findings": list(self._findings.values()),
        }
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        tmp.replace(self.path)  # atomic
        return self.path

    # ---------- upsert ----------

    def upsert(self, finding: Finding | dict[str, Any]) -> bool:
        """
        finding_id 기준으로 추가 또는 갱신.
        반환값: True=새로 추가, False=기존 갱신(중복이었음)
        """
        item = self._to_dict(finding)
        fid = item.get("finding_id")
        if not fid:
            raise FindingStoreError("finding has no finding_id")

        # 안전망: 저장 직전 evidence 가 마스킹됐는지 가볍게 검증
        self._assert_masked(item)

        is_new = fid not in self._findings
        if is_new:
            self._findings[fid] = item
        else:
            # 기존 항목 보존하면서 갱신.
            # 단, Evaluator 가 채운 risk/next_actions 는 덮어쓰지 않는다
            # (재스캔이 점수를 0으로 되돌리면 안 되므로).
            merged = dict(self._findings[fid])
            preserved = {
                "risk": merged.get("risk"),
                "next_actions": merged.get("next_actions"),
                "reproducibility": self._better_reproducibility(
                    merged.get("reproducibility"), item.get("reproducibility")
                ),
            }
            merged.update(item)
            if preserved["risk"] and any(preserved["risk"].values()):
                merged["risk"] = preserved["risk"]
            if preserved["next_actions"]:
                merged["next_actions"] = preserved["next_actions"]
            merged["reproducibility"] = preserved["reproducibility"]
            self._findings[fid] = merged

        return is_new

    def upsert_many(self, findings: list[Finding | dict[str, Any]]) -> dict[str, int]:
        added, updated = 0, 0
        for f in findings:
            if self.upsert(f):
                added += 1
            else:
                updated += 1
        return {"added": added, "updated": updated, "total": len(self._findings)}

    # ---------- 조회 ----------

    def all(self) -> list[dict[str, Any]]:
        return list(self._findings.values())

    def get(self, finding_id: str) -> dict[str, Any] | None:
        return self._findings.get(finding_id)

    def by_severity(self, severity: str) -> list[dict[str, Any]]:
        return [f for f in self._findings.values() if f.get("severity") == severity]

    def by_category(self, category: str) -> list[dict[str, Any]]:
        return [f for f in self._findings.values() if f.get("category") == category]

    def __len__(self) -> int:
        return len(self._findings)

    # ---------- 내부 ----------

    def _to_dict(self, finding: Finding | dict[str, Any]) -> dict[str, Any]:
        if isinstance(finding, dict):
            return dict(finding)
        if is_dataclass(finding):
            return asdict(finding)
        raise FindingStoreError(f"unsupported finding type: {type(finding)}")

    def _assert_masked(self, item: dict[str, Any]) -> None:
        """
        안전망. evidence 안에 JWT 같은 게 평문으로 남아있으면 저장 거부.
        Normalizer 를 우회해 raw dict 가 들어오는 경우를 대비.
        """
        evidence = item.get("evidence") or {}
        blob = " ".join(
            str(evidence.get(k) or "")
            for k in ("request_sample", "response_sample", "matched_text")
        )
        # JWT 패턴이 평문으로 남아있으면 거부
        import re
        if re.search(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", blob):
            raise FindingStoreError(
                f"unmasked secret detected in finding {item.get('finding_id')}; "
                "normalize through NucleiNormalizer first"
            )

    @staticmethod
    def _better_reproducibility(old: Any, new: Any) -> str:
        order = ["unknown", "not_tested", "failed", "partial", "confirmed"]
        old_s = old if old in order else "not_tested"
        new_s = new if new in order else "not_tested"
        # 더 강한 재현 상태를 유지 (confirmed 를 not_tested 로 되돌리지 않음)
        return old_s if order.index(old_s) >= order.index(new_s) else new_s
