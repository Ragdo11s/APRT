# reporting/report_generator.py
"""
findings.json -> 마크다운/HTML 보고서.

핵심 설계:
- 그룹핑: 같은 (title, url) finding 을 한 항목으로 묶는다. 보안 헤더 누락처럼
  matcher 별로 흩어진 finding 들이 "1건 + 누락 헤더 목록"으로 정리된다.
  finding 원자성은 store 에 유지하고, 묶기는 표현 계층(여기)의 책임.
- 정렬: 심각도 (critical -> info), 그 안에서 카테고리.
- evidence: 길면 잘라낸다 (SSH 응답 등 거대 본문 대비).

문서 10번 목차를 따른다:
  1.개요 2.범위 3.도구 4.요약 5.목록 6.상세 7.우선조치 8.추가확인
"""

from __future__ import annotations

import html
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_RANK = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
_EVIDENCE_MAX = 400  # evidence 본문 표시 최대 길이


@dataclass
class FindingGroup:
    title: str
    url: str
    severity: str
    category: str
    members: list[dict[str, Any]] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.members)

    @property
    def matched_items(self) -> list[str]:
        seen: list[str] = []
        for m in self.members:
            mt = (m.get("evidence") or {}).get("matched_text")
            if mt and mt not in seen:
                seen.append(mt)
        return seen

    @property
    def cwes(self) -> list[str]:
        out: list[str] = []
        for m in self.members:
            for c in (m.get("mappings") or {}).get("cwe", []) or []:
                if c not in out:
                    out.append(c)
        return out

    @property
    def representative(self) -> dict[str, Any]:
        return self.members[0]


class ReportGenerator:
    def __init__(
        self,
        run_id: str,
        runs_dir: str | Path = "runs",
        manifest: dict[str, Any] | None = None,
    ) -> None:
        self.run_id = run_id
        self.runs_dir = Path(runs_dir)
        self.manifest = manifest or {}

    @property
    def findings_path(self) -> Path:
        return self.runs_dir / self.run_id / "normalized" / "findings.json"

    @property
    def report_dir(self) -> Path:
        return self.runs_dir / self.run_id / "reports"

    # ---------- 메인 ----------

    def generate(self) -> dict[str, str]:
        findings = self._load_findings()
        groups = self._group(findings)

        md = self._render_markdown(findings, groups)
        html_doc = self._render_html(findings, groups)

        self.report_dir.mkdir(parents=True, exist_ok=True)
        md_path = self.report_dir / "report.md"
        html_path = self.report_dir / "report.html"
        md_path.write_text(md, encoding="utf-8")
        html_path.write_text(html_doc, encoding="utf-8")
        return {"markdown": str(md_path), "html": str(html_path)}

    # ---------- 데이터 처리 ----------

    def _load_findings(self) -> list[dict[str, Any]]:
        data = json.loads(self.findings_path.read_text(encoding="utf-8"))
        return data.get("findings", []) if isinstance(data, dict) else data

    def _group(self, findings: list[dict[str, Any]]) -> list[FindingGroup]:
        buckets: dict[tuple[str, str], FindingGroup] = {}
        for f in findings:
            key = (f.get("title", ""), f.get("url", ""))
            if key not in buckets:
                buckets[key] = FindingGroup(
                    title=f.get("title", ""),
                    url=f.get("url", ""),
                    severity=f.get("severity", "info"),
                    category=f.get("category", "unknown"),
                )
            g = buckets[key]
            g.members.append(f)
            # 그룹 심각도는 가장 높은 것으로
            if _SEVERITY_RANK.get(f.get("severity", "info"), 99) < _SEVERITY_RANK.get(g.severity, 99):
                g.severity = f.get("severity", "info")

        groups = list(buckets.values())
        groups.sort(key=lambda g: (_SEVERITY_RANK.get(g.severity, 99), g.category, g.title))
        return groups

    def _severity_counts(self, findings: list[dict[str, Any]]) -> dict[str, int]:
        counts = {s: 0 for s in _SEVERITY_ORDER}
        for f in findings:
            sev = f.get("severity", "info")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _truncate(self, text: Any) -> str | None:
        if not text:
            return None
        s = str(text)
        if len(s) > _EVIDENCE_MAX:
            return s[:_EVIDENCE_MAX] + f"\n... (생략, 총 {len(s)}자)"
        return s

    # ---------- 마크다운 렌더 ----------

    def _render_markdown(self, findings: list[dict[str, Any]], groups: list[FindingGroup]) -> str:
        scope = self.manifest.get("scope", {})
        targets = self.manifest.get("targets", [])
        counts = self._severity_counts(findings)
        now = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M %Z")

        actionable = [g for g in groups if g.severity in ("critical", "high")]
        attack_surface = [g for g in groups if g.severity == "info"]

        lines: list[str] = []
        lines.append(f"# 보안 점검 보고서 — {self.manifest.get('project', {}).get('name', self.run_id)}")
        lines.append("")
        lines.append(f"- 생성 시각: {now}")
        lines.append(f"- Run ID: `{self.run_id}`")
        lines.append("")

        # 1. 개요
        lines.append("## 1. 점검 개요")
        lines.append("")
        lines.append(f"자동화 점검 도구를 사용해 대상 자산에 대한 비침투(safe) 스캔을 수행했습니다. "
                     f"총 {len(findings)}건의 탐지 결과가 {len(groups)}개 항목으로 정리되었습니다.")
        lines.append("")

        # 2. 범위
        lines.append("## 2. 점검 범위")
        lines.append("")
        allowed = scope.get("allowed_hosts", [])
        if allowed:
            lines.append("허용 호스트:")
            for h in allowed:
                lines.append(f"- {h}")
        if targets:
            lines.append("")
            lines.append("대상:")
            for t in targets:
                lines.append(f"- `{t.get('id')}` — {t.get('base_url')}")
        lines.append("")
        lines.append(f"- 최대 위험 강도: {scope.get('max_risk_level', 'safe')}")
        lines.append(f"- Active scan 허용: {scope.get('active_scan_allowed', False)}")
        lines.append("")

        # 3. 도구
        lines.append("## 3. 사용 도구")
        lines.append("")
        tools = sorted({f.get("tool", "unknown") for f in findings})
        lines.append(", ".join(tools) if tools else "없음")
        lines.append("")

        # 4. 요약
        lines.append("## 4. 주요 결과 요약")
        lines.append("")
        lines.append("| 심각도 | 건수 |")
        lines.append("| --- | ---: |")
        for s in _SEVERITY_ORDER:
            if counts[s]:
                lines.append(f"| {s} | {counts[s]} |")
        lines.append("")
        if not actionable:
            lines.append("> 즉시 조치가 필요한 high/critical 항목은 발견되지 않았습니다. "
                         "탐지된 항목은 대부분 자산·기술 식별(정보성) 결과입니다.")
            lines.append("")

        # 5. 목록
        lines.append("## 5. 취약점 목록")
        lines.append("")
        lines.append("| # | 심각도 | 카테고리 | 항목 | 위치 | 탐지수 |")
        lines.append("| ---: | --- | --- | --- | --- | ---: |")
        for i, g in enumerate(groups, 1):
            lines.append(f"| {i} | {g.severity} | {g.category} | {g.title} | `{g.url}` | {g.count} |")
        lines.append("")

        # 6. 상세
        lines.append("## 6. 상세 결과")
        lines.append("")
        for i, g in enumerate(groups, 1):
            lines.append(f"### {i}. {g.title}")
            lines.append("")
            lines.append(f"- 심각도: **{g.severity}**  |  카테고리: {g.category}  |  탐지: {g.count}건")
            lines.append(f"- 위치: `{g.url}`")
            if g.cwes:
                lines.append(f"- CWE: {', '.join(g.cwes)}")
            rep = g.representative
            desc = (rep.get("description") or "").strip()
            if desc:
                lines.append(f"- 설명: {desc}")
            if g.count > 1 and g.matched_items:
                lines.append(f"- 탐지 세부 ({len(g.matched_items)}개):")
                for item in g.matched_items:
                    lines.append(f"  - `{item}`")
            elif g.matched_items:
                lines.append(f"- 매칭: `{g.matched_items[0]}`")

            ev = rep.get("evidence") or {}
            resp = self._truncate(ev.get("response_sample"))
            if resp:
                lines.append("")
                lines.append("증적 (응답 일부):")
                lines.append("```")
                lines.append(resp)
                lines.append("```")
            lines.append("")

        # 7. 우선 조치
        lines.append("## 7. 우선 조치 항목")
        lines.append("")
        if actionable:
            for g in actionable:
                lines.append(f"- **{g.title}** (`{g.url}`) — {g.severity}")
        else:
            lines.append("해당 없음. (high/critical 미발견)")
        lines.append("")

        # 8. 추가 확인
        lines.append("## 8. 추가 확인 필요 사항")
        lines.append("")
        lines.append("아래는 취약점은 아니지만 공격 표면(attack surface) 관점에서 수동 확인이 권장되는 항목입니다.")
        lines.append("")
        seen_notes: set[str] = set()
        for g in attack_surface:
            note = self._surface_note(g)
            if note and note not in seen_notes:
                seen_notes.add(note)
                lines.append(f"- {note}")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("> 본 보고서는 자동 생성되었으며, 모든 항목은 수동 검증 전까지 미확인(not_tested) 상태입니다. "
                     "정보성(info) 항목은 그 자체로 취약점을 의미하지 않습니다.")
        return "\n".join(lines)

    def _surface_note(self, g: FindingGroup) -> str | None:
        """info 항목을 attack-surface 관점 코멘트로."""
        t = g.title.lower()
        if "ssh" in t or "openssh" in t:
            return f"SSH 서비스 노출 ({g.url}) — 외부에서 22번 포트 접근 가능 여부 및 접근통제 확인 권장"
        if "missing security headers" in t:
            return f"보안 헤더 누락 ({g.url}) — {len(g.matched_items)}개 헤더 미설정. 헤더 추가 검토"
        if "spring" in t:
            return f"Spring 기반 확인 ({g.url}) — actuator 등 관리 엔드포인트 노출 여부 별도 점검 권장"
        if "waf" in t:
            return f"WAF 탐지 ({g.url}) — 우회 가능성은 별도 검증 필요"
        if "whois" in t or "rdap" in t or "ns record" in t or "caa" in t:
            return f"도메인/DNS 등록정보 노출 ({g.title}) — 정상적 공개 정보이나 정찰에 활용될 수 있음"
        return f"{g.title} ({g.url})"

    # ---------- HTML 렌더 (간단) ----------

    def _render_html(self, findings: list[dict[str, Any]], groups: list[FindingGroup]) -> str:
        counts = self._severity_counts(findings)
        sev_color = {
            "critical": "#7c1d1d", "high": "#b91c1c", "medium": "#b45309",
            "low": "#2563eb", "info": "#64748b",
        }
        rows = []
        for i, g in enumerate(groups, 1):
            c = sev_color.get(g.severity, "#64748b")
            rows.append(
                f"<tr><td>{i}</td>"
                f"<td><span style='background:{c};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px'>{g.severity}</span></td>"
                f"<td>{html.escape(g.category)}</td>"
                f"<td>{html.escape(g.title)}</td>"
                f"<td><code>{html.escape(g.url)}</code></td>"
                f"<td style='text-align:right'>{g.count}</td></tr>"
            )
        summary = "".join(
            f"<span style='margin-right:14px'><b style='color:{sev_color.get(s)}'>{s}</b>: {counts[s]}</span>"
            for s in _SEVERITY_ORDER if counts[s]
        )
        return f"""<!DOCTYPE html>
<html lang="ko"><head><meta charset="utf-8">
<title>보안 점검 보고서 — {html.escape(self.run_id)}</title>
<style>
  body{{font-family:-apple-system,'Segoe UI',sans-serif;max-width:960px;margin:40px auto;padding:0 20px;color:#1e293b;line-height:1.6}}
  h1{{border-bottom:2px solid #e2e8f0;padding-bottom:8px}}
  table{{border-collapse:collapse;width:100%;margin:16px 0;font-size:14px}}
  th,td{{border:1px solid #e2e8f0;padding:8px 10px;text-align:left}}
  th{{background:#f8fafc}}
  code{{background:#f1f5f9;padding:1px 5px;border-radius:3px;font-size:13px}}
  .meta{{color:#64748b;font-size:13px}}
</style></head><body>
<h1>보안 점검 보고서</h1>
<p class="meta">Run ID: <code>{html.escape(self.run_id)}</code> · 총 {len(findings)}건 / {len(groups)}개 항목</p>
<h2>요약</h2><p>{summary}</p>
<h2>항목 목록</h2>
<table><thead><tr><th>#</th><th>심각도</th><th>카테고리</th><th>항목</th><th>위치</th><th>탐지수</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<p class="meta">자동 생성 보고서 · 모든 항목 수동 검증 전 미확인(not_tested) 상태 · 정보성 항목은 취약점이 아님</p>
</body></html>"""
