# normalizers/nuclei_normalizer.py
"""
Nuclei jsonl -> 공통 Finding 변환.

핵심 책임:
1. jsonl 한 줄 = nuclei 탐지 1건 -> Finding 1건
2. evidence(request/response)는 저장 전 반드시 마스킹
3. info.tags -> category 매핑 (우선순위 기반)
4. severity 그대로 통과, confidence 는 matcher-status 기반 추정
5. cwe 매핑 추출

하지 않는 것:
- risk 점수 계산 (Evaluator)
- 다음 액션 선택 (NextActionSelector)
- 재현 검증 (별도 단계) -> reproducibility 는 항상 not_tested 로 둔다
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from normalizers.base import BaseNormalizer, Evidence, Finding, Mappings
from utils.masking import mask_secrets
from normalizers.base import Cvss


# tags -> category. 위에서부터 검사, 첫 매치 채택 (구체적/위험한 것 우선).
_CATEGORY_RULES: list[tuple[str, set[str]]] = [
    ("injection",      {"sqli", "xss", "rce", "ssrf", "lfi", "rfi", "ssti",
                        "xxe", "injection", "cmdi", "crlf", "redirect"}),
    ("auth",           {"auth", "default-login", "login", "jwt", "oauth",
                        "weak-credentials", "token"}),
    ("access_control", {"idor", "bola", "access-control", "authz", "privilege"}),
    ("exposure",       {"exposure", "exposures", "files", "file", "backup",
                        "logs", "config", "disclosure", "secret", "leak",
                        "swagger", "openapi"}),
    ("crypto",         {"ssl", "tls", "crypto", "cipher", "weak-cipher"}),
    ("header",         {"headers", "header", "csp", "hsts", "cors"}),
    ("misconfiguration", {"misconfig", "misconfiguration", "default-page"}),
]

# 순수 탐지/기술식별 태그만 있는 경우 (waf-detect 등) -> unknown 으로 정직하게.
# (스키마에 'informational' 카테고리가 없어서 unknown 으로 둠. 추후 카테고리 추가 검토.)
_DETECTION_ONLY = {"tech", "detect", "detection", "discovery", "waf", "network", "enum"}


class NucleiNormalizer(BaseNormalizer):
    tool_name = "nuclei"

    def normalize_file(self, raw_path: str) -> list[Finding]:
        findings: list[Finding] = []
        with open(raw_path, "r", encoding="utf-8") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    # 깨진 줄은 건너뛰되 조용히 삼키지 않도록 표시 가능 (여기선 skip)
                    continue
                findings.append(self._to_finding(record))
        return findings

    def _to_finding(self, rec: dict[str, Any]) -> Finding:
        info = rec.get("info", {}) or {}
        tags = self._as_list(info.get("tags"))

        url = rec.get("matched-at") or rec.get("url") or rec.get("host") or ""
        method = self._parse_method(rec.get("request"))
        status_code = self._parse_status(rec.get("response"))

        # --- 마스킹: evidence 로 옮기기 전에 반드시 ---
        req_masked, hit_req = mask_secrets(rec.get("request"))
        resp_masked, hit_resp = mask_secrets(rec.get("response"))
        matched = rec.get("matcher-name") or rec.get("extracted-results")
        if isinstance(matched, list):
            matched = ", ".join(str(m) for m in matched)
        matched_masked, hit_match = mask_secrets(matched)

        masked_patterns = sorted(set(hit_req + hit_resp + hit_match))

        evidence = Evidence(
            request_sample=req_masked,
            response_sample=resp_masked,
            matched_text=matched_masked,
            status_code=status_code,
            masked=bool(masked_patterns),
            masked_patterns=masked_patterns,
        )

        mappings = Mappings(cwe=self._extract_cwe(info),cve=self._extract_cve(info))
        cvss = self._extract_cvss(info)

        return Finding(
            finding_id=self._finding_id(rec, url),
            run_id=self.run_id,
            tool=self.tool_name,
            target_id=self.target_id,
            title=str(info.get("name") or rec.get("template-id") or "unknown"),
            description=str(info.get("description") or "").strip(),
            category=self._map_category(tags),
            severity=self._normalize_severity(info.get("severity")),
            confidence=self._infer_confidence(rec),
            reproducibility="not_tested",
            url=url,
            method=method,
            parameter=None,
            evidence=evidence,
            mappings=mappings,
            cvss=cvss
        )

    # ---------- 매핑 헬퍼 ----------

    def _map_category(self, tags: list[str]) -> str:
        tagset = {t.lower() for t in tags}
        for category, keys in _CATEGORY_RULES:
            if tagset & keys:
                return category
        # 위험 카테고리에 안 걸리고 탐지/기술 태그만 있으면 unknown
        if tagset & _DETECTION_ONLY:
            return "unknown"
        return "unknown"

    def _normalize_severity(self, sev: Any) -> str:
        s = str(sev or "").lower()
        if s in {"info", "low", "medium", "high", "critical"}:
            return s
        if s in {"informational", "information"}:
            return "info"
        return "info"

    def _infer_confidence(self, rec: dict[str, Any]) -> str:
        # nuclei 는 confidence 필드가 없다. matcher 성공 = 매칭이 일어남.
        # 단, '매칭'이 곧 '취약점 확정'은 아니므로 보수적으로 medium 기본.
        if rec.get("matcher-status") is True:
            return "medium"
        return "low"

    def _extract_cwe(self, info: dict[str, Any]) -> list[str]:
        classification = info.get("classification") or {}
        cwe = classification.get("cwe-id")
        items = self._as_list(cwe)
        # "cwe-200" -> "CWE-200" 정규화
        return [str(c).upper().replace("CWE-", "CWE-") for c in items if c]

    def _parse_method(self, request: Any) -> str:
        if not isinstance(request, str) or not request:
            return "UNKNOWN"
        first = request.splitlines()[0] if request.splitlines() else ""
        parts = first.split()
        if parts and parts[0].upper() in {
            "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"
        }:
            return parts[0].upper()
        return "UNKNOWN"

    def _parse_status(self, response: Any) -> int | None:
        if not isinstance(response, str) or not response:
            return None
        first = response.splitlines()[0] if response.splitlines() else ""
        # "HTTP/1.1 500 " -> 500
        parts = first.split()
        for p in parts:
            if p.isdigit() and len(p) == 3:
                return int(p)
        return None

    def _finding_id(self, rec: dict[str, Any], url: str) -> str:
        # run 무관하게 안정적 -> dedup 가능. template-id + url + matcher
        key = "|".join([
            str(rec.get("template-id", "")),
            url,
            str(rec.get("matcher-name", "")),
        ])
        return "f-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]

    def _extract_cve(self, info: dict) -> list[str]:
        classification = info.get("classification") or {}
        return [str(c).upper() for c in self._as_list(classification.get("cve-id")) if c]
 
 
    def _extract_cvss(self, info: dict) -> "Cvss":
        classification = info.get("classification") or {}
        vector = classification.get("cvss-metrics")        # e.g. "CVSS:3.1/AV:N/..."
        score = classification.get("cvss-score")
        # nuclei emits EPSS under classification or metadata depending on version
        epss = classification.get("epss-score")
        if epss is None:
            epss = (info.get("metadata") or {}).get("epss-score")
 
        if not (vector or score or epss):
            return Cvss()   # detection-only finding -> evaluator falls back to CWE
 
        version = None
        if isinstance(vector, str):
            version = "3.1" if "CVSS:3.1" in vector else ("4.0" if "CVSS:4.0" in vector else None)
 
        return Cvss(
            source_vector=vector or None,
            source_score=float(score) if score not in (None, "") else None,
            source_version=version,
            epss_score=float(epss) if epss not in (None, "") else None,
        )

    @staticmethod
    def _as_list(value: Any) -> list[Any]:
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]
