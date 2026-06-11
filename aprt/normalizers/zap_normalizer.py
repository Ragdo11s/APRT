# normalizers/zap_normalizer.py
"""
ZAP traditional-json report -> 공통 Finding 변환.

nuclei_normalizer 와 동일 계약:
  BaseNormalizer 상속 / normalize_file(raw_path) -> list[Finding]
  evidence 는 저장 전 마스킹 / risk 점수는 매기지 않음(Evaluator) / reproducibility=not_tested

ZAP 고유:
  - 입력은 ZAP automation framework 의 report 잡(template: traditional-json)이 만든
    runs/<run_id>/raw/zap-report.json
  - 구조(가정): { "site": [ { "@name": ..., "alerts": [ {alert..., "instances":[...]} ] } ] }
  - alert 1건의 instance 1건 = Finding 1건 (instance 에 param/method/uri 가 들어있어
    스키마의 url/method/parameter 와 1:1로 맞음). instance 가 없으면 alert 대표 1건.
  - riskcode 0/1/2/3 -> info/low/medium/high (ZAP 엔 critical 없음)
  - confidence 0..3 -> low/low/medium/high
  - cweid -> CWE-<id>, desc/solution 의 HTML 은 제거
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from normalizers.base import BaseNormalizer, Evidence, Finding, Mappings
from utils.masking import mask_secrets


_RISK_TO_SEVERITY = {"0": "info", "1": "low", "2": "medium", "3": "high"}
_CONFIDENCE_MAP = {"0": "low", "1": "low", "2": "medium", "3": "high"}

# alert 이름 키워드 -> category (위에서부터, 첫 매치 채택; 위험한 것 우선)
_CATEGORY_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    ("injection", ("sql injection", "cross site scripting", "xss", "command injection",
                   "code injection", "ssrf", "server side request", "xxe", "external entity",
                   "path traversal", "remote file", "ldap injection", "xpath")),
    ("auth", ("authentication", "session fixation", "session id", "login", "credential", "jwt")),
    ("access_control", ("authorization", "access control", "idor", "directory browsing")),
    ("exposure", ("information disclosure", "information leak", "exposure", "backup",
                  "source code", ".git", "directory listing", "sensitive", "private ip")),
    ("crypto", ("ssl", "tls", "certificate", "cipher", "hsts not", "weak")),
    ("header", ("header", "content security policy", "csp", "x-frame", "x-content",
                "cookie", "cors", "referrer", "anti-clickjacking")),
    ("misconfiguration", ("misconfiguration", "default", "debug", "verbose", "stack trace",
                          "error", "timestamp disclosure")),
]

_HTML_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"\s+")


class ZapNormalizer(BaseNormalizer):
    tool_name = "zap"

    def normalize_file(self, raw_path: str) -> list[Finding]:
        with open(raw_path, "r", encoding="utf-8") as fh:
            report = json.load(fh)

        sites = report.get("site")
        if isinstance(sites, dict):          # 단일 site 가 객체로 올 수도
            sites = [sites]
        if not isinstance(sites, list):
            return []

        findings: list[Finding] = []
        for site in sites:
            if not isinstance(site, dict):
                continue
            alerts = site.get("alerts") or []
            for alert in alerts:
                if not isinstance(alert, dict):
                    continue
                findings.extend(self._alert_to_findings(alert))
        return findings

    def _alert_to_findings(self, alert: dict[str, Any]) -> list[Finding]:
        instances = alert.get("instances") or [{}]
        if not isinstance(instances, list) or not instances:
            instances = [{}]

        severity = _RISK_TO_SEVERITY.get(str(alert.get("riskcode", "")), "info")
        confidence = _CONFIDENCE_MAP.get(str(alert.get("confidence", "")), "low")
        name = str(alert.get("name") or alert.get("alert") or "unknown")
        description = self._strip_html(alert.get("desc"))
        category = self._map_category(name)
        cwe = self._extract_cwe(alert)

        out: list[Finding] = []
        for inst in instances:
            if not isinstance(inst, dict):
                inst = {}
            url = str(inst.get("uri") or "")
            method = str(inst.get("method") or "GET").upper()
            param = inst.get("param") or None

            evidence_raw = inst.get("evidence") or inst.get("attack") or alert.get("otherinfo")
            ev_masked, hit_ev = mask_secrets(evidence_raw)
            # traditional-json 은 보통 full req/resp 를 안 담지만, 있으면 마스킹해서 보존
            req_masked, hit_req = mask_secrets(inst.get("requestheader"))
            resp_masked, hit_resp = mask_secrets(inst.get("responseheader"))
            masked_patterns = sorted(set(hit_ev + hit_req + hit_resp))

            evidence = Evidence(
                request_sample=req_masked,
                response_sample=resp_masked,
                matched_text=ev_masked,
                status_code=None,                 # traditional-json instance 엔 상태코드 없음
                masked=bool(masked_patterns),
                masked_patterns=masked_patterns,
            )

            out.append(Finding(
                finding_id=self._finding_id(alert, url, str(param or ""), method),
                run_id=self.run_id,
                tool=self.tool_name,
                target_id=self.target_id,
                title=name,
                description=description,
                category=category,
                severity=severity,
                confidence=confidence,
                reproducibility="not_tested",
                url=url,
                method=method if method in {
                    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"} else "UNKNOWN",
                parameter=param,
                evidence=evidence,
                mappings=Mappings(cwe=cwe),
            ))
        return out

    # ---------- 헬퍼 ----------

    def _map_category(self, name: str) -> str:
        n = name.lower()
        for category, keys in _CATEGORY_KEYWORDS:
            if any(k in n for k in keys):
                return category
        return "unknown"

    def _extract_cwe(self, alert: dict[str, Any]) -> list[str]:
        cwe = alert.get("cweid")
        if cwe in (None, "", "-1", -1):
            return []
        return [f"CWE-{str(cwe).strip().replace('CWE-', '')}"]

    def _strip_html(self, value: Any) -> str:
        if not isinstance(value, str) or not value:
            return ""
        return _WS.sub(" ", _HTML_TAG.sub(" ", value)).strip()

    def _finding_id(self, alert: dict[str, Any], url: str, param: str, method: str) -> str:
        # run 무관 안정적 -> dedup. pluginid + uri + param + method
        key = "|".join([
            str(alert.get("pluginid") or alert.get("alertRef") or ""),
            url, param, method,
        ])
        return "f-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
