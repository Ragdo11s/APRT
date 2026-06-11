# normalizers/base.py
"""
공통 Finding 모델 + normalizer 인터페이스.

모든 도구별 normalizer(nuclei, zap, ...)는 BaseNormalizer 를 상속하고
raw 결과를 Finding 리스트로 변환한다. 출력 형식이 동일해야
Evaluator / NextActionSelector 가 도구를 구분하지 않고 처리할 수 있다.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Evidence:
    request_sample: str | None = None
    response_sample: str | None = None
    matched_text: str | None = None
    status_code: int | None = None
    # 마스킹 추적: 어떤 민감정보 종류가 가려졌는지
    masked: bool = False
    masked_patterns: list[str] = field(default_factory=list)

@dataclass
class Cvss:                                                 
    source_vector: str | None = None        # e.g. "CVSS:3.1/AV:N/AC:L/..."
    source_score: float | None = None
    source_version: str | None = None        # "3.1" | "4.0"
    epss_score: float | None = None           # 0.0 - 1.0
    epss_percentile: float | None = None

@dataclass
class Risk:
    # normalizer 는 점수를 매기지 않는다. Evaluator 가 채운다.
    impact_score: float = 0.0
    exploitability_score: float = 0.0
    exposure_score: float = 0.0
    final_score: float = 0.0

    cvss_vector: str | None = None            # vector actually used to score
    cvss_version: str = "3.1"
    provenance: str = "unscored"              # authoritative|tool|derived|heuristic|unscored
    rationale: str = ""
    scored_at: str | None = None


@dataclass
class Mappings:
    owasp_top10: list[str] = field(default_factory=list)
    owasp_asvs: list[str] = field(default_factory=list)
    mitre_attack: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)
    cve: list[str] = field(default_factory=list)


@dataclass
class Finding:
    finding_id: str
    run_id: str
    tool: str               # nuclei | zap | custom
    target_id: str

    title: str
    description: str
    category: str           # exposure|misconfiguration|injection|auth|access_control|crypto|header|unknown

    severity: str           # info|low|medium|high|critical
    confidence: str         # low|medium|high
    reproducibility: str    # unknown|not_tested|failed|partial|confirmed

    url: str
    method: str             # GET|POST|...|UNKNOWN
    parameter: str | None = None

    evidence: Evidence = field(default_factory=Evidence)
    risk: Risk = field(default_factory=Risk)
    mappings: Mappings = field(default_factory=Mappings)
    cvss: Cvss = field(default_factory=Cvss)

    next_actions: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BaseNormalizer(ABC):
    tool_name: str = "base"

    def __init__(self, run_id: str, target_id: str) -> None:
        self.run_id = run_id
        self.target_id = target_id

    @abstractmethod
    def normalize_file(self, raw_path: str) -> list[Finding]:
        """raw 결과 파일을 읽어 Finding 리스트로 변환."""
        raise NotImplementedError
