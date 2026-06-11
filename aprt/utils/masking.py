# utils/masking.py
"""
민감정보 마스킹 유틸.

Policy Guard "민감정보 원문 저장 금지" 원칙을 코드로 강제하는 지점.
nuclei/zap normalizer가 evidence(request/response/curl 등)를 Finding 으로
옮기기 전에 반드시 통과시킨다.

설계 원칙:
- 값은 복구 불가능하게 가린다 (부분 노출도 하지 않음 -> JWT는 앞부분만 봐도 위험).
- 어떤 종류가 가려졌는지는 기록한다 (masked_patterns) -> 디버깅/감사용.
- 패턴은 추가 가능하게 둔다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MASK = "***MASKED***"


@dataclass(frozen=True)
class _Rule:
    name: str
    pattern: re.Pattern[str]
    # group 1 = 보존할 접두(헤더명 등), group 2 = 가릴 값
    keep_prefix: bool


# 주의: 순서대로 적용된다. 더 구체적인 규칙을 위에 둔다.
_RULES: list[_Rule] = [
    _Rule(
        "authorization_bearer",
        re.compile(r"(?i)(authorization:\s*bearer\s+)(\S+)"),
        keep_prefix=True,
    ),
    _Rule(
        "authorization_basic",
        re.compile(r"(?i)(authorization:\s*basic\s+)(\S+)"),
        keep_prefix=True,
    ),
    _Rule(
        "cookie_header",
        re.compile(r"(?i)(cookie:\s*)([^\r\n]+)"),
        keep_prefix=True,
    ),
    _Rule(
        "set_cookie_header",
        re.compile(r"(?i)(set-cookie:\s*)([^\r\n]+)"),
        keep_prefix=True,
    ),
    _Rule(
        "api_key_kv",
        re.compile(r"(?i)(api[_-]?key[\"'\s:=]+)([A-Za-z0-9_\-]{16,})"),
        keep_prefix=True,
    ),
    _Rule(
        "aws_access_key",
        re.compile(r"()(AKIA[0-9A-Z]{16})"),
        keep_prefix=False,
    ),
    # JWT는 헤더 밖(본문, curl-command 등)에 박혀도 잡아야 해서 전역 패턴으로.
    _Rule(
        "jwt",
        re.compile(r"()(eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)"),
        keep_prefix=False,
    ),
]


def mask_secrets(text: str | None) -> tuple[str | None, list[str]]:
    """
    text 안의 민감정보를 가리고 (가린 텍스트, 적중한 규칙 이름 목록)을 반환.
    None 입력은 (None, []) 그대로 반환.
    """
    if text is None:
        return None, []

    hit: list[str] = []
    result = text

    for rule in _RULES:
        def _repl(m: re.Match[str]) -> str:
            return (m.group(1) if rule.keep_prefix else "") + MASK

        new_result, count = rule.pattern.subn(_repl, result)
        if count > 0:
            hit.append(rule.name)
            result = new_result

    return result, hit
