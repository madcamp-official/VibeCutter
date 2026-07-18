"""공통 값 집합: severity · OWASP category (P4 제안, D1-P1 요청 응답).

D1-P1.md "다른 역할에 필요한 사항": *severity/owasp_category 는 자유 문자열로 열어뒀으니
SAST(Semgrep) 결과 매핑 시 합의된 값 집합이 있으면 알려달라.* 에 대한 P4 안이다.

- `Finding.severity` 는 아래 `SEVERITY` 5단계 중 하나로 채운다.
- `Finding.owasp_category` 는 `OWASP_2021` 코드(예: `A03:2021`) 중 하나로 채운다.

candidate 는 severity/owasp 를 `signals` 문자열(`severity:<raw>`, `owasp:<raw>`)로만
갖는다(스키마에 필드 없음). 여기 헬퍼가 그 raw 값을 정규화해 P1/P3 가 Finding 을 만들 때
바로 쓰게 한다. **기존 signal 은 provenance 로 그대로 두고(비파괴), 정규화는 읽기 전용.**

이 값 집합은 P1 이 스키마/문서에 채택하면 공통 계약이 된다 — 이견 있으면 handoff 로.
"""

from __future__ import annotations

from typing import Optional

from contracts.schemas import Candidate

# --- severity 5단계 (기획서 severity, OWASP risk 관례) --------------------------------
SEVERITY = ("critical", "high", "medium", "low", "info")

# 도구별 raw severity → 정규 severity. SAST(Semgrep: ERROR/WARNING/INFO)·
# SCA(OSV/CVSS: CRITICAL/HIGH/MODERATE/MEDIUM/LOW) 두 어휘 모두 수용.
_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "ERROR": "high",       # semgrep ERROR ≈ high
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "WARNING": "medium",   # semgrep WARNING ≈ medium
    "LOW": "low",
    "INFO": "info",        # semgrep INFO ≈ info
}

# --- OWASP Top 10 2021 카테고리 --------------------------------------------------------
OWASP_2021 = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}

# 3군(focus) → 대표 OWASP 카테고리(참고 매핑).
FOCUS_TO_OWASP = {
    "idor": "A01:2021",       # Broken Access Control
    "injection": "A03:2021",  # Injection
    "xss": "A03:2021",        # XSS 는 2021 에서 Injection 에 통합
}


def normalize_severity(raw: Optional[str], *, default: Optional[str] = None) -> Optional[str]:
    """raw severity 문자열 → SEVERITY 중 하나. 모르면 default."""
    if raw is None:
        return default
    return _SEVERITY_MAP.get(str(raw).strip().upper(), default)


def normalize_owasp(raw: Optional[str]) -> Optional[str]:
    """`A03:2021 - Injection` / `A03:2021` 등에서 유효한 OWASP 코드만 추출."""
    if not raw:
        return None
    token = str(raw).strip().split()[0].rstrip("-").strip()
    return token if token in OWASP_2021 else None


def is_owasp_category(value: str) -> bool:
    return value in OWASP_2021


def candidate_severity(candidate: Candidate) -> Optional[str]:
    """candidate 의 `severity:<raw>` signal → 정규 severity(Finding.severity 용)."""
    for s in candidate.signals:
        if s.startswith("severity:"):
            return normalize_severity(s.split(":", 1)[1])
    return None


def candidate_owasp(candidate: Candidate) -> Optional[str]:
    """candidate 에서 OWASP 코드 결정: `owasp:` signal 우선, 없으면 focus 로 추론."""
    for s in candidate.signals:
        if s.startswith("owasp:"):
            code = normalize_owasp(s.split(":", 1)[1])
            if code:
                return code
    for s in candidate.signals:
        if s.startswith("focus:"):
            return FOCUS_TO_OWASP.get(s.split(":", 1)[1])
    return None
