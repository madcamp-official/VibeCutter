"""Candidate 통합 · 중복제거 · FP reject · 우선순위 (P4 소유, D2).

여러 스캐너(SAST/SCA/DAST)가 낸 `contracts.schemas.Candidate[]` 를 하나로 합치고,
같은 위치를 가리키는 중복을 병합하고, 명백한 오탐(test/vendor/생성물 경로 등)을 걸러
P3 verifier 의 검증 부하를 줄인다. 기획서 12.2절 "Semgrep/ZAP aggregation 및 false
positive reject", 5일 계획 D2 P4 "candidate 통합 + FP reject".

- 병합 기준(중복): (정규화 위치, focus, cwe)가 같으면 한 후보로 합치고 signals 를 union,
  confidence 는 최대값. 서로 다른 도구가 같은 지점을 가리키면 **교차검증(corroboration)**
  으로 보고 우선순위를 올린다.
- FP reject(보수적): 기본은 **비-앱 코드 경로**(tests/vendor/dist/생성물)만 제거.
  low-confidence 제거는 옵션(min_confidence)으로만 — 실제 취약점을 날리지 않기 위함.
- 우선순위: base confidence + 교차검증 보너스 + severity 보너스. LLM+RAG 재랭킹은
  `rerank_fn` 훅으로 교체(base LLM 추론은 GPU 필요, D2 에는 휴리스틱만).

이 결과(kept)가 P3 가 verify 할 후보 목록이 된다. focus 는 `focus:<group>` signal 로 읽는다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional, Sequence

from contracts.schemas import Candidate

# 비-앱 코드 경로(정적 분석 오탐의 주요 원천). 이 경로의 후보는 기본 reject.
_NONCODE_PATH = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|__mocks__|mocks?|fixtures?|examples?|"
    r"samples?|docs?|node_modules|bower_components|vendor|dist|build|out|"
    r"\.next|coverage|migrations?)(/|$)",
    re.IGNORECASE,
)
_MINIFIED = re.compile(r"\.(min|bundle)\.(js|css)(:|$)", re.IGNORECASE)

# severity signal → 우선순위 보너스. SCA(CRITICAL/HIGH/…)와 SAST(ERROR/WARNING/INFO)
# 두 어휘를 모두 인식해야 코드흐름 후보가 부당하게 밀리지 않는다.
_SEVERITY_BONUS = {
    "CRITICAL": 0.3, "HIGH": 0.2, "MODERATE": 0.1, "MEDIUM": 0.1, "LOW": 0.0,
    "ERROR": 0.2, "WARNING": 0.1, "INFO": 0.0,   # semgrep 어휘
}


def _location(c: Candidate) -> str:
    return c.source_symbols[0] if c.source_symbols else c.id


def _focus_of(c: Candidate) -> Optional[str]:
    for s in c.signals:
        if s.startswith("focus:"):
            return s.split(":", 1)[1]
    return None


def _severity_of(c: Candidate) -> Optional[str]:
    for s in c.signals:
        if s.startswith("severity:"):
            return s.split(":", 1)[1].upper()
    return None


def _rag_relevance_of(c: Candidate) -> float:
    """`rag:relevance=` signal(scanners.rag_enrich.enrich 가 붙임). 없으면 0."""
    for s in c.signals:
        if s.startswith("rag:relevance="):
            try:
                return float(s.split("=", 1)[1])
            except ValueError:
                return 0.0
    return 0.0


def _dedup_key(c: Candidate) -> tuple:
    return (_location(c), _focus_of(c), c.cwe)


def merge_duplicates(candidates: Iterable[Candidate]) -> list[Candidate]:
    """같은 (위치, focus, cwe) 후보를 하나로 병합. signals union, confidence 최대."""
    grouped: dict[tuple, Candidate] = {}
    order: list[tuple] = []
    for c in candidates:
        key = _dedup_key(c)
        if key not in grouped:
            grouped[key] = c.model_copy(deep=True)
            order.append(key)
            continue
        base = grouped[key]
        merged_signals = list(dict.fromkeys([*base.signals, *c.signals]))  # 순서보존 union
        conf = max(base.confidence or 0.0, c.confidence or 0.0)
        grouped[key] = base.model_copy(update={"signals": merged_signals, "confidence": conf})
    return [grouped[k] for k in order]


def _corroboration(c: Candidate) -> int:
    """이 후보를 지지하는 서로 다른 도구 수(병합 후 signals 기준)."""
    tools = set()
    for s in c.signals:
        if s.startswith("semgrep:"):
            tools.add("semgrep")
        elif s.startswith("sca:"):
            tools.add("sca")
        elif s.startswith("crawl:") or s.startswith("playwright:"):
            tools.add("crawl")
    return max(len(tools), 1)


def priority_score(c: Candidate) -> float:
    """휴리스틱 우선순위. base confidence + 교차검증 + severity + RAG 관련도 보너스.

    RAG 관련도(scanners.rag_enrich.enrich 로 선주입)는 코드 컨텍스트에 focus sink 어휘가
    있을수록 높다 → 최대 +0.1. LLM 재랭킹(GPU)은 aggregate 의 rerank_fn 훅에서.
    """
    base = c.confidence if c.confidence is not None else 0.4
    corr_bonus = 0.15 * (_corroboration(c) - 1)  # 도구 2개면 +0.15, 3개면 +0.30
    sev_bonus = _SEVERITY_BONUS.get(_severity_of(c) or "", 0.0)
    rag_bonus = 0.1 * _rag_relevance_of(c)       # 관련도 1.0 이면 +0.1
    return round(base + corr_bonus + sev_bonus + rag_bonus, 4)


def _reject_reason(c: Candidate, *, min_confidence: float) -> Optional[str]:
    loc = _location(c)
    if _NONCODE_PATH.search(loc) or _MINIFIED.search(loc):
        return "non-app-code-path"
    if min_confidence > 0 and (c.confidence or 0.0) < min_confidence and _corroboration(c) == 1:
        return f"low-confidence(<{min_confidence})"
    return None


@dataclass
class AggregateResult:
    kept: list[Candidate] = field(default_factory=list)   # 우선순위 내림차순
    rejected: list[tuple[Candidate, str]] = field(default_factory=list)

    @property
    def summary(self) -> dict:
        by_focus: dict[str, int] = {}
        for c in self.kept:
            f = _focus_of(c) or "none"
            by_focus[f] = by_focus.get(f, 0) + 1
        return {
            "kept": len(self.kept),
            "rejected": len(self.rejected),
            "by_focus": by_focus,
            "reject_reasons": _count([r for _, r in self.rejected]),
        }


def _count(items: Sequence[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for i in items:
        out[i] = out.get(i, 0) + 1
    return out


def aggregate(
    *candidate_lists: Iterable[Candidate],
    min_confidence: float = 0.0,
    rerank_fn: Optional[Callable[[list[Candidate]], list[Candidate]]] = None,
) -> AggregateResult:
    """여러 스캐너 출력 → 병합 → FP reject → 우선순위 정렬.

    min_confidence: >0 이면 단일 도구 + 저신뢰 후보를 추가로 reject(기본 0=미적용).
    rerank_fn: kept 를 받아 재정렬하는 훅(LLM+RAG 재랭킹 자리). 없으면 휴리스틱 정렬.
    """
    flat: list[Candidate] = [c for lst in candidate_lists for c in lst]
    merged = merge_duplicates(flat)

    kept: list[Candidate] = []
    rejected: list[tuple[Candidate, str]] = []
    for c in merged:
        reason = _reject_reason(c, min_confidence=min_confidence)
        if reason:
            rejected.append((c, reason))
        else:
            kept.append(c)

    if rerank_fn is not None:
        kept = rerank_fn(kept)
    else:
        kept.sort(key=priority_score, reverse=True)

    return AggregateResult(kept=kept, rejected=rejected)
