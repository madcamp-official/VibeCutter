"""RAG 기반 candidate 보강·우선순위 신호 (P4 소유, D2 "RAG 가설 우선순위"의 RAG 부분).

`model.code_index.CodeIndex` 로 각 candidate 위치의 **코드 컨텍스트를 검색(RAG)** 해
붙이고, focus 별 sink 키워드가 그 코드에 실제로 있는지로 **관련도(relevance)** 를
계산한다. LLM 없이(GPU 없이) 도는 검색 기반 신호이며, base LLM 재랭킹(`aggregate` 의
`rerank_fn`, GPU)의 입력이자 그 전 단계의 우선순위 보정으로 쓴다.

효과:
- candidate 에 `rag:loc=<file:lo-hi>`, `rag:relevance=<0~1>`, `rag:symbols=<...>` signal 추가.
- `aggregate.priority_score` 가 `rag:relevance` 를 우선순위 보너스로 반영한다.
- 붙은 코드 컨텍스트는 P3 verifier / D4 LLM 이 근거로 소비.

비파괴: index 로 위치를 못 찾으면 아무 signal 도 안 붙인다(우선순위 불변).
"""

from __future__ import annotations

from typing import Iterable, Optional

from contracts.schemas import Candidate
from model.code_index import CodeIndex

# focus 별 "취약 sink/source" 어휘. chunk 토큰에 이게 있으면 그 위치가 해당 취약점군
# 코드 흐름일 개연성이 높다(코드 검색 토크나이저가 이미 camelCase/snake 분해함).
FOCUS_SINK_TERMS = {
    "injection": ("query", "execute", "exec", "sql", "cursor", "raw", "concat",
                  "format", "statement", "where"),
    "xss": ("render", "html", "innerhtml", "send", "response", "template",
            "escape", "write", "body"),
    "idor": ("find", "get", "where", "user", "owner", "id", "authorize",
             "permission", "role", "account"),
}


def _parse_loc(candidate: Candidate) -> Optional[tuple[str, int]]:
    """source_symbols[0] `path:line` → (path, line). 라인 없으면 None."""
    if not candidate.source_symbols:
        return None
    raw = candidate.source_symbols[0]
    path, _, line = raw.rpartition(":")
    if not path or not line.isdigit():
        return None
    return path, int(line)


def _focus_of(candidate: Candidate) -> Optional[str]:
    for s in candidate.signals:
        if s.startswith("focus:"):
            return s.split(":", 1)[1]
    return None


def _relevance(focus: Optional[str], chunk_tokens: set[str]) -> tuple[float, list[str]]:
    """focus sink 어휘가 chunk 에 몇 개 있나 → 0~1 관련도 + 매칭된 용어."""
    terms = FOCUS_SINK_TERMS.get(focus or "", ())
    matched = [t for t in terms if t in chunk_tokens]
    score = round(min(len(matched) / 3.0, 1.0), 2)  # 3개 이상이면 1.0
    return score, matched


def enrich(candidates: Iterable[Candidate], index: CodeIndex) -> list[Candidate]:
    """각 candidate 에 RAG 코드 컨텍스트/관련도 signal 을 붙여 새 리스트로 반환."""
    out: list[Candidate] = []
    for c in candidates:
        loc = _parse_loc(c)
        chunk = index.chunk_at(*loc) if loc else None
        if chunk is None:
            out.append(c)  # 위치 매칭 실패 → 원본 유지(비파괴)
            continue
        score, _ = _relevance(_focus_of(c), set(chunk.tokens))
        added = [
            f"rag:loc={chunk.file}:{chunk.start_line}-{chunk.end_line}",
            f"rag:relevance={score}",
        ]
        if chunk.symbols:
            added.append(f"rag:symbols={','.join(chunk.symbols)}")
        merged = list(dict.fromkeys([*c.signals, *added]))
        out.append(c.model_copy(update={"signals": merged}))
    return out


def rag_relevance(candidate: Candidate) -> Optional[float]:
    """candidate 의 `rag:relevance=` signal 값(없으면 None). aggregate 우선순위가 소비."""
    for s in candidate.signals:
        if s.startswith("rag:relevance="):
            try:
                return float(s.split("=", 1)[1])
            except ValueError:
                return None
    return None
