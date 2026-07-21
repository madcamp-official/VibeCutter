"""RAG 기반 candidate 보강·우선순위 신호 (P4 소유, D2 "RAG 가설 우선순위"의 RAG 부분).

`model.code_index.CodeIndex` 로 각 candidate 위치의 **코드 컨텍스트를 검색(RAG)** 해
붙이고, focus 별 sink 키워드가 그 코드에 실제로 있는지로 **관련도(relevance)** 를
계산한다. LLM 없이(GPU 없이) 도는 검색 기반 신호이며, base LLM 재랭킹(`aggregate` 의
`rerank_fn`, GPU)의 입력이자 그 전 단계의 우선순위 보정으로 쓴다.

효과:
- candidate 에 `rag:loc=<file:lo-hi>`, `rag:relevance=<0~1>`, `rag:symbols=<...>` signal 추가.
- `aggregate.priority_score` 가 `rag:relevance` 를 우선순위 보너스로 반영한다.
- `code_context()` 가 LLM 재랭킹/패치 합성에 넘길 **코드 본문 스니펫**을 만든다(R-1).

비파괴: index 로 위치를 못 찾으면 아무 signal 도 안 붙인다(우선순위 불변).

**signal 과 코드 본문을 왜 나눴나**: `Candidate.signals` 는 문자열 리스트(공통 계약)라
40 줄 코드를 담기에 부적절하고, Day5 freeze 로 스키마에 필드를 더할 수도 없다. 그래서
코드 본문은 candidate 를 오염시키지 않는 **곁채널**(`{candidate_id: 스니펫}` 매핑)로 나른다.
"""

from __future__ import annotations

from typing import Iterable, Mapping, Optional

from contracts.schemas import Candidate
from model.code_index import CodeChunk, CodeIndex

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


# 일부 sink 어휘는 변별력이 낮다(코드 절반에 있는 범용 CRUD/식별자 토큰)/높다(그 취약점군의
# 진짜 신호). G-1 실측: idor 어휘 find/get/where/user/id 가 너무 흔해 청크의 44% 가 relevance
# 0.67+ 를 받아 순위가 안 갈렸다(injection 0.9%·xss 2.6% 는 정상). 그래서 idor 는 접근제어/소유권
# 토큰에 무게를 주고 범용 토큰을 깎아 순위를 가른다. **가중이 없는 focus 는 전부 1.0 → 기존과 동일.**
_TERM_WEIGHTS: dict[str, dict[str, float]] = {
    "idor": {
        "find": 0.4, "get": 0.4, "where": 0.4, "user": 0.4, "id": 0.4,   # 범용 CRUD/식별자
        "account": 0.8, "role": 1.0,                                      # 중간
        "owner": 1.2, "authorize": 1.2, "permission": 1.2,               # 접근제어 = IDOR 진짜 신호
    },
}


def _term_weight(focus: Optional[str], term: str) -> float:
    """sink 어휘의 변별 가중. override 없으면 1.0(기존 동작)."""
    return _TERM_WEIGHTS.get(focus or "", {}).get(term, 1.0)


def _relevance(focus: Optional[str], chunk_tokens: set[str]) -> tuple[float, list[str]]:
    """focus sink 어휘의 **가중 합**이 얼마나 되나 → 0~1 관련도 + 매칭된 용어.

    범용 토큰은 낮게·변별 토큰은 높게 가중해 순위를 가른다(G-1). 가중 없는 focus
    (injection/xss)는 모든 매칭이 1.0 → `len(matched)/3` 인 기존 계산과 동일하다.
    """
    terms = FOCUS_SINK_TERMS.get(focus or "", ())
    matched = [t for t in terms if t in chunk_tokens]
    weight = sum(_term_weight(focus, t) for t in matched)
    score = round(min(weight / 3.0, 1.0), 2)  # 가중합 3.0 이상이면 1.0
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


def _snippet(chunk: CodeChunk, line: int, *, radius: int) -> str:
    """chunk 에서 candidate 가 가리키는 줄 주변만 잘라 **줄번호를 붙여** 돌려준다.

    chunk 는 40 줄 고정 창이라 그대로 넘기면 관심 없는 코드가 프롬프트 예산을 먹는다.
    줄번호를 붙이는 건 모델이 "몇 번째 줄이 sink 다"라고 짚을 수 있게 하기 위함이고,
    파일 안 절대 줄번호를 쓴다(스니펫 내부 상대번호가 아니라).
    """
    lines = chunk.text.splitlines()
    hit = line - chunk.start_line              # chunk 내 0-based 위치
    lo = max(0, hit - radius)
    hi = min(len(lines), hit + radius + 1)
    return "\n".join(
        f"{chunk.start_line + i:>5} | {lines[i]}" for i in range(lo, hi)
    )


def code_context(
    candidates: Iterable[Candidate], index: CodeIndex, *, radius: int = 10
) -> dict[str, str]:
    """candidate → 그 위치의 코드 스니펫 매핑 (LLM 재랭킹·패치 합성이 소비).

    `enrich()` 와 같은 위치 해석(`_parse_loc` + `chunk_at`)을 쓰되, signal 대신 **코드 본문**을
    낸다. 위치를 못 찾은 candidate 는 매핑에서 그냥 빠진다(비파괴 — 호출측은 없는 키를
    "컨텍스트 없음"으로 다루면 된다).

    redaction 은 여기서 하지 않는다 — **프롬프트를 조립하는 egress 경계**
    (`model.serving.build_rerank_messages`)에서 일괄로 건다. `evidence_store.write_artifact()`
    가 저장 계층 한 곳에서 redaction 을 거는 것과 같은 이유로, 생산자마다 거는 것보다
    경계 한 곳에서 거는 편이 빠뜨릴 여지가 없다.
    """
    out: dict[str, str] = {}
    for c in candidates:
        loc = _parse_loc(c)
        if loc is None:
            continue
        chunk = index.chunk_at(*loc)
        if chunk is None:
            continue
        out[c.id] = _snippet(chunk, loc[1], radius=radius)
    return out


def has_indexable_location(candidates: Iterable[Candidate]) -> bool:
    """`파일:줄` 위치를 가진 candidate 가 하나라도 있나.

    SCA candidate 는 의존성 취약점이라 `source_symbols` 가 `파일:줄` 형태가 아니다 → 전부
    실패한다. 호출측이 이걸 먼저 물어보고 `CodeIndex.build()` 를 **아예 건너뛰게** 하기 위한
    것(vc_run_sca 가 헛되이 소스 트리를 훑지 않도록).
    """
    return any(_parse_loc(c) is not None for c in candidates)


def rag_relevance(candidate: Candidate) -> Optional[float]:
    """candidate 의 `rag:relevance=` signal 값(없으면 None). aggregate 우선순위가 소비."""
    for s in candidate.signals:
        if s.startswith("rag:relevance="):
            try:
                return float(s.split("=", 1)[1])
            except ValueError:
                return None
    return None
