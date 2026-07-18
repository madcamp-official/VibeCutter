"""GPU 서빙된 모델을 P4 파이프라인 훅에 연결한다 (P4, GPU STEP).

지금까지 파이프라인은 두 자리를 훅으로 비워뒀다(GPU 확보 후 연결):
- `scanners.aggregate.aggregate(..., rerank_fn=)` — LLM 이 candidate 를 재정렬.
- `model.code_index.CodeIndex.search(..., embed_fn=)` — 임베딩으로 코드 검색.

이 모듈이 그 두 훅을 **서빙 endpoint(vLLM 의 OpenAI 호환 API)** 로 만든다.

설계(프로젝트의 pure-parser + wrapper 패턴 그대로):
- 네트워크/GPU 는 주입식 `chat_fn`/`embed_call` 뒤로 숨긴다 → 목으로 유닛테스트.
- 응답 파싱(`_parse_rerank_order`)·프롬프트 조립은 순수 함수 → GPU 없이 검증.
- HTTP 는 stdlib(urllib)만 → 공통 requirements 에 의존성 추가 안 함(torch/openai 불필요).

실제 endpoint 는 vLLM 을 이렇게 띄운 것을 가정한다:
    python -m vllm.entrypoints.openai.api_server \
        --model Qwen/Qwen2.5-Coder-7B-Instruct --port 8000
그러면 base_url="http://localhost:8000/v1".
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Callable, Optional, Sequence

from contracts.schemas import Candidate

# 주입 지점의 타입.
ChatFn = Callable[[list[dict]], str]                       # messages → assistant text
EmbedCall = Callable[[Sequence[str]], list[list[float]]]   # texts → vectors


# --- 순수 로직: rerank 응답 파싱 --------------------------------------------------------

def _parse_rerank_order(text: str, n: int) -> list[int]:
    """모델 출력에서 0..n-1 의 순열을 복원한다(견고하게).

    모델에게 "가장 유력·심각한 순서로 인덱스를 나열"하라고 시키고, 그 텍스트에서
    정수를 뽑는다. 범위 밖·중복은 버리고, 빠진 인덱스는 원래 순서로 뒤에 붙인다
    → **항상 유효한 순열을 보장**(모델이 헛소리해도 후보를 잃지 않는다)."""
    seen: list[int] = []
    for tok in re.findall(r"-?\d+", text):
        i = int(tok)
        if 0 <= i < n and i not in seen:
            seen.append(i)
    for i in range(n):
        if i not in seen:
            seen.append(i)
    return seen


def _candidate_brief(c: Candidate, idx: int) -> str:
    """rerank 프롬프트용 candidate 한 줄 요약(민감정보 없이 메타만)."""
    loc = c.source_symbols[0] if c.source_symbols else "?"
    sig = ",".join(s for s in c.signals if s.startswith(("focus:", "severity:", "rag:")))
    return (f"[{idx}] class={c.vuln_class or '?'} cwe={c.cwe or '?'} "
            f"conf={c.confidence if c.confidence is not None else '?'} loc={loc} {sig}".strip())


def build_rerank_messages(cands: Sequence[Candidate]) -> list[dict]:
    """candidate 목록 → chat messages. 모델은 인덱스 순열만 답하도록 유도한다."""
    listing = "\n".join(_candidate_brief(c, i) for i, c in enumerate(cands))
    system = (
        "You are a security triage assistant. Rank vulnerability candidates by how "
        "likely each is a TRUE, exploitable finding and how severe it is. "
        "Reply with ONLY the indices in ranked order, most likely/severe first, "
        "comma-separated. No prose."
    )
    user = f"Candidates:\n{listing}\n\nRanked indices:"
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


# --- 훅 팩토리 -------------------------------------------------------------------------

def make_rerank_fn(
    chat_fn: ChatFn, *, max_candidates: int = 40
) -> Callable[[list[Candidate]], list[Candidate]]:
    """`aggregate(..., rerank_fn=)` 에 넣을 LLM 재랭킹 훅을 만든다.

    실패(네트워크/파싱 오류)하면 입력을 그대로 돌려준다 — 비파괴. aggregate 의
    휴리스틱 정렬이 이미 kept 를 정렬해 두므로, 훅 실패 시 그 순서가 유지된다.
    후보가 max_candidates 를 넘으면 상위 그만큼만 LLM 에 보내고 나머지는 뒤에 붙인다.
    """
    def rerank(kept: list[Candidate]) -> list[Candidate]:
        if len(kept) <= 1:
            return kept
        head, tail = kept[:max_candidates], kept[max_candidates:]
        try:
            text = chat_fn(build_rerank_messages(head))
            order = _parse_rerank_order(text, len(head))
        except Exception:
            return kept
        return [head[i] for i in order] + tail

    return rerank


def make_embed_fn(embed_call: EmbedCall) -> EmbedCall:
    """`code_index.search(..., embed_fn=)` 에 넣을 임베딩 훅.

    code_index 는 `[query] + [chunk.text ...]` 를 한 번에 넘기고 코사인 유사도를
    직접 계산하므로, 여기선 텍스트→벡터 호출을 그대로 위임하면 된다.
    """
    def embed(texts: Sequence[str]) -> list[list[float]]:
        return embed_call(texts)

    return embed


# --- wrapper: OpenAI 호환 endpoint (vLLM) — stdlib urllib ------------------------------

def _post_json(url: str, payload: dict, *, api_key: Optional[str], timeout: float) -> dict:
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (내부 endpoint)
        return json.loads(resp.read().decode("utf-8"))


def openai_chat_fn(
    base_url: str, model: str, *,
    api_key: Optional[str] = None, timeout: float = 60.0, temperature: float = 0.0,
) -> ChatFn:
    """vLLM `/v1/chat/completions` 를 부르는 ChatFn. base_url 예: http://host:8000/v1"""
    url = base_url.rstrip("/") + "/chat/completions"

    def chat(messages: list[dict]) -> str:
        body = {"model": model, "messages": messages, "temperature": temperature}
        out = _post_json(url, body, api_key=api_key, timeout=timeout)
        return out["choices"][0]["message"]["content"]

    return chat


def openai_embed_call(
    base_url: str, model: str, *,
    api_key: Optional[str] = None, timeout: float = 60.0,
) -> EmbedCall:
    """vLLM `/v1/embeddings` 를 부르는 EmbedCall. 임베딩 모델을 서빙해야 한다."""
    url = base_url.rstrip("/") + "/embeddings"

    def embed(texts: Sequence[str]) -> list[list[float]]:
        body = {"model": model, "input": list(texts)}
        out = _post_json(url, body, api_key=api_key, timeout=timeout)
        # OpenAI 포맷: data[i].embedding, index 순서 보장 위해 정렬.
        rows = sorted(out["data"], key=lambda d: d["index"])
        return [r["embedding"] for r in rows]

    return embed


def health_check(base_url: str, *, timeout: float = 5.0) -> bool:
    """endpoint 가 살아있고 모델을 응답하는지(/models) 확인. 서빙 기동 검증용."""
    url = base_url.rstrip("/") + "/models"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            body = json.loads(resp.read().decode("utf-8"))
        return bool(body.get("data"))
    except (urllib.error.URLError, OSError, ValueError, KeyError):
        return False
