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
from typing import Callable, Mapping, Optional, Sequence

from contracts.schemas import Candidate
from core.redaction import redact

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
    """rerank 프롬프트용 candidate 한 줄 요약(메타).

    **주의(R-1 이전과 달라진 점)**: 예전엔 이 함수가 "민감정보 없이 메타만" 보내는 것이
    프롬프트 전체의 보증이었다. 지금은 `build_rerank_messages` 가 코드 본문도 함께
    보내므로, 그 보증은 이 함수가 아니라 거기서 거는 `redact()` 가 진다.
    """
    loc = c.source_symbols[0] if c.source_symbols else "?"
    sig = ",".join(s for s in c.signals if s.startswith(("focus:", "severity:", "rag:")))
    return (f"[{idx}] class={c.vuln_class or '?'} cwe={c.cwe or '?'} "
            f"conf={c.confidence if c.confidence is not None else '?'} loc={loc} {sig}".strip())


# 코드 본문을 붙일 상위 후보 수. 7.7 tok/s 라 프롬프트가 길어지면 그대로 지연이 된다 —
# 순위를 가르는 건 결국 상위권이므로 앞쪽에만 코드를 준다(뒤는 메타만).
DEFAULT_MAX_CONTEXT = 10


def build_rerank_messages(
    cands: Sequence[Candidate],
    *,
    contexts: Optional[Mapping[str, str]] = None,
    max_context: int = DEFAULT_MAX_CONTEXT,
) -> list[dict]:
    """candidate 목록 → chat messages. 모델은 인덱스 순열만 답하도록 유도한다.

    `contexts` 는 `scanners.rag_enrich.code_context()` 가 만든 `{candidate_id: 코드 스니펫}`.
    주면 **상위 `max_context` 개 후보에 한해** 코드 본문을 함께 싣는다(RAG). 없으면 예전처럼
    메타만 — 인덱스 없이도(오프라인) 재랭킹은 계속 돈다.

    **redaction egress 경계**: 프롬프트에 실리는 코드는 전부 `core.redaction.redact()` 를
    거친다. 대상 소스에 하드코딩된 JWT/세션쿠키/password 가 공유 GPU 서버로 흘러가지
    않게 하는 마지막 관문이다 — `evidence_store.write_artifact()` 가 저장 계층 한 곳에서
    거는 것과 같은 패턴(cowork_rule 4절).
    """
    listing = "\n".join(_candidate_brief(c, i) for i, c in enumerate(cands))
    system = (
        "You are a security triage assistant. Rank vulnerability candidates by how "
        "likely each is a TRUE, exploitable finding and how severe it is. "
        "Reply with ONLY the indices in ranked order, most likely/severe first, "
        "comma-separated. No prose."
    )
    parts = [f"Candidates:\n{listing}"]

    if contexts:
        blocks = []
        for i, c in enumerate(cands[:max_context]):
            snippet = contexts.get(c.id)
            if snippet:
                blocks.append(f"[{i}] {c.source_symbols[0] if c.source_symbols else '?'}\n"
                              f"```\n{redact(snippet)}\n```")
        if blocks:
            parts.append("Code at each candidate location:\n" + "\n\n".join(blocks))

    parts.append("Ranked indices:")
    return [{"role": "system", "content": system},
            {"role": "user", "content": "\n\n".join(parts)}]


# --- 훅 팩토리 -------------------------------------------------------------------------

def make_rerank_fn(
    chat_fn: ChatFn,
    *,
    max_candidates: int = 40,
    contexts: Optional[Mapping[str, str]] = None,
    max_context: int = DEFAULT_MAX_CONTEXT,
) -> Callable[[list[Candidate]], list[Candidate]]:
    """`aggregate(..., rerank_fn=)` 에 넣을 LLM 재랭킹 훅을 만든다.

    실패(네트워크/파싱 오류)하면 입력을 그대로 돌려준다 — 비파괴. aggregate 의
    휴리스틱 정렬이 이미 kept 를 정렬해 두므로, 훅 실패 시 그 순서가 유지된다.
    후보가 max_candidates 를 넘으면 상위 그만큼만 LLM 에 보내고 나머지는 뒤에 붙인다.

    `contexts` 는 `scanners.rag_enrich.code_context()` 의 `{candidate_id: 코드 스니펫}`.
    주면 상위 후보의 코드 본문이 프롬프트에 함께 실린다(R-1). 없으면 메타만.
    """
    def rerank(kept: list[Candidate]) -> list[Candidate]:
        if len(kept) <= 1:
            return kept
        head, tail = kept[:max_candidates], kept[max_candidates:]
        try:
            text = chat_fn(build_rerank_messages(
                head, contexts=contexts, max_context=max_context))
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


_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)


def strip_reasoning(text: str) -> str:
    """추론형 모델(qwen3 등)의 `<think>...</think>` 블록을 제거한다.

    rerank 파서는 텍스트에서 정수를 전부 긁어오므로, 사고 과정에 섞인 숫자가 순열을
    오염시킨다. 닫히지 않은 `<think>` (출력이 잘린 경우)는 그 뒤 전부를 버린다.
    """
    text = _THINK_RE.sub(" ", text)
    if "<think>" in text.lower():
        text = text[: text.lower().index("<think>")]
    return text.strip()


def openai_chat_fn(
    base_url: str, model: str, *,
    api_key: Optional[str] = None, timeout: float = 60.0, temperature: float = 0.0,
    max_tokens: Optional[int] = None, extra_body: Optional[dict] = None,
) -> ChatFn:
    """OpenAI 호환 `/v1/chat/completions` 를 부르는 ChatFn. base_url 예: http://host:8080/v1

    `extra_body` 는 서버별 확장 필드(예: qwen3 의 `chat_template_kwargs`)를 그대로 실어
    보낸다. 응답의 `<think>` 블록은 제거해서 돌려준다(rerank 파서 오염 방지).
    """
    url = base_url.rstrip("/") + "/chat/completions"

    def chat(messages: list[dict]) -> str:
        body = {"model": model, "messages": messages, "temperature": temperature}
        if max_tokens is not None:
            body["max_tokens"] = max_tokens
        if extra_body:
            body.update(extra_body)
        out = _post_json(url, body, api_key=api_key, timeout=timeout)
        return strip_reasoning(out["choices"][0]["message"]["content"] or "")

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


def _server_root(base_url: str) -> str:
    """`http://host:8080/v1` → `http://host:8080`. /health 는 /v1 아래가 아니다."""
    root = base_url.rstrip("/")
    if root.endswith("/v1"):
        root = root[: -len("/v1")]
    return root


def liveness_check(base_url: str, *, timeout: float = 5.0) -> bool:
    """서버 루트의 `GET /health` 확인(인증 불필요).

    외부 API(qwen3-235b)는 `/health` 를 인증 없이 열어두므로, 도달 가능한 endpoint 를
    고를 때 이쪽을 쓴다. `/v1/models` 는 인증이 필요할 수 있어 도달성 판정에 부적합.
    """
    url = _server_root(base_url) + "/health"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return 200 <= resp.status < 300
    except (urllib.error.URLError, OSError, ValueError):
        return False


def make_chained_chat_fn(
    chat_fns: Sequence[ChatFn], *, on_fallback: Optional[Callable[[int, Exception], None]] = None,
) -> ChatFn:
    """여러 ChatFn 을 순서대로 시도하는 ChatFn (앞이 primary, 뒤가 fallback).

    앞의 endpoint 가 **답을 못 주거나(연결 실패/HTTP 오류) 너무 오래 걸리면**(각 ChatFn 의
    timeout 이 socket timeout 으로 터진다) 다음 것으로 넘어간다. 큰 모델(qwen3-235b)을
    primary 로, 기존 7B 를 fallback 으로 두는 구성이 이 함수의 용도다.

    빈 응답도 실패로 본다 — rerank 파서가 빈 텍스트를 항등 순열로 삼켜버려서 fallback
    기회를 잃기 때문. 전부 실패하면 마지막 예외를 올린다(호출측 `make_rerank_fn` 이
    잡아서 비파괴로 처리한다).
    """
    fns = list(chat_fns)
    if not fns:
        raise ValueError("chat_fns must not be empty")

    def chat(messages: list[dict]) -> str:
        last: Exception = RuntimeError("no chat endpoint attempted")
        for i, fn in enumerate(fns):
            try:
                text = fn(messages)
            except Exception as exc:  # 네트워크/타임아웃/응답형식 — 다음 tier 로.
                last = exc
            else:
                if text and text.strip():
                    return text
                last = RuntimeError("empty completion")
            if on_fallback is not None:
                on_fallback(i, last)
        raise last

    return chat
