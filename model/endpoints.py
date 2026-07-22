"""LLM endpoint 티어 구성: 큰 외부 모델을 primary, 로컬 모델을 fallback 으로 묶는다.

배경(D5 결정): qwen3-235b 를 **외부 OpenAI 호환 API** 로 호출한다. 이 모델은 너무 커서
학습시키지 않는다 — 우리는 쓰기만 한다. fallback 은 큰 모델이 **답을 못 주거나 너무
오래 걸릴 때** 쓴다. **fallback 은 7B → 72B 로 전환 중**(REMAINING_PLAN §3; 72B 기동·
model id 는 P2 소관). 현재 `.env` 엔 fallback endpoint 가 미설정이라 235B 단독 운영이다.

계층 분리는 프로젝트 관행 그대로:
- `model/serving.py` = 전송(urllib wrapper) + 훅 팩토리.
- 이 모듈 = **정책**(어떤 endpoint 를 어떤 순서로, 어떤 timeout 으로 쓸지) + env 해석.
  순수 함수 `resolve_tiers(env)` 로 분리해서 네트워크 없이 테스트한다.

env (모두 선택 — 없으면 아래 기본값):
  VIBECUTTER_LLM_ENDPOINTS   primary base_url 들, 콤마 구분. 순서대로 시도.
                             기본: 내부망 → 외부망 (내부망이 붙으면 그걸로 끝)
  VIBECUTTER_LLM_MODEL       기본 qwen3-235b
  VIBECUTTER_LLM_API_KEY     Authorization: Bearer <key>
  VIBECUTTER_LLM_TIMEOUT     기본 600 (7.7 tok/s → 긴 응답이 정상)
  VIBECUTTER_LLM_MAX_TOKENS  기본 512 (rerank 는 인덱스 나열이면 충분 — 폭주 방지)
  VIBECUTTER_LLM_FALLBACK_ENDPOINT  7B base_url (미설정이면 fallback 없음)
  VIBECUTTER_LLM_FALLBACK_MODEL     기본 Qwen/Qwen2.5-Coder-7B-Instruct
  VIBECUTTER_LLM_FALLBACK_TIMEOUT   기본 60
  VIBECUTTER_LLM_DISABLE     "1" 이면 LLM 훅을 전부 끈다(휴리스틱만 — CI/오프라인).

하위호환: 기존 `VIBECUTTER_MODEL_ENDPOINT`/`VIBECUTTER_MODEL_NAME` 은 **fallback(7B)**
설정으로 읽는다 — 그 변수들이 가리키던 게 로컬 7B 서빙이었기 때문.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, replace
from typing import Callable, Mapping, Optional, Sequence

from model.serving import ChatFn, liveness_check, make_chained_chat_fn, openai_chat_fn

DEFAULT_PRIMARY_ENDPOINTS = (
    "http://192.168.0.226:8080/v1",   # 내부망
    "http://172.10.7.246:8080/v1",    # 외부망(도달되면)
)
DEFAULT_PRIMARY_MODEL = "qwen3-235b"
DEFAULT_PRIMARY_TIMEOUT = 600.0
DEFAULT_PRIMARY_MAX_TOKENS = 512
# fallback tier 의 기본 모델. 팀 결정: fallback 을 **72B 로 전환**(7B 는 72B 작동 확인 후 폐기,
# REMAINING_PLAN §3). ⚠️ 72B 의 **정확한 model id 는 P2 가 endpoint 기동 시 제공** — 확정되면
# 이 상수를 그 id 로 교체하거나 env `VIBECUTTER_LLM_FALLBACK_MODEL=<72B id>` 로 지정한다.
# 그 전까지는 레거시 7B 문자열을 둔다(fallback endpoint 자체가 미설정이라 현재 미사용).
DEFAULT_FALLBACK_MODEL = "Qwen/Qwen2.5-Coder-7B-Instruct"  # TODO(P2 72B id): 72B 로 교체
DEFAULT_FALLBACK_TIMEOUT = 60.0


@dataclass(frozen=True)
class Endpoint:
    """호출 가능한 하나의 OpenAI 호환 endpoint."""

    base_url: str
    model: str
    timeout: float
    api_key: Optional[str] = None
    max_tokens: Optional[int] = None
    tier: str = "primary"          # "primary" | "fallback" — 로깅/진단용

    def chat_fn(self) -> ChatFn:
        return openai_chat_fn(
            self.base_url, self.model,
            api_key=self.api_key, timeout=self.timeout, max_tokens=self.max_tokens,
        )


def _float(env: Mapping[str, str], key: str, default: float) -> float:
    try:
        return float(env[key])
    except (KeyError, ValueError):
        return default


def _int_or_none(env: Mapping[str, str], key: str, default: Optional[int]) -> Optional[int]:
    raw = env.get(key)
    if raw is None:
        return default
    if raw.strip() in ("", "0", "none"):
        return None
    try:
        return int(raw)
    except ValueError:
        return default


def resolve_tiers(env: Mapping[str, str]) -> list[Endpoint]:
    """env → 시도 순서대로 정렬된 endpoint 목록(순수 함수).

    앞이 primary(큰 모델, 내부망→외부망), 뒤가 fallback(7B). DISABLE 이면 빈 목록.
    """
    if env.get("VIBECUTTER_LLM_DISABLE", "").strip() in ("1", "true", "yes"):
        return []

    raw = env.get("VIBECUTTER_LLM_ENDPOINTS")
    urls: Sequence[str]
    if raw is None:
        urls = DEFAULT_PRIMARY_ENDPOINTS
    else:
        urls = [u.strip() for u in raw.split(",") if u.strip()]

    api_key = env.get("VIBECUTTER_LLM_API_KEY") or None
    model = env.get("VIBECUTTER_LLM_MODEL", DEFAULT_PRIMARY_MODEL)
    timeout = _float(env, "VIBECUTTER_LLM_TIMEOUT", DEFAULT_PRIMARY_TIMEOUT)
    max_tokens = _int_or_none(env, "VIBECUTTER_LLM_MAX_TOKENS", DEFAULT_PRIMARY_MAX_TOKENS)

    tiers = [
        Endpoint(base_url=u, model=model, timeout=timeout, api_key=api_key,
                 max_tokens=max_tokens, tier="primary")
        for u in urls
    ]

    fb_url = (env.get("VIBECUTTER_LLM_FALLBACK_ENDPOINT")
              or env.get("VIBECUTTER_MODEL_ENDPOINT") or "").strip()
    if fb_url:
        fb_model = (env.get("VIBECUTTER_LLM_FALLBACK_MODEL")
                    or env.get("VIBECUTTER_MODEL_NAME") or DEFAULT_FALLBACK_MODEL)
        tiers.append(Endpoint(
            base_url=fb_url, model=fb_model,
            timeout=_float(env, "VIBECUTTER_LLM_FALLBACK_TIMEOUT", DEFAULT_FALLBACK_TIMEOUT),
            api_key=env.get("VIBECUTTER_LLM_FALLBACK_API_KEY") or None,
            tier="fallback",
        ))
    return tiers


def _with_max_tokens(tiers: Sequence[Endpoint], max_tokens: Optional[int]) -> list[Endpoint]:
    """override 가 주어지면 모든 tier 의 `max_tokens` 를 그것으로 교체한다.

    rerank 는 인덱스 나열이면 충분해 env 기본(512)을 쓰지만, 패치 합성은 diff 본문에
    (qwen3 는 `<think>` 사고까지) 더 많은 토큰이 필요하다. 그 용도에서 큰 예산을 주입한다.
    """
    if max_tokens is None:
        return list(tiers)
    return [replace(t, max_tokens=max_tokens) for t in tiers]


def _prepared_tiers(
    env: Optional[Mapping[str, str]], *,
    precheck: bool, precheck_timeout: float, max_tokens: Optional[int],
) -> list[Endpoint]:
    """env → (max_tokens override + precheck 통과) 최종 tier 목록. 살아있는 게 없으면 []."""
    tiers = _with_max_tokens(resolve_tiers(os.environ if env is None else env), max_tokens)
    if precheck:
        tiers = [t for t in tiers if liveness_check(t.base_url, timeout=precheck_timeout)]
    return tiers


def chat_fn_from_env(
    env: Optional[Mapping[str, str]] = None, *,
    precheck: bool = True, precheck_timeout: float = 3.0,
    max_tokens: Optional[int] = None,
) -> Optional[ChatFn]:
    """env 로 구성한 티어 체인 ChatFn. 쓸 endpoint 가 없으면 None.

    `precheck` 는 구성 시점에 **한 번** 각 tier 의 `GET /health` 를 짧은 timeout 으로 찔러
    죽은 endpoint 를 체인에서 뺀다. 이게 없으면 endpoint 가 전부 안 붙는 환경(CI·오프라인)에서
    primary timeout(600s)만큼 통째로 멈춘다 — 3초 probe 한 번이 그걸 막는다. 살아있는 게
    하나도 없으면 None 을 돌려 호출측이 휴리스틱으로 진행하게 한다.

    `max_tokens` override(선택): 주어지면 모든 tier 의 응답 토큰 상한을 그것으로 바꾼다.
    패치 합성처럼 rerank 기본(512)보다 긴 출력이 필요할 때 쓴다(`model.patch_client`).

    체인 자체가 호출 실패를 다음 tier 로 흘려보내므로, probe 이후에 primary 가 느려지거나
    죽어도 fallback 은 그대로 동작한다. **어느 tier 가 답했는지 기록**하려면
    `observed_chat_fn_from_env` 를 쓴다(T-1).
    """
    tiers = _prepared_tiers(
        env, precheck=precheck, precheck_timeout=precheck_timeout, max_tokens=max_tokens)
    if not tiers:
        return None
    return make_chained_chat_fn([t.chat_fn() for t in tiers])


# --- T-1: 조용한 degrade 관측 (어느 tier 가 답했나 / LLM 이 실제로 쓰였나) -----------------

@dataclass(frozen=True)
class LlmCallOutcome:
    """LLM 호출 한 번의 결과. degrade 가 로그·run 메타에 드러나게 하는 근거(T-1/T-2)."""

    llm_used: bool                    # LLM 이 실제로 답을 줬는가(전 tier 실패면 False)
    tier: str                         # "primary" | "fallback" | "none"
    tier_index: Optional[int] = None  # 답한 endpoint 인덱스(전체 실패면 None)
    error: Optional[str] = None       # 전체 실패 시 마지막 예외 타입명

    @classmethod
    def unavailable(cls, error: Optional[str] = None) -> "LlmCallOutcome":
        """호출 안 됨/전 tier 실패 → 휴리스틱으로 진행한 run 을 표시한다."""
        return cls(llm_used=False, tier="none", tier_index=None, error=error)

    def as_metadata(self) -> dict:
        """trajectory step `result` dict 에 담을 형태(T-2 — schemas freeze 우회)."""
        return {
            "llm_used": self.llm_used,
            "tier": self.tier,
            "tier_index": self.tier_index,
            "endpoint_health": "up" if self.llm_used else "down",
            **({"llm_error": self.error} if self.error else {}),
        }


def make_observed_chain(
    chat_fns: Sequence[ChatFn], tier_labels: Sequence[str],
) -> tuple[ChatFn, Callable[[], LlmCallOutcome]]:
    """관측 가능한 체인 ChatFn + `recorder()`. 호출 뒤 recorder() 가 마지막 결과를 준다.

    `make_chained_chat_fn` 의 fallback 의미(빈 응답=실패 포함)를 그대로 쓰되, `on_fallback` 이
    **실패한 tier 마다 정확히 1번** 불리는 성질을 이용해 '몇 번째 tier 가 답했는가'를 복원한다:
    성공 시 답한 index == 그때까지 쌓인 실패 이벤트 수. (전 tier 실패면 예외 → llm_used=False.)

    주의: recorder 는 **마지막 호출** 상태다. run 내 순차 호출(rerank 1회, patch n회)을 전제로 한다
    (driver 는 target 당 순차 — TEAM_CONTRACT 3A-8). 병렬 호출은 이 인스턴스를 공유하지 말 것.
    """
    if len(chat_fns) != len(tier_labels):
        raise ValueError("chat_fns 와 tier_labels 길이가 다르다")
    failures: list[int] = []
    state: dict = {"outcome": LlmCallOutcome.unavailable()}
    chain = make_chained_chat_fn(
        list(chat_fns), on_fallback=lambda i, exc: failures.append(i))

    def chat(messages: list[dict]) -> str:
        failures.clear()
        try:
            text = chain(messages)
        except Exception as exc:  # 전 tier 실패 — 호출측이 휴리스틱으로 degrade.
            state["outcome"] = LlmCallOutcome.unavailable(error=type(exc).__name__)
            raise
        idx = len(failures)  # 실패는 0..idx-1 에서 났고, idx 에서 성공했다.
        state["outcome"] = LlmCallOutcome(
            llm_used=True, tier=tier_labels[idx], tier_index=idx)
        return text

    return chat, (lambda: state["outcome"])


def observed_chat_fn_from_env(
    env: Optional[Mapping[str, str]] = None, *,
    precheck: bool = True, precheck_timeout: float = 3.0,
    max_tokens: Optional[int] = None,
) -> Optional[tuple[ChatFn, Callable[[], LlmCallOutcome]]]:
    """`chat_fn_from_env` 와 같되 (chat_fn, recorder) 를 돌려준다. endpoint 없으면 None.

    호출측(P1 rerank 배선)은 chat_fn 을 `make_rerank_fn` 에 넣고, aggregate 뒤 `recorder()` 로
    얻은 `LlmCallOutcome.as_metadata()` 를 trajectory step `result` 에 기록한다(T-2). None 이면
    LLM 없이 휴리스틱으로 돈 run → `LlmCallOutcome.unavailable().as_metadata()` 로 표시한다.
    """
    tiers = _prepared_tiers(
        env, precheck=precheck, precheck_timeout=precheck_timeout, max_tokens=max_tokens)
    if not tiers:
        return None
    return make_observed_chain([t.chat_fn() for t in tiers], [t.tier for t in tiers])


def probe(env: Optional[Mapping[str, str]] = None, *, timeout: float = 5.0) -> list[tuple[Endpoint, bool]]:
    """각 tier 의 `GET /health` 도달성을 확인한다(인증 불필요). 진단·기동 점검용."""
    tiers = resolve_tiers(os.environ if env is None else env)
    return [(t, liveness_check(t.base_url, timeout=timeout)) for t in tiers]


def _main() -> None:
    """`python -m model.endpoints` → 현재 env 로 구성될 티어와 도달성을 출력."""
    results = probe()
    if not results:
        print("LLM endpoint 없음 (VIBECUTTER_LLM_DISABLE 이거나 endpoints 비어 있음)")
        return
    for endpoint, alive in results:
        mark = "UP  " if alive else "DOWN"
        key = "key:yes" if endpoint.api_key else "key:no "
        print(f"[{mark}] {endpoint.tier:8s} {endpoint.base_url}  "
              f"model={endpoint.model} timeout={endpoint.timeout:g}s {key}")


if __name__ == "__main__":
    _main()
