"""패치 합성용 LLM 클라이언트 (P4 제공 → P3 어댑터가 소비). TEAM_CONTRACT §3.3 / P4_new_plan C-3.

`repair.llm_synth.PatchModelClient` 프로토콜(`synthesize_patch(prompt: str) -> str`)의 구현체를
env 로 구성해 돌려준다. `model.endpoints.chat_fn_from_env()` 위의 **얇은 래퍼**일 뿐이다:
    프롬프트 문자열 → messages 1개(user) → 티어 체인(235B → 7B fallback) 호출 → 모델 원문.

경계 (여기서 하지 않는 것 — 전부 P3 소유):
- **redaction·injection guard·소스 발췌**: `llm_synth.build_prompt`/`_read_source_excerpt`가
  이미 `core.redaction.redact()` 로 secret 을 지우고 프롬프트를 조립한다. 이 클라이언트는 그
  문자열을 **그대로** 실어 보내고 원문을 **그대로** 돌려준다(전송만).
- **diff 파싱·후보화**: `llm_synth.parse_diffs`/`_to_candidate` 가 한다. 원문을 손대지 않는다.

안전:
- endpoint 가 하나도 안 붙으면 `None` → `make_llm_synthesizer(None)` 이 no-op → template-only 로
  안전 degrade. (안전 불변식 3: **판정엔 LLM 없음** — 이 훅은 '합성' 전용, 6게이트는 결정론적.)
- 모델 출력(diff)은 untrusted 로 취급된다 — apply 는 run-scoped worktree 에만, scope 게이트가
  밖 경로를 차단한다. 이 클라이언트는 그 계약을 바꾸지 않는다.

max_tokens: rerank(512)보다 크게 잡는다. 패치는 diff 본문에 더해 (qwen3) `<think>` 사고까지
생성되므로 예산이 작으면 diff 가 나오기 전에 잘린다. 기본 2048, `VIBECUTTER_LLM_PATCH_MAX_TOKENS`
로 조정한다. (timeout·티어·fallback 은 `model.endpoints` env 계약을 그대로 따른다.)
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Mapping, Optional

from model.endpoints import chat_fn_from_env
from model.serving import ChatFn

if TYPE_CHECKING:  # 런타임 결합 회피(model → repair import 안 함). 구조적 Protocol 이라 충족만 하면 된다.
    from repair.llm_synth import PatchModelClient

# 패치 합성 응답 토큰 상한 기본값. rerank 기본(512)보다 커야 한다(diff + <think> 여유).
DEFAULT_PATCH_MAX_TOKENS = 2048


class _ChatPatchClient:
    """`ChatFn` 을 `PatchModelClient` 프로토콜로 감싼다 — 프롬프트 1개 → 모델 원문."""

    def __init__(self, chat_fn: ChatFn) -> None:
        self._chat = chat_fn

    def synthesize_patch(self, prompt: str) -> str:
        """프롬프트 문자열을 user 메시지 하나로 감싸 호출하고 원문을 그대로 반환한다.

        프롬프트는 P3 `build_prompt` 가 이미 redaction·injection guard·형식 지시를 넣어 만든 것.
        여기서 system 프롬프트를 덧대지 않는다(계약: messages 1개).
        """
        return self._chat([{"role": "user", "content": prompt}])


def resolve_patch_max_tokens(
    env: Optional[Mapping[str, str]] = None, *, override: Optional[int] = None
) -> int:
    """패치용 max_tokens 결정: override > `VIBECUTTER_LLM_PATCH_MAX_TOKENS` > 기본(2048).

    파싱 실패·비양수는 기본값으로 떨어진다(폭주 방지·안전한 기본).
    """
    if override is not None:
        return override
    raw = (os.environ if env is None else env).get("VIBECUTTER_LLM_PATCH_MAX_TOKENS")
    if raw is None:
        return DEFAULT_PATCH_MAX_TOKENS
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_PATCH_MAX_TOKENS
    return value if value > 0 else DEFAULT_PATCH_MAX_TOKENS


def build_patch_model_client(
    env: Optional[Mapping[str, str]] = None, *,
    precheck: bool = True, precheck_timeout: float = 3.0,
    max_tokens: Optional[int] = None,
) -> "Optional[PatchModelClient]":
    """env 로 구성한 `PatchModelClient`. 쓸 endpoint 가 없으면 `None`(→ template-only degrade).

    `chat_fn_from_env` 의 티어 체인·precheck·fallback 계약을 그대로 따르되, 패치에 맞는 큰
    `max_tokens` 를 주입한다. P1 은 이 반환값을 `make_llm_synthesizer(client)` 에 넘겨
    `generate_patch(synthesize_fn=...)` 로 배선한다(그 배선은 P1/P3 소유 — 여기서 하지 않는다).
    """
    chat = chat_fn_from_env(
        env, precheck=precheck, precheck_timeout=precheck_timeout,
        max_tokens=resolve_patch_max_tokens(env, override=max_tokens),
    )
    if chat is None:
        return None
    return _ChatPatchClient(chat)
