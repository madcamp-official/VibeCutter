"""model.patch_client 단위 테스트 (네트워크 불필요). 실행: python -m model.test_patch_client

_ChatPatchClient 는 주입된 fake ChatFn 으로, build_* 는 env 만으로 검증한다 —
precheck=False 또는 endpoint 없음/DISABLE 경로만 써서 실제 소켓을 열지 않는다.
"""

from __future__ import annotations

from model.patch_client import (
    DEFAULT_PATCH_MAX_TOKENS,
    _ChatPatchClient,
    build_patch_model_client,
    resolve_patch_max_tokens,
)


def test_synthesize_wraps_prompt_in_single_user_message() -> None:
    seen: dict = {}

    def fake_chat(messages):
        seen["messages"] = messages
        return "```diff\n--- a/x\n+++ b/x\n@@ -1 +1,2 @@\n x\n+y\n```"

    out = _ChatPatchClient(fake_chat).synthesize_patch("PROMPT-TEXT")
    assert seen["messages"] == [{"role": "user", "content": "PROMPT-TEXT"}]  # 정확히 1개, user
    assert "diff" in out


def test_synthesize_returns_model_text_verbatim() -> None:
    # 원문을 손대지 않는다(diff 파싱은 P3 parse_diffs 몫).
    assert _ChatPatchClient(lambda m: "RAW-COMPLETION").synthesize_patch("p") == "RAW-COMPLETION"


def test_build_returns_none_when_llm_disabled() -> None:
    assert build_patch_model_client({"VIBECUTTER_LLM_DISABLE": "1"}) is None


def test_build_returns_none_when_no_endpoints() -> None:
    # DISABLE 은 아니지만 endpoints 가 비면 tiers 없음 → None (네트워크 접촉 없음).
    assert build_patch_model_client({"VIBECUTTER_LLM_ENDPOINTS": ""}) is None


def test_build_returns_client_when_precheck_off() -> None:
    # precheck=False → liveness 프로브 생략(소켓 X). synthesize_patch 를 부르지 않으면 endpoint 접촉 없음.
    client = build_patch_model_client(
        {"VIBECUTTER_LLM_ENDPOINTS": "http://unused.local:8080/v1"}, precheck=False,
    )
    assert client is not None and hasattr(client, "synthesize_patch")


def test_patch_max_tokens_is_larger_than_rerank_default() -> None:
    assert DEFAULT_PATCH_MAX_TOKENS > 512  # 계약: rerank 기본(512)보다 커야 diff 가 안 잘린다


def test_patch_max_tokens_resolution_order() -> None:
    assert resolve_patch_max_tokens({}) == DEFAULT_PATCH_MAX_TOKENS
    assert resolve_patch_max_tokens({"VIBECUTTER_LLM_PATCH_MAX_TOKENS": "4096"}) == 4096
    assert resolve_patch_max_tokens({"VIBECUTTER_LLM_PATCH_MAX_TOKENS": "4096"}, override=3000) == 3000
    # 파싱 실패·비양수는 안전 기본으로.
    assert resolve_patch_max_tokens({"VIBECUTTER_LLM_PATCH_MAX_TOKENS": "bad"}) == DEFAULT_PATCH_MAX_TOKENS
    assert resolve_patch_max_tokens({"VIBECUTTER_LLM_PATCH_MAX_TOKENS": "0"}) == DEFAULT_PATCH_MAX_TOKENS


def _run() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")


if __name__ == "__main__":
    _run()
