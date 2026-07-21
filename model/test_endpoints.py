"""model.endpoints / 티어 fallback 단위 테스트 (네트워크 불필요).

실행: python -m model.test_endpoints
"""

from __future__ import annotations

from model.endpoints import (
    DEFAULT_FALLBACK_MODEL,
    DEFAULT_PRIMARY_ENDPOINTS,
    DEFAULT_PRIMARY_MODEL,
    LlmCallOutcome,
    _with_max_tokens,
    make_observed_chain,
    resolve_tiers,
)
from model.serving import make_chained_chat_fn, strip_reasoning


def test_defaults_are_internal_then_external_primary() -> None:
    tiers = resolve_tiers({})
    assert [t.base_url for t in tiers] == list(DEFAULT_PRIMARY_ENDPOINTS)
    assert all(t.tier == "primary" and t.model == DEFAULT_PRIMARY_MODEL for t in tiers)
    assert all(t.timeout == 600.0 for t in tiers)      # 7.7 tok/s → 긴 timeout


def test_fallback_appended_last_with_own_model_and_timeout() -> None:
    tiers = resolve_tiers({
        "VIBECUTTER_LLM_ENDPOINTS": "http://a:8080/v1",
        "VIBECUTTER_LLM_FALLBACK_ENDPOINT": "http://127.0.0.1:8000/v1",
    })
    assert [t.tier for t in tiers] == ["primary", "fallback"]
    fb = tiers[-1]
    assert fb.model == DEFAULT_FALLBACK_MODEL and fb.timeout == 60.0


def test_legacy_model_endpoint_env_maps_to_fallback() -> None:
    # 기존 VIBECUTTER_MODEL_ENDPOINT 는 로컬 7B 를 가리키던 변수 → fallback 자리로.
    tiers = resolve_tiers({
        "VIBECUTTER_MODEL_ENDPOINT": "http://127.0.0.1:8000/v1",
        "VIBECUTTER_MODEL_NAME": "legacy-7b",
    })
    assert tiers[-1].tier == "fallback"
    assert tiers[-1].base_url == "http://127.0.0.1:8000/v1"
    assert tiers[-1].model == "legacy-7b"


def test_api_key_and_overrides_applied() -> None:
    tiers = resolve_tiers({
        "VIBECUTTER_LLM_ENDPOINTS": " http://a:8080/v1 , http://b:8080/v1 ",
        "VIBECUTTER_LLM_API_KEY": "sk-x",
        "VIBECUTTER_LLM_MODEL": "qwen3-235b",
        "VIBECUTTER_LLM_TIMEOUT": "120",
        "VIBECUTTER_LLM_MAX_TOKENS": "64",
    })
    assert [t.base_url for t in tiers] == ["http://a:8080/v1", "http://b:8080/v1"]
    assert all(t.api_key == "sk-x" and t.timeout == 120.0 and t.max_tokens == 64 for t in tiers)


def test_disable_yields_no_tiers() -> None:
    assert resolve_tiers({"VIBECUTTER_LLM_DISABLE": "1"}) == []


def test_max_tokens_override_replaces_all_tiers() -> None:
    # 패치 합성은 rerank 기본(512)보다 큰 예산이 필요 → 모든 tier(primary+fallback)에 주입.
    tiers = resolve_tiers({
        "VIBECUTTER_LLM_ENDPOINTS": "http://a:8080/v1",
        "VIBECUTTER_LLM_MAX_TOKENS": "512",
        "VIBECUTTER_LLM_FALLBACK_ENDPOINT": "http://127.0.0.1:8000/v1",
    })
    assert [t.max_tokens for t in _with_max_tokens(tiers, 2048)] == [2048, 2048]
    assert _with_max_tokens(tiers, None) == tiers  # override 없으면 그대로(비파괴)


def test_bad_numbers_fall_back_to_defaults() -> None:
    tiers = resolve_tiers({"VIBECUTTER_LLM_TIMEOUT": "not-a-number"})
    assert tiers[0].timeout == 600.0


def test_chain_uses_primary_when_it_answers() -> None:
    calls = []
    chain = make_chained_chat_fn([
        lambda m: (calls.append("big"), "1,0")[1],
        lambda m: (calls.append("7b"), "0,1")[1],
    ])
    assert chain([]) == "1,0" and calls == ["big"]


def test_chain_falls_back_when_primary_raises() -> None:
    def dead(m):
        raise TimeoutError("too slow")

    calls = []
    chain = make_chained_chat_fn([dead, lambda m: (calls.append("7b"), "0,1")[1]])
    assert chain([]) == "0,1" and calls == ["7b"]


def test_chain_falls_back_on_empty_completion() -> None:
    # 빈 응답을 성공으로 치면 rerank 가 항등 순열로 삼켜 fallback 기회를 잃는다.
    chain = make_chained_chat_fn([lambda m: "   ", lambda m: "2,1,0"])
    assert chain([]) == "2,1,0"


def test_chain_raises_when_every_tier_fails() -> None:
    def dead(m):
        raise ConnectionError("down")

    try:
        make_chained_chat_fn([dead, dead])([])
    except ConnectionError:
        pass
    else:
        raise AssertionError("모든 tier 실패 시 예외가 올라와야 한다")


def test_chain_reports_fallback_events() -> None:
    seen = []
    chain = make_chained_chat_fn(
        [lambda m: (_ for _ in ()).throw(TimeoutError("slow")), lambda m: "ok"],
        on_fallback=lambda i, exc: seen.append((i, type(exc).__name__)),
    )
    assert chain([]) == "ok" and seen == [(0, "TimeoutError")]


def _dead(_m):
    raise TimeoutError("slow")


def test_observed_chain_records_primary_when_it_answers() -> None:
    chat, rec = make_observed_chain([lambda m: "ok", lambda m: "fb"], ["primary", "fallback"])
    assert chat([]) == "ok"
    out = rec()
    assert out == LlmCallOutcome(llm_used=True, tier="primary", tier_index=0)


def test_observed_chain_records_fallback_when_primary_raises() -> None:
    chat, rec = make_observed_chain([_dead, lambda m: "fb"], ["primary", "fallback"])
    assert chat([]) == "fb"
    assert rec() == LlmCallOutcome(llm_used=True, tier="fallback", tier_index=1)


def test_observed_chain_counts_empty_completion_as_failure() -> None:
    # 빈 응답은 실패로 쳐서 fallback 이 답한다 → 답한 tier 는 fallback(1)이어야 한다.
    chat, rec = make_observed_chain([lambda m: "   ", lambda m: "fb"], ["primary", "fallback"])
    assert chat([]) == "fb"
    assert rec().tier == "fallback" and rec().tier_index == 1


def test_observed_chain_marks_unavailable_when_all_tiers_fail() -> None:
    chat, rec = make_observed_chain([_dead, _dead], ["primary", "fallback"])
    try:
        chat([])
    except TimeoutError:
        pass
    else:
        raise AssertionError("전 tier 실패 시 예외가 올라와야 한다")
    out = rec()
    assert out.llm_used is False and out.tier == "none" and out.error == "TimeoutError"


def test_observed_recorder_defaults_to_unavailable_before_any_call() -> None:
    _, rec = make_observed_chain([lambda m: "ok"], ["primary"])
    assert rec().llm_used is False and rec().tier == "none"


def test_outcome_as_metadata_shape() -> None:
    up = LlmCallOutcome(llm_used=True, tier="primary", tier_index=0).as_metadata()
    assert up == {"llm_used": True, "tier": "primary", "tier_index": 0, "endpoint_health": "up"}
    down = LlmCallOutcome.unavailable(error="ConnectionError").as_metadata()
    assert down["llm_used"] is False and down["endpoint_health"] == "down"
    assert down["llm_error"] == "ConnectionError"


def test_strip_reasoning_removes_think_block() -> None:
    # qwen3 의 사고 과정에 섞인 숫자가 rerank 순열을 오염시키면 안 된다.
    assert strip_reasoning("<think>maybe 7 or 9</think>\n1,0") == "1,0"
    assert strip_reasoning("1,0") == "1,0"
    assert strip_reasoning("<think>잘린 출력") == ""            # 닫히지 않은 블록


def _run() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")


if __name__ == "__main__":
    _run()
