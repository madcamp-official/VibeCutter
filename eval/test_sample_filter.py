"""eval.sample_filter 단위 테스트 (T-3). 실행: python -m eval.test_sample_filter"""

from __future__ import annotations

from eval.sample_filter import FilteredSample, filter_llm_condition, llm_used_map
from model.trajectory import RunLlmUsage


def _usage(run_id, calls, used, tiers) -> RunLlmUsage:
    return RunLlmUsage(run_id=run_id, calls=calls, used=used, tiers=tiers)


def test_llm_used_map_all_policy_is_conservative() -> None:
    usage = {
        "app-clean": _usage("app-clean", 2, 2, ("primary", "primary")),
        "app-degraded": _usage("app-degraded", 2, 1, ("primary", "none")),
    }
    m = llm_used_map(usage, policy="all")
    assert m == {"app-clean": True, "app-degraded": False}  # degrade 섞이면 제외


def test_llm_used_map_any_policy_is_loose() -> None:
    usage = {"app-degraded": _usage("app-degraded", 2, 1, ("primary", "none"))}
    assert llm_used_map(usage, policy="any") == {"app-degraded": True}


def test_llm_used_map_rejects_bad_policy() -> None:
    try:
        llm_used_map({}, policy="sometimes")
    except ValueError:
        pass
    else:
        raise AssertionError("잘못된 policy 는 ValueError 여야 한다")


def test_filter_keeps_only_llm_backed_predictions() -> None:
    preds = {"a": {"injection"}, "b": {"xss"}, "c": {"idor"}}
    used = {"a": True, "b": False, "c": True}
    res = filter_llm_condition(preds, used)
    assert isinstance(res, FilteredSample)
    assert set(res.kept) == {"a", "c"} and res.excluded == ["b"]


def test_filter_excludes_keys_missing_usage_info() -> None:
    # usage 에 없는 키는 'LLM 조건'으로 신뢰 불가 → 보수적으로 제외.
    preds = {"a": {"injection"}, "b": {"xss"}}
    res = filter_llm_condition(preds, {"a": True})
    assert set(res.kept) == {"a"} and res.excluded == ["b"]


def test_filtered_sample_note_reports_exclusions() -> None:
    res = filter_llm_condition({"a": {"x"}, "b": {"y"}}, {"a": True, "b": False})
    assert "제외" in res.note and "b" in res.note
    clean = filter_llm_condition({"a": {"x"}}, {"a": True})
    assert "제외 0" in clean.note


def test_end_to_end_usage_to_filter() -> None:
    # 판독기 → 필터 파이프라인이 키 기준으로 맞물리는지(run_id == 예측 키 가정).
    usage = {"rA": _usage("rA", 1, 1, ("primary",)), "rB": _usage("rB", 1, 0, ("none",))}
    preds = {"rA": {"idor"}, "rB": {"idor"}}
    res = filter_llm_condition(preds, llm_used_map(usage, policy="all"))
    assert set(res.kept) == {"rA"} and res.excluded == ["rB"]


def _run() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")


if __name__ == "__main__":
    _run()
