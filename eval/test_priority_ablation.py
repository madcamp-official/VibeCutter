"""eval.priority_ablation 단위 테스트 (E-1). 실행: python -m eval.test_priority_ablation"""

from __future__ import annotations

from contracts.schemas import Candidate
from eval.priority_ablation import (
    compare_by_class,
    compare_orderings,
    first_true_rank,
    is_true,
    reciprocal_rank,
)


def _c(cid: str, focus: str) -> Candidate:
    return Candidate(id=cid, run_id="r", vuln_class=focus, confidence=0.5,
                     source_symbols=[f"{cid}.py:1"], signals=[f"focus:{focus}"])


def test_is_true_matches_focus_against_truth() -> None:
    assert is_true(_c("a", "idor"), {"idor", "xss"})
    assert not is_true(_c("a", "xss"), {"idor"})


def test_first_true_rank_and_reciprocal() -> None:
    ordered = [_c("a", "xss"), _c("b", "idor"), _c("c", "injection")]  # 참(idor)은 2위
    assert first_true_rank(ordered, {"idor"}) == 2
    assert reciprocal_rank(ordered, {"idor"}) == 0.5


def test_no_true_candidate_yields_none_and_zero() -> None:
    ordered = [_c("a", "xss"), _c("b", "injection")]
    assert first_true_rank(ordered, {"idor"}) is None
    assert reciprocal_rank(ordered, {"idor"}) == 0.0


def test_compare_orderings_rewards_higher_true_rank() -> None:
    # heuristic: 참(idor)이 3위 / rag-llm: 참이 1위로 올라감 → rag-llm MRR 이 더 높다.
    heuristic = {"app1": [_c("x", "xss"), _c("y", "injection"), _c("z", "idor")]}
    ragllm = {"app1": [_c("z", "idor"), _c("x", "xss"), _c("y", "injection")]}
    truth = {"app1": {"idor"}}
    rep = compare_orderings(heuristic, ragllm, truth)
    assert rep.heuristic_mrr == 1 / 3
    assert rep.ragllm_mrr == 1.0
    assert rep.mrr_delta > 0
    assert rep.improved_apps() == ["app1"]


def test_compare_ignores_apps_without_truth() -> None:
    heuristic = {"app1": [_c("a", "idor")], "app2": [_c("b", "xss")]}
    ragllm = {"app1": [_c("a", "idor")], "app2": [_c("b", "xss")]}
    truth = {"app1": {"idor"}}  # app2 는 정답 없음 → 제외
    rep = compare_orderings(heuristic, ragllm, truth)
    assert [a.app_id for a in rep.per_app] == ["app1"]


def test_render_contains_mrr_and_delta() -> None:
    rep = compare_orderings(
        {"app1": [_c("z", "idor")]}, {"app1": [_c("z", "idor")]}, {"app1": {"idor"}})
    out = rep.render()
    assert "MRR" in out and "Δ" in out


def test_compare_by_class_breaks_out_injection_and_xss() -> None:
    # M1: injection·xss 를 클래스별로. heuristic은 injection 참을 2위, rag-llm은 1위로.
    heuristic = {
        "app1": [_c("x", "xss"), _c("i", "injection")],   # injection 참 2위
        "app2": [_c("y", "xss"), _c("z", "idor")],        # xss 참 1위
    }
    ragllm = {
        "app1": [_c("i", "injection"), _c("x", "xss")],   # injection 참 1위로 개선
        "app2": [_c("y", "xss"), _c("z", "idor")],
    }
    truth = {"app1": {"injection"}, "app2": {"xss"}}
    by_class = compare_by_class(heuristic, ragllm, truth)
    assert set(by_class) == {"injection", "xss"}          # idor 는 truth 에 없어 제외
    assert by_class["injection"].mrr_delta > 0            # injection 순위 개선 잡힘
    assert by_class["xss"].heuristic_mrr == 1.0           # xss 는 이미 1위


def _run() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")


if __name__ == "__main__":
    _run()
