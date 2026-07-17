"""eval.baseline 단위 테스트. 실행: python -m eval.test_baseline"""

from __future__ import annotations

from contracts.schemas import Candidate
from eval.baseline import (
    Confusion,
    evaluate,
    focus_set_from_candidates,
    vuln_tokens_to_focus,
)


def test_vuln_tokens_map_to_three_groups() -> None:
    assert vuln_tokens_to_focus(["sqli", "nosqli", "cmdi"]) == {"injection"}
    assert vuln_tokens_to_focus(["xss"]) == {"xss"}
    assert vuln_tokens_to_focus(["bola", "idor"]) == {"idor"}
    # scope 밖 토큰은 버린다.
    assert vuln_tokens_to_focus(["auth", "ssrf", "csrf"]) == set()
    assert vuln_tokens_to_focus(["sqli", "xss", "auth"]) == {"injection", "xss"}


def test_focus_set_from_candidates() -> None:
    cands = [
        Candidate(id="a", run_id="r", signals=["semgrep:x", "focus:xss"]),
        Candidate(id="b", run_id="r", signals=["focus:injection"]),
        Candidate(id="c", run_id="r", signals=["category:sca"]),  # focus 없음
    ]
    assert focus_set_from_candidates(cands) == {"xss", "injection"}


def test_confusion_metrics() -> None:
    c = Confusion(tp=3, fp=1, fn=2, tn=4)
    assert round(c.precision, 3) == 0.75
    assert round(c.recall, 3) == 0.6
    assert round(c.fpr, 3) == 0.2
    assert round(c.benchmark_score, 3) == 0.4  # 0.6 - 0.2


def test_evaluate_perfect_detector() -> None:
    truth = {"a": {"idor", "xss"}, "b": {"injection"}}
    report = evaluate(dict(truth), truth)
    assert report.overall.fp == 0 and report.overall.fn == 0
    assert report.overall.precision == 1.0 and report.overall.recall == 1.0


def test_evaluate_counts_cells_over_three_groups() -> None:
    truth = {"a": {"idor"}}                       # 3 cells: idor=T, injection=F, xss=F
    pred = {"a": {"idor", "xss"}}                 # idor TP, xss FP, injection TN
    report = evaluate(pred, truth)
    o = report.overall
    assert (o.tp, o.fp, o.fn, o.tn) == (1, 1, 0, 1)
    assert report.per_group["idor"].tp == 1
    assert report.per_group["xss"].fp == 1
    assert report.per_group["injection"].tn == 1


def test_evaluate_missing_prediction_is_all_negative() -> None:
    truth = {"a": {"injection"}}
    report = evaluate({}, truth)   # 예측 없음 → injection FN, 나머지 TN
    assert report.overall.fn == 1
    assert report.overall.tp == 0


def _run() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")


if __name__ == "__main__":
    _run()
