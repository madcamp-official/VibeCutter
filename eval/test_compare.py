"""eval.compare 단위 테스트 (GPU/학습/DB 불필요, 목 BaselineReport).

실행: python -m eval.test_compare
"""

from __future__ import annotations

from eval.baseline import evaluate
from eval.compare import compare


def _report(pred, truth):
    return evaluate(pred, truth)


# 정답: a=idor+injection, b=xss, clean=음성(0건)
_TRUTH = {"a": {"idor", "injection"}, "b": {"xss"}, "clean": set()}


def test_full_beats_base_overall_precision() -> None:
    # base: clean 에 오탐(idor) + b 미탐 / full: 오탐 제거 + b 맞춤
    base = _report({"a": {"idor", "injection"}, "b": set(), "clean": {"idor"}}, _TRUTH)
    full = _report({"a": {"idor", "injection"}, "b": {"xss"}, "clean": set()}, _TRUTH)
    cmp = compare(base, full)
    overall = next(r for r in cmp.rows if r.name == "overall")
    assert overall.delta["precision"] > 0        # 오탐 제거 → precision 상승
    assert overall.delta["recall"] > 0           # b 탐지 → recall 상승


def test_per_app_improved_and_regressed() -> None:
    base = _report({"a": {"idor"}, "b": {"xss"}, "clean": set()}, _TRUTH)
    # full: a 는 injection 추가로 개선, b 는 xss 놓쳐 악화, clean 은 그대로
    full = _report({"a": {"idor", "injection"}, "b": set(), "clean": set()}, _TRUTH)
    cmp = compare(base, full)
    assert cmp.improved_apps() == ["a"]
    assert cmp.regressed_apps() == ["b"]
    assert "clean" not in cmp.per_app             # 변화 없는 앱은 제외


def test_clean_app_false_positive_shows_as_regression() -> None:
    base = _report({"clean": set()}, {"clean": set()})       # 정답: 오탐 없음
    full = _report({"clean": {"idor"}}, {"clean": set()})    # 오탐 발생
    cmp = compare(base, full)
    assert cmp.regressed_apps() == ["clean"]
    overall = cmp.rows[0]
    assert overall.delta["fpr"] > 0               # FPR 악화


def test_render_contains_rows_and_app_lists() -> None:
    base = _report({"a": {"idor"}}, {"a": {"idor", "injection"}})
    full = _report({"a": {"idor", "injection"}}, {"a": {"idor", "injection"}})
    out = compare(base, full).render()
    assert "overall" in out and "idor" in out and "injection" in out
    assert "개선된 앱" in out and "악화된 앱" in out
    assert "TPR-FPR" in out


def _run() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")


if __name__ == "__main__":
    _run()
