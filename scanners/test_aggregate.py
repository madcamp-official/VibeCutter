"""scanners.aggregate 단위 테스트. 실행: python -m scanners.test_aggregate"""

from __future__ import annotations

from contracts.schemas import Candidate
from scanners.aggregate import (
    aggregate,
    merge_duplicates,
    priority_score,
)


def _c(id, *, loc, focus=None, cwe=None, conf=0.5, tool="semgrep", sev=None) -> Candidate:
    signals = []
    if tool == "semgrep":
        signals.append("semgrep:rule.x")
    elif tool == "sca":
        signals += ["sca:osv", "category:sca"]
    elif tool == "crawl":
        signals.append("crawl:playwright")
    if focus:
        signals.append(f"focus:{focus}")
    if sev:
        signals.append(f"severity:{sev}")
    return Candidate(id=id, run_id="r", cwe=cwe, source_symbols=[loc], confidence=conf, signals=signals)


def test_merge_same_location_focus_cwe() -> None:
    a = _c("a", loc="app/db.py:10", focus="injection", cwe="CWE-89", conf=0.5, tool="semgrep")
    b = _c("b", loc="app/db.py:10", focus="injection", cwe="CWE-89", conf=0.8, tool="crawl")
    merged = merge_duplicates([a, b])
    assert len(merged) == 1
    m = merged[0]
    assert m.confidence == 0.8                       # 최대값
    assert "semgrep:rule.x" in m.signals and "crawl:playwright" in m.signals  # union


def test_different_locations_not_merged() -> None:
    a = _c("a", loc="app/db.py:10", focus="injection")
    b = _c("b", loc="app/db.py:20", focus="injection")
    assert len(merge_duplicates([a, b])) == 2


def test_corroboration_raises_priority() -> None:
    single = _c("a", loc="x.py:1", focus="injection", conf=0.5, tool="semgrep")
    two = merge_duplicates([
        _c("a", loc="y.py:1", focus="injection", conf=0.5, tool="semgrep"),
        _c("b", loc="y.py:1", focus="injection", conf=0.5, tool="crawl"),
    ])[0]
    assert priority_score(two) > priority_score(single)


def test_fp_reject_noncode_paths() -> None:
    good = _c("g", loc="src/app.py:5", focus="xss")
    test_file = _c("t", loc="tests/test_app.py:5", focus="xss")
    vendor = _c("v", loc="node_modules/lib/index.js:1", focus="xss")
    minified = _c("m", loc="static/app.min.js:1", focus="xss")
    res = aggregate([good, test_file, vendor, minified])
    kept_ids = {c.id for c in res.kept}
    assert kept_ids == {"g"}
    reasons = {r for _, r in res.rejected}
    assert reasons == {"non-app-code-path"}


def test_min_confidence_opt_in_reject() -> None:
    low = _c("low", loc="src/a.py:1", focus="xss", conf=0.2, tool="semgrep")
    # 기본(min_confidence=0): 저신뢰라도 유지
    assert "low" in {c.id for c in aggregate([low]).kept}
    # min_confidence=0.3: 단일 도구 + 저신뢰 → reject
    res = aggregate([low], min_confidence=0.3)
    assert "low" not in {c.id for c in res.kept}
    assert res.rejected[0][1].startswith("low-confidence")


def test_min_confidence_keeps_corroborated() -> None:
    # 저신뢰라도 두 도구가 지지하면 유지돼야 한다.
    dup = [
        _c("a", loc="src/a.py:1", focus="xss", conf=0.2, tool="semgrep"),
        _c("b", loc="src/a.py:1", focus="xss", conf=0.2, tool="crawl"),
    ]
    res = aggregate(dup, min_confidence=0.3)
    assert len(res.kept) == 1


def test_kept_sorted_by_priority() -> None:
    lo = _c("lo", loc="a.py:1", focus="xss", conf=0.3)
    hi = _c("hi", loc="b.py:1", focus="xss", conf=0.9, sev="HIGH")
    res = aggregate([lo, hi])
    assert [c.id for c in res.kept] == ["hi", "lo"]


def test_rerank_hook_used() -> None:
    a = _c("a", loc="a.py:1", focus="xss", conf=0.9)
    b = _c("b", loc="b.py:1", focus="xss", conf=0.1)
    # 훅이 역순 정렬을 강제하면 그게 반영돼야 한다.
    res = aggregate([a, b], rerank_fn=lambda ks: sorted(ks, key=lambda c: c.confidence or 0))
    assert [c.id for c in res.kept] == ["b", "a"]


def test_summary_shape() -> None:
    res = aggregate([_c("a", loc="s.py:1", focus="idor"), _c("t", loc="tests/x.py:1", focus="idor")])
    s = res.summary
    assert s["kept"] == 1 and s["rejected"] == 1
    assert s["by_focus"] == {"idor": 1}


def _run() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")


if __name__ == "__main__":
    _run()
