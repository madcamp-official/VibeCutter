"""scanners.vocab 단위 테스트. 실행: python -m scanners.test_vocab"""

from __future__ import annotations

from contracts.schemas import Candidate
from scanners.vocab import (
    OWASP_2021,
    SEVERITY,
    candidate_owasp,
    candidate_severity,
    normalize_owasp,
    normalize_severity,
)


def test_normalize_severity_both_vocabs() -> None:
    assert normalize_severity("ERROR") == "high"       # semgrep
    assert normalize_severity("WARNING") == "medium"
    assert normalize_severity("INFO") == "info"
    assert normalize_severity("CRITICAL") == "critical"  # sca
    assert normalize_severity("MODERATE") == "medium"
    assert normalize_severity("bogus") is None
    assert normalize_severity(None, default="info") == "info"
    assert all(v in SEVERITY for v in ["critical", "high", "medium", "low", "info"])


def test_normalize_owasp_extracts_code() -> None:
    assert normalize_owasp("A03:2021 - Injection") == "A03:2021"
    assert normalize_owasp("A03:2021") == "A03:2021"
    assert normalize_owasp("not-owasp") is None
    assert normalize_owasp(None) is None
    assert set(OWASP_2021) >= {"A01:2021", "A03:2021", "A06:2021"}


def test_candidate_severity_from_signal() -> None:
    c = Candidate(id="x", run_id="r", signals=["semgrep:rule", "severity:ERROR"])
    assert candidate_severity(c) == "high"
    sca = Candidate(id="y", run_id="r", signals=["sca:osv", "severity:CRITICAL"])
    assert candidate_severity(sca) == "critical"
    none = Candidate(id="z", run_id="r", signals=["semgrep:rule"])
    assert candidate_severity(none) is None


def test_candidate_owasp_signal_then_focus_fallback() -> None:
    # owasp signal 우선
    c = Candidate(id="a", run_id="r", signals=["owasp:A03:2021 - Injection", "focus:idor"])
    assert candidate_owasp(c) == "A03:2021"
    # owasp 없으면 focus 로 추론
    idor = Candidate(id="b", run_id="r", signals=["focus:idor"])
    assert candidate_owasp(idor) == "A01:2021"    # Broken Access Control
    xss = Candidate(id="c", run_id="r", signals=["focus:xss"])
    assert candidate_owasp(xss) == "A03:2021"
    # 둘 다 없으면 None
    assert candidate_owasp(Candidate(id="d", run_id="r", signals=["category:sca"])) is None


def _run() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")


if __name__ == "__main__":
    _run()
