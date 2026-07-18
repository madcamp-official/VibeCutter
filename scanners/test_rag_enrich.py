"""scanners.rag_enrich 단위 테스트. 실행: python -m scanners.test_rag_enrich"""

from __future__ import annotations

from pathlib import Path

from contracts.schemas import Candidate
from model.code_index import CodeIndex
from scanners.aggregate import priority_score
from scanners.rag_enrich import enrich, rag_relevance

REPO = Path(__file__).parent.parent / "model" / "testdata" / "sample_repo"


def _index() -> CodeIndex:
    return CodeIndex.build(REPO)


def _cand(loc: str, focus: str, cid="c1") -> Candidate:
    return Candidate(id=cid, run_id="r", source_symbols=[loc],
                     confidence=0.5, signals=[f"focus:{focus}", "semgrep:x"])


def test_chunk_at_finds_containing_chunk() -> None:
    idx = _index()
    c = idx.chunk_at("app/users.py", 5)   # get_user_by_id 근처(SQLi)
    assert c is not None and c.file.endswith("users.py")
    assert c.start_line <= 5 <= c.end_line


def test_enrich_attaches_rag_signals_for_injection() -> None:
    idx = _index()
    # app/users.py:5 는 SQL 문자열 연결 위치 → injection sink 어휘 다수
    cand = _cand("app/users.py:5", "injection")
    [out] = enrich([cand], idx)
    rel = rag_relevance(out)
    assert rel is not None and rel > 0.0            # sink 어휘 매칭됨
    assert any(s.startswith("rag:loc=") for s in out.signals)
    assert any(s.startswith("rag:symbols=") for s in out.signals)


def test_enrich_low_relevance_when_focus_mismatch() -> None:
    idx = _index()
    # 같은 SQL 코드 위치에 xss focus 를 붙이면 xss sink 어휘는 거의 없음
    inj = enrich([_cand("app/users.py:5", "injection", "a")], idx)[0]
    xss = enrich([_cand("app/users.py:5", "xss", "b")], idx)[0]
    assert (rag_relevance(inj) or 0) >= (rag_relevance(xss) or 0)


def test_enrich_noop_when_location_not_indexed() -> None:
    idx = _index()
    cand = _cand("nonexistent/file.py:99", "injection")
    [out] = enrich([cand], idx)
    assert rag_relevance(out) is None               # 매칭 실패 → signal 없음
    assert out.signals == cand.signals              # 비파괴


def test_enrich_noop_when_no_line() -> None:
    idx = _index()
    cand = Candidate(id="x", run_id="r", source_symbols=["app/users.py"],  # 라인 없음
                     signals=["focus:injection"])
    [out] = enrich([cand], idx)
    assert out.signals == cand.signals


def test_rag_relevance_raises_priority() -> None:
    idx = _index()
    base = _cand("app/users.py:5", "injection")
    enriched = enrich([base], idx)[0]
    assert priority_score(enriched) > priority_score(base)   # RAG 보너스로 상승


def _run() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")


if __name__ == "__main__":
    _run()
