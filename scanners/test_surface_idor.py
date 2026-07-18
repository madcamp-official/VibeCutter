"""scanners.surface_idor 단위 테스트 (앱 실행 불필요, 합성 소스).

실행: python -m scanners.test_surface_idor
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from contracts.schemas import Candidate
from scanners.surface_idor import run_surface_idor

_FASTAPI = """\
from fastapi import FastAPI
app = FastAPI()

@app.get("/users/{user_id}/orders")
def get_orders(user_id: int):
    return db.query(Order).filter(Order.user_id == user_id).all()

@app.get("/health")
def health():
    return {"ok": True}
"""


def _write(src: str) -> Path:
    d = Path(tempfile.mkdtemp())
    (d / "api.py").write_text(src, encoding="utf-8")
    return d


def test_detects_idcandidate_from_path_param() -> None:
    cands = run_surface_idor(_write(_FASTAPI), run_id="r")
    assert len(cands) == 1                          # /health 는 id 없어 제외
    c = cands[0]
    assert isinstance(c, Candidate)
    assert c.vuln_class == "idor" and c.cwe == "CWE-639"
    assert "focus:idor" in c.signals
    assert c.endpoint == "/users/{user_id}/orders"
    assert c.run_id == "r"


def test_signals_carry_surface_provenance() -> None:
    c = run_surface_idor(_write(_FASTAPI), run_id="r")[0]
    assert any(s.startswith("surface:") for s in c.signals)   # path|signature
    assert any(s.startswith("score:") for s in c.signals)


def test_min_score_filters() -> None:
    # score 하한을 아주 높게 주면 전부 컷.
    assert run_surface_idor(_write(_FASTAPI), run_id="r", min_score=99.0) == []


def test_deterministic_ids() -> None:
    src = _write(_FASTAPI)
    a = run_surface_idor(src, run_id="r")
    b = run_surface_idor(src, run_id="r")
    assert [c.id for c in a] == [c.id for c in b]
    assert all(c.id.startswith("cand-surface-") for c in a)


def test_no_handlers_yields_empty() -> None:
    plain = _write("x = 1\ndef f():\n    return 2\n")
    assert run_surface_idor(plain, run_id="r") == []


def _run() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")


if __name__ == "__main__":
    _run()
