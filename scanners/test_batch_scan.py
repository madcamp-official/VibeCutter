"""scanners.batch_scan 단위 테스트 (git/semgrep 불필요, 주입으로 검증).

실행: python -m scanners.test_batch_scan
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from contracts.schemas import Candidate
from datasets.inventory import AppEntry
from scanners.batch_scan import (
    CLONE_FAILED,
    ERROR,
    SCAN_UNAVAILABLE,
    SCANNED,
    SOURCE_MISSING,
    run_batch,
)


def _app(app_id: str) -> AppEntry:
    return AppEntry(
        id=app_id, name=app_id, repo_url=f"https://example.com/{app_id}.git",
        stack="python", adapter="fastapi", focus=("idor",), expected_vulns=(), verify=True,
    )


def _ok_clone(app, dest):
    dest.mkdir(parents=True, exist_ok=True)
    (dest / ".git").mkdir(exist_ok=True)


def test_scanned_writes_jsonl_and_summary() -> None:
    apps = [_app("a"), _app("b")]

    def scan(app, root, run_id):
        return [Candidate(id=f"c-{app.id}", run_id=run_id, signals=["semgrep:x", "focus:idor"])]

    with tempfile.TemporaryDirectory() as td:
        results = run_batch(apps, td, clone_fn=_ok_clone, scan_fn=scan)
        assert all(r.status == SCANNED and r.n_candidates == 1 for r in results)
        jsonl = Path(td) / "candidates" / "a.candidates.jsonl"
        assert jsonl.exists()
        rec = json.loads(jsonl.read_text(encoding="utf-8").strip())
        assert rec["run_id"] == "batch-a"
        summary = json.loads((Path(td) / "summary.json").read_text(encoding="utf-8"))
        assert summary["n_scanned"] == 2 and summary["n_candidates"] == 2


def test_clone_failure_is_isolated() -> None:
    def bad_clone(app, dest):
        raise RuntimeError("network down")

    def scan(app, root, run_id):
        return []

    with tempfile.TemporaryDirectory() as td:
        results = run_batch([_app("a")], td, clone_fn=bad_clone, scan_fn=scan)
        assert results[0].status == CLONE_FAILED
        assert "network down" in results[0].detail


def test_scanner_unavailable_marked() -> None:
    def scan(app, root, run_id):
        return None  # 스캐너 미설치 신호

    with tempfile.TemporaryDirectory() as td:
        results = run_batch([_app("a")], td, clone_fn=_ok_clone, scan_fn=scan)
        assert results[0].status == SCAN_UNAVAILABLE
        assert results[0].n_candidates == 0


def test_scan_exception_recorded_as_error_and_continues() -> None:
    calls = []

    def scan(app, root, run_id):
        calls.append(app.id)
        if app.id == "a":
            raise ValueError("boom")
        return []

    with tempfile.TemporaryDirectory() as td:
        results = run_batch([_app("a"), _app("b")], td, clone_fn=_ok_clone, scan_fn=scan)
        assert results[0].status == ERROR and "boom" in results[0].detail
        assert results[1].status == SCANNED       # 다음 앱은 계속 진행
        assert calls == ["a", "b"]


def test_p2_source_reuse_scans_without_clone() -> None:
    """source_root_fn 제공 시 clone 없이 그 경로를 스캔한다(P2 소스 재사용)."""
    scanned_paths = []

    def scan(app, root, run_id):
        scanned_paths.append(Path(root))
        return [Candidate(id="c", run_id=run_id, signals=["semgrep:x"])]

    def no_clone(app, dest):
        raise AssertionError("clone 이 호출되면 안 됨")

    with tempfile.TemporaryDirectory() as td:
        p2src = Path(td) / "p2" / "a"
        p2src.mkdir(parents=True)          # P2 가 clone 해둔 소스가 존재
        results = run_batch([_app("a")], Path(td) / "wd",
                            clone_fn=no_clone, scan_fn=scan,
                            source_root_fn=lambda app: Path(td) / "p2" / app.id)
        assert results[0].status == SCANNED
        assert scanned_paths == [p2src]     # P2 경로를 직접 스캔


def test_p2_source_missing_marked() -> None:
    def scan(app, root, run_id):
        raise AssertionError("소스 없으면 scan 안 됨")

    with tempfile.TemporaryDirectory() as td:
        results = run_batch([_app("a")], Path(td) / "wd",
                            scan_fn=scan,
                            source_root_fn=lambda app: Path(td) / "nope" / app.id)
        assert results[0].status == SOURCE_MISSING


def _run() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")


if __name__ == "__main__":
    _run()
