"""eval.reflect_runs 단위 테스트. 실행: python -m eval.test_reflect_runs"""

from __future__ import annotations

import tempfile
from pathlib import Path

from contracts.schemas import RunState
from eval.reflect_runs import load_runtime_metadata, reflect_run, reflect_runs, render
from model.trajectory import TrajectoryRecorder


def _write_traj(d: Path, run_id: str, *, llm_used, tier) -> None:
    TrajectoryRecorder(d / f"{run_id}.jsonl").record_step(
        run_id=run_id, state=RunState.MAPPING, action={},
        result={"llm_used": llm_used, "tier": tier}, next_state=RunState.CANDIDATE_SCAN)


def test_llm_run_is_rag_llm_sample() -> None:
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        _write_traj(d, "run-a", llm_used=True, tier="primary")
        r = reflect_run("run-a", traj_dir=d, runtime_meta={
            "run-a": {"run_id": "run-a", "target_id": "juice-shop", "llm_endpoint_state": "up"}})
        assert r.sample == "rag-llm" and r.trajectory_state == "up"
        assert r.target_id == "juice-shop" and r.consistent


def test_degrade_run_is_excluded() -> None:
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        _write_traj(d, "run-b", llm_used=False, tier="none")
        r = reflect_run("run-b", traj_dir=d, runtime_meta={
            "run-b": {"run_id": "run-b", "llm_endpoint_state": "down"}})
        assert r.sample == "excluded" and r.trajectory_state == "down" and r.consistent


def test_no_trajectory_is_unknown() -> None:
    with tempfile.TemporaryDirectory() as td:
        r = reflect_run("run-missing", traj_dir=Path(td), runtime_meta={})
        assert r.sample == "unknown" and r.trajectory_state == "unknown"


def test_p2_mismatch_flags_inconsistent() -> None:
    # 내 trajectory는 up인데 P2가 down이라 기록 → 배선/데이터 오류 신호.
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        _write_traj(d, "run-c", llm_used=True, tier="primary")
        r = reflect_run("run-c", traj_dir=d, runtime_meta={
            "run-c": {"run_id": "run-c", "llm_endpoint_state": "down"}})
        assert r.trajectory_state == "up" and r.p2_state == "down"
        assert r.consistent is False


def test_missing_p2_metadata_is_treated_consistent() -> None:
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        _write_traj(d, "run-d", llm_used=True, tier="primary")
        r = reflect_run("run-d", traj_dir=d, runtime_meta={})  # P2 값 없음
        assert r.p2_state is None and r.consistent  # 대조 불가 → OK 취급


def test_load_runtime_metadata_last_record_wins() -> None:
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "rt.jsonl"
        p.write_text(
            '{"run_id":"r1","llm_endpoint_state":"down"}\n'
            '{"run_id":"r1","llm_endpoint_state":"up"}\n'
            'not-json\n', encoding="utf-8")
        meta = load_runtime_metadata(p)
        assert meta["r1"]["llm_endpoint_state"] == "up"  # 마지막이 이김, 깨진 줄 무시


def test_render_summarizes_counts() -> None:
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        _write_traj(d, "run-x", llm_used=True, tier="primary")
        _write_traj(d, "run-y", llm_used=False, tier="none")
        out = render(reflect_runs(["run-x", "run-y"], traj_dir=d, runtime_meta={}))
        assert "rag-llm(235B) 표본: 1" in out and "제외(degrade): 1" in out


def _run() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")


if __name__ == "__main__":
    _run()
