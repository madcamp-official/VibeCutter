"""P4 trajectory 기록 인터페이스로의 얇은 래퍼.

D2-P4.md 요청 (a)에 대한 P1 결정: 상태 전이의 label(verified/fixed/rejected/human_review)은
P1 judge 판정 순간에만 확정되므로, P4가 evidence_store에서 사후 조립하지 않고 P1이 각 tool
호출 지점에서 직접 기록한다. `model.trajectory.TrajectoryRecorder`(P4 소유)를 그대로 쓰고,
run별 JSONL 파일 위치 관례만 여기서 고정한다.
"""

from __future__ import annotations

from typing import Optional
from uuid import uuid4

from contracts.schemas import RunState, Trajectory
from core.db import DATA_DIR
from model.trajectory import TrajectoryRecorder

TRAJECTORY_DIR = DATA_DIR / "trajectories"


def record_trajectory_step(
    run_id: str,
    *,
    state: RunState,
    action: dict,
    result: dict,
    next_state: RunState,
    reward: Optional[float] = None,
    label: Optional[str] = None,
) -> Trajectory:
    """run별 `.vibecutter/trajectories/<run_id>.jsonl`에 상태 전이 한 스텝을 append한다."""
    recorder = TrajectoryRecorder(TRAJECTORY_DIR / f"{run_id}.jsonl")
    return recorder.record_step(
        run_id=run_id,
        state=state,
        action=action,
        result=result,
        next_state=next_state,
        reward=reward,
        label=label,
        traj_id=f"{run_id}-step-{uuid4().hex[:8]}",
    )
