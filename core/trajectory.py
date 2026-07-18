"""P4 trajectory 기록 인터페이스로의 얇은 래퍼 + Day4 aggregate export.

D2-P4.md 요청 (a)에 대한 P1 결정: 상태 전이의 label(verified/fixed/rejected/human_review)은
P1 judge 판정 순간에만 확정되므로, P4가 evidence_store에서 사후 조립하지 않고 P1이 각 tool
호출 지점에서 직접 기록한다. `model.trajectory.TrajectoryRecorder`(P4 소유)를 그대로 쓰고,
run별 JSONL 파일 위치 관례만 여기서 고정한다.

`export_training_dataset()`(Day4)은 여러 run에 흩어진 `<run_id>.jsonl`을 P4의 7B QLoRA
배치가 바로 읽을 수 있는 학습 샘플 하나로 묶는다 — 새 필터링/변환 로직을 만들지 않고
P4가 이미 만든 `model.trajectory.training_samples()`(evidence/validation 연결된 스텝만,
cowork_rule 5절)와 `to_sft_sample()`(evidence 조인)을 그대로 재사용한다.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Optional
from uuid import uuid4

from contracts.schemas import Observation, RunState, Trajectory
from core.db import DATA_DIR
from model.trajectory import TrajectoryRecorder, load_trajectories, to_sft_sample, training_samples

TRAJECTORY_DIR = DATA_DIR / "trajectories"
TRAJECTORY_EXPORT_DIR = TRAJECTORY_DIR / "export"
DEFAULT_EXPORT_PATH = TRAJECTORY_EXPORT_DIR / "training_samples.jsonl"


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


def export_training_dataset(
    output_path: Path | str | None = None,
    *,
    run_ids: Sequence[str] | None = None,
) -> Path:
    """여러 run의 trajectory를 모아 P4 학습 배치가 바로 읽을 수 있는 JSONL 하나로 export한다.

    `run_ids`를 지정하지 않으면 `.vibecutter/trajectories/*.jsonl`에 있는 모든 run을 쓴다.
    run마다 `training_samples()`로 evidence/validation이 연결된 스텝만 남기고(label 없는
    스텝은 제외 — raw LLM 주장이 아니라 judge 판정이 붙은 것만 학습에 쓴다는 cowork_rule
    5절 원칙), `to_sft_sample()`로 그 run의 Observation을 evidence로 조인해 한 줄씩 쓴다.

    순환 import 방지를 위해 `core.evidence_store`는 함수 안에서 지연 import한다
    (`evidence_store` → `state_machine`/`redaction`은 이미 있고, 이 모듈이 최상단에서
    `evidence_store`를 끌어오면 향후 `evidence_store`가 trajectory를 참조하게 될 때
    순환이 생기기 쉬워서 여기서만 좁게 연다).
    """
    from core.evidence_store import list_by_run

    output = Path(output_path) if output_path else DEFAULT_EXPORT_PATH
    output.parent.mkdir(parents=True, exist_ok=True)

    if run_ids is None:
        run_ids = sorted(p.stem for p in TRAJECTORY_DIR.glob("*.jsonl"))

    with output.open("w", encoding="utf-8") as f:
        for run_id in run_ids:
            path = TRAJECTORY_DIR / f"{run_id}.jsonl"
            if not path.exists():
                continue
            trajectories = load_trajectories(path)
            observations = list_by_run(Observation, run_id)
            for traj in training_samples(trajectories):
                sample = to_sft_sample(traj, observations=observations)
                f.write(json.dumps(sample, ensure_ascii=False) + "\n")
    return output
