"""Trajectory 수집 (P4 소유, D2) — LoRA 학습 데이터의 원자 단위.

기획서 4.5절 학습 샘플, 11.3절 `Trajectory`(state, action, result, next_state,
reward/label), 5일 계획 D2 P4 "trajectory 수집 시작".

파이프라인이 상태를 전이할 때마다 한 스텝(`contracts.schemas.Trajectory`)을 JSONL 로
남긴다. **cowork_rule 5절**: P4 는 raw LLM 주장이 아니라 **evidence·validation 이 연결된
trajectory 만** 학습·평가에 쓴다 → `training_samples(...)` 가 label/reward 없는 스텝을
기본 제외한다.

이 recorder 는 P1 evidence_store/planner 가 상태 전이 시 호출하거나(권장), P4 가 배치
결과에서 사후 조립할 수 있다. 실제 판정(verified/fixed)은 P1 judge 가 하므로 label 은
그 결과를 받아 채운다.

CLI:
    python -m model.trajectory --stats runs/d1/trajectory.jsonl   # 요약
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable, Optional, Sequence

from typing import Sequence

from contracts.schemas import Observation, ObservationType, RunState, Trajectory

# 학습에 쓸 수 있는 label(=evidence/validation 으로 판정된 것). cowork_rule 3절 Finding 상태.
LEARNABLE_LABELS = {"verified", "fixed", "rejected", "human_review"}

# Observation.type 값 집합. D1-P3 이견 3(P3 제안) → P4 채택 → **P1 이 contracts 의
# `ObservationType` enum 으로 정식 채택**(rebase 반영). 이제 스키마가 강제하므로 여기서는
# 계약 enum 에서 파생해 drift 를 원천 차단한다.
OBSERVATION_TYPES = tuple(t.value for t in ObservationType)


def is_evidence_type(t: str) -> bool:
    return t in OBSERVATION_TYPES


def valid_evidence(
    observations: Sequence[Observation],
) -> tuple[list[Observation], list[str]]:
    """(합의된 type 인 Observation, 알 수 없는 type 목록). Observation.type 이 이제 enum 이라
    정상 생성된 것은 항상 valid — unknown 은 방어적으로만 남긴다(예: 외부 dict 우회 대비)."""
    ok: list[Observation] = []
    unknown: list[str] = []
    for o in observations:
        if is_evidence_type(o.type):
            ok.append(o)
        else:
            unknown.append(str(o.type))
    return ok, unknown


class TrajectoryRecorder:
    """상태 전이 스텝을 JSONL 로 append. run 별 파일 하나 권장."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq = 0

    def record(self, traj: Trajectory) -> Trajectory:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(traj.model_dump(mode="json"), ensure_ascii=False) + "\n")
        self._seq += 1
        return traj

    def record_step(
        self,
        *,
        run_id: str,
        state: RunState,
        action: dict,
        result: dict,
        next_state: RunState,
        reward: Optional[float] = None,
        label: Optional[str] = None,
        traj_id: Optional[str] = None,
    ) -> Trajectory:
        traj = Trajectory(
            id=traj_id or f"{run_id}-step-{self._seq}",
            run_id=run_id,
            state=state,
            action=action,
            result=result,
            next_state=next_state,
            reward=reward,
            label=label,
        )
        return self.record(traj)


def load_trajectories(path: Path | str) -> list[Trajectory]:
    """JSONL → Trajectory[]. 빈 줄 무시."""
    p = Path(path)
    out: list[Trajectory] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(Trajectory.model_validate(json.loads(line)))
    return out


def training_samples(
    trajectories: Iterable[Trajectory],
    *,
    require_label: bool = True,
) -> list[Trajectory]:
    """학습에 쓸 수 있는 스텝만 남긴다.

    require_label=True(기본): label 이 LEARNABLE_LABELS 이거나 reward 가 있는 스텝만.
    (evidence/validation 이 연결된 것만 쓴다는 cowork_rule 5절 원칙.)
    """
    kept: list[Trajectory] = []
    for t in trajectories:
        if not require_label:
            kept.append(t)
            continue
        if (t.label in LEARNABLE_LABELS) or (t.reward is not None):
            kept.append(t)
    return kept


def to_sft_sample(
    traj: Trajectory,
    observations: Sequence[Observation] | None = None,
) -> dict:
    """Trajectory → 지도학습(SFT) 샘플 초안. (state, action) → result.

    observations 를 주면 **evidence 를 조인**한다: OBSERVATION_TYPES 로 검증된 것만
    `evidence`(type/uri/hash/producer)로 붙이고, 알 수 없는 type 은 `evidence_warnings`
    로 남긴다(조용히 버리지 않음). 실제 프롬프트 템플릿은 D4 학습 단계에서 확정.
    """
    sample = {
        "input": {"state": str(traj.state), "action": traj.action},
        "output": traj.result,
        "label": traj.label,
        "reward": traj.reward,
        "run_id": traj.run_id,
    }
    if observations is not None:
        ok, unknown = valid_evidence(observations)
        sample["evidence"] = [
            {"type": o.type, "uri": o.artifact_uri, "hash": o.hash, "producer": o.producer}
            for o in ok
        ]
        if unknown:
            sample["evidence_warnings"] = unknown
    return sample


def stats(trajectories: Sequence[Trajectory]) -> dict:
    by_label: dict[str, int] = {}
    for t in trajectories:
        k = t.label or "unlabeled"
        by_label[k] = by_label.get(k, 0) + 1
    learnable = len(training_samples(trajectories))
    return {"total": len(trajectories), "learnable": learnable, "by_label": by_label}


def _main() -> None:
    parser = argparse.ArgumentParser(description="Trajectory 수집 유틸 (P4)")
    parser.add_argument("--stats", metavar="JSONL", help="trajectory JSONL 요약 출력")
    args = parser.parse_args()
    if args.stats:
        trajs = load_trajectories(args.stats)
        print(json.dumps(stats(trajs), ensure_ascii=False, indent=2))
    else:
        parser.error("--stats <JSONL> 필요")


if __name__ == "__main__":
    _main()
