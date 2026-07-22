"""전달받은 run을 235B/heuristic ablation 표본에 반영한다 (P4).

3자 협업의 P4 몫: P3가 closed-loop를 돌려 `run_id`/evidence/FIXED를 주고, P2가 그 run의
runtime metadata(`llm_endpoint_state`)를 연결하면, 여기서 **그 run이 235B(rag-llm) 표본인지
heuristic degrade라 제외인지**를 판정한다.

두 출처를 대조한다(반드시 일치해야 함 — 같은 소스라서):
  (a) 내 trajectory 판독: `model.trajectory.llm_usage_from_trajectories` → `any_used`
  (b) P2 `.vibecutter/runtime_metadata.jsonl`의 `llm_endpoint_state`
      (driver가 (a)와 **같은 함수**로 채운다 — W-10). 어긋나면 배선/데이터 오류 신호.

표본 규칙(P2 2026-07-22 확정):
  - LLM이 실제로 답한 run(up)  → **rag-llm(235B) 표본**.
  - 235B 장애로 heuristic degrade한 run(down) → **표본에서 제외**(LLM 표본 아님).
  - 관측 메타가 없는 run(unknown) → 판정 보류(rag-llm 표본에 넣지 않음).

CLI:
    python -m eval.reflect_runs --run-id run-xxxx        # 특정 run
    python -m eval.reflect_runs --all                    # trajectory 있는 전체
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Optional

from core.trajectory import TRAJECTORY_DIR
from model.trajectory import RunLlmUsage, llm_usage_from_trajectories, load_trajectories

RUNTIME_METADATA_PATH = Path(".vibecutter/runtime_metadata.jsonl")


def _state_from_usage(usage: Optional[RunLlmUsage]) -> str:
    """driver._llm_endpoint_state_for와 **같은 규칙**: any_used면 up, 아니면 down, 없으면 unknown."""
    if usage is None:
        return "unknown"
    return "up" if usage.any_used else "down"


def _sample_of(state: str) -> str:
    return {"up": "rag-llm", "down": "excluded", "unknown": "unknown"}[state]


def load_runtime_metadata(
    path: Path | str = RUNTIME_METADATA_PATH,
) -> dict[str, dict]:
    """P2 runtime_metadata.jsonl → {run_id: 마지막 레코드}. 없으면 빈 dict."""
    p = Path(path)
    if not p.is_file():
        return {}
    out: dict[str, dict] = {}
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        rid = rec.get("run_id")
        if rid:
            out[rid] = rec  # 같은 run_id는 마지막 것이 이긴다
    return out


@dataclass(frozen=True)
class RunReflection:
    run_id: str
    target_id: Optional[str]
    sample: str                     # "rag-llm" | "excluded" | "unknown"
    trajectory_state: str           # "up" | "down" | "unknown" (내 판독)
    p2_state: Optional[str]         # P2 runtime_metadata의 llm_endpoint_state (없으면 None)
    tiers: tuple[str, ...]

    @property
    def consistent(self) -> bool:
        """P2 값이 없으면 대조 불가(True 취급). 있으면 내 판독과 같아야 한다."""
        return self.p2_state is None or self.p2_state == self.trajectory_state


def reflect_run(
    run_id: str,
    *,
    traj_dir: Path | str = TRAJECTORY_DIR,
    runtime_meta: Optional[Mapping[str, dict]] = None,
) -> RunReflection:
    """단일 run → 표본 판정 + P2 대조."""
    meta = (runtime_meta if runtime_meta is not None else load_runtime_metadata()).get(run_id, {})
    path = Path(traj_dir) / f"{run_id}.jsonl"
    usage = None
    if path.is_file():
        usage = llm_usage_from_trajectories(load_trajectories(path)).get(run_id)
    state = _state_from_usage(usage)
    return RunReflection(
        run_id=run_id,
        target_id=meta.get("target_id"),
        sample=_sample_of(state),
        trajectory_state=state,
        p2_state=meta.get("llm_endpoint_state"),
        tiers=usage.tiers if usage else (),
    )


def reflect_runs(
    run_ids: Iterable[str],
    *,
    traj_dir: Path | str = TRAJECTORY_DIR,
    runtime_meta: Optional[Mapping[str, dict]] = None,
) -> list[RunReflection]:
    meta = runtime_meta if runtime_meta is not None else load_runtime_metadata()
    return [reflect_run(r, traj_dir=traj_dir, runtime_meta=meta) for r in run_ids]


def render(reflections: list[RunReflection]) -> str:
    lines = [f"{'run_id':<20}{'target':<16}{'sample':<10}{'traj':<8}{'p2':<8}{'일치'}"]
    lines.append("-" * 70)
    for r in reflections:
        lines.append(
            f"{r.run_id:<20}{(r.target_id or '-'):<16}{r.sample:<10}"
            f"{r.trajectory_state:<8}{(r.p2_state or '-'):<8}{'OK' if r.consistent else '⚠불일치'}")
    n_llm = sum(1 for r in reflections if r.sample == "rag-llm")
    n_excl = sum(1 for r in reflections if r.sample == "excluded")
    n_incons = sum(1 for r in reflections if not r.consistent)
    lines.append("")
    lines.append(f"rag-llm(235B) 표본: {n_llm} | 제외(degrade): {n_excl} | "
                 f"P2 불일치: {n_incons}")
    return "\n".join(lines)


def _main() -> None:
    ap = argparse.ArgumentParser(description="run을 235B/heuristic 표본에 반영 (P4)")
    ap.add_argument("--run-id", action="append", help="판정할 run_id (여러 번 가능)")
    ap.add_argument("--all", action="store_true", help="trajectory 디렉토리의 모든 run")
    args = ap.parse_args()

    if args.all:
        ids = sorted(p.stem for p in Path(TRAJECTORY_DIR).glob("run-*.jsonl"))
    elif args.run_id:
        ids = args.run_id
    else:
        ap.error("--run-id <id> 또는 --all 필요")
    print(render(reflect_runs(ids)))


if __name__ == "__main__":
    _main()
