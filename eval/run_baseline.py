"""Baseline 실행 배선 (P4 소유, D2) — 스캔 산출물 → 정확도 리포트.

`scanners/batch_scan.py` 가 만든 앱별 candidate JSONL(`<app>.candidates.jsonl`)을 읽어
`{app_id: set[focus]}` 예측으로 바꾸고, 벤치마크 inventory 정답과 대조해 B1/B2 성능
리포트를 낸다. 하네스 자체는 `eval/baseline.py` 이고, 여기서는 **실데이터 배선**만 한다.

주의: precision/recall 은 **정답이 있는 벤치마크 앱**(inventory_benchmark.yaml)에서만
의미가 있다. 학생앱(inventory.yaml)은 expected_vulns 가 비어 있어 정답이 없으므로,
B1/B2 는 벤치마크 앱을 스캔한 산출물에 대해 돌린다:

    # 벤치마크 앱을 배치 스캔한 뒤(예: runs/b1), 정확도 측정
    python -m eval.run_baseline --candidates runs/b1/candidates --label B1

CLI 는 벤치마크 inventory 를 정답으로 자동 로드한다.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Mapping

from contracts.schemas import Candidate
from eval.baseline import (
    BaselineReport,
    evaluate,
    focus_set_from_candidates,
    ground_truth_from_inventory,
)

CANDIDATE_SUFFIX = ".candidates.jsonl"


def _app_id_from_filename(path: Path) -> str:
    name = path.name
    if name.endswith(CANDIDATE_SUFFIX):
        return name[: -len(CANDIDATE_SUFFIX)]
    return path.stem


def load_candidates_jsonl(path: Path | str) -> list[Candidate]:
    p = Path(path)
    out: list[Candidate] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(Candidate.model_validate(json.loads(line)))
    return out


def predictions_from_candidate_dir(candidates_dir: Path | str) -> dict[str, set[str]]:
    """`<dir>/*.candidates.jsonl` → {app_id: 탐지한 3군 focus 집합}."""
    d = Path(candidates_dir)
    preds: dict[str, set[str]] = {}
    for f in sorted(d.glob(f"*{CANDIDATE_SUFFIX}")):
        app_id = _app_id_from_filename(f)
        preds[app_id] = focus_set_from_candidates(load_candidates_jsonl(f))
    return preds


def baseline_report(
    candidates_dir: Path | str,
    ground_truth: Mapping[str, set[str]],
) -> BaselineReport:
    """스캔 산출물 예측 vs 정답 → BaselineReport."""
    preds = predictions_from_candidate_dir(candidates_dir)
    return evaluate(preds, ground_truth)


def _main() -> None:
    parser = argparse.ArgumentParser(description="Baseline 실행 배선 (P4)")
    parser.add_argument("--candidates", required=True, help="배치 산출 candidate 디렉토리")
    parser.add_argument("--label", default="baseline", help="리포트 라벨(B1/B2 등)")
    parser.add_argument(
        "--benchmark",
        default="datasets/inventory_benchmark.yaml",
        help="정답 inventory 경로",
    )
    args = parser.parse_args()

    from datasets.inventory import Inventory  # 지연 import

    bench = Inventory.load(Path(args.benchmark))
    truth = ground_truth_from_inventory(bench)
    report = baseline_report(args.candidates, truth)
    print(f"[{args.label}]")
    print(report.render())


if __name__ == "__main__":
    _main()
