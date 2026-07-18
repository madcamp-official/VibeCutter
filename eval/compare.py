"""base vs fine-tuned 비교 하네스 (P4, D4 "비교표 초안"의 GPU-free 부분).

D4 밤에 base 모델과 QLoRA fine-tuned 모델로 같은 벤치마크를 각각 돌려 두 산출물이
나오면, 이 하네스가 두 `BaselineReport` 를 나란히 놓고 metric 델타 표를 만든다.
GPU/학습 없이도 **비교 로직 자체는 지금 완성·검증**해 둔다 — 두 산출물만 나오면 바로 표가 나온다.

- 순수: `compare(base, full) -> ComparisonReport` — 두 BaselineReport 만 받아 델타 계산.
- wrapper: `compare_dirs(base_dir, full_dir, ...)` — candidate 디렉토리 두 개 → 두 리포트 → 비교.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from eval.baseline import FOCUS_GROUPS, BaselineReport, Confusion

_METRICS = [
    ("P", "precision"), ("R", "recall"), ("FPR", "fpr"),
    ("F1", "f1"), ("TPR-FPR", "benchmark_score"),
]


@dataclass
class RowDelta:
    """한 행(overall 또는 focus 군)의 base/full metric 과 델타."""
    name: str
    base: dict[str, float]
    full: dict[str, float]

    @property
    def delta(self) -> dict[str, float]:
        return {k: self.full[k] - self.base[k] for k in self.base}


@dataclass
class ComparisonReport:
    rows: list[RowDelta]
    per_app: dict[str, dict] = field(default_factory=dict)

    def improved_apps(self) -> list[str]:
        return sorted(a for a, d in self.per_app.items() if d["change"] == "improved")

    def regressed_apps(self) -> list[str]:
        return sorted(a for a, d in self.per_app.items() if d["change"] == "regressed")

    def render(self) -> str:
        head = f"{'':10}" + "".join(f"{label:>22}" for label, _ in _METRICS)
        lines = ["base → full (Δ)", head, "-" * len(head)]
        for row in self.rows:
            cells = ""
            for _, attr in _METRICS:
                b, f, d = row.base[attr], row.full[attr], row.delta[attr]
                cells += f"{b:5.2f}→{f:5.2f}({d:+.2f})".rjust(22)
            lines.append(f"{row.name:10}" + cells)
        imp, reg = self.improved_apps(), self.regressed_apps()
        lines.append("")
        lines.append(f"개선된 앱({len(imp)}): {', '.join(imp) or '-'}")
        lines.append(f"악화된 앱({len(reg)}): {', '.join(reg) or '-'}")
        return "\n".join(lines)


def _metrics_of(c: Confusion) -> dict[str, float]:
    return {attr: getattr(c, attr) for _, attr in _METRICS}


def _classify_app(base_app: dict, full_app: dict) -> str:
    """앱의 예측이 정답 대비 좋아졌나/나빠졌나 (correct focus 수로 판단)."""
    truth = set(base_app["truth"])
    b_pred, f_pred = set(base_app["predicted"]), set(full_app["predicted"])
    # 정확도 = |맞은 양성| - |오탐|
    def score(pred: set[str]) -> int:
        return len(pred & truth) - len(pred - truth)
    b, f = score(b_pred), score(f_pred)
    if f > b:
        return "improved"
    if f < b:
        return "regressed"
    return "same"


def compare(base: BaselineReport, full: BaselineReport) -> ComparisonReport:
    """두 BaselineReport → 비교 리포트(overall + 3군 델타 + 앱별 변화)."""
    rows = [RowDelta("overall", _metrics_of(base.overall), _metrics_of(full.overall))]
    for g in FOCUS_GROUPS:
        rows.append(RowDelta(g, _metrics_of(base.per_group[g]), _metrics_of(full.per_group[g])))

    per_app: dict[str, dict] = {}
    for app_id, b_app in base.per_app.items():
        f_app = full.per_app.get(app_id)
        if f_app is None:
            continue
        change = _classify_app(b_app, f_app)
        if change != "same":
            per_app[app_id] = {
                "change": change,
                "truth": b_app["truth"],
                "base_pred": b_app["predicted"],
                "full_pred": f_app["predicted"],
            }
    return ComparisonReport(rows=rows, per_app=per_app)


def compare_dirs(
    base_dir: Path | str, full_dir: Path | str, ground_truth: Mapping[str, set[str]],
) -> ComparisonReport:
    """candidate 디렉토리 두 개 → 두 BaselineReport → 비교."""
    from eval.run_baseline import baseline_report  # 지연 import(순수부와 분리)
    base = baseline_report(base_dir, ground_truth)
    full = baseline_report(full_dir, ground_truth)
    return compare(base, full)


def _main() -> None:
    ap = argparse.ArgumentParser(description="base vs full 비교 (P4)")
    ap.add_argument("--base-candidates", required=True, help="base 모델 산출 candidate 디렉토리")
    ap.add_argument("--full-candidates", required=True, help="fine-tuned 산출 candidate 디렉토리")
    ap.add_argument("--benchmark", default="datasets/inventory_benchmark.yaml")
    args = ap.parse_args()

    from datasets.inventory import Inventory
    from eval.baseline import ground_truth_from_inventory

    truth = ground_truth_from_inventory(Inventory.load(Path(args.benchmark)))
    print(compare_dirs(args.base_candidates, args.full_candidates, truth).render())


if __name__ == "__main__":
    _main()
