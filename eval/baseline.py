"""Baseline 탐지 성능 하네스 (P4 소유) — 기획서 12.2절 B1/B2, 12.3절 지표.

detector 무관(detector-agnostic). 어떤 탐지기(B1 Semgrep-only, B2 ZAP-only, …)가
앱별로 어떤 3군(idor/xss/injection)을 flag 했는지를 정답과 비교해
precision/recall/FPR/F1 과 OWASP Benchmark 식 score(TPR-FPR)를 낸다.

정답(ground truth)은 `datasets/inventory_benchmark.yaml` 의 `expected_vulns` 에서
온다. 이 공개 취약앱들은 **앱 단위 취약점군 라벨**만 있으므로(라인 단위 정답 없음),
평가 단위도 **(앱 × 3군) 셀**이다. 즉 "앱 A 에 injection 취약점이 있다/없다"를 맞췄는지
본다 — 세밀한 라인 단위 precision 이 아님을 보고 시 명시할 것(12.5절).

expected_vulns 토큰(sqli/nosqli/cmdi/xss/idor/bola/…) 중 3군에 매핑되는 것만 정답에
반영하고, 나머지(auth/ssrf/csrf/deserialization 등)는 이 baseline scope 밖이라 무시한다.

사용:
    from eval.baseline import ground_truth_from_inventory, evaluate, focus_set_from_candidates
    truth = ground_truth_from_inventory(Inventory.load(BENCH))
    pred  = {app_id: focus_set_from_candidates(cands) for app_id, cands in per_app.items()}
    report = evaluate(pred, truth)
    print(report.render())

CLI:
    python -m eval.baseline --predictions preds.json   # {app_id: ["idor","xss"], ...}
    python -m eval.baseline --demo                     # 하네스 동작 데모
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping

from contracts.schemas import Candidate

FOCUS_GROUPS = ("idor", "injection", "xss")

# expected_vulns / 기타 취약점 토큰 → 3군. scope 밖 토큰은 매핑하지 않는다.
VULN_TO_FOCUS = {
    "idor": "idor",
    "bola": "idor",
    "bfla": "idor",
    "access-control": "idor",
    "xss": "xss",
    "injection": "injection",
    "sqli": "injection",
    "nosqli": "injection",
    "cmdi": "injection",
    "command-injection": "injection",
    "rce": "injection",
}


def vuln_tokens_to_focus(tokens: Iterable[str]) -> set[str]:
    """취약점 토큰 집합 → 3군 focus 집합(scope 밖은 버림)."""
    out: set[str] = set()
    for t in tokens:
        f = VULN_TO_FOCUS.get(str(t).strip().lower())
        if f:
            out.add(f)
    return out


def focus_set_from_candidates(candidates: Iterable[Candidate]) -> set[str]:
    """Candidate[] 의 `focus:<group>` signal 을 모아 앱이 flag 한 3군 집합으로."""
    out: set[str] = set()
    for c in candidates:
        for s in c.signals:
            if s.startswith("focus:"):
                g = s.split(":", 1)[1]
                if g in FOCUS_GROUPS:
                    out.add(g)
    return out


def ground_truth_from_inventory(inventory) -> dict[str, set[str]]:
    """벤치마크 Inventory → {app_id: 정답 3군 집합}. expected_vulns 기반."""
    return {app.id: vuln_tokens_to_focus(app.expected_vulns) for app in inventory.apps}


@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def add(self, predicted: bool, actual: bool) -> None:
        if predicted and actual:
            self.tp += 1
        elif predicted and not actual:
            self.fp += 1
        elif not predicted and actual:
            self.fn += 1
        else:
            self.tn += 1

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def recall(self) -> float:  # TPR
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def fpr(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def benchmark_score(self) -> float:
        """OWASP Benchmark 식 Youden's J = TPR - FPR."""
        return self.recall - self.fpr


@dataclass
class BaselineReport:
    overall: Confusion
    per_group: dict[str, Confusion]
    per_app: dict[str, dict] = field(default_factory=dict)
    n_apps: int = 0

    def render(self) -> str:
        o = self.overall
        lines = [
            f"apps={self.n_apps}  cells={o.tp + o.fp + o.fn + o.tn} (앱×3군)",
            f"{'':10}{'P':>7}{'R(TPR)':>9}{'FPR':>7}{'F1':>7}{'TPR-FPR':>9}"
            f"{'  (TP/FP/FN/TN)':>18}",
            "-" * 72,
        ]
        def row(name: str, c: Confusion) -> str:
            return (
                f"{name:10}{c.precision:7.2f}{c.recall:9.2f}{c.fpr:7.2f}"
                f"{c.f1:7.2f}{c.benchmark_score:9.2f}"
                f"   {c.tp}/{c.fp}/{c.fn}/{c.tn}"
            )
        lines.append(row("overall", o))
        for g in FOCUS_GROUPS:
            lines.append(row(g, self.per_group[g]))
        return "\n".join(lines)


def evaluate(
    predicted: Mapping[str, set[str]],
    truth: Mapping[str, set[str]],
) -> BaselineReport:
    """(앱 × 3군) 셀 단위 confusion 집계. 평가 대상 앱 = truth 의 키."""
    overall = Confusion()
    per_group = {g: Confusion() for g in FOCUS_GROUPS}
    per_app: dict[str, dict] = {}

    for app_id, actual_set in truth.items():
        pred_set = set(predicted.get(app_id, set()))
        for g in FOCUS_GROUPS:
            p = g in pred_set
            a = g in actual_set
            overall.add(p, a)
            per_group[g].add(p, a)
        per_app[app_id] = {
            "predicted": sorted(pred_set & set(FOCUS_GROUPS)),
            "truth": sorted(actual_set),
        }

    return BaselineReport(
        overall=overall, per_group=per_group, per_app=per_app, n_apps=len(truth)
    )


def _demo() -> BaselineReport:
    """정답과 3개 앱짜리 mock 탐지기로 하네스 동작을 보여준다."""
    truth = {
        "app-a": {"idor", "injection"},
        "app-b": {"xss"},
        "app-c": {"injection", "xss"},
    }
    # mock detector: app-a 완벽, app-b 는 injection 오탐 + xss 미탐, app-c 는 injection 만.
    pred = {
        "app-a": {"idor", "injection"},
        "app-b": {"injection"},
        "app-c": {"injection"},
    }
    return evaluate(pred, truth)


def _main() -> None:
    parser = argparse.ArgumentParser(description="Baseline 탐지 성능 하네스 (P4)")
    parser.add_argument("--predictions", help="{app_id: [focus,...]} JSON. 정답은 벤치마크 inventory.")
    parser.add_argument("--demo", action="store_true", help="mock 데이터로 하네스 데모")
    args = parser.parse_args()

    if args.demo:
        print(_demo().render())
        return
    if not args.predictions:
        parser.error("--predictions 또는 --demo 필요")

    from datasets.inventory import Inventory  # 지연 import (CLI 에서만 필요)

    bench = Inventory.load(Path("datasets/inventory_benchmark.yaml"))
    truth = ground_truth_from_inventory(bench)
    raw = json.loads(Path(args.predictions).read_text(encoding="utf-8"))
    pred = {k: set(v) for k, v in raw.items()}
    print(evaluate(pred, truth).render())


if __name__ == "__main__":
    _main()
