"""M1 실주행 (P4) — 벤치 소스 → SAST+RAG → heuristic vs 235B rerank → 클래스별 ablation.

`datasets/benchmark_source_lock.yaml` 로 체크아웃된 소스(`.vibecutter/targets/sources/<id>`)를
스캔해 RQ3 클래스별(injection/xss/idor) 우선순위(MRR)·precision·candidate 수·235B health/tier 를 낸다.
**runtime build/health/port 불필요** — 정적 semgrep 스캔 + code_index RAG + 235B rerank + 벤치
정답(inventory_benchmark.yaml) 대조뿐.

CLI:
    python -m eval.run_m1 --app dsvw --app juice-shop
"""

from __future__ import annotations

import argparse
from pathlib import Path

from datasets.inventory import Inventory
from eval.baseline import evaluate, focus_set_from_candidates, ground_truth_from_inventory
from eval.priority_ablation import FOCUS_CLASSES, compare_by_class
from model.code_index import CodeIndex
from model.endpoints import LlmCallOutcome, observed_chat_fn_from_env
from model.serving import make_rerank_fn
from scanners.aggregate import aggregate
from scanners.rag_enrich import enrich, has_indexable_location
from scanners.sast.semgrep_runner import FOCUS_RULESETS, run_semgrep
from scanners.surface_idor import run_surface_idor

SOURCES = Path(".vibecutter/targets/sources")
BENCHMARK = Path("datasets/inventory_benchmark.yaml")


def scan_app(source_root: Path, run_id: str) -> list:
    """focus별 semgrep 룰셋을 순회하며 스캔 → candidate 합침. 룰셋 실패는 건너뛰고 기록."""
    cands: list = []
    for focus, rulesets in FOCUS_RULESETS.items():
        for rs in rulesets:
            try:
                cands += run_semgrep(source_root, run_id=run_id, config=rs, ruleset_focus=focus)
            except Exception as exc:  # noqa: BLE001 (룰셋 다운로드/실행 실패는 부분 진행)
                print(f"  [semgrep 실패] {focus}:{rs} — {type(exc).__name__}: {str(exc)[:120]}")
    # IDOR 는 SAST(dataflow sink)로 안 잡히므로 구조적 프리필터(surface_idor)로 후보를 낸다.
    try:
        idor_cands = run_surface_idor(source_root, run_id=run_id)
        cands += idor_cands
        if idor_cands:
            print(f"  [surface_idor] idor 후보 {len(idor_cands)}개")
    except Exception as exc:  # noqa: BLE001
        print(f"  [surface_idor 실패] {type(exc).__name__}: {str(exc)[:120]}")
    return cands


def run_app(app_id: str, source_root: Path):
    """한 앱 → (heuristic 순서, rag-llm 순서, LlmCallOutcome, 전체 candidate)."""
    cands = scan_app(source_root, app_id)
    if has_indexable_location(cands):
        cands = enrich(cands, CodeIndex.build(source_root))

    heuristic = aggregate(cands).kept                       # rerank 없음
    pair = observed_chat_fn_from_env()
    if pair is None:
        return heuristic, heuristic, LlmCallOutcome.unavailable(), cands
    chat_fn, recorder = pair
    ragllm = aggregate(cands, rerank_fn=make_rerank_fn(chat_fn)).kept  # 235B 재정렬
    return heuristic, ragllm, recorder(), cands


def _focus_counts(cands) -> dict[str, int]:
    out = {c: 0 for c in FOCUS_CLASSES}
    for cand in cands:
        f = None
        for s in cand.signals:
            if s.startswith("focus:"):
                f = s.split(":", 1)[1]
        f = f or cand.vuln_class
        if f in out:
            out[f] += 1
    return out


def main(app_ids: list[str]) -> None:
    bench = Inventory.load(BENCHMARK)
    truth = ground_truth_from_inventory(bench)              # {app: focus set}
    focus_of_bench = {a.id: set(a.focus) for a in bench.apps}

    heuristic: dict[str, list] = {}
    ragllm: dict[str, list] = {}
    predictions: dict[str, set] = {}
    per_app_meta: dict[str, dict] = {}

    for app_id in app_ids:
        root = SOURCES / app_id
        if not root.is_dir():
            print(f"[SKIP] {app_id}: 소스 없음({root}) — benchmark_source_lock revision으로 checkout 필요")
            continue
        print(f"[SCAN] {app_id} ({root}) …")
        h, r, outcome, cands = run_app(app_id, root)
        heuristic[app_id] = h
        ragllm[app_id] = r
        predictions[app_id] = focus_set_from_candidates(h)
        per_app_meta[app_id] = {
            "candidates": len(cands), "kept": len(h),
            "focus_counts": _focus_counts(h),
            "llm_used": outcome.llm_used, "tier": outcome.tier,
            "endpoint_health": "up" if outcome.llm_used else "down",
        }
        print(f"  candidates={len(cands)} kept={len(h)} focus={per_app_meta[app_id]['focus_counts']} "
              f"235B={outcome.tier}({'up' if outcome.llm_used else 'down'})")

    if not heuristic:
        print("실행할 소스가 하나도 없음. checkout 먼저.")
        return

    # 클래스별 순위 ablation(MRR) — heuristic vs rag-llm
    by_class = compare_by_class(heuristic, ragllm, {k: truth[k] for k in heuristic if k in truth})
    # 클래스별 precision (정답 대조; set 기반이라 두 팔 동일 → detection precision)
    report = evaluate({k: predictions[k] for k in heuristic},
                      {k: truth[k] for k in heuristic if k in truth})

    print("\n" + "=" * 72)
    print(f"M1 결과 (앱 {list(heuristic)}) — RQ3 클래스별")
    print("=" * 72)
    print(f"{'class':<12}{'MRR_heur':>10}{'MRR_ragllm':>12}{'Δ':>8}{'precision':>11}{'recall':>9}{'cands':>7}")
    print("-" * 72)
    total_focus = {c: sum(m['focus_counts'].get(c, 0) for m in per_app_meta.values()) for c in FOCUS_CLASSES}
    for c in FOCUS_CLASSES:
        conf = report.per_group[c]
        if c in by_class:
            b = by_class[c]
            print(f"{c:<12}{b.heuristic_mrr:>10.3f}{b.ragllm_mrr:>12.3f}{b.mrr_delta:>+8.3f}"
                  f"{conf.precision:>11.2f}{conf.recall:>9.2f}{total_focus[c]:>7}")
        else:
            print(f"{c:<12}{'—':>10}{'—':>12}{'—':>8}{conf.precision:>11.2f}{conf.recall:>9.2f}{total_focus[c]:>7}")
    print("-" * 72)
    print(f"235B health/tier (앱별): " +
          ", ".join(f"{a}={m['tier']}/{m['endpoint_health']}" for a, m in per_app_meta.items()))


def _main() -> None:
    ap = argparse.ArgumentParser(description="M1 실주행 — 클래스별 ablation (P4)")
    ap.add_argument("--app", action="append", required=True, help="benchmark app id (여러 번)")
    main(ap.parse_args().app)


if __name__ == "__main__":
    _main()
