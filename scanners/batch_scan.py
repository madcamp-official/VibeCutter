"""전 앱 스캔 배치 (P4 소유) — 밤 배치 D1.

inventory 의 각 앱을 clone → SAST(Semgrep)[+SCA(OSV)] → 공통 계약 Candidate[] 로
모아 앱별 JSONL 과 summary 로 저장한다(기획서 밤 배치 "전 앱 Semgrep 스캔").

핵심 루프 `run_batch()` 는 clone/scan 함수를 **주입**받아 네트워크·semgrep 없이도
테스트된다(cowork_rule 5·8절). CLI 는 실제 git + Semgrep(+OSV)로 배선한다.

scan_fn 규약: `list[Candidate]` 반환(빈 리스트=발견 0), `None` 반환=스캐너 미설치라
스킵. 예외는 배치가 잡아 해당 앱만 error 로 기록하고 계속 진행한다.

CLI:
    python -m scanners.batch_scan --workdir runs/d1-batch            # 전 앱
    python -m scanners.batch_scan --workdir runs/d1-batch --limit 3  # 앞 3개만
    python -m scanners.batch_scan --workdir runs/d1-batch --sca      # SCA 도 함께
    python -m scanners.batch_scan --workdir runs/d1-batch --dry-run  # clone 없이 계획만
"""

from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence

from contracts.schemas import Candidate
from datasets.inventory import AppEntry, Inventory

CloneFn = Callable[[AppEntry, Path], None]
ScanFn = Callable[[AppEntry, Path, str], Optional[list[Candidate]]]
SourceRootFn = Callable[[AppEntry], Path]

# 상태 상수.
SCANNED = "scanned"
CLONE_FAILED = "clone_failed"
SCAN_UNAVAILABLE = "scan_unavailable"
SOURCE_MISSING = "source_missing"
ERROR = "error"

# P2 가 관리하는 target 소스 체크아웃 위치(D1-P2 handoff). 여기를 스캔하면 재-clone 불필요.
# 더 견고하게는 runtime.catalog.TargetCatalog.source_root_for(id) 를 쓸 수 있으나,
# 그건 P2 runtime 초기화가 필요해 여기서는 문서화된 경로 관례를 기본으로 둔다.
P2_SOURCE_BASE = Path(".vibecutter/targets/sources")


def p2_source_root(app: AppEntry, *, base: Path | None = None) -> Path:
    """P2 가 clone 해둔 target 소스 경로. `--use-p2-sources` 에서 clone 대신 이걸 스캔."""
    return (base or P2_SOURCE_BASE) / app.id


@dataclass
class BatchItemResult:
    app_id: str
    status: str
    n_candidates: int = 0
    detail: str = ""


def default_clone_fn(app: AppEntry, dest: Path, *, timeout: int = 300) -> None:
    """git clone --depth 1. dest 가 이미 있으면 재사용(재클론 안 함)."""
    if (dest / ".git").exists():
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run(
        ["git", "clone", "--depth", "1", "--quiet", app.repo_url, str(dest)],
        capture_output=True, text=True, timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git clone 실패: {proc.stderr.strip()[:200]}")


def make_default_scan_fn(*, include_sca: bool = False) -> ScanFn:
    """실제 Semgrep(+선택 OSV) 로 스캔하는 scan_fn 생성. 스캐너 미설치면 None."""
    from scanners.sast.semgrep_runner import SemgrepUnavailableError, run_semgrep

    def scan(app: AppEntry, src_root: Path, run_id: str) -> Optional[list[Candidate]]:
        cands: list[Candidate] = []
        any_ran = False
        try:
            cands += run_semgrep(src_root, run_id=run_id)
            any_ran = True
        except SemgrepUnavailableError:
            pass
        if include_sca:
            from scanners.sca.osv_runner import OSVUnavailableError, run_osv
            try:
                cands += run_osv(src_root, run_id=run_id)
                any_ran = True
            except OSVUnavailableError:
                pass
        return cands if any_ran else None

    return scan


def run_batch(
    apps: Sequence[AppEntry],
    workdir: Path | str,
    *,
    clone_fn: CloneFn = default_clone_fn,
    scan_fn: Optional[ScanFn] = None,
    source_root_fn: Optional[SourceRootFn] = None,
    write: bool = True,
) -> list[BatchItemResult]:
    """앱들을 순회하며 (clone 또는 P2 소스)→scan→candidate 저장. 앱 단위 실패 격리.

    source_root_fn 을 주면 clone 대신 그 경로를 직접 스캔한다(P2 가 이미 clone 한 소스
    재사용 — `p2_source_root`). 경로가 없으면 SOURCE_MISSING 으로 기록하고 계속.
    """
    if scan_fn is None:
        scan_fn = make_default_scan_fn()
    workdir = Path(workdir)
    clones = workdir / "clones"
    cand_dir = workdir / "candidates"
    if write:
        cand_dir.mkdir(parents=True, exist_ok=True)

    results: list[BatchItemResult] = []
    for app in apps:
        run_id = f"batch-{app.id}"
        if source_root_fn is not None:
            dest = source_root_fn(app)
            if not dest.exists():
                results.append(BatchItemResult(app.id, SOURCE_MISSING, detail=str(dest)))
                continue
        else:
            dest = clones / app.id
            try:
                clone_fn(app, dest)
            except Exception as e:  # noqa: BLE001 — 앱 단위 격리
                results.append(BatchItemResult(app.id, CLONE_FAILED, detail=str(e)[:200]))
                continue
        try:
            cands = scan_fn(app, dest, run_id)
        except Exception as e:  # noqa: BLE001
            results.append(BatchItemResult(app.id, ERROR, detail=str(e)[:200]))
            continue
        if cands is None:
            results.append(BatchItemResult(app.id, SCAN_UNAVAILABLE))
            continue
        if write:
            out = cand_dir / f"{app.id}.candidates.jsonl"
            out.write_text(
                "".join(json.dumps(c.model_dump(mode="json"), ensure_ascii=False) + "\n" for c in cands),
                encoding="utf-8",
            )
        results.append(BatchItemResult(app.id, SCANNED, n_candidates=len(cands)))

    if write:
        _write_summary(workdir, results)
    return results


def _write_summary(workdir: Path, results: list[BatchItemResult]) -> None:
    summary = {
        "n_apps": len(results),
        "n_scanned": sum(r.status == SCANNED for r in results),
        "n_candidates": sum(r.n_candidates for r in results),
        "by_status": {
            s: sum(r.status == s for r in results)
            for s in (SCANNED, CLONE_FAILED, SCAN_UNAVAILABLE, SOURCE_MISSING, ERROR)
        },
        "items": [asdict(r) for r in results],
    }
    (workdir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def _print_results(results: list[BatchItemResult]) -> None:
    for r in results:
        extra = f"  ({r.detail})" if r.detail else ""
        n = f"{r.n_candidates} cand" if r.status == SCANNED else ""
        print(f"  {r.app_id:34}{r.status:18}{n}{extra}")
    scanned = sum(r.status == SCANNED for r in results)
    total = sum(r.n_candidates for r in results)
    print(f"\n{scanned}/{len(results)} scanned, {total} candidates 총계")


def _main() -> None:
    parser = argparse.ArgumentParser(description="전 앱 스캔 배치 (P4)")
    parser.add_argument("--workdir", required=True, help="clone/candidate/summary 저장 위치")
    parser.add_argument("--limit", type=int, help="앞 N개만")
    parser.add_argument("--sca", action="store_true", help="SCA(OSV)도 함께")
    parser.add_argument("--dry-run", action="store_true", help="clone 없이 대상만 출력")
    parser.add_argument(
        "--benchmark", action="store_true",
        help="벤치마크 inventory 스캔(B1/B2 정확도 측정용, 정답 있는 앱)",
    )
    parser.add_argument(
        "--use-p2-sources", action="store_true",
        help="clone 대신 P2 소스(.vibecutter/targets/sources/<id>)를 스캔(재-clone 방지)",
    )
    args = parser.parse_args()

    inv_path = Path("datasets/inventory_benchmark.yaml") if args.benchmark else None
    apps = (Inventory.load(inv_path) if inv_path else Inventory.load()).apps
    if args.limit:
        apps = apps[: args.limit]

    if args.dry_run:
        print(f"# {len(apps)}개 앱 스캔 예정 (workdir={args.workdir}, sca={args.sca})")
        for a in apps:
            print(f"  {a.id:34}{a.adapter:16}{a.repo_url}")
        return

    scan_fn = make_default_scan_fn(include_sca=args.sca)
    src_fn = p2_source_root if args.use_p2_sources else None
    results = run_batch(apps, args.workdir, scan_fn=scan_fn, source_root_fn=src_fn)
    _print_results(results)


if __name__ == "__main__":
    _main()
