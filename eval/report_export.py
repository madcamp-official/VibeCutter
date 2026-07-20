"""SARIF 리포트 export (P4 소유) + HTML export(위임).

입력: P1 의 `core.report.build_run_report(run_id) -> RunReport`
(finding + evidence + patch + validation 조인).

**소유권(rebase 후 정리)**: HTML 렌더링은 P1 이 `core.report.render_html` 로 채웠다
(공식 REPORT.html). 여기서는 그걸 위임 호출만 하고, **SARIF 2.1.0 렌더링만 P4 소유**로
유지한다(중복 HTML 렌더러 제거). SARIF → GitHub code scanning 등 표준 도구에 업로드 가능.

구조: 순수 렌더러 `render_sarif(report)` — RunReport 만 받아 dict 를 낸다(목으로 유닛테스트).
wrapper `export_report(run_id, ...)` — build_run_report(DB 조회) 후 파일로 쓴다.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional

from core.report import (
    FindingReportEntry,
    RunReport,
    build_run_report,
    render_html,  # HTML 은 P1 소유(core.report) — 위임
)

# severity(정규 5단계, scanners.vocab.SEVERITY) → SARIF level.
_SARIF_LEVEL = {
    "critical": "error", "high": "error",
    "medium": "warning",
    "low": "note", "info": "note",
}

# validation 6게이트(SARIF properties.validation 에 첨부).
_GATE_LABELS = [
    ("build", "빌드"), ("attack", "공격 차단"), ("positive_test", "정상 기능"),
    ("regression", "회귀"), ("static", "정적"), ("scope", "범위"),
]


# --- 위치 파싱: source_symbols "파일:줄" -----------------------------------------------

def _split_location(sym: str) -> tuple[str, Optional[int]]:
    """"app/db/users.py:5" → ("app/db/users.py", 5). 줄 없으면 (sym, None)."""
    if ":" in sym:
        path, _, tail = sym.rpartition(":")
        if path and tail.isdigit():
            return path, int(tail)
    return sym, None


# --- SARIF (P4 소유) -------------------------------------------------------------------

def _finding_to_sarif_result(entry: FindingReportEntry) -> dict:
    f = entry.finding
    level = _SARIF_LEVEL.get((f.severity or "").lower(), "warning")
    locations = []
    for sym in f.source_symbols or ([f.affected_endpoint] if f.affected_endpoint else []):
        if not sym:
            continue
        uri, line = _split_location(sym)
        phys: dict = {"artifactLocation": {"uri": uri}}
        if line is not None:
            phys["region"] = {"startLine": line}
        locations.append({"physicalLocation": phys})

    msg = f.title
    if f.impact:
        msg += f" — {f.impact}"

    validation = None
    if entry.validation is not None:
        validation = {k: getattr(entry.validation, k) for k, _ in _GATE_LABELS}
        validation["verdict"] = entry.validation.verdict

    result = {
        "ruleId": f.cwe or "vibecutter",
        "level": level,
        "message": {"text": msg},
        "properties": {
            "owasp": f.owasp_category,
            "severity": f.severity,
            "verification_state": str(f.verification_state),
            "confidence": f.confidence,
            "affected_roles": f.affected_roles,
            "evidence_count": len(entry.evidence),
            "patched": entry.patch is not None,
            "validation": validation,
        },
    }
    if locations:
        result["locations"] = locations
    return result


def render_sarif(report: RunReport) -> dict:
    """RunReport → SARIF 2.1.0 dict. json.dumps 로 직렬화하면 표준 파일."""
    rule_ids = sorted({e.finding.cwe for e in report.findings if e.finding.cwe})
    rules = [{"id": rid, "name": rid} for rid in rule_ids]
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "VibeCutter",
                "informationUri": "https://github.com/vibecutter",
                "rules": rules,
            }},
            "properties": {"run_id": report.run_id},
            "results": [_finding_to_sarif_result(e) for e in report.findings],
        }],
    }


# --- wrapper ---------------------------------------------------------------------------

def export_report(
    run_id: str, *, html_path: Optional[str | Path] = None,
    sarif_path: Optional[str | Path] = None, report: Optional[RunReport] = None,
) -> RunReport:
    """run_id 의 리포트를 HTML/SARIF 파일로 쓴다. HTML 은 core.report.render_html(P1),
    SARIF 는 render_sarif(P4). report 를 주면 그걸 쓰고, 없으면 build_run_report 로
    DB 에서 조립한다(테스트는 report 주입으로 DB 우회)."""
    rep = report if report is not None else build_run_report(run_id)
    if html_path is not None:
        Path(html_path).write_text(render_html(rep), encoding="utf-8")
    if sarif_path is not None:
        Path(sarif_path).write_text(json.dumps(render_sarif(rep), indent=2, ensure_ascii=False),
                                    encoding="utf-8")
    return rep


def _main() -> None:
    ap = argparse.ArgumentParser(description="HTML/SARIF 리포트 export (P4)")
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--html", help="HTML 출력 경로 (core.report.render_html)")
    ap.add_argument("--sarif", help="SARIF 출력 경로 (P4 render_sarif)")
    args = ap.parse_args()
    if not args.html and not args.sarif:
        ap.error("--html 또는 --sarif 중 최소 하나가 필요하다")
    rep = export_report(args.run_id, html_path=args.html, sarif_path=args.sarif)
    print(f"[report] run={rep.run_id} findings={len(rep.findings)} "
          f"html={args.html or '-'} sarif={args.sarif or '-'}")


if __name__ == "__main__":
    _main()
