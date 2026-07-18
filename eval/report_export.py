"""HTML / SARIF 리포트 export (P4, D3 완료기준 "report 1건 export").

입력: P1 의 `core.report.build_run_report(run_id) -> RunReport`
(finding + evidence + patch + validation 조인). 렌더링은 P4 소유(D3-P1 합의).

구조(프로젝트의 순수+wrapper 패턴):
- **순수 렌더러** `render_html(report)` / `render_sarif(report)` — RunReport 만 받아
  문자열/dict 를 낸다. DB·evidence_store 불필요 → 목 RunReport 로 유닛테스트.
- **wrapper** `export_report(run_id, ...)` — build_run_report(DB 조회) 후 파일로 쓴다.

SARIF 2.1.0 로 낸다 → GitHub code scanning 등 표준 도구에 그대로 업로드 가능.
"""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from typing import Optional

from core.report import FindingReportEntry, RunReport, build_run_report

# severity(정규 5단계, scanners.vocab.SEVERITY) → SARIF level.
_SARIF_LEVEL = {
    "critical": "error", "high": "error",
    "medium": "warning",
    "low": "note", "info": "note",
}

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


# --- SARIF -----------------------------------------------------------------------------

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


# --- HTML ------------------------------------------------------------------------------

def _esc(v: object) -> str:
    return html.escape("" if v is None else str(v))


def _gate_badges(entry: FindingReportEntry) -> str:
    if entry.validation is None:
        return '<span class="muted">검증 없음</span>'
    out = []
    for attr, label in _GATE_LABELS:
        v = getattr(entry.validation, attr)
        cls = "pass" if v is True else ("fail" if v is False else "na")
        mark = "✓" if v is True else ("✗" if v is False else "–")
        out.append(f'<span class="gate {cls}">{label} {mark}</span>')
    return "".join(out)


def _finding_card(entry: FindingReportEntry, idx: int) -> str:
    f = entry.finding
    sev = (f.severity or "unknown").lower()
    meta = " · ".join(_esc(x) for x in [f.cwe, f.owasp_category, f.affected_endpoint] if x)
    evidence_rows = "".join(
        f'<li><code>{_esc(o.type)}</code> {_esc(o.artifact_uri)} '
        f'<span class="muted">({_esc(o.producer)}, {_esc(o.hash)[:12]})</span></li>'
        for o in entry.evidence
    ) or '<li class="muted">증거 없음</li>'
    steps = "".join(f"<li>{_esc(s)}</li>" for s in f.reproduction_steps)
    steps_html = f"<h4>재현 절차</h4><ol>{steps}</ol>" if steps else ""
    patch_html = ""
    if entry.patch is not None:
        patch_html = (
            f'<h4>패치 <span class="muted">({_esc(entry.patch.approval)}, '
            f'시도 {entry.patch.attempt_no})</span></h4>'
            f'<pre class="diff">{_esc(entry.patch.diff)}</pre>'
        )
    return f"""
    <section class="finding sev-{_esc(sev)}">
      <header>
        <span class="sev-badge sev-{_esc(sev)}">{_esc(sev)}</span>
        <h3>#{idx} {_esc(f.title)}</h3>
        <span class="state">{_esc(f.verification_state)}</span>
      </header>
      <p class="meta">{meta or '<span class="muted">메타 없음</span>'}</p>
      <div class="gates">{_gate_badges(entry)}</div>
      {steps_html}
      <h4>증거 ({len(entry.evidence)})</h4>
      <ul class="evidence">{evidence_rows}</ul>
      {patch_html}
    </section>"""


def render_html(report: RunReport) -> str:
    """RunReport → 자기완결 HTML 문자열(인라인 CSS, 라이트/다크 대응)."""
    n = len(report.findings)
    by_state: dict[str, int] = {}
    for e in report.findings:
        s = str(e.finding.verification_state)
        by_state[s] = by_state.get(s, 0) + 1
    summary = " · ".join(f"{k}: {v}" for k, v in sorted(by_state.items())) or "finding 없음"
    cards = "".join(_finding_card(e, i + 1) for i, e in enumerate(report.findings))
    return f"""<!doctype html>
<html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VibeCutter Report — {_esc(report.run_id)}</title>
<style>
  :root {{ color-scheme: light dark;
    --bg:#fff; --fg:#1a1a1a; --muted:#6b7280; --card:#f7f7f8; --border:#e5e7eb;
    --crit:#b91c1c; --high:#dc2626; --med:#d97706; --low:#2563eb; --info:#6b7280;
    --pass:#16a34a; --fail:#dc2626; --na:#9ca3af; }}
  @media (prefers-color-scheme: dark) {{ :root {{
    --bg:#0f1115; --fg:#e5e7eb; --muted:#9ca3af; --card:#181b21; --border:#2a2f3a; }} }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; padding:2rem 1rem; background:var(--bg); color:var(--fg);
    font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }}
  .wrap {{ max-width:900px; margin:0 auto; }}
  h1 {{ font-size:1.5rem; margin:0 0 .25rem; }}
  .sub {{ color:var(--muted); margin:0 0 1.5rem; }}
  .finding {{ background:var(--card); border:1px solid var(--border);
    border-left:4px solid var(--info); border-radius:8px; padding:1rem 1.25rem; margin:1rem 0; }}
  .finding.sev-critical {{ border-left-color:var(--crit); }}
  .finding.sev-high {{ border-left-color:var(--high); }}
  .finding.sev-medium {{ border-left-color:var(--med); }}
  .finding.sev-low {{ border-left-color:var(--low); }}
  .finding header {{ display:flex; align-items:center; gap:.6rem; flex-wrap:wrap; }}
  .finding h3 {{ margin:0; font-size:1.05rem; flex:1; }}
  .sev-badge {{ font-size:.7rem; text-transform:uppercase; font-weight:700; color:#fff;
    padding:.15rem .5rem; border-radius:4px; background:var(--info); }}
  .sev-badge.sev-critical {{ background:var(--crit); }}
  .sev-badge.sev-high {{ background:var(--high); }}
  .sev-badge.sev-medium {{ background:var(--med); }}
  .sev-badge.sev-low {{ background:var(--low); }}
  .state {{ font-size:.8rem; color:var(--muted); border:1px solid var(--border);
    padding:.1rem .5rem; border-radius:999px; }}
  .meta {{ color:var(--muted); font-size:.9rem; margin:.5rem 0; }}
  .gates {{ display:flex; gap:.4rem; flex-wrap:wrap; margin:.5rem 0; }}
  .gate {{ font-size:.75rem; padding:.1rem .45rem; border-radius:4px; border:1px solid var(--border); }}
  .gate.pass {{ color:var(--pass); border-color:var(--pass); }}
  .gate.fail {{ color:var(--fail); border-color:var(--fail); }}
  .gate.na {{ color:var(--na); }}
  h4 {{ margin:.9rem 0 .3rem; font-size:.85rem; text-transform:uppercase;
    letter-spacing:.03em; color:var(--muted); }}
  ul,ol {{ margin:.3rem 0; padding-left:1.4rem; }}
  code {{ background:var(--border); padding:.05rem .3rem; border-radius:3px; font-size:.85em; }}
  .muted {{ color:var(--muted); }}
  pre.diff {{ background:var(--bg); border:1px solid var(--border); border-radius:6px;
    padding:.75rem; overflow-x:auto; font-size:.82rem; }}
</style></head>
<body><div class="wrap">
  <h1>VibeCutter 리포트</h1>
  <p class="sub">run <code>{_esc(report.run_id)}</code> · finding {n}건 · {_esc(summary)}</p>
  {cards or '<p class="muted">finding 이 없습니다.</p>'}
</div></body></html>"""


# --- wrapper ---------------------------------------------------------------------------

def export_report(
    run_id: str, *, html_path: Optional[str | Path] = None,
    sarif_path: Optional[str | Path] = None, report: Optional[RunReport] = None,
) -> RunReport:
    """run_id 의 리포트를 HTML/SARIF 파일로 쓴다. report 를 주면 그걸 쓰고, 없으면
    build_run_report 로 DB 에서 조립한다(테스트는 report 주입으로 DB 우회)."""
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
    ap.add_argument("--html", help="HTML 출력 경로")
    ap.add_argument("--sarif", help="SARIF 출력 경로")
    args = ap.parse_args()
    if not args.html and not args.sarif:
        ap.error("--html 또는 --sarif 중 최소 하나가 필요하다")
    rep = export_report(args.run_id, html_path=args.html, sarif_path=args.sarif)
    print(f"[report] run={rep.run_id} findings={len(rep.findings)} "
          f"html={args.html or '-'} sarif={args.sarif or '-'}")


if __name__ == "__main__":
    _main()
