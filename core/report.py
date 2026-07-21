"""Report 데이터 조인 + HTML 렌더링 (D2-P4.md 요청 (c) 응답 + Extra Day 1-3).

`build_run_report()`가 finding+evidence+patch+validation을 run 단위로 조인하고,
`render_html()`이 그 결과를 부록 B Finding Report Schema 형태의 self-contained HTML로
렌더한다(REPORT.html, DoD C-7). SARIF export는 P4가 같은 `build_run_report` 데이터 소스를
소비한다 — HTML은 P4 응답 지연으로 P1이 채웠고, SARIF만 P4 소유로 남는다.
"""

from __future__ import annotations

import html

from pydantic import BaseModel, Field

from contracts.schemas import Finding, Observation, Patch, Validation
from core.evidence_store import get, list_by_run
from core.redaction import redact


class FindingReportEntry(BaseModel):
    """Finding 하나 + 그 evidence/patch/validation 조인 결과."""

    finding: Finding
    evidence: list[Observation] = Field(default_factory=list)
    patch: Patch | None = None
    validation: Validation | None = None


class RunReport(BaseModel):
    run_id: str
    findings: list[FindingReportEntry] = Field(default_factory=list)


def build_run_report(run_id: str) -> RunReport:
    """run_id의 모든 Finding을 evidence/patch/validation과 조인해 묶는다.

    evidence는 `Finding.evidence_ids`로 조회한다(존재하지 않는 id는 조용히 건너뛴다 —
    `core.evidence_store.update_finding_status`의 하드 가드가 생성 시점에 이미 막으므로
    정상 경로에서는 없어야 하지만, report 조합은 읽기 전용이라 방어적으로 처리한다).
    patch/validation은 같은 run 안에서 `Patch.finding_id`/`Patch.validation_id`로
    역참조한다 — Finding 쪽에는 patch_id를 들고 있지 않기 때문.
    """
    findings = list_by_run(Finding, run_id)
    patches_by_finding = {p.finding_id: p for p in list_by_run(Patch, run_id)}

    entries: list[FindingReportEntry] = []
    for finding in findings:
        evidence = [
            obs for eid in finding.evidence_ids if (obs := get(Observation, eid)) is not None
        ]
        patch = patches_by_finding.get(finding.id)
        validation = get(Validation, patch.validation_id) if patch and patch.validation_id else None
        entries.append(
            FindingReportEntry(finding=finding, evidence=evidence, patch=patch, validation=validation)
        )
    return RunReport(run_id=run_id, findings=entries)


# --- HTML 렌더링 (부록 B Finding Report Schema, Extra Day 1-3) --------------------------
#
# 최종 산출물 REPORT.html(15.1절) + DoD C-7(holdout 결과·실패 사례 보고서)을 위한 최소
# 렌더러. 외부 의존 없이 self-contained HTML을 만든다(SARIF export는 P4가 같은
# build_run_report 데이터 소스를 소비). 모든 사용자/evidence 유래 문자열은 html.escape로
# 이스케이프한다 — evidence에 남은 페이로드/코드가 리포트 마크업을 깨거나 주입되지 않게.

_GATE_LABELS = (
    ("build", "Build"),
    ("attack", "Attack"),
    ("positive_test", "Positive"),
    ("regression", "Regression"),
    ("static", "Static"),
    ("scope", "Scope"),
)


def _esc(value: object) -> str:
    """모든 렌더링 값이 거치는 단일 지점 — 여기서 redaction 후 HTML escape한다(§3A-10).

    `_render_finding`/`render_html`의 모든 동적 값(특히 `patch.diff`, `finding.impact`,
    `root_cause.rationale`처럼 자유 텍스트인 필드)이 예외 없이 `_esc()`를 거치므로,
    `evidence_store.write_artifact()`/prompt 조립과 같은 원칙으로 egress 경계 한 곳에서
    redaction을 걸면 개별 호출부마다 잊고 빠뜨릴 여지가 없다. HTML escape보다 먼저
    적용한다 — escape 후 문자열은 `&`/`<` 등이 엔티티로 바뀌어 redaction 정규식이
    원문과 다르게 매치될 수 있다.
    """
    return html.escape(redact("" if value is None else str(value)))


def _gate_cell(value: object) -> str:
    if value is None:
        return '<td class="gate na">—</td>'
    cls = "pass" if value else "fail"
    return f'<td class="gate {cls}">{"PASS" if value else "FAIL"}</td>'


def _render_finding(entry: FindingReportEntry) -> str:
    f = entry.finding
    rows = [
        ("Status", _esc(f.verification_state)),
        ("CWE", _esc(f.cwe)),
        ("OWASP", _esc(f.owasp_category)),
        ("Severity", _esc(f.severity)),
        ("Endpoint", _esc(f.affected_endpoint)),
        ("Affected roles", _esc(", ".join(f.affected_roles))),
        ("Impact", _esc(f.impact)),
    ]
    meta = "".join(f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in rows)

    root_cause = ""
    if f.root_cause is not None:
        rc = f.root_cause
        root_cause = (
            f"<p class='rootcause'><strong>Root cause:</strong> {_esc(rc.file)}"
            f"{(' · ' + _esc(rc.symbol)) if rc.symbol else ''}"
            f"{(' — ' + _esc(rc.rationale)) if rc.rationale else ''}</p>"
        )

    evidence = ""
    if entry.evidence:
        items = "".join(
            f"<li>{_esc(o.type)} · <code>{_esc(o.producer)}</code> · "
            f"<span class='hash'>{_esc(o.hash[:16])}…</span></li>"
            for o in entry.evidence
        )
        evidence = f"<div class='evidence'><h4>Evidence ({len(entry.evidence)})</h4><ul>{items}</ul></div>"

    patch_html = ""
    if entry.patch is not None:
        patch_html = (
            f"<div class='patch'><h4>Patch <span class='approval'>{_esc(entry.patch.approval)}</span></h4>"
            f"<pre>{_esc(entry.patch.diff)}</pre></div>"
        )

    validation_html = ""
    if entry.validation is not None:
        gates = "".join(_gate_cell(getattr(entry.validation, attr)) for attr, _ in _GATE_LABELS)
        headers = "".join(f"<th>{label}</th>" for _, label in _GATE_LABELS)
        validation_html = (
            f"<div class='validation'><h4>Validation "
            f"<span class='verdict'>{_esc(entry.validation.verdict)}</span></h4>"
            f"<table class='gates'><tr>{headers}</tr><tr>{gates}</tr></table></div>"
        )

    limitations = ""
    if f.limitations:
        items = "".join(f"<li>{_esc(x)}</li>" for x in f.limitations)
        limitations = f"<div class='limitations'><h4>Limitations</h4><ul>{items}</ul></div>"

    return (
        f"<section class='finding sev-{_esc(f.severity)}'>"
        f"<h2>{_esc(f.title)}</h2>"
        f"<table class='meta'>{meta}</table>"
        f"{root_cause}{evidence}{patch_html}{validation_html}{limitations}"
        f"</section>"
    )


_STYLE = """
body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:900px;color:#1a1a1a;line-height:1.5}
h1{border-bottom:2px solid #333;padding-bottom:.3rem}
.finding{border:1px solid #ddd;border-radius:6px;padding:1rem 1.25rem;margin:1.25rem 0}
.finding h2{margin-top:0;font-size:1.15rem}
table.meta{border-collapse:collapse;width:100%;margin:.5rem 0}
table.meta th{text-align:left;width:9rem;color:#555;font-weight:600;padding:.15rem .5rem;vertical-align:top}
table.meta td{padding:.15rem .5rem}
pre{background:#f6f8fa;border:1px solid #e1e4e8;border-radius:4px;padding:.75rem;overflow-x:auto;font-size:.85rem}
.hash{color:#888;font-family:monospace}
.gates{border-collapse:collapse;margin-top:.3rem}
.gates th,.gates td{border:1px solid #ccc;padding:.25rem .6rem;text-align:center;font-size:.8rem}
.gate.pass{background:#e6ffed;color:#22863a;font-weight:600}
.gate.fail{background:#ffeef0;color:#cb2431;font-weight:600}
.gate.na{color:#aaa}
.verdict,.approval{font-size:.8rem;background:#eef;padding:.1rem .4rem;border-radius:3px;margin-left:.4rem}
"""


def render_html(report: RunReport) -> str:
    """RunReport를 self-contained HTML 문자열로 렌더한다(부록 B 스키마)."""
    body = (
        "".join(_render_finding(e) for e in report.findings)
        if report.findings
        else "<p><em>이 run에는 아직 finding이 없습니다.</em></p>"
    )
    return (
        "<!doctype html><html lang='ko'><head><meta charset='utf-8'>"
        f"<title>VibeCutter Report · {_esc(report.run_id)}</title>"
        f"<style>{_STYLE}</style></head><body>"
        f"<h1>Security Audit Report</h1>"
        f"<p>Run <code>{_esc(report.run_id)}</code> · Findings: {len(report.findings)}</p>"
        f"{body}</body></html>"
    )
