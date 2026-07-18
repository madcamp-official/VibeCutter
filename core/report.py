"""Report 데이터 조인 (D2-P4.md 요청 (c) 응답).

P4가 Day3에 만드는 HTML/SARIF export(`vc_generate_report`/`vc_export_sarif`)가 그대로
순회해 소비할 수 있도록, finding+evidence+patch+validation을 run 단위로 미리 조인해 둔다.
실제 HTML/SARIF 렌더링은 P4 소유 — 여기는 그 입력 데이터 소스만 준비한다.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from contracts.schemas import Finding, Observation, Patch, Validation
from core.evidence_store import get, list_by_run


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
