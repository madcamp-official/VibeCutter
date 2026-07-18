"""Repair + Mutation + Judge + Report 카테고리 MCP tools.

vc_localize_root_cause, vc_generate_patch (Repair, P3 소유)
vc_apply_patch (Mutation, P1 게이트 — 명시적 승인 없이는 호출 불가)
vc_build_and_test, vc_replay_attack, vc_validate_regression (Judge, P1 배선)
vc_generate_report, vc_export_sarif (Report, P1/P4 소유)

generate와 apply를 별도 도구로 분리하는 것은 절대 원칙(원본 branch 직접 변경 금지,
worktree에만 적용, 6.7절)과 직결되므로 오늘부터 시그니처로 강제한다: apply는
`confirmed: bool` 없이는 무조건 거부한다.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

from contracts.schemas import Finding, Patch, RootCause, Run, Validation
from core.audit_log import audited
from core.evidence_store import get
from mcp_server.tools_inventory import _service
from repair.locator import localize


class ReportResult(BaseModel):
    run_id: str
    artifact_uri: str
    format: str


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    @audited
    def vc_localize_root_cause(finding_id: str) -> RootCause:
        """verified finding의 근본 원인 위치를 추적한다.

        실제 판정 로직은 P3 소유(`repair.locator.localize`) — P1은 finding → run → target →
        source_root(P2 `catalog.source_root_for(target_id)`, 경로 탈출 검사 포함)를 조회해
        넘기는 배선만 담당한다(D3-P3.md 요청).

        **[갱신 — D1-P2.md 12:14본에서 해소 확인]** 예전엔 3개 manifest가 `role_fixtures.secret_env_names`
        검증 실패로 catalog 전체 로드가 죽어 있었으나, P2가 수정해 checked-in manifest 22개가
        전부 `TargetCatalog.load()`를 통과한다 — 이 tool은 이제 실제 target으로 호출 가능하다.
        """
        finding = get(Finding, finding_id)
        if finding is None:
            raise ValueError(f"finding {finding_id} not found")
        run = get(Run, finding.run_id)
        if run is None:
            raise ValueError(f"run {finding.run_id} not found")

        source_root = _service().catalog.source_root_for(run.target_id)
        return localize(finding, source_root=source_root)

    @mcp.tool()
    @audited
    def vc_generate_patch(finding_id: str) -> Patch:
        """root cause 기반 patch 후보를 생성한다(원본 미변경). P3 소유."""
        raise NotImplementedError("P3 repair agent 구현 대기")

    @mcp.tool()
    @audited
    def vc_apply_patch(patch_id: str, confirmed: bool = False) -> Patch:
        """명시적 승인이 있어야만 git worktree에 patch를 적용한다. 원본 branch는 절대 건드리지 않는다."""
        if not confirmed:
            raise PermissionError("vc_apply_patch는 confirmed=True 없이 호출할 수 없습니다")
        raise NotImplementedError("worktree apply 로직은 Day3에 구현")

    @mcp.tool()
    @audited
    def vc_build_and_test(patch_id: str) -> Validation:
        """Build gate + Regression gate를 실행한다. P1 배선, P2 test runner 호출."""
        raise NotImplementedError("Day2~3에 judge 게이트로 구현")

    @mcp.tool()
    @audited
    def vc_replay_attack(patch_id: str) -> Validation:
        """Attack gate: 동일 공격이 더 이상 통하지 않는지 재실행한다. P1 배선, P3 verifier 재사용."""
        raise NotImplementedError("Day2~3에 judge 게이트로 구현")

    @mcp.tool()
    @audited
    def vc_validate_regression(patch_id: str) -> Validation:
        """Positive functionality gate + Static/Scope gate를 실행한다."""
        raise NotImplementedError("Day2~3에 judge 게이트로 구현")

    @mcp.tool()
    @audited
    def vc_generate_report(run_id: str) -> ReportResult:
        """부록 B Finding Report Schema 기준 HTML 리포트를 생성한다. P1/P4 소유."""
        raise NotImplementedError("Day3에 report 인프라로 구현")

    @mcp.tool()
    @audited
    def vc_export_sarif(run_id: str) -> ReportResult:
        """SARIF 포맷으로 export한다."""
        raise NotImplementedError("Day3에 report 인프라로 구현")
