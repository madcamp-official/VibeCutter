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

from contracts.schemas import Patch, RootCause, Validation


class ReportResult(BaseModel):
    run_id: str
    artifact_uri: str
    format: str


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    def vc_localize_root_cause(finding_id: str) -> RootCause:
        """verified finding의 근본 원인 위치를 추적한다. P3 소유."""
        raise NotImplementedError("P3 root-cause locator 구현 대기")

    @mcp.tool()
    def vc_generate_patch(finding_id: str) -> Patch:
        """root cause 기반 patch 후보를 생성한다(원본 미변경). P3 소유."""
        raise NotImplementedError("P3 repair agent 구현 대기")

    @mcp.tool()
    def vc_apply_patch(patch_id: str, confirmed: bool = False) -> Patch:
        """명시적 승인이 있어야만 git worktree에 patch를 적용한다. 원본 branch는 절대 건드리지 않는다."""
        if not confirmed:
            raise PermissionError("vc_apply_patch는 confirmed=True 없이 호출할 수 없습니다")
        raise NotImplementedError("worktree apply 로직은 Day3에 구현")

    @mcp.tool()
    def vc_build_and_test(patch_id: str) -> Validation:
        """Build gate + Regression gate를 실행한다. P1 배선, P2 test runner 호출."""
        raise NotImplementedError("Day2~3에 judge 게이트로 구현")

    @mcp.tool()
    def vc_replay_attack(patch_id: str) -> Validation:
        """Attack gate: 동일 공격이 더 이상 통하지 않는지 재실행한다. P1 배선, P3 verifier 재사용."""
        raise NotImplementedError("Day2~3에 judge 게이트로 구현")

    @mcp.tool()
    def vc_validate_regression(patch_id: str) -> Validation:
        """Positive functionality gate + Static/Scope gate를 실행한다."""
        raise NotImplementedError("Day2~3에 judge 게이트로 구현")

    @mcp.tool()
    def vc_generate_report(run_id: str) -> ReportResult:
        """부록 B Finding Report Schema 기준 HTML 리포트를 생성한다. P1/P4 소유."""
        raise NotImplementedError("Day3에 report 인프라로 구현")

    @mcp.tool()
    def vc_export_sarif(run_id: str) -> ReportResult:
        """SARIF 포맷으로 export한다."""
        raise NotImplementedError("Day3에 report 인프라로 구현")
