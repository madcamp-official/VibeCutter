"""Inventory + Lifecycle 카테고리 MCP tools (기획서 11.2절 repo 구조 기준 3-file 그룹핑).

vc_register_target, vc_inspect_stack, vc_check_readiness (Inventory)
vc_build_target, vc_start_target, vc_reset_target (Lifecycle)

Lifecycle 도구의 실제 빌드/실행/reset 로직은 P2(target manifest/adapter) 소유다.
여기서는 부록 A 방식으로 스키마만 고정하고 본문은 NotImplementedError로 남겨둔다.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from contracts.schemas import Run, Target


class StackInfo(BaseModel):
    target_id: str
    stack: list[str] = Field(default_factory=list)
    detected_by: str


class ReadinessResult(BaseModel):
    target_id: str
    ready: bool
    reasons: list[str] = Field(default_factory=list)


class RuntimeHandleInfo(BaseModel):
    target_id: str
    base_url: str | None = None
    healthy: bool = False


class ResetResult(BaseModel):
    target_id: str
    ok: bool


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    def vc_register_target(manifest: dict) -> Target:
        """manifest(9.3절 형식)를 policy allowlist에 등록하고 Target을 반환한다."""
        raise NotImplementedError("policy_engine 연동 후 구현 (Day1 오후 후반)")

    @mcp.tool()
    def vc_inspect_stack(target_id: str) -> StackInfo:
        """target의 실행 스택을 탐지한다. P2 adapter.detect() 소유."""
        raise NotImplementedError("P2 adapter 구현 대기")

    @mcp.tool()
    def vc_check_readiness(target_id: str) -> ReadinessResult:
        """target이 등록/빌드/실행 가능한 상태인지 확인한다."""
        raise NotImplementedError("policy_engine/evidence_store 연동 후 구현")

    @mcp.tool()
    def vc_build_target(target_id: str) -> Run:
        """target을 빌드한다(BUILDING→READY). P2 adapter.build() 소유."""
        raise NotImplementedError("P2 adapter.build() 구현 대기")

    @mcp.tool()
    def vc_start_target(target_id: str) -> RuntimeHandleInfo:
        """격리 환경에서 target을 실행한다. P2 adapter.start() 소유."""
        raise NotImplementedError("P2 adapter.start() 구현 대기")

    @mcp.tool()
    def vc_reset_target(target_id: str) -> ResetResult:
        """DB seed/volume snapshot을 복원한다. P2 adapter.reset() 소유."""
        raise NotImplementedError("P2 adapter.reset() 구현 대기")
