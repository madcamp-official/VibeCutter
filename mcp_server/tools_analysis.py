"""Mapping + Analysis + Verification 카테고리 MCP tools.

vc_map_routes, vc_map_roles, vc_index_code (Mapping)
vc_run_sast, vc_run_sca, vc_run_secret_scan, vc_browser_crawl (Analysis)
vc_verify_access_control, vc_verify_injection, vc_verify_xss (Verification)

전부 P3(공격 표면/verifier) 또는 P4(SAST/SCA/secret) 소유이며, 오늘은 부록 A 방식으로
스키마만 고정한다. Verification 도구의 실배선(승인 게이트 + judge 연동)은 Day2에 한다.
"""

from __future__ import annotations

from typing import Annotated

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from contracts.schemas import VerificationResult
from core.audit_log import audited
from verifiers.types import MAX_REQUESTS_DEFAULT, MAX_REQUESTS_MAX, MAX_REQUESTS_MIN

# 부록 A `max_requests` 입력 제약(`{"type":"integer","minimum":1,"maximum":20}`)을 실제
# 생성 inputSchema에 반영한다. D1-P3.md 구멍 ③: 예전에는 `max_requests: int = 10`뿐이라
# 스키마에 min/max가 없어 `max_requests=100000`도 통과했다.
MaxRequests = Annotated[int, Field(ge=MAX_REQUESTS_MIN, le=MAX_REQUESTS_MAX)]


class MapResult(BaseModel):
    run_id: str
    observation_ids: list[str] = Field(default_factory=list)
    summary: str | None = None


class ScanResult(BaseModel):
    run_id: str
    tool: str
    candidate_ids: list[str] = Field(default_factory=list)


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    @audited
    def vc_map_routes(run_id: str) -> MapResult:
        """소스 route + 동적 크롤링으로 endpoint를 수집한다. P3 소유."""
        raise NotImplementedError("P3 attack surface mapper 구현 대기")

    @mcp.tool()
    @audited
    def vc_map_roles(run_id: str) -> MapResult:
        """역할별 접근 가능 endpoint를 매핑한다. P3 소유."""
        raise NotImplementedError("P3 attack surface mapper 구현 대기")

    @mcp.tool()
    @audited
    def vc_index_code(run_id: str) -> MapResult:
        """소스 코드 심볼 그래프를 인덱싱한다. P3 소유."""
        raise NotImplementedError("P3 attack surface mapper 구현 대기")

    @mcp.tool()
    @audited
    def vc_run_sast(run_id: str) -> ScanResult:
        """Semgrep 등 정적 분석으로 candidate를 생성한다. P4 소유."""
        raise NotImplementedError("P4 Semgrep 통합 대기")

    @mcp.tool()
    @audited
    def vc_run_sca(run_id: str) -> ScanResult:
        """dependency/SBOM 취약점을 스캔한다. P4 소유."""
        raise NotImplementedError("P4 SCA 통합 대기")

    @mcp.tool()
    @audited
    def vc_run_secret_scan(run_id: str) -> ScanResult:
        """secret exposure를 스캔한다. P4 소유."""
        raise NotImplementedError("P4 secret scanner 통합 대기")

    @mcp.tool()
    @audited
    def vc_browser_crawl(run_id: str) -> ScanResult:
        """Playwright로 역할별 화면을 크롤링해 behavioral diff candidate를 만든다. P3 소유."""
        raise NotImplementedError("P3 Playwright crawler 구현 대기")

    @mcp.tool()
    @audited
    def vc_verify_access_control(
        run_id: str, candidate_id: str, max_requests: MaxRequests = MAX_REQUESTS_DEFAULT
    ) -> VerificationResult:
        """Broken Access Control/IDOR 후보를 실제 재현으로 검증한다. P3 소유."""
        raise NotImplementedError("P3 verifier 구현 대기, Day2에 승인 게이트 배선")

    @mcp.tool()
    @audited
    def vc_verify_injection(
        run_id: str, candidate_id: str, max_requests: MaxRequests = MAX_REQUESTS_DEFAULT
    ) -> VerificationResult:
        """SQL/Command Injection 후보를 제한된 fixture에서 검증한다. P3 소유."""
        raise NotImplementedError("P3 verifier 구현 대기, Day2에 승인 게이트 배선")

    @mcp.tool()
    @audited
    def vc_verify_xss(
        run_id: str, candidate_id: str, max_requests: MaxRequests = MAX_REQUESTS_DEFAULT
    ) -> VerificationResult:
        """XSS 후보를 격리 브라우저의 benign marker로 검증한다. P3 소유."""
        raise NotImplementedError("P3 verifier 구현 대기, Day2에 승인 게이트 배선")
