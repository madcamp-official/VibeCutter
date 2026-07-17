"""vibecutter:// MCP resources (6.4절).

target/run/evidence/finding을 담을 evidence_store가 아직 없으므로(item 8에서 구현),
오늘은 최종 스키마 모양을 보여주는 더미 데이터로 응답한다. `vibecutter://policies/scope`는
예외적으로 실제 policies/scope.yaml을 그대로 읽어 반환한다 — 이건 mock이 아니라 진짜
정책 상태다. Finding 관련 resource는 Day2 item 4에서 evidence_store 연동으로 "완성"된다.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from contracts.schemas import Finding, FindingStatus, Observation, Run, RunState, Target
from core.policy_engine import load_scope
from mcp_server.tools_repair import ReportResult


# --- target manifest 형태 (9.3절). P2가 실제 manifest 작성 규격을 확정하면 맞춰 조정한다. ---


class AuthFixture(BaseModel):
    role: str


class BuildSpec(BaseModel):
    command_id: str


class RunSpec(BaseModel):
    command_id: str
    healthcheck: str | None = None


class NetworkPolicy(BaseModel):
    allowed_hosts: list[str] = Field(default_factory=list)
    internet_egress: bool = False


class AuthSpec(BaseModel):
    fixtures: list[AuthFixture] = Field(default_factory=list)


class TestsSpec(BaseModel):
    regression_command_id: str | None = None


class ScopeSpec(BaseModel):
    writable_paths: list[str] = Field(default_factory=list)


class TargetManifest(BaseModel):
    version: int = 1
    id: str
    source_root: str
    stack: list[str] = Field(default_factory=list)
    build: BuildSpec
    run: RunSpec
    network: NetworkPolicy
    auth: AuthSpec
    tests: TestsSpec
    scope: ScopeSpec


# --- 더미 데이터 (evidence_store 연동 전까지) --------------------------------------------


def _dummy_target() -> Target:
    return Target(
        id="scrum-helper",
        manifest_hash="dummy-hash",
        adapter="spring-boot",
        allowed_hosts=["127.0.0.1"],
    )


def _dummy_manifest(target_id: str) -> TargetManifest:
    return TargetManifest(
        id=target_id,
        source_root=f"/lab/targets/{target_id}",
        stack=["react", "spring-boot", "mysql"],
        build=BuildSpec(command_id="spring-react-compose-build"),
        run=RunSpec(
            command_id="docker-compose-up",
            healthcheck="http://127.0.0.1:${PORT}/api/health",
        ),
        network=NetworkPolicy(allowed_hosts=["127.0.0.1", "target-db"], internet_egress=False),
        auth=AuthSpec(
            fixtures=[
                AuthFixture(role="USER_A"),
                AuthFixture(role="USER_B"),
                AuthFixture(role="ADMIN"),
            ]
        ),
        tests=TestsSpec(regression_command_id="gradle-test-plus-playwright"),
        scope=ScopeSpec(writable_paths=["backend/src", "frontend/src", "tests"]),
    )


def _dummy_run(run_id: str) -> Run:
    return Run(id=run_id, target_id="scrum-helper", status=RunState.REGISTERED)


def _dummy_evidence(run_id: str) -> list[Observation]:
    return [
        Observation(
            id="obs-1",
            run_id=run_id,
            type="http_exchange",
            artifact_uri=f"file://.vibecutter/runs/{run_id}/obs-1.json",
            hash="0" * 64,
            producer="vc_verify_access_control",
        )
    ]


def _dummy_finding(finding_id: str) -> Finding:
    return Finding(
        id=finding_id,
        run_id="run-dummy",
        title="(예시) IDOR on DELETE /api/posts/{id}",
        cwe="CWE-639",
        verification_state=FindingStatus.CANDIDATE,
    )


def register(mcp: FastMCP) -> None:
    @mcp.resource("vibecutter://targets")
    def list_targets() -> list[Target]:
        """등록된 target 목록. evidence_store 연동 전까지 예시 1건을 반환한다."""
        return [_dummy_target()]

    @mcp.resource("vibecutter://targets/{target_id}/manifest")
    def get_target_manifest(target_id: str) -> TargetManifest:
        """target manifest(9.3절 형식). P2 manifest 저장소 연동 전까지 예시를 반환한다."""
        return _dummy_manifest(target_id)

    @mcp.resource("vibecutter://runs/{run_id}/state")
    def get_run_state(run_id: str) -> Run:
        """run의 현재 RunState. evidence_store 연동 전까지 예시를 반환한다."""
        return _dummy_run(run_id)

    @mcp.resource("vibecutter://runs/{run_id}/evidence")
    def get_run_evidence(run_id: str) -> list[Observation]:
        """run에 쌓인 evidence(Observation) 목록. evidence_store 연동 전까지 예시를 반환한다."""
        return _dummy_evidence(run_id)

    @mcp.resource("vibecutter://findings/{finding_id}")
    def get_finding(finding_id: str) -> Finding:
        """부록 B Finding Report Schema. evidence_store 연동은 Day2에 완성한다(현재는 예시)."""
        return _dummy_finding(finding_id)

    @mcp.resource("vibecutter://policies/scope")
    def get_scope_policy() -> dict:
        """target allowlist 정책 — mock이 아니라 policies/scope.yaml 실제 내용.

        core.policy_engine.load_scope()를 그대로 재사용한다 — 이 파일을 읽는 로직이
        두 군데(정책 강제 경로 + 조회용 resource)에서 따로 구현되어 있으면, 한쪽만
        고치고 다른 쪽(예: 파일 없을 때 에러 처리)을 놓치기 쉽다.
        """
        return {"targets": load_scope()}

    @mcp.resource("vibecutter://reports/{run_id}")
    def get_report(run_id: str) -> ReportResult:
        """run의 최종 리포트 위치. report 인프라(Day3) 연동 전까지 예시를 반환한다."""
        return ReportResult(
            run_id=run_id,
            artifact_uri=f".vibecutter/runs/{run_id}/report.html",
            format="html",
        )
