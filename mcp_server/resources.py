"""vibecutter:// MCP resources (6.4절).

전부 실데이터를 반환한다(Extra Day 2-1에 더미 제거):
- `vibecutter://targets` — P2 catalog의 checked-in target(Target projection) 목록.
- `vibecutter://targets/{target_id}/manifest` — P2 catalog의 실제 manifest(9.3절).
- `vibecutter://runs/{run_id}/state` — evidence_store의 실제 Run(없으면 ValueError).
- `vibecutter://runs/{run_id}/evidence` — evidence_store의 실제 Observation 목록.
- `vibecutter://findings/{finding_id}` — evidence_store의 실제 Finding(부록 B).
- `vibecutter://policies/scope` — policies/scope.yaml 실제 내용.
- `vibecutter://reports/{run_id}` — vc_generate_report가 저장하는 실제 리포트 경로.

Day1 Notion 완료 기준("Host에서 상태·artifact 조회 가능") + 11.5 P0("Host에서 run 상태와
artifact 조회")를 실제로 충족시킨다 — 예전엔 run state가 항상 REGISTERED 더미를 반환해
"틀린 상태를 자신 있게 보고"하는 문제가 있었다.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from contracts.schemas import Finding, Observation, Run, Target
from core.db import DATA_DIR
from core.evidence_store import get, list_by_run
from core.policy_engine import load_scope
from mcp_server.tools_inventory import _service
from mcp_server.tools_repair import ReportResult
from runtime.manifest import TargetManifest


def register(mcp: FastMCP) -> None:
    @mcp.resource("vibecutter://targets")
    def list_targets() -> list[Target]:
        """checked-in target 목록(P1-facing Target projection). P2 catalog가 진실 소스다."""
        return [rt.contract_target for rt in _service().catalog.list()]

    @mcp.resource("vibecutter://targets/{target_id}/manifest")
    def get_target_manifest(target_id: str) -> TargetManifest:
        """target manifest(9.3절). P2 catalog의 checked-in manifest를 그대로 반환한다."""
        try:
            return _service().catalog.get(target_id).manifest
        except KeyError as exc:
            raise ValueError(f"target {target_id} not found") from exc

    @mcp.resource("vibecutter://runs/{run_id}/state")
    def get_run_state(run_id: str) -> Run:
        """run의 현재 RunState. evidence_store에서 실제 Run을 조회한다."""
        run = get(Run, run_id)
        if run is None:
            raise ValueError(f"run {run_id} not found")
        return run

    @mcp.resource("vibecutter://runs/{run_id}/evidence")
    def get_run_evidence(run_id: str) -> list[Observation]:
        """run에 쌓인 evidence(Observation) 목록. 없으면 빈 목록."""
        return list_by_run(Observation, run_id)

    @mcp.resource("vibecutter://findings/{finding_id}")
    def get_finding(finding_id: str) -> Finding:
        """부록 B Finding Report Schema. evidence_store에서 실제 Finding을 조회한다."""
        finding = get(Finding, finding_id)
        if finding is None:
            raise ValueError(f"finding {finding_id} not found")
        return finding

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
        """run의 최종 리포트 위치. `vc_generate_report`가 저장하는 실제 경로를 반환한다
        (아직 생성 전이면 그 경로가 어디일지를 알려준다 — 파일 존재는 별개)."""
        report_path = DATA_DIR / "runs" / run_id / "report.html"
        return ReportResult(run_id=run_id, artifact_uri=f"file://{report_path}", format="html")
