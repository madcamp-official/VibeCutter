"""Mapping + Analysis + Verification 카테고리 MCP tools.

vc_map_routes, vc_map_roles, vc_index_code (Mapping)
vc_run_sast, vc_run_sca, vc_run_secret_scan, vc_browser_crawl (Analysis)
vc_verify_access_control, vc_verify_injection, vc_verify_xss (Verification)

Mapping 도구(vc_map_*)는 P3(공격 표면) 소유이며 아직 스텁이다. vc_run_sast/vc_run_sca는
Day3에 P1이 실배선했다(D2-P4.md 요청 (e)): policy 검사 + CANDIDATE_SCAN 전이 + target
source_root 조회는 P1, 실제 스캐너(`scanners.sast.run_semgrep`/`scanners.sca.run_osv`)와
FP reject/우선순위(`scanners.aggregate.aggregate`)는 P4 소유를 그대로 호출한다.
vc_run_secret_scan/vc_browser_crawl은 아직 스텁(각각 P4/P3 소유). Verification 도구는
Day2에 P1이 실배선했다: policy 검사 + run-level 승인 게이트 + RunState 전이 +
Candidate→Finding 승격 + evidence 기반 judge 판정(core.evidence_store.update_finding_status)은
P1이 맡고, "이 후보가 실제 보안 영향인가"만 판정하는 verifier 본문은 P3 소유(`verifiers/*.py`)를
그대로 호출한다.
"""

from __future__ import annotations

from typing import Annotated

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from contracts.schemas import Candidate, Finding, FindingStatus, Run, RunState, VerificationResult
from core.audit_log import audited
from core.evidence_store import find_or_create_finding, get, save, update_finding_status
from core.policy_engine import require_target_allowed
from core.state_machine import transition
from core.trajectory import record_trajectory_step
from mcp_server.tools_inventory import _service
from scanners.aggregate import aggregate
from scanners.sast import run_semgrep
from scanners.sca import run_osv
from verifiers.access_control import verify as verify_access_control
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


def _prepare_verification(
    run_id: str, candidate_id: str, *, approved: bool, tool_name: str
) -> tuple[Run, Candidate, Finding]:
    """모든 `vc_verify_*` tool이 공유하는 배선: 승인 게이트 → policy 검사 → VERIFYING 전이
    → candidate 조회 → Finding 지연 생성(find_or_create_finding).

    verifier 호출과 최종 Finding 판정(update_finding_status)은 각 tool 본문이 이어서 한다
    (verifier마다 실제 재현 로직이 다르므로 여기서 하지 않는다).

    **알려진 한계**: 여기서는 `run.target_id`가 정책에 등록됐는지만 확인한다(`require_target_allowed`).
    verifier가 실제로 요청을 보낼 host/port까지 이 계층에서 검사하려면 Candidate에 typed
    공격 파라미터가 있어야 하는데 아직 없다(오늘 계약 이견 섹션의 `vuln_class`/`attack_params`
    항목, D1-P3.md 이견 1) — 스키마가 개선되면 여기서 `require_host_allowed`도 추가한다.
    """
    if not approved:
        raise PermissionError(f"{tool_name}는 run-level 승인(approved=True) 없이 호출할 수 없습니다")

    run = get(Run, run_id)
    if run is None:
        raise ValueError(f"run {run_id} not found")
    require_target_allowed(run.target_id)

    if run.status != RunState.VERIFYING:
        run.status = transition(run.status, RunState.VERIFYING)
        save(run)

    candidate = get(Candidate, candidate_id)
    if candidate is None:
        raise ValueError(f"candidate {candidate_id} not found")

    finding = find_or_create_finding(run_id, candidate)
    return run, candidate, finding


def _prepare_scan(run_id: str, *, tool_name: str) -> Run:
    """`vc_run_sast`/`vc_run_sca`가 공유하는 배선: policy 검사 → CANDIDATE_SCAN 전이(1회만).

    **알려진 한계(D2-P4.md 요청 (e) 배선 중 발견)**: RunState 그래프(`core/state_machine.py`)는
    READY→MAPPING→CANDIDATE_SCAN 순서를 강제하는데, MAPPING 도구(`vc_map_routes` 등, P3 소유)가
    아직 스텁이라 실제로 Run을 READY→MAPPING으로 옮기는 tool call 경로가 없다. 그래서 이 함수는
    Run이 이미 MAPPING이면 CANDIDATE_SCAN으로 1회 전이하고, 이미 CANDIDATE_SCAN이면 그대로
    두어 `vc_run_sast`/`vc_run_sca`를 여러 번(스캐너별로) 호출할 수 있게 한다 — `_prepare_verification`이
    VERIFYING을 멱등하게 다루는 것과 같은 패턴. MAPPING도 CANDIDATE_SCAN도 아니면 명확한 에러로
    거부한다(P3 mapping 완료 전까지는 테스트/리허설에서 Run을 직접 CANDIDATE_SCAN으로 만들어야
    한다 — `tests/test_verify_tool_wiring.py`가 이미 이 방식을 쓰고 있다).
    """
    run = get(Run, run_id)
    if run is None:
        raise ValueError(f"run {run_id} not found")
    require_target_allowed(run.target_id)

    if run.status == RunState.MAPPING:
        run.status = transition(run.status, RunState.CANDIDATE_SCAN)
        save(run)
    elif run.status != RunState.CANDIDATE_SCAN:
        raise ValueError(
            f"{tool_name}는 run이 MAPPING 또는 CANDIDATE_SCAN 상태여야 호출할 수 있습니다"
            f"(현재 {run.status})"
        )
    return run


def _store_scan_candidates(
    run: Run, candidates: list[Candidate], *, tool: str
) -> ScanResult:
    """공통 후처리: FP reject+우선순위(`scanners.aggregate.aggregate`) → kept만 저장 → trajectory 기록.

    **알려진 한계(D2-P4.md 요청 (b) 결정)**: 이 tool 자기 스캐너 결과만 aggregate하므로
    SAST·SCA 교차 중복 제거는 안 된다 — 두 tool이 독립 호출되기 때문. 스캔 완료 시점을
    묶는 별도 단계가 생기면 그때 cross-scanner aggregate로 바꾼다.
    """
    result = aggregate(candidates)
    for candidate in result.kept:
        save(candidate)
    record_trajectory_step(
        run.id,
        state=run.status,
        action={"tool": tool},
        result=result.summary,
        next_state=run.status,
    )
    return ScanResult(run_id=run.id, tool=tool, candidate_ids=[c.id for c in result.kept])


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
        """Semgrep 정적 분석으로 candidate를 생성한다.

        실제 스캐너(`scanners.sast.run_semgrep`)와 FP reject/우선순위(`scanners.aggregate.aggregate`)는
        P4 소유 — P1은 policy 검사/상태 전이/target source_root 조회/candidate 저장/trajectory
        기록만 배선한다(D2-P4.md 요청 (e)).

        **알려진 한계**: `semgrep` 바이너리가 PATH에 없으면 `SemgrepUnavailableError`가 그대로
        전파된다(로컬에 설치되지 않은 환경 다수).
        """
        run = _prepare_scan(run_id, tool_name="vc_run_sast")
        source_root = _service().catalog.source_root_for(run.target_id)
        candidates = run_semgrep(source_root, run_id=run_id)
        return _store_scan_candidates(run, candidates, tool="vc_run_sast")

    @mcp.tool()
    @audited
    def vc_run_sca(run_id: str) -> ScanResult:
        """OSV-Scanner로 dependency/SBOM 취약점 candidate를 생성한다.

        실제 스캐너(`scanners.sca.run_osv`)와 FP reject/우선순위(`scanners.aggregate.aggregate`)는
        P4 소유 — P1은 policy 검사/상태 전이/target source_root 조회/candidate 저장/trajectory
        기록만 배선한다(D2-P4.md 요청 (e)).

        **알려진 한계**: `osv-scanner` 바이너리가 PATH에 없으면 `OSVUnavailableError`가 그대로
        전파된다(로컬에 설치되지 않은 환경 다수).
        """
        run = _prepare_scan(run_id, tool_name="vc_run_sca")
        source_root = _service().catalog.source_root_for(run.target_id)
        candidates = run_osv(source_root, run_id=run_id)
        return _store_scan_candidates(run, candidates, tool="vc_run_sca")

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
        run_id: str,
        candidate_id: str,
        max_requests: MaxRequests = MAX_REQUESTS_DEFAULT,
        approved: bool = False,
    ) -> VerificationResult:
        """Broken Access Control/IDOR 후보를 실제 재현으로 검증한다.

        policy 검사/승인 게이트/RunState 전이/Finding 판정은 P1이 배선했다. 실제 재현·판정
        로직(`verifiers.access_control.verify`)은 P3 소유 — Day2에 WebGoat로 검증 완료.
        """
        _, candidate, finding = _prepare_verification(
            run_id, candidate_id, approved=approved, tool_name="vc_verify_access_control"
        )
        result = verify_access_control(run_id, candidate, max_requests=max_requests)
        target_status = FindingStatus.VERIFIED if result.verified else FindingStatus.REJECTED
        update_finding_status(finding.id, target_status, evidence_ids=result.evidence_ids)
        return result

    @mcp.tool()
    @audited
    def vc_verify_injection(
        run_id: str,
        candidate_id: str,
        max_requests: MaxRequests = MAX_REQUESTS_DEFAULT,
        approved: bool = False,
    ) -> VerificationResult:
        """SQL/Command Injection 후보를 제한된 fixture에서 검증한다.

        policy 검사/승인 게이트/RunState 전이/Finding 지연 생성까지는 P1이 배선했다.
        verifier 본문(`verifiers/injection.py`)은 P3가 아직 구현하지 않아 그 앞에서 멈춘다.
        """
        _prepare_verification(
            run_id, candidate_id, approved=approved, tool_name="vc_verify_injection"
        )
        raise NotImplementedError("P3 injection verifier 구현 대기 (policy/승인/상태 전이는 배선 완료)")

    @mcp.tool()
    @audited
    def vc_verify_xss(
        run_id: str,
        candidate_id: str,
        max_requests: MaxRequests = MAX_REQUESTS_DEFAULT,
        approved: bool = False,
    ) -> VerificationResult:
        """XSS 후보를 격리 브라우저의 benign marker로 검증한다.

        policy 검사/승인 게이트/RunState 전이/Finding 지연 생성까지는 P1이 배선했다.
        verifier 본문(`verifiers/xss.py`)은 P3가 아직 구현하지 않아 그 앞에서 멈춘다.
        """
        _prepare_verification(run_id, candidate_id, approved=approved, tool_name="vc_verify_xss")
        raise NotImplementedError("P3 XSS verifier 구현 대기 (policy/승인/상태 전이는 배선 완료)")
