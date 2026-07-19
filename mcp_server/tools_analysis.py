"""Mapping + Analysis + Verification 카테고리 MCP tools.

vc_map_routes, vc_map_roles, vc_index_code (Mapping)
vc_run_sast, vc_run_sca, vc_scan_access_control, vc_run_secret_scan, vc_browser_crawl (Analysis)
vc_verify_access_control, vc_verify_mutation_access_control, vc_verify_injection, vc_verify_xss (Verification)

Mapping 도구(vc_map_*)는 P3(공격 표면) 소유이며 아직 스텁이다. vc_run_sast/vc_run_sca는
Day3에 P1이 실배선했다(D2-P4.md 요청 (e)): policy 검사 + CANDIDATE_SCAN 전이 + target
source_root 조회는 P1, 실제 스캐너(`scanners.sast.run_semgrep`/`scanners.sca.run_osv`)와
FP reject/우선순위(`scanners.aggregate.aggregate`)는 P4 소유를 그대로 호출한다.
vc_scan_access_control은 Day4에 P1이 배선했다(`docs/VERIFIER_BATCH_INTERFACE.md` §3
"P1 orchestration loop" 4번 — P3 suspect bridge 결과를 evidence store에 저장): 실제
suspect 탐지+provisioning 매칭(`surface.candidates.candidates_for_target`)은 P3 소유를
그대로 호출한다. vc_run_secret_scan/vc_browser_crawl은 아직 스텁(각각 P4/P3 소유).
Verification 도구는 Day2에 P1이 실배선했다: policy 검사 + run-level 승인 게이트 +
RunState 전이 + Candidate→Finding 승격 + evidence 기반 judge 판정
(core.evidence_store.update_finding_status)은 P1이 맡고, "이 후보가 실제 보안 영향인가"만
판정하는 verifier 본문은 P3 소유(`verifiers/*.py`)를 그대로 호출한다.
"""

from __future__ import annotations

from typing import Annotated

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from contracts.schemas import Candidate, Finding, FindingStatus, Run, RunState, VerificationResult
from core.audit_log import audited
from core.evidence_store import find_or_create_finding, get, save, update_finding_status
from core.kill_switch import check_not_paused
from core.policy_engine import require_target_allowed
from core.state_machine import transition
from core.trajectory import record_trajectory_step
from mcp_server.tools_inventory import _service
from scanners.aggregate import aggregate
from scanners.sast import run_semgrep
from scanners.sca import run_osv
from surface.candidates import candidates_for_target
from verifiers.access_control import verify as verify_access_control
from verifiers.access_control import verify_mutation_access_control
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
    check_not_paused()
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


def _finalize_verification_run(run: Run, *, verified: bool) -> None:
    """verify tool 판정 이후 Run 상태를 마무리한다: verified일 때만 VERIFYING→VERIFIED.

    스캔 tool의 `_prepare_scan()`이 READY→MAPPING→CANDIDATE_SCAN을 멱등 전이하는 것과
    같은 패턴 — 이미 VERIFIED면 다시 전이하지 않는다(멱등). 이 전이가 없으면
    `vc_generate_patch`(Run이 VERIFIED 이상이어야 함)가 항상 막혀 드라이버가 직접
    `transition(run, VERIFIED)`를 수동 호출해 우회해야 했다(D4-P3-closed-loop.md,
    라이브 run `run-e32346b2a4b0`에서 실측).

    rejected는 의도적으로 Run에 반영하지 않는다 — REJECTED는 RunState 종료 상태라,
    같은 run에서 다른 candidate를 마저 검증할 길(`_prepare_verification`이 이미 지원하는
    "여러 candidate를 같은 run에서 검증 가능" 설계)이 막히기 때문이다. 어떤 candidate가
    실제로 VERIFIED되면 그 run은 그 finding 하나를 끝까지 끌고 가는 것으로 확정되므로,
    이후 같은 run으로 다른 candidate를 검증하려는 시도는 (Run이 더 이상 VERIFYING이
    아니므로) 자연히 거부된다 — 이것도 의도된 동작이다.
    """
    if verified and run.status != RunState.VERIFIED:
        run.status = transition(run.status, RunState.VERIFIED)
        save(run)


def _prepare_scan(run_id: str, *, tool_name: str) -> Run:
    """`vc_run_sast`/`vc_run_sca`/`vc_scan_access_control`이 공유하는 배선: policy 검사 →
    CANDIDATE_SCAN 전이(1회만).

    **[Day4에 닫음] READY→MAPPING gap**: RunState 그래프(`core/state_machine.py`)는
    READY→MAPPING→CANDIDATE_SCAN 순서를 강제하는데, MAPPING 도구(`vc_map_routes` 등, P3
    소유)가 여전히 스텁이라 실제로 Run을 READY→MAPPING으로 옮기는 tool call 경로가 없다
    (SKILL.md 작성 중 재확인 — Host가 tool 호출만으로는 이 단계를 통과할 수 없었다). P3의
    `surface.graph.find_idor_suspects`가 사실상 "mapping"(attack surface 식별)을 이미
    하고 있으므로, 이 함수가 Run이 `READY`면 `MAPPING`을 거쳐 `CANDIDATE_SCAN`까지 한
    호출로 대신 전이시킨다 — `vc_map_routes` 등 개별 mapping tool 구현을 더는 기다리지
    않는다. `MAPPING`으로 들어오면 `CANDIDATE_SCAN`으로 1회 전이하고, 이미
    `CANDIDATE_SCAN`이면 그대로 두어 여러 스캐너를 순서대로 호출할 수 있게 한다 —
    `_prepare_verification`이 VERIFYING을 멱등하게 다루는 것과 같은 패턴. 그 밖의 상태는
    명확한 에러로 거부한다.
    """
    check_not_paused()
    run = get(Run, run_id)
    if run is None:
        raise ValueError(f"run {run_id} not found")
    require_target_allowed(run.target_id)

    if run.status == RunState.READY:
        run.status = transition(run.status, RunState.MAPPING)
        save(run)
    if run.status == RunState.MAPPING:
        run.status = transition(run.status, RunState.CANDIDATE_SCAN)
        save(run)
    elif run.status != RunState.CANDIDATE_SCAN:
        raise ValueError(
            f"{tool_name}는 run이 READY/MAPPING/CANDIDATE_SCAN 상태여야 호출할 수 있습니다"
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
    def vc_scan_access_control(run_id: str) -> ScanResult:
        """IDOR/BOLA attack-surface 프리필터로 검증 가능한 candidate를 생성한다.

        `docs/VERIFIER_BATCH_INTERFACE.md` §3 "P1 orchestration loop" 4번("P3 suspect
        bridge 결과의 Candidate를 evidence store에 저장")을 배선한다. 실제 suspect
        탐지(`surface.graph.find_idor_suspects`)와 provisioning 매칭(`surface.candidates.
        candidates_for_target`)은 P3 소유 — P1은 policy 검사/상태 전이/target
        source_root·provisioning 조회/candidate 저장/trajectory 기록만 한다
        (`vc_run_sast`/`vc_run_sca`와 같은 패턴).

        provisioning 전략(fixture_file/self_signup)이 아직 준비되지 않은 target은 P3
        계약대로 candidate를 만들지 않고 `blocked`로 남는다("endpoint만 보고 공격하지
        않는다") — 여기서 우회하지 않고, blocked 사유를 trajectory에 그대로 남긴다.
        """
        run = _prepare_scan(run_id, tool_name="vc_scan_access_control")
        service = _service()
        source_root = service.catalog.source_root_for(run.target_id)
        provisioning = service.verifier_provisioning(run.target_id)
        bridge_result = candidates_for_target(run.id, provisioning, source_root)

        if bridge_result.blocked:
            record_trajectory_step(
                run.id,
                state=run.status,
                action={"tool": "vc_scan_access_control"},
                result={"blocked": [b.model_dump(mode="json") for b in bridge_result.blocked]},
                next_state=run.status,
            )
        return _store_scan_candidates(
            run, bridge_result.candidates, tool="vc_scan_access_control"
        )

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
        run, candidate, finding = _prepare_verification(
            run_id, candidate_id, approved=approved, tool_name="vc_verify_access_control"
        )
        result = verify_access_control(run_id, candidate, max_requests=max_requests)
        target_status = FindingStatus.VERIFIED if result.verified else FindingStatus.REJECTED
        update_finding_status(finding.id, target_status, evidence_ids=result.evidence_ids)
        _finalize_verification_run(run, verified=result.verified)
        return result

    @mcp.tool()
    @audited
    def vc_verify_mutation_access_control(
        run_id: str,
        candidate_id: str,
        max_requests: MaxRequests = MAX_REQUESTS_DEFAULT,
        approved: bool = False,
    ) -> VerificationResult:
        """Write-IDOR(상태변화) 후보를 실제 재현으로 검증한다.

        policy 검사/승인 게이트/RunState 전이/Finding 판정은 `vc_verify_access_control`과
        같은 배선. `verify_access_control`(read-oracle: 공격 응답에 피해자 marker가
        새어나오는지)과 달리, 이 tool은 `verifiers.access_control.verify_mutation`(P3
        소유)을 호출해 before/mutation/after 상태 비교로 "공격자가 실제로 피해자 자원을
        바꿨는가"를 판정한다 — `PUT /api/tiers`(26s-w1-c3-09)나 `PATCH /api/reviews/<id>/`
        (26s-w1-c2-08)처럼 읽기 marker 유출이 아니라 쓰기 권한 부재로 나타나는 IDOR용.

        candidate는 `verifiers.access_control.mutation_probe_from_candidate()` 계약을
        따라야 한다(`attack_params`에 `observe_path`/`mutation_method`/`mutation_path`/
        `mutation_marker` 필수, `extra_body_json`/`marker_field` 선택).
        """
        run, candidate, finding = _prepare_verification(
            run_id, candidate_id, approved=approved, tool_name="vc_verify_mutation_access_control"
        )
        result = verify_mutation_access_control(run_id, candidate, max_requests=max_requests)
        target_status = FindingStatus.VERIFIED if result.verified else FindingStatus.REJECTED
        update_finding_status(finding.id, target_status, evidence_ids=result.evidence_ids)
        _finalize_verification_run(run, verified=result.verified)
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
