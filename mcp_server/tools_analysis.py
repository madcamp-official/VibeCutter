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

import os
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from contracts.schemas import Candidate, Finding, FindingStatus, Run, RunState, VerificationResult
from core.audit_log import audited
from core.evidence_store import find_or_create_finding, get, save, update_finding_status
from core.kill_switch import check_not_paused
from core.orchestrator import materialize_worker_run
from core.policy_engine import require_host_allowed, require_target_allowed
from core.state_machine import transition
from core.trajectory import record_trajectory_step
from mcp_server.tools_inventory import _service
from scanners.aggregate import aggregate
from scanners.sast import run_semgrep
from scanners.sca import run_osv
from surface.candidates import candidates_for_target
from verifiers.access_control import verify as verify_access_control
from verifiers.access_control import verify_mutation_access_control
from verifiers.injection import verify as verify_injection
from verifiers.xss import verify as verify_xss
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


class WorkerRunResult(BaseModel):
    """`vc_materialize_worker_run` 출력: scan 후보를 검증용 worker Run으로 분리한 결과."""

    worker_run_id: str
    worker_candidate_id: str
    origin_candidate_id: str


def _prepare_verification(
    run_id: str, candidate_id: str, *, approved: bool, tool_name: str
) -> tuple[Run, Candidate, Finding]:
    """모든 `vc_verify_*` tool이 공유하는 배선: 승인 게이트 → policy 검사 → VERIFYING 전이
    → candidate 조회 → Finding 지연 생성(find_or_create_finding).

    verifier 호출과 최종 Finding 판정(update_finding_status)은 각 tool 본문이 이어서 한다
    (verifier마다 실제 재현 로직이 다르므로 여기서 하지 않는다).

    **host 정책 검증(부록 C-2, 1-1)**: `run.target_id`가 등록됐는지뿐 아니라, verifier가
    실제로 요청을 보낼 `candidate.attack_params["base_url"]`의 host가 그 target의
    `allowed_hosts` 안인지도 검사한다(`require_host_allowed`). Candidate에 typed
    `attack_params`가 생기면서(Day2) 가능해진 검사로, DoD "미등록 IP/URL 거부"의 URL/IP
    절반을 verify 경로에서 강제한다. `base_url`이 없는 candidate(hand-built 등)는 종전대로
    target 등록만 확인한다. 정책 위반은 VERIFYING 전이·Finding 생성 전에 거부한다.
    """
    check_not_paused()
    if not approved:
        raise PermissionError(f"{tool_name}는 run-level 승인(approved=True) 없이 호출할 수 없습니다")

    run = get(Run, run_id)
    if run is None:
        raise ValueError(f"run {run_id} not found")

    candidate = get(Candidate, candidate_id)
    if candidate is None:
        raise ValueError(f"candidate {candidate_id} not found")

    base_url = candidate.attack_params.get("base_url")
    if base_url:
        # require_host_allowed는 target 등록 검사(require_target_allowed)를 내부에 포함한다.
        require_host_allowed(run.target_id, base_url)
    else:
        require_target_allowed(run.target_id)

    if run.status != RunState.VERIFYING:
        run.status = transition(run.status, RunState.VERIFYING)
        save(run)

    finding = find_or_create_finding(run_id, candidate)
    return run, candidate, finding


def _finalize_verification_run(
    run: Run, *, verified: bool, tool_name: str, finding_id: str
) -> None:
    """verify tool 판정 이후 Run 상태를 마무리하고 trajectory에 판정 label을 남긴다.

    verified일 때만 VERIFYING→VERIFIED로 전이한다(스캔 tool `_prepare_scan()`의 멱등 전이와
    같은 패턴 — 이미 VERIFIED면 다시 전이하지 않는다). 이 전이가 없으면 `vc_generate_patch`
    (Run이 VERIFIED 이상이어야 함)가 항상 막혀 드라이버가 직접 `transition(run, VERIFIED)`를
    수동 호출해 우회해야 했다(D4-P3-closed-loop.md, 라이브 run `run-e32346b2a4b0` 실측).

    rejected는 의도적으로 Run에 반영하지 않는다 — REJECTED는 RunState 종료 상태라, 같은
    run에서 다른 candidate를 마저 검증할 길이 막히기 때문이다.

    **trajectory label(2-4, P4 학습 배치 전제)**: verified/rejected 판정을 label과 reward로
    남긴다 — `model.trajectory.training_samples()`가 `label in {verified,fixed,rejected,
    human_review}` 또는 `reward is not None`인 스텝만 학습에 쓰므로, 이 기록이 없으면
    `export_training_dataset()`이 0줄이 된다(P4 D4 밤 QLoRA 입력 0건). verified=1.0/
    rejected=0.0 reward는 이후 preference 데이터(8.2절 Phase 2)에도 쓸 수 있다.
    """
    if verified and run.status != RunState.VERIFIED:
        run.status = transition(run.status, RunState.VERIFIED)
        save(run)
    record_trajectory_step(
        run.id,
        state=run.status,
        action={"tool": tool_name, "finding_id": finding_id},
        result={"verified": verified},
        next_state=run.status,
        label="verified" if verified else "rejected",
        reward=1.0 if verified else 0.0,
    )


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


def _rerank_fn_from_env(contexts=None):
    """LLM candidate 재랭킹 훅을 만든다(8.4절 "모델=가설 우선순위", RQ3, D4-P4 요청).

    endpoint 구성은 `model.endpoints`가 env에서 해석한다 — 큰 외부 모델(qwen3-235b)이
    primary(내부망→외부망), 기존 7B가 fallback인 티어 체인. 앞 tier가 답을 못 주거나
    timeout이면 자동으로 다음 tier로 넘어간다. 쓸 endpoint가 없으면(`..._DISABLE`) `None`을
    돌려 aggregate의 휴리스틱 정렬을 그대로 쓴다 — GPU/네트워크 없는 CI에서도 스캔이 돈다.
    `make_rerank_fn`은 체인이 전부 실패해도 입력을 그대로 돌려주므로(비파괴) 후보를 잃지 않는다.

    `contexts`(`{candidate_id: 코드 스니펫}`)를 주면 상위 후보의 **코드 본문**이 프롬프트에
    함께 실린다(R-1). 없으면 메타만 — 인덱싱이 안 되는 SCA 후보도 그대로 재랭킹된다.
    """
    from model.endpoints import chat_fn_from_env
    from model.serving import make_rerank_fn

    chat_fn = chat_fn_from_env()
    if chat_fn is None:
        return None
    return make_rerank_fn(chat_fn, contexts=contexts)


def _rag_enrich(run: Run, candidates: list[Candidate]) -> tuple[list[Candidate], dict]:
    """RAG 보강: candidate에 `rag:` signal을 붙이고 코드 스니펫 곁채널을 만든다(R-2).

    `aggregate.priority_score`가 `rag:relevance`를 우선순위 보너스로 반영하고(최대 +0.1),
    스니펫은 LLM 재랭킹 프롬프트로 간다. **인덱스를 만들 수 없거나 실패하면 입력을 그대로
    돌려준다** — 비파괴(RAG는 보정이지 필수 경로가 아니다).

    `CodeIndex.build()`는 소스 트리 전체를 훑으므로, **위치(`파일:줄`)를 가진 후보가 하나도
    없으면 아예 만들지 않는다** — SCA candidate는 의존성 취약점이라 전부 여기 해당한다
    (`vc_run_sca`가 헛되이 트리를 훑지 않게).
    """
    from scanners.rag_enrich import code_context, enrich, has_indexable_location

    if not has_indexable_location(candidates):
        return candidates, {}
    try:
        from model.code_index import CodeIndex

        source_root = _service().catalog.source_root_for(run.target_id)
        index = CodeIndex.build(source_root)
        return enrich(candidates, index), code_context(candidates, index)
    except Exception:
        return candidates, {}


def _store_scan_candidates(
    run: Run, candidates: list[Candidate], *, tool: str
) -> ScanResult:
    """공통 후처리: RAG 보강 → FP reject+우선순위(`scanners.aggregate.aggregate`) → kept만 저장 → trajectory 기록.

    우선순위 정렬은 `_rerank_fn_from_env()`가 만든 LLM 재랭킹 훅을 aggregate에 주입한다
    (endpoint 미설정 시 None=휴리스틱). 후보가 우선순위순으로 저장되므로, 이후 driver/Host가
    `list_by_run` 순서대로 verify하면 유력·심각한 후보부터 검증한다.

    RAG 보강(`_rag_enrich`)이 aggregate **앞에** 온다 — `rag:relevance` signal이 붙어야
    `priority_score`가 그걸 반영하고, 코드 스니펫이 있어야 LLM이 코드를 보고 순위를 매긴다.

    **알려진 한계(D2-P4.md 요청 (b) 결정)**: 이 tool 자기 스캐너 결과만 aggregate하므로
    SAST·SCA 교차 중복 제거는 안 된다 — 두 tool이 독립 호출되기 때문. 스캔 완료 시점을
    묶는 별도 단계가 생기면 그때 cross-scanner aggregate로 바꾼다.
    """
    candidates, contexts = _rag_enrich(run, candidates)
    result = aggregate(candidates, rerank_fn=_rerank_fn_from_env(contexts))
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
    def vc_materialize_worker_run(scan_run_id: str, candidate_id: str) -> WorkerRunResult:
        """scan Run의 후보 하나를 검증용 worker Run으로 분리한다 (candidate-per-worker-Run 계약).

        scan Run은 여러 후보를 수집하는 부모이고 `CANDIDATE_SCAN`에서 멈춘다. 후보 하나를
        verify→patch loop로 독립 진행하려면 이 tool로 별도 worker Run을 만든 뒤, 반환된
        `worker_run_id`/`worker_candidate_id`로 `vc_verify_*`→`vc_localize_root_cause`→
        `vc_generate_patch`→…를 부른다. 원본 scan 후보는 `origin_candidate_id` lineage로
        보존되고 그 `run_id`는 바뀌지 않는다(D5-P2.md 계약 ②).

        `Run.status`가 candidate 하나당 하나의 검증 흐름만 담도록 고정돼 있어(VERIFIED는
        LOCALIZING으로만 진행) scan Run에서 여러 후보를 직접 검증할 수 없기 때문에 필요하다.
        밤 배치(`mcp_server/driver.py:run_target_audit`)는 같은 `materialize_worker_run`을
        코드로 부르고, 대화형 Host는 이 tool로 같은 경계를 만든다.
        """
        check_not_paused()
        scan_run = get(Run, scan_run_id)
        if scan_run is None:
            raise ValueError(f"scan run {scan_run_id} not found")
        require_target_allowed(scan_run.target_id)

        candidate = get(Candidate, candidate_id)
        if candidate is None:
            raise ValueError(f"candidate {candidate_id} not found")
        if candidate.run_id != scan_run_id:
            raise ValueError(
                f"candidate {candidate_id}는 scan run {scan_run_id} 소속이 아닙니다"
                f"(run_id={candidate.run_id})"
            )

        worker_run, worker_candidate = materialize_worker_run(scan_run, candidate)
        record_trajectory_step(
            worker_run.id,
            state=worker_run.status,
            action={
                "tool": "vc_materialize_worker_run",
                "scan_run_id": scan_run_id,
                "origin_candidate_id": candidate.id,
            },
            result={"worker_candidate_id": worker_candidate.id},
            next_state=worker_run.status,
        )
        return WorkerRunResult(
            worker_run_id=worker_run.id,
            worker_candidate_id=worker_candidate.id,
            origin_candidate_id=candidate.id,
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
        _finalize_verification_run(
            run, verified=result.verified, tool_name="vc_verify_access_control", finding_id=finding.id
        )
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
        _finalize_verification_run(
            run,
            verified=result.verified,
            tool_name="vc_verify_mutation_access_control",
            finding_id=finding.id,
        )
        return result

    @mcp.tool()
    @audited
    def vc_verify_injection(
        run_id: str,
        candidate_id: str,
        max_requests: MaxRequests = MAX_REQUESTS_DEFAULT,
        approved: bool = False,
    ) -> VerificationResult:
        """SQL/Command Injection 후보를 제한된 fixture에서 불리언 차등으로 검증한다.

        policy 검사/승인 게이트/RunState 전이/Finding 판정은 `vc_verify_access_control`과
        같은 배선. 실제 재현·판정 로직(`verifiers.injection.verify` — 참/거짓 payload의
        응답 차이로 쿼리 제어 여부를 판정, OS 외부 영향 없음)은 P3 소유로, 실앱 4개
        (c2-04/c2-05/c3-08/c1-05)로 오탐 저항까지 검증 완료(D4-P3-verifier-validation.md).
        """
        run, candidate, finding = _prepare_verification(
            run_id, candidate_id, approved=approved, tool_name="vc_verify_injection"
        )
        result = verify_injection(run_id, candidate, max_requests=max_requests)
        target_status = FindingStatus.VERIFIED if result.verified else FindingStatus.REJECTED
        update_finding_status(finding.id, target_status, evidence_ids=result.evidence_ids)
        _finalize_verification_run(
            run, verified=result.verified, tool_name="vc_verify_injection", finding_id=finding.id
        )
        return result

    @mcp.tool()
    @audited
    def vc_verify_xss(
        run_id: str,
        candidate_id: str,
        max_requests: MaxRequests = MAX_REQUESTS_DEFAULT,
        approved: bool = False,
    ) -> VerificationResult:
        """XSS 후보를 격리 브라우저의 benign marker로 검증한다.

        policy 검사/승인 게이트/RunState 전이/Finding 판정은 `vc_verify_access_control`과
        같은 배선. 실제 재현·판정 로직(`verifiers.xss.verify` — 격리 브라우저에서 지정된
        benign marker가 실제로 실행/DOM 삽입되는지 판정, reflected/escaped 구분)은 P3
        소유로, 실앱 4개(c2-04/c2-05/c3-08/c1-05)로 오탐 저항까지 검증 완료
        (D4-P3-verifier-validation.md).
        """
        run, candidate, finding = _prepare_verification(
            run_id, candidate_id, approved=approved, tool_name="vc_verify_xss"
        )
        result = verify_xss(run_id, candidate, max_requests=max_requests)
        target_status = FindingStatus.VERIFIED if result.verified else FindingStatus.REJECTED
        update_finding_status(finding.id, target_status, evidence_ids=result.evidence_ids)
        _finalize_verification_run(
            run, verified=result.verified, tool_name="vc_verify_xss", finding_id=finding.id
        )
        return result
