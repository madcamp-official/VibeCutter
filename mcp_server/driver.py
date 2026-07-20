"""batch 오케스트레이션 driver (Extra Day 1B-3, D5-P2.md candidate-per-worker-Run 계약).

`run_target_audit(target_id)` = Day5 데모의 "명령 한 줄 → 전체 파이프라인"에 해당하는 단일
진입점이다. Host(LLM)가 `audit_local_target` 프롬프트를 따라 tool을 순차 호출하는 것과 같은
순서를, 밤 배치/CLI에서 코드로 재현한다.

**tool을 우회하지 않는다**: 각 파이프라인 단계는 실제 MCP tool(`mcp.call_tool`)로 호출한다 —
정책/승인 게이트/상태 전이/audit log 같은 안전장치는 tool 계층이 단일 지점으로 강제하므로,
driver가 core 함수를 직접 조합해 그 게이트를 우회하면 안 된다. 단계 결과는 반환값을 파싱하지
않고 evidence_store에서 조회한다(store가 truth — 기존 테스트들과 같은 패턴).

**레이어링**: worker Run 경계 생성(`core.orchestrator.materialize_worker_run`)은 순수 core
로직이고, tool 호출(mcp 의존)과 P2 runtime(sweep/reset_run) 배선은 이 mcp_server 레이어에
둔다. sweep/reset_run은 tool이 아니라 `TargetRuntimeService`(P2) 직접 호출이다.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Callable, Optional
from uuid import uuid4

from pydantic import BaseModel

from contracts.schemas import Candidate, Finding, FindingStatus, Patch, Run, RunState
from core.evidence_store import get, list_by_run, save
from core.orchestrator import materialize_worker_run
from core.policy_engine import require_target_allowed
from mcp_server.tools_inventory import _service
from verifiers.dispatch import class_of

logger = logging.getLogger(__name__)


class WorkerResult(BaseModel):
    """worker Run 하나(=candidate 하나)의 감사 결과 요약."""

    worker_run_id: str
    worker_candidate_id: str
    origin_candidate_id: str
    verified: bool
    verdict: Optional[str] = None  # RunState.FIXED / RETRY / HUMAN_REVIEW 값 또는 None(미확정)
    overlay_reset: Optional[bool] = None  # overlay를 만든 worker만: reset_run 결과, 아니면 None
    error: Optional[str] = None  # 이 worker 파이프라인이 실패한 사유(다음 후보는 계속 진행)


class AuditReport(BaseModel):
    target_id: str
    scan_run_id: str
    worker_results: list[WorkerResult]


def _default_invoke(tool_name: str, **arguments) -> None:
    """실제 MCP tool을 호출한다(반환값은 store에서 조회하므로 버린다).

    lazy import로 `mcp_server.server`(전체 tool register가 도는 모듈)를 끌어와 순환/등록
    순서 문제를 피한다.
    """
    from mcp_server.server import mcp

    asyncio.run(mcp.call_tool(tool_name, arguments))


def _verify_tool_for(candidate: Candidate) -> str:
    """candidate의 vuln_class(+ IDOR은 idor_mode)로 알맞은 verify tool 이름을 고른다.

    `verifiers.dispatch.class_of`(vuln_class 우선, 없으면 CWE 보정)를 재사용해 tool 선택도
    verifier 라우팅과 같은 기준을 쓴다 — driver가 별도 매핑을 들고 드리프트하지 않도록.
    """
    vuln = class_of(candidate)
    if vuln == "idor":
        if candidate.attack_params.get("idor_mode") == "write":
            return "vc_verify_mutation_access_control"
        return "vc_verify_access_control"
    if vuln == "xss":
        return "vc_verify_xss"
    if vuln == "injection":
        return "vc_verify_injection"
    raise ValueError(
        f"candidate {candidate.id}의 verify tool을 고를 수 없습니다 "
        f"(vuln_class={candidate.vuln_class!r}, cwe={candidate.cwe!r})"
    )


def _finding_for(run_id: str, candidate_id: str) -> Optional[Finding]:
    return next(
        (f for f in list_by_run(Finding, run_id) if f.candidate_id == candidate_id), None
    )


def _latest_patch_for(run_id: str, finding_id: str) -> Optional[Patch]:
    patches = [p for p in list_by_run(Patch, run_id) if p.finding_id == finding_id]
    return max(patches, key=lambda p: p.created_at, default=None)


def _audit_one_candidate(
    target_id: str,
    scan_run: Run,
    scan_candidate: Candidate,
    *,
    service,
    invoke: Callable[..., None],
) -> WorkerResult:
    """scan candidate 하나를 worker Run으로 materialize해 verify→(verified면)repair 루프를 돈다.

    overlay를 만든(=`vc_apply_patch`까지 성공한) worker Run만 종료 `finally`에서
    `reset_run`으로 정리한다(D5-P2.md: `reset_run`은 run-scoped patched overlay 전용이라
    scan/verify-only worker엔 호출하면 안 된다). reset 실패는 예외로 죽이지 않고 로깅만 한다
    (P2가 artifact/worktree를 진단용으로 보존).

    **worker 단위 예외 격리**: 파이프라인 어느 단계가 실패해도(예: verify HTTP 연결 실패,
    build timeout) 그 사유를 `result.error`에 담아 반환하고 배치는 다음 후보로 계속한다 —
    한 후보의 실패가 target 전체 audit(밤 배치)를 죽이면 안 되기 때문(1B-5 라이브 실측:
    target 미기동 시 verify가 Connection refused로 전체 배치를 중단시켰다).
    """
    worker_run, worker_candidate = materialize_worker_run(scan_run, scan_candidate)
    # 결과 객체를 미리 만들어 두면 finally에서 overlay_reset을 그대로 채워 반환할 수 있다
    # (finally 실행 후 return되며, 같은 객체 참조라 갱신이 반영된다).
    result = WorkerResult(
        worker_run_id=worker_run.id,
        worker_candidate_id=worker_candidate.id,
        origin_candidate_id=scan_candidate.id,
        verified=False,
    )
    overlay_created = False
    try:
        invoke(
            _verify_tool_for(worker_candidate),
            run_id=worker_run.id,
            candidate_id=worker_candidate.id,
            approved=True,
        )
        finding = _finding_for(worker_run.id, worker_candidate.id)
        if finding is None or finding.verification_state != FindingStatus.VERIFIED:
            return result  # verified=False — repair 루프를 타지 않는다.

        result.verified = True
        invoke("vc_localize_root_cause", finding_id=finding.id)
        invoke("vc_generate_patch", finding_id=finding.id)
        patch = _latest_patch_for(worker_run.id, finding.id)
        if patch is None:
            raise RuntimeError(f"vc_generate_patch 후 worker run {worker_run.id}에 patch가 없습니다")

        invoke("vc_apply_patch", patch_id=patch.id, confirmed=True)
        overlay_created = True  # apply가 예외 없이 끝나면 run-scoped overlay/worktree가 생겼다.

        invoke("vc_build_and_test", patch_id=patch.id)
        invoke("vc_replay_attack", patch_id=patch.id)
        invoke("vc_validate_regression", patch_id=patch.id)

        final_run = get(Run, worker_run.id)
        result.verdict = final_run.status.value if final_run is not None else None
        return result
    except Exception as exc:  # noqa: BLE001 — 한 후보 실패가 배치를 죽이면 안 된다
        result.error = f"{type(exc).__name__}: {exc}"
        logger.warning(
            "worker run %s (target %s) pipeline failed: %s",
            worker_run.id,
            target_id,
            exc,
            exc_info=True,
        )
        return result
    finally:
        if overlay_created:
            try:
                result.overlay_reset = service.reset_run(target_id, worker_run.id, approved=True)
            except Exception:  # noqa: BLE001 — 정리 실패가 배치를 죽이면 안 된다
                logger.warning(
                    "reset_run failed for worker run %s (target %s); "
                    "P2 preserves the overlay/worktree for retry",
                    worker_run.id,
                    target_id,
                    exc_info=True,
                )
                result.overlay_reset = False


# 3개 취약점군을 모두 수집하는 scan tool 묶음(D5-P2 요청 "injection/xss를 단일 경로에"):
#   - vc_scan_access_control : IDOR/BOLA 프리필터(read/write)
#   - vc_run_sast            : Semgrep이 vuln_class=idor/xss/injection candidate 생성
#   - vc_run_sca             : dependency/SBOM candidate
# 셋 다 같은 scan Run에 후보를 쌓고, worker materialize 후 verify tool은 candidate의
# vuln_class로 자동 선택된다(`_verify_tool_for`). 한 스캐너 실패(예: semgrep 미설치)는
# 배치를 죽이지 않고 로깅만 한다 — 나머지 스캐너 후보는 그대로 진행.
DEFAULT_SCAN_TOOLS: tuple[str, ...] = (
    "vc_scan_access_control",
    "vc_run_sast",
    "vc_run_sca",
)


def run_target_audit(
    target_id: str,
    *,
    service=None,
    invoke: Callable[..., None] | None = None,
    scan_tools: tuple[str, ...] = DEFAULT_SCAN_TOOLS,
) -> AuditReport:
    """target 하나에 대한 candidate-per-worker-Run 감사를 순차 실행한다.

    순서(D5-P2.md P2 호출 조건 + candidate-per-worker-Run 계약):
      1. batch 시작 전 `sweep_stale_run_overlays(target_id, active_run_ids=(), approved=True)`
         — 이전 배치가 남긴 관리 overlay를 정리한다(임의 `vc-*` project는 안 건드림).
      2. `vc_build_target`→`vc_start_target`으로 격리 환경에서 target을 띄운다(프롬프트 step 2와
         동일 — 이게 없으면 verify가 Connection refused로 막힌다, 1B-5 라이브 실측).
      3. scan Run 1개를 만들어 `scan_tools`(IDOR+SAST+SCA)로 3개 취약점군 후보를 모두
         수집한다. 한 스캐너 실패는 로깅만 하고 나머지로 계속. scan Run은 `CANDIDATE_SCAN`에서
         종료하고 이후 전이시키지 않는다(계약 ①).
      4. 후보마다 **순차로**(고정 host port라 병렬 불가, 계약 ④) worker Run을 materialize해
         verify(vuln_class로 tool 자동 선택)→(verified면)localize→patch→apply→build/replay/
         validate를 돌린다(계약 ②③).
      5. overlay를 만든 worker Run만 종료 시 `reset_run`으로 정리한다.

    `service`/`invoke`는 테스트에서 주입한다(기본값은 실제 P2 서비스 + 실제 MCP tool 호출).
    build/start 실패는 audit할 target 자체가 없다는 뜻이라 그대로 전파한다(worker 단위 격리와
    달리 여기서 잡지 않는다).
    """
    service = service if service is not None else _service()
    invoke = invoke if invoke is not None else _default_invoke

    require_target_allowed(target_id)  # 미등록 target은 스캔 시작 전에 조기 거부.
    service.sweep_stale_run_overlays(target_id, active_run_ids=(), approved=True)

    invoke("vc_build_target", target_id=target_id)
    invoke("vc_start_target", target_id=target_id)

    scan_run = Run(id=f"run-{uuid4().hex[:12]}", target_id=target_id, status=RunState.READY)
    save(scan_run)
    for scan_tool in scan_tools:
        try:
            invoke(scan_tool, run_id=scan_run.id)
        except Exception as exc:  # noqa: BLE001 — 한 스캐너 실패가 전체 감사를 죽이면 안 된다
            logger.warning(
                "scan tool %s failed for run %s (target %s): %s",
                scan_tool,
                scan_run.id,
                target_id,
                exc,
                exc_info=True,
            )

    scan_candidates = list_by_run(Candidate, scan_run.id)
    worker_results = [
        _audit_one_candidate(target_id, scan_run, scan_candidate, service=service, invoke=invoke)
        for scan_candidate in scan_candidates  # 순차 — 고정 포트 공유 target
    ]
    return AuditReport(
        target_id=target_id, scan_run_id=scan_run.id, worker_results=worker_results
    )
