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
from runtime.metadata import RuntimeMetadata, append_runtime_metadata
from runtime.target_lease import TargetLeaseManager
from verifiers.dispatch import class_of

logger = logging.getLogger(__name__)


class WorkerResult(BaseModel):
    """worker Run 하나(=candidate 하나)의 감사 결과 요약.

    §3A-7/W-4(안전 불변식 4) 이후: verified worker는 `vc_generate_patch`(PATCH_PROPOSED)에서
    멈춘다. apply/build/replay/validate/export/reset은 여기서 자동으로 일어나지 않는다 —
    사용자가 diff를 보고 `vc_apply_patch(patch_id, confirmed=True)`로 승인해야 이어지고,
    그 뒤는 `vc_resume_audit(run_id)`가 담당한다. 그래서 `verdict`/`overlay_reset`은 이
    batch driver 경로에서는 항상 `None`이다 — driver가 그 값을 낼 방법이 없어서지 실패해서가
    아니다.
    """

    worker_run_id: str
    worker_candidate_id: str
    origin_candidate_id: str
    verified: bool
    patch_id: Optional[str] = None  # verified worker만: PATCH_PROPOSED 상태로 남은 patch id
    verdict: Optional[str] = None  # 이 batch 경로에서는 채워지지 않는다 — vc_resume_audit 소관
    overlay_reset: Optional[bool] = None  # 이 batch 경로에서는 채워지지 않는다 — vc_resume_audit 소관
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
    invoke: Callable[..., None],
) -> WorkerResult:
    """scan candidate 하나를 worker Run으로 materialize해 verify→(verified면)localize+patch까지 돈다.

    **§3A-7/W-4(안전 불변식 4)**: verified worker는 `vc_generate_patch` 직후, 즉
    `PATCH_PROPOSED`에서 멈춘다. `vc_apply_patch`를 여기서 자동으로 호출하지 않는다 — 이전엔
    driver가 `confirmed=True`를 자동으로 넘겨 사용자 승인 없이 patch를 worktree에 적용했다
    (실제 결함). 이제 재개 주체는 항상 Host다: 사용자가 diff를 보고
    `vc_apply_patch(patch_id, confirmed=True)` → `vc_resume_audit(run_id)`(build/replay/
    validate/export/reset)로 명시적으로 이어간다. 그래서 이 함수는 overlay를 만들지 않고,
    `reset_run`도 호출하지 않는다(만든 적 없는 걸 정리할 필요가 없다).

    **worker 단위 예외 격리**: 파이프라인 어느 단계가 실패해도(예: verify HTTP 연결 실패)
    그 사유를 `result.error`에 담아 반환하고 배치는 다음 후보로 계속한다 — 한 후보의 실패가
    target 전체 audit(밤 배치)를 죽이면 안 되기 때문(1B-5 라이브 실측: target 미기동 시
    verify가 Connection refused로 전체 배치를 중단시켰다).
    """
    worker_run, worker_candidate = materialize_worker_run(scan_run, scan_candidate)
    result = WorkerResult(
        worker_run_id=worker_run.id,
        worker_candidate_id=worker_candidate.id,
        origin_candidate_id=scan_candidate.id,
        verified=False,
    )
    try:
        invoke(
            _verify_tool_for(worker_candidate),
            run_id=worker_run.id,
            candidate_id=worker_candidate.id,
            approved=True,
        )
        finding = _finding_for(worker_run.id, worker_candidate.id)
        if finding is None or finding.verification_state != FindingStatus.VERIFIED:
            return result  # verified=False — patch 생성으로 넘어가지 않는다.

        result.verified = True
        invoke("vc_localize_root_cause", finding_id=finding.id)
        invoke("vc_generate_patch", finding_id=finding.id)
        patch = _latest_patch_for(worker_run.id, finding.id)
        if patch is None:
            raise RuntimeError(f"vc_generate_patch 후 worker run {worker_run.id}에 patch가 없습니다")
        result.patch_id = patch.id  # Host가 diff를 보고 승인할 patch — PATCH_PROPOSED에서 정지.
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


def _llm_endpoint_state_for(scan_run_id: str) -> str:
    """T-3(`eval.sample_filter`)와 같은 소스로 이 scan run의 LLM 사용 여부를 읽는다(W-10).

    `mcp_server.tools_analysis._store_scan_candidates`가 rerank 단계마다 trajectory
    `result`에 `llm_used`/`tier` 메타를 남긴다(P4 `LlmCallOutcome.as_metadata()`, T-2).
    여기서 그 trajectory 파일을 `model.trajectory.llm_usage_from_trajectories()`로 — T-3
    표본 필터가 쓰는 **바로 그 함수**로 — 다시 읽어 "up"/"down"/"unknown"으로 접는다.
    runtime metadata와 eval 표본 필터가 서로 다른 값을 보면 ablation 표본과 관측이
    어긋나므로(P4 요청), 별도로 계산하지 않고 반드시 같은 판독 경로를 공유한다.
    """
    from core.trajectory import TRAJECTORY_DIR
    from model.trajectory import llm_usage_from_trajectories, load_trajectories

    path = TRAJECTORY_DIR / f"{scan_run_id}.jsonl"
    if not path.exists():
        return "unknown"
    usage = llm_usage_from_trajectories(load_trajectories(path)).get(scan_run_id)
    if usage is None:
        return "unknown"
    return "up" if usage.any_used else "down"


def _record_runtime_metadata(
    service,
    target_id: str,
    scan_run_id: str,
    lease,
    worker_results: list[WorkerResult],
) -> None:
    """배치 종료 시점에 `runtime.metadata.RuntimeMetadata` 1건을 남긴다(W-9, P2 긴급 요청 2번).

    P1이 직접 조회 가능한 값만 채운다: `base_url`/`source_commit`은 P2 catalog에서, `health`는
    `adapter.health()`로 지금 다시 확인(마지막 worker가 overlay를 reset하고 원본으로 돌아온
    뒤라 "배치가 target을 정상 상태로 남겼는가"를 의미한다), `readiness`는 `check_readiness()`,
    `reset_result`는 이 배치의 worker들이 만든 overlay가 전부 정리됐는지(overlay를 하나도
    안 만들었으면 `None` — 해당 없음, K-2 원칙과 동일하게 모르는/해당 없는 값을 지어내지 않는다),
    `lease_run_id`/`lease_expires_at`은 방금 갱신된 lease 그대로.

    `llm_endpoint_state`(W-10)는 이 scan run의 rerank 단계가 남긴 trajectory를
    `model.trajectory.llm_usage_from_trajectories()`로 읽어 채운다 — T-3 표본 필터
    (`eval.sample_filter`)가 **같은 함수, 같은 파일**을 읽으므로 두 값이 서로 어긋날 수 없다.
    `gpu_worker`/`remaining_*`(P2 runtime 소관, 출처 확인 중)는 스키마 기본값(`None`/빈
    리스트)으로 남겨 둔다.

    이 기록 자체의 실패(디스크 IO, catalog 조회 예외 등)는 로깅만 하고 삼킨다 — observability
    부가 정보일 뿐이라 감사 배치의 안전 불변식과 무관하다(worker/scanner 예외 격리와 같은 원칙).
    """
    try:
        reset_flags = [r.overlay_reset for r in worker_results if r.overlay_reset is not None]
        reset_result = all(reset_flags) if reset_flags else None

        target = service.catalog.get(target_id)
        health = service.catalog.adapter_for(target_id).health().status == "ready"
        readiness = service.check_readiness(target_id).ready

        metadata = RuntimeMetadata(
            run_id=scan_run_id,
            target_id=target_id,
            source_commit=target.contract_target.source_commit,
            base_url=target.manifest.base_url,
            health=health,
            readiness=readiness,
            reset_result=reset_result,
            lease_run_id=lease.run_id,
            lease_expires_at=lease.expires_at,
            llm_endpoint_state=_llm_endpoint_state_for(scan_run_id),
        )
        append_runtime_metadata(metadata)
    except Exception:  # noqa: BLE001 — 관측 기록 실패가 감사 배치를 죽이면 안 된다
        logger.warning(
            "runtime metadata append failed for run %s (target %s)",
            scan_run_id,
            target_id,
            exc_info=True,
        )


def run_target_audit(
    target_id: str,
    *,
    service=None,
    invoke: Callable[..., None] | None = None,
    scan_tools: tuple[str, ...] = DEFAULT_SCAN_TOOLS,
    lease_manager: TargetLeaseManager | None = None,
) -> AuditReport:
    """target 하나에 대한 candidate-per-worker-Run 감사를 순차 실행한다.

    순서(D5-P2.md P2 호출 조건 + candidate-per-worker-Run 계약):
      1. `require_target_allowed` 통과 후 **target lease를 배치 전체 단위로 선점**한다
         (P2 긴급 요청 3번, §3A-8) — scan Run과 그 아래 모든 worker Run이 같은 고정 host
         port를 공유하므로, build/start부터 마지막 worker까지 통째로 한 배치가 target을
         독점해야 한다. 이미 다른 배치가 쥐고 있으면 `TargetBusyError`(`RuntimeError` 상속)를
         그대로 전파한다 — audit log의 `PermissionError` 집계를 오염시키지 않는다.
      2. batch 시작 전 `sweep_stale_run_overlays(target_id, active_run_ids=(), approved=True)`
         — 이전 배치가 남긴 관리 overlay를 정리한다(임의 `vc-*` project는 안 건드림).
      3. `vc_build_target`→`vc_start_target`으로 격리 환경에서 target을 띄운다(프롬프트 step 2와
         동일 — 이게 없으면 verify가 Connection refused로 막힌다, 1B-5 라이브 실측).
      4. scan Run 1개를 만들어 `scan_tools`(IDOR+SAST+SCA)로 3개 취약점군 후보를 모두
         수집한다. 한 스캐너 실패는 로깅만 하고 나머지로 계속. scan Run은 `CANDIDATE_SCAN`에서
         종료하고 이후 전이시키지 않는다(계약 ①).
      5. 후보마다 **순차로**(고정 host port라 병렬 불가, 계약 ④) worker Run을 materialize해
         verify(vuln_class로 tool 자동 선택)→(verified면)localize→patch를 돌리고
         **`PATCH_PROPOSED`에서 멈춘다**(계약 ②③, §3A-7/W-4 안전 불변식 4). apply/build/
         replay/validate/export/reset은 여기서 자동으로 일어나지 않는다 — 이전엔 driver가
         `confirmed=True`를 자동으로 넘겨 사용자 승인 없이 patch를 적용했다(실제 결함,
         지금은 제거됨). 사용자가 diff를 승인하면 Host가 `vc_apply_patch(patch_id,
         confirmed=True)` → `vc_resume_audit(run_id)`로 명시적으로 이어간다. worker 하나가
         끝날 때마다 lease를 `renew()`한다 — c1-05 실측 기준 후보 1개 136초라, 후보 10개면
         기본 TTL(900초)을 넘긴다.
      6. 이 batch 경로는 patch를 적용하지 않으므로 정리할 overlay가 없다 — `reset_run`은
         `vc_resume_audit`가 6게이트+export 이후에 호출한다.
      7. 배치 종료 시점에 `runtime.metadata.RuntimeMetadata` 1건을 남긴다(W-9, P2 긴급
         요청 2번) — health/readiness/source_commit/base_url/lease 정보. `reset_result`는
         이 경로에서 overlay를 안 만드니 항상 `None`이다(§3A-6/7 이후, `vc_resume_audit`
         쪽 reset은 별도 경로라 이 metadata에 잡히지 않는다). `_record_runtime_metadata`가
         실패해도 로깅만 하고 삼킨다(관측 부가 정보).
      8. `finally`에서 lease를 `release()`한다 — 배치 성공/실패와 무관하게 다음 배치가
         이 target을 쓸 수 있게 한다.

    `service`/`invoke`/`lease_manager`는 테스트에서 주입한다(기본값은 실제 P2 서비스 + 실제
    MCP tool 호출 + `~/.vibecutter/leases` 실 lease store). build/start 실패는 audit할 target
    자체가 없다는 뜻이라 그대로 전파한다(worker 단위 격리와 달리 여기서 잡지 않는다).
    """
    service = service if service is not None else _service()
    invoke = invoke if invoke is not None else _default_invoke
    lease_manager = lease_manager if lease_manager is not None else TargetLeaseManager()

    require_target_allowed(target_id)  # 미등록 target은 lease/스캔 시작 전에 조기 거부.

    scan_run_id = f"run-{uuid4().hex[:12]}"
    lease = lease_manager.acquire(target_id, scan_run_id)  # 배치 전체(build~마지막 worker) 단위 선점.
    try:
        service.sweep_stale_run_overlays(target_id, active_run_ids=(), approved=True)

        invoke("vc_build_target", target_id=target_id)
        invoke("vc_start_target", target_id=target_id)

        scan_run = Run(id=scan_run_id, target_id=target_id, status=RunState.READY)
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
        worker_results: list[WorkerResult] = []
        for scan_candidate in scan_candidates:  # 순차 — 고정 포트 공유 target
            worker_results.append(
                _audit_one_candidate(target_id, scan_run, scan_candidate, invoke=invoke)
            )
            lease = lease_manager.renew(target_id, scan_run_id)  # 살아있으면 TTL 연장, 죽었으면 만료.

        _record_runtime_metadata(service, target_id, scan_run_id, lease, worker_results)
        return AuditReport(
            target_id=target_id, scan_run_id=scan_run.id, worker_results=worker_results
        )
    finally:
        lease_manager.release(target_id, scan_run_id)
