"""Repair + Mutation + Judge + Report 카테고리 MCP tools.

vc_localize_root_cause, vc_generate_patch (Repair, P3 소유)
vc_apply_patch (Mutation, P1 게이트 — 명시적 승인 없이는 호출 불가)
vc_build_and_test, vc_replay_attack, vc_validate_regression (Judge, P1 배선)
vc_kill_run (Rollback, P1 소유 — P2 reset_run() 호출, kill switch와 무관하게 항상 가능)
vc_generate_report, vc_export_sarif (Report, P1/P4 소유)

generate와 apply를 별도 도구로 분리하는 것은 절대 원칙(원본 branch 직접 변경 금지,
worktree에만 적용, 6.7절)과 직결되므로 오늘부터 시그니처로 강제한다: apply는
`confirmed: bool` 없이는 무조건 거부한다.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

from contracts.schemas import (
    ApprovalStatus,
    Finding,
    FindingStatus,
    Patch,
    RootCause,
    Run,
    RunState,
    Validation,
)
from core.audit_log import audited
from core.evidence_store import find_or_create_validation, get, save, update_finding_status, write_artifact
from core.judge import (
    ScopeViolationError,
    assert_diff_within_worktree,
    check_attack,
    check_build,
    check_positive_functionality,
    check_regression,
    check_scope,
    check_static,
    compute_verdict,
)
from core.kill_switch import check_not_paused
from core.planner import enforce_retry_budget, patch_attempt_count
from core.state_machine import transition
from core.trajectory import record_trajectory_step
from mcp_server.tools_inventory import _service
from repair.locator import localize
from repair.patcher import generate_patch


class ReportResult(BaseModel):
    run_id: str
    artifact_uri: str
    format: str


class RunResetResult(BaseModel):
    run_id: str
    target_id: str
    ok: bool


def _advance_to_patch_proposed(run: Run) -> None:
    """VERIFIED/LOCALIZING/RETRY → PATCH_PROPOSED로 전진시킨다(멱등).

    RunState 그래프는 VERIFIED→LOCALIZING→PATCH_PROPOSED를 강제하고, RETRY도
    PATCH_PROPOSED로 되돌아간다(재시도). `vc_generate_patch`가 이미 PATCH_PROPOSED인
    run에서 다시 호출되면(예: patch 후보 재생성) 상태는 그대로 두고 통과시킨다.
    """
    if run.status == RunState.VERIFIED:
        run.status = transition(run.status, RunState.LOCALIZING)
        save(run)
    if run.status in (RunState.LOCALIZING, RunState.RETRY):
        run.status = transition(run.status, RunState.PATCH_PROPOSED)
        save(run)
    elif run.status != RunState.PATCH_PROPOSED:
        raise ValueError(
            "vc_generate_patch는 run이 VERIFIED/LOCALIZING/RETRY/PATCH_PROPOSED 상태여야 "
            f"호출할 수 있습니다(현재 {run.status})"
        )


def _require_patch_proposed_or_applied(run: Run) -> bool:
    """PATCH_PROPOSED(정상) 또는 이미 PATCH_APPLIED(재시도)만 허용, 그 외는 거부.

    반환값 True면 이미 적용됨(재적용 skip), False면 아직 적용 전(PATCH_PROPOSED) — 호출자가
    scope 검사/git apply를 계속 진행해야 한다는 뜻이다.
    """
    if run.status == RunState.PATCH_APPLIED:
        return True
    if run.status != RunState.PATCH_PROPOSED:
        raise ValueError(
            f"vc_apply_patch는 run이 PATCH_PROPOSED 상태여야 호출할 수 있습니다(현재 {run.status})"
        )
    return False


def _advance_to_patch_applied(run: Run) -> None:
    """PATCH_PROPOSED → WAITING_APPROVAL → PATCH_APPLIED. diff가 실제로 적용된 뒤에만
    호출한다 — scope 위반이나 git apply 실패 시에는 run을 PATCH_PROPOSED에 그대로 둔다.
    """
    run.status = transition(run.status, RunState.WAITING_APPROVAL)
    run.status = transition(run.status, RunState.PATCH_APPLIED)
    save(run)


def _git_apply(worktree_path: Path, diff: str) -> None:
    result = subprocess.run(
        [
            "git",
            "-c",
            "core.autocrlf=false",
            "-C",
            str(worktree_path),
            "apply",
            "--ignore-space-change",
            "-",
        ],
        input=diff,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
    )
    if result.returncode != 0:
        raise ValueError(f"patch가 worktree에 적용되지 않았습니다: {result.stderr.strip()}")


def _advance_to_validating(run: Run) -> None:
    """PATCH_APPLIED → VALIDATING(멱등).

    `vc_build_and_test`/`vc_replay_attack`/`vc_validate_regression` 셋 다 같은 Validation
    row에 게이트를 나눠 채우는 동안 여러 번(서로 다른 tool에서) 불릴 수 있으므로, 이미
    VALIDATING이면 그대로 둔다.
    """
    if run.status == RunState.PATCH_APPLIED:
        run.status = transition(run.status, RunState.VALIDATING)
        save(run)
    elif run.status != RunState.VALIDATING:
        raise ValueError(
            "이 judge tool은 run이 PATCH_APPLIED 또는 VALIDATING 상태여야 호출할 수 있습니다"
            f"(현재 {run.status})"
        )


def _finalize_validation(run: Run, patch: Patch, validation: Validation) -> None:
    """6게이트가 모두 채워지면 verdict를 확정하고 RunState/Finding까지 마무리한다.

    `compute_verdict()`가 아직 `None`(게이트 미완)이면 아무것도 하지 않는다 — 나머지
    judge tool 호출을 기다린다. `FIXED`면 validation 요약을 evidence artifact로 남기고
    (`update_finding_status`의 하드 가드가 실제 evidence_id를 요구하므로) Finding을
    `FIXED`로 승격한다. `RETRY`면 Finding은 그대로 두고(다음 patch 재시도를 기다림) Run만
    전이한다 — 3회 실패 후 human review로 보내는 재시도 횟수 상한은 `core/planner.py`
    (Day4) 소관이다.
    """
    verdict = compute_verdict(validation)
    if verdict is None:
        return

    validation.verdict = verdict
    save(validation)
    patch.validation_id = validation.id
    save(patch)

    run.status = transition(run.status, RunState(verdict))
    save(run)

    if verdict == RunState.FIXED.value:
        summary = json.dumps(validation.model_dump(mode="json"), ensure_ascii=False).encode("utf-8")
        artifact = write_artifact(
            run.id, observation_type="log", producer="vc_validate_patch:verdict", data=summary
        )
        update_finding_status(patch.finding_id, FindingStatus.FIXED, evidence_ids=[artifact.id])


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    @audited
    def vc_localize_root_cause(finding_id: str) -> RootCause:
        """verified finding의 근본 원인 위치를 추적한다.

        실제 판정 로직은 P3 소유(`repair.locator.localize`) — P1은 finding → run → target →
        source_root(P2 `catalog.source_root_for(target_id)`, 경로 탈출 검사 포함)를 조회해
        넘기는 배선만 담당한다(D3-P3.md 요청).

        **[갱신 — D1-P2.md 12:14본에서 해소 확인]** 예전엔 3개 manifest가 `role_fixtures.secret_env_names`
        검증 실패로 catalog 전체 로드가 죽어 있었으나, P2가 수정해 checked-in manifest 22개가
        전부 `TargetCatalog.load()`를 통과한다 — 이 tool은 이제 실제 target으로 호출 가능하다.
        """
        check_not_paused()
        finding = get(Finding, finding_id)
        if finding is None:
            raise ValueError(f"finding {finding_id} not found")
        run = get(Run, finding.run_id)
        if run is None:
            raise ValueError(f"run {finding.run_id} not found")

        source_root = _service().catalog.source_root_for(run.target_id)
        return localize(finding, source_root=source_root)

    @mcp.tool()
    @audited
    def vc_generate_patch(finding_id: str) -> Patch:
        """root cause 기반 patch 후보를 생성한다(원본 미변경, `approval=PENDING`).

        실제 합성·랭킹 로직은 P3 소유(`repair.patcher.generate_patch`) — P1은 finding → run →
        target → source_root 조회, root_cause 계산(`repair.locator.localize` 재호출 —
        `vc_localize_root_cause`와 별도 entry point, D3-P3.md 요청대로 이 tool 안에서 직접
        계산한다), RunState 전이(VERIFIED/LOCALIZING/RETRY → PATCH_PROPOSED), Patch 저장,
        trajectory 기록만 배선한다.

        **실패 처리**: 패치 후보를 하나도 합성 못 하면 `generate_patch()`가 `ValueError`를
        내는데, 이때는 RunState를 전이하지 않는다(패치가 없는데 PATCH_PROPOSED로 넘어가지
        않도록) — 실패해도 run은 원래 상태(예: VERIFIED)에 그대로 남는다.

        **재시도 상한(Day4, `core/planner.py`)**: 이 finding에 이미 생성된 Patch 수로 다음
        `attempt_no`를 계산해 `generate_patch()`에 그대로 넘긴다(예전엔 항상 1로 고정돼
        있어 RETRY 재시도가 attempt_no를 올리지 않는 버그가 있었다). `attempt_no`가
        `core.planner.MAX_PATCH_ATTEMPTS`(3)를 넘으면 patch를 생성하지 않고 Finding을
        `HUMAN_REVIEW`로 강제 승격한 뒤 `RetryBudgetExhausted`를 던진다 — Host가 재시도를
        멈추길 기대하는 대신 tool 자체가 4번째 시도를 거부한다.
        """
        check_not_paused()
        finding = get(Finding, finding_id)
        if finding is None:
            raise ValueError(f"finding {finding_id} not found")
        run = get(Run, finding.run_id)
        if run is None:
            raise ValueError(f"run {finding.run_id} not found")

        attempt_no = patch_attempt_count(run.id, finding.id) + 1
        enforce_retry_budget(run, finding, next_attempt_no=attempt_no)

        source_root = _service().catalog.source_root_for(run.target_id)
        root_cause = localize(finding, source_root=source_root)
        patch = generate_patch(
            run.id, finding, root_cause, source_root=source_root, attempt_no=attempt_no
        )
        save(patch)
        _advance_to_patch_proposed(run)
        record_trajectory_step(
            run.id,
            state=run.status,
            action={"tool": "vc_generate_patch", "finding_id": finding_id, "attempt_no": attempt_no},
            result={"patch_id": patch.id, "files": patch.files, "approval": patch.approval},
            next_state=run.status,
        )
        return patch

    @mcp.tool()
    @audited
    def vc_apply_patch(patch_id: str, confirmed: bool = False) -> Patch:
        """명시적 승인이 있어야만 git worktree에 patch를 적용한다. 원본 branch는 절대 건드리지 않는다.

        P2의 `catalog.worktree_manager_for(target_id)`로 run-scoped detached worktree를
        만들고(이미 있으면 재사용), diff가 그 worktree 밖 경로를 건드리지 않는지 사전에
        강제(`assert_diff_within_worktree`, `check_scope` judge 게이트와 동일 규칙 공유)한
        뒤 `git apply`로 적용한다. RunState는 PATCH_PROPOSED→WAITING_APPROVAL→PATCH_APPLIED로
        전이(이미 PATCH_APPLIED면 재적용하지 않고 그대로 반환 — 재시도 안전).
        """
        check_not_paused()
        if not confirmed:
            raise PermissionError("vc_apply_patch는 confirmed=True 없이 호출할 수 없습니다")

        patch = get(Patch, patch_id)
        if patch is None:
            raise ValueError(f"patch {patch_id} not found")
        run = get(Run, patch.run_id)
        if run is None:
            raise ValueError(f"run {patch.run_id} not found")

        already_applied = _require_patch_proposed_or_applied(run)

        worktree_manager = _service().catalog.worktree_manager_for(run.target_id)
        worktree_path = worktree_manager.path_for(run.id)
        if not worktree_path.exists():
            worktree_path = worktree_manager.create(run.id)

        if already_applied:
            return patch

        try:
            assert_diff_within_worktree(patch.diff, worktree_path)
        except ScopeViolationError as exc:
            raise PermissionError(str(exc)) from exc
        _git_apply(worktree_path, patch.diff)

        _advance_to_patch_applied(run)
        patch.approval = ApprovalStatus.APPROVED
        save(patch)
        record_trajectory_step(
            run.id,
            state=run.status,
            action={"tool": "vc_apply_patch", "patch_id": patch_id},
            result={"worktree_path": str(worktree_path), "files": patch.files},
            next_state=run.status,
        )
        return patch

    @mcp.tool()
    @audited
    def vc_build_and_test(patch_id: str) -> Validation:
        """Build gate + Regression gate를 실행한다. P1 배선, P2 test runner 호출.

        patch당 하나의 Validation row(`find_or_create_validation`)를 `vc_replay_attack`/
        `vc_validate_regression`과 공유한다 — 세 tool이 각자 맡은 게이트만 채우고, 6개가
        모두 채워지는 순간 verdict가 확정된다(`_finalize_validation`).
        """
        check_not_paused()
        patch = get(Patch, patch_id)
        if patch is None:
            raise ValueError(f"patch {patch_id} not found")
        run = get(Run, patch.run_id)
        if run is None:
            raise ValueError(f"run {patch.run_id} not found")

        _advance_to_validating(run)
        validation = find_or_create_validation(run.id, patch.id)
        validation.build = check_build(run.id, patch.id)
        validation.regression = check_regression(run.id, patch.id)
        save(validation)
        _finalize_validation(run, patch, validation)
        record_trajectory_step(
            run.id,
            state=run.status,
            action={"tool": "vc_build_and_test", "patch_id": patch_id},
            result={
                "build": validation.build,
                "regression": validation.regression,
                "verdict": validation.verdict,
            },
            next_state=run.status,
        )
        return validation

    @mcp.tool()
    @audited
    def vc_replay_attack(patch_id: str) -> Validation:
        """Attack gate: 동일 공격이 더 이상 통하지 않는지 재실행한다. P1 배선, P3 verifier 재사용."""
        check_not_paused()
        patch = get(Patch, patch_id)
        if patch is None:
            raise ValueError(f"patch {patch_id} not found")
        run = get(Run, patch.run_id)
        if run is None:
            raise ValueError(f"run {patch.run_id} not found")

        _advance_to_validating(run)
        validation = find_or_create_validation(run.id, patch.id)
        validation.attack = check_attack(run.id, patch.finding_id)
        save(validation)
        _finalize_validation(run, patch, validation)
        record_trajectory_step(
            run.id,
            state=run.status,
            action={"tool": "vc_replay_attack", "patch_id": patch_id},
            result={"attack": validation.attack, "verdict": validation.verdict},
            next_state=run.status,
        )
        return validation

    @mcp.tool()
    @audited
    def vc_validate_regression(patch_id: str) -> Validation:
        """Positive functionality gate + Static/Scope gate를 실행한다."""
        check_not_paused()
        patch = get(Patch, patch_id)
        if patch is None:
            raise ValueError(f"patch {patch_id} not found")
        run = get(Run, patch.run_id)
        if run is None:
            raise ValueError(f"run {patch.run_id} not found")

        _advance_to_validating(run)
        validation = find_or_create_validation(run.id, patch.id)
        validation.positive_test = check_positive_functionality(run.id, patch.id)
        validation.static = check_static(run.id, patch.id)
        validation.scope = check_scope(run.id, patch.id)
        save(validation)
        _finalize_validation(run, patch, validation)
        record_trajectory_step(
            run.id,
            state=run.status,
            action={"tool": "vc_validate_regression", "patch_id": patch_id},
            result={
                "positive_test": validation.positive_test,
                "static": validation.static,
                "scope": validation.scope,
                "verdict": validation.verdict,
            },
            next_state=run.status,
        )
        return validation

    @mcp.tool()
    @audited
    def vc_kill_run(run_id: str, approved: bool) -> RunResetResult:
        """kill switch의 rollback 경로: 이 run의 patched worktree/runtime을 정리한다.

        P2의 `TargetRuntimeService.reset_run(target_id, run_id, approved=True)`(D3-P2.md)를
        그대로 호출한다 — generated Compose reset이 성공한 뒤에만 target-source worktree를
        지운다. reset이 실패하면 worktree는 보존되고(P2 계약, 삭제 재시도 없음) 이 tool도
        `ok=False`를 반환한다.

        **Run 상태는 바꾸지 않는다**: kill/rollback은 인프라 정리이지 verified/fixed 같은
        보안 판정이 아니고, `core/state_machine.py`의 RunState 그래프에는 kill 전용 상태가
        없다 — 오늘 이 공통 계약을 새로 확장하지 않기로 결정했다(D4-P1.md 참고, 확장이
        필요해지면 P2/P3와 먼저 공유). 강제 중단 사실은 `@audited`가 자동 기록하는 audit
        log와 trajectory에 남는다.

        **kill switch(pause)와 무관하게 항상 호출 가능**: `vc_pause`/`vc_resume`과 같은
        이유로 `check_not_paused()`를 타지 않는다 — pause 중에도 이미 시작된 run을 정리할
        수 있어야 한다(정리를 막는 kill switch는 스스로 목적에 반한다).
        """
        if not approved:
            raise PermissionError("vc_kill_run은 approved=True 없이 호출할 수 없습니다")

        run = get(Run, run_id)
        if run is None:
            raise ValueError(f"run {run_id} not found")

        ok = _service().reset_run(run.target_id, run.id, approved=True)
        record_trajectory_step(
            run.id,
            state=run.status,
            action={"tool": "vc_kill_run", "run_id": run_id},
            result={"ok": ok},
            next_state=run.status,
        )
        return RunResetResult(run_id=run.id, target_id=run.target_id, ok=ok)

    @mcp.tool()
    @audited
    def vc_generate_report(run_id: str) -> ReportResult:
        """부록 B Finding Report Schema 기준 HTML 리포트를 생성한다. P1/P4 소유.

        입력 데이터 조인은 `core.report.build_run_report(run_id)`로 준비했다(D2-P4.md 요청
        (c) 응답) — finding+evidence+patch+validation을 run 단위로 이미 묶어 낸다. 실제
        HTML 렌더링(P4 Day3 소유)은 아직 이 데이터 소스를 소비하도록 배선하지 않았다.
        """
        raise NotImplementedError("Day3에 P4 HTML export로 구현 — core.report.build_run_report가 입력 데이터")

    @mcp.tool()
    @audited
    def vc_export_sarif(run_id: str) -> ReportResult:
        """SARIF 포맷으로 export한다.

        `vc_generate_report`와 동일한 `core.report.build_run_report(run_id)` 데이터 소스를
        SARIF 스키마로 변환하면 된다(P4 소유, 미배선).
        """
        raise NotImplementedError("Day3에 P4 SARIF export로 구현 — core.report.build_run_report가 입력 데이터")
