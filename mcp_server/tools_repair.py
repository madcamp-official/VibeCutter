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
    Candidate,
    Finding,
    FindingStatus,
    Patch,
    RootCause,
    Run,
    RunState,
    Validation,
)
from core.audit_log import audited
from core.evidence_store import (
    find_or_create_validation,
    get,
    list_by_run,
    save,
    update_finding_status,
    write_artifact,
)
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
from core.db import DATA_DIR
from core.kill_switch import check_not_paused
from core.planner import enforce_retry_budget, patch_attempt_count
from core.report import build_run_report, render_html
from core.state_machine import transition
from core.trajectory import record_trajectory_step
from mcp_server.tools_inventory import _service
from model.patch_client import build_patch_model_client
from repair.locator import localize
from repair.llm_synth import make_llm_synthesizer
from repair.patcher import generate_patch


class ReportResult(BaseModel):
    run_id: str
    artifact_uri: str
    format: str


class RunResetResult(BaseModel):
    run_id: str
    target_id: str
    ok: bool


class PatchExportResult(BaseModel):
    run_id: str
    patch_id: str
    path: str


class ResumeAuditResult(BaseModel):
    run_id: str
    patch_id: str
    verdict: str | None
    export_path: str
    reset_ok: bool


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


def _applied_patch_for_run(run_id: str) -> Patch:
    """run에 현재 적용된(approval=APPROVED) patch를 찾는다 — `vc_export_patch`/`vc_resume_audit`가
    쓴다. RETRY로 여러 patch가 쌓여도 `vc_apply_patch`가 적용 시 `approval=APPROVED`로 표시하는
    건 그 시점의 patch 하나뿐이라, 그중 가장 최근 것이 "지금 worktree에 있는 diff"다.
    """
    applied = [p for p in list_by_run(Patch, run_id) if p.approval == ApprovalStatus.APPROVED]
    if not applied:
        raise ValueError(
            f"run {run_id}에 적용된 patch가 없습니다 — 먼저 vc_apply_patch(patch_id, confirmed=True)를 호출하세요"
        )
    return max(applied, key=lambda p: p.created_at)


def _patch_directory_prefix(catalog, target_id: str) -> str | None:
    """patcher(P3)의 diff 기준 경로(`source_root_for` = manifest `source_dir`)를 apply
    worktree 기준 경로(`source_repository_for` = git toplevel)로 보정할 상대경로.

    `source_dir`가 git toplevel과 같으면(대부분의 target) None — 접두사가 필요 없다.
    """
    source_root = catalog.source_root_for(target_id)
    repo_root = catalog.source_repository_for(target_id)
    if source_root == repo_root:
        return None
    return source_root.relative_to(repo_root).as_posix()


def _git_apply(worktree_path: Path, diff: str, *, directory: str | None = None) -> None:
    """patch.diff를 worktree_path에 적용한다.

    patcher(P3)는 diff 경로를 `catalog.source_root_for(target_id)`(manifest `source_dir`,
    예: `backend/server`) 기준 상대경로로 낸다. 반면 `worktree_path`는
    `catalog.source_repository_for(target_id)`(git 저장소 toplevel, `source_dir`의 상위일 수
    있음)에서 만든 worktree라 두 기준이 다르면 `git apply`가 파일을 못 찾는다. `directory`에
    `source_dir`의 repo-root 기준 상대경로를 넘기면 `git apply --directory=`가 그 접두사를
    보정해 준다(patcher/diff 형식은 그대로 두고 apply 쪽에서만 흡수).
    """
    argv = ["git", "-c", "core.autocrlf=false", "-C", str(worktree_path), "apply", "--ignore-space-change"]
    if directory and directory != ".":
        argv.append(f"--directory={directory}")
    argv.append("-")
    result = subprocess.run(
        argv,
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

    **trajectory label(2-4, P4 학습 배치 전제)**: verdict가 확정되면 그 판정을 label/reward로
    남긴다. FIXED는 `label="fixed"`, `reward=1.0`(성공 학습 샘플). RETRY는 학습 label에
    해당하지 않지만 `reward=0.0`을 남겨 "실패 trajectory도 보존"(4.6절) — 두 경우 다
    `model.trajectory.training_samples()` 필터를 통과해 `export_training_dataset()`이 샘플을
    낸다.
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

    # 2-3: verdict가 확정된 patch/validation을 Finding에 연결한다(부록 B "selected diff",
    # validation). update_finding_status(FIXED)보다 먼저 set+save 해야 그 함수가 get으로
    # 최신 finding을 읽어 selected_patch_id를 유지한다.
    finding = get(Finding, patch.finding_id)
    if finding is not None:
        finding.selected_patch_id = patch.id
        finding.validation_id = validation.id
        save(finding)

    is_fixed = verdict == RunState.FIXED.value
    if is_fixed:
        summary = json.dumps(validation.model_dump(mode="json"), ensure_ascii=False).encode("utf-8")
        artifact = write_artifact(
            run.id, observation_type="log", producer="vc_validate_patch:verdict", data=summary
        )
        update_finding_status(patch.finding_id, FindingStatus.FIXED, evidence_ids=[artifact.id])

    record_trajectory_step(
        run.id,
        state=run.status,
        action={"tool": "judge_verdict", "patch_id": patch.id},
        result={"verdict": verdict, "validation_id": validation.id},
        next_state=run.status,
        label="fixed" if is_fixed else None,  # RETRY는 학습 label이 아니라 reward로만 보존.
        reward=1.0 if is_fixed else 0.0,
    )


_UNSET = object()
_llm_client_cache: object = _UNSET


def _get_llm_client():
    """`build_patch_model_client()`를 프로세스당 한 번만 만든다(P3 요청, 배선 #7).

    매 `vc_generate_patch` 호출마다 새로 만들면 `chat_fn_from_env`의 3초 `/health` precheck을
    호출마다 다시 물게 된다 — RETRY로 같은 finding에 여러 번 patch를 시도하면 그때마다 3초씩
    쌓인다. `None`(endpoint 전부 DOWN)도 그대로 캐시한다 — 그 자체가 유효한 "지금은 template만"
    상태이고, 매번 재확인해도 어차피 같은 결과이기 때문이다.
    """
    global _llm_client_cache
    if _llm_client_cache is _UNSET:
        _llm_client_cache = build_patch_model_client()
    return _llm_client_cache


def _reset_llm_client_cache() -> None:
    """테스트/장수명 서버에서 endpoint 상태가 바뀐 뒤 캐시를 비우고 다시 probe하게 한다."""
    global _llm_client_cache
    _llm_client_cache = _UNSET


def _line_for_root_cause(finding: Finding, root_cause: RootCause) -> int | None:
    """finding.source_symbols(SAST "파일:줄")에서 root_cause.file과 같은 파일의 줄번호를 복원한다.

    `RootCause`엔 줄번호 필드가 없다(스키마 freeze) — patcher의 `_read_source_excerpt`는 그래서
    파일 전체를 읽는다. P4 `code_context()`는 candidate의 `source_symbols`(파일:줄)로 위치를
    찾으므로, 여기서 줄을 못 찾으면 스니펫을 만들 수 없다 — 그 경우 `None`을 돌려줘 호출측이
    전체 파일 폴백으로 떨어지게 한다(추측으로 줄번호를 지어내지 않는다).
    """
    for symbol in finding.source_symbols:
        path, _, raw_line = symbol.rpartition(":")
        if not path or not raw_line.isdigit():
            continue
        if path == root_cause.file or path.endswith(root_cause.file) or root_cause.file.endswith(path):
            return int(raw_line)
    return None


def _code_context_for(finding: Finding, root_cause: RootCause, source_root: Path) -> str | None:
    """`make_llm_synthesizer(context_provider=...)` 어댑터 — P4 `code_context()`를 배선한다.

    계약 3.4의 `context_provider` 시그니처는 `(Finding, RootCause, Path) -> str | None`인데 P4
    `scanners.rag_enrich.code_context()`는 `(candidates, index) -> {candidate_id: 스니펫}`이라
    시그니처가 다르다(P3 2026-07-21 요청). 여기서 `root_cause.file:줄` 하나짜리 최소 probe
    Candidate를 만들어 그 함수에 그대로 넘긴다 — rerank(`_rag_enrich`)와 패치 합성이 같은
    스니펫 생성기(같은 CodeIndex, 같은 줄번호 부착 형식)를 공유하게 된다.

    줄을 못 찾거나(`_line_for_root_cause` None) 인덱싱이 실패하면 `None` — `make_llm_synthesizer`가
    `_read_source_excerpt`(파일 전체)로 폴백하므로 패치 합성 자체는 죽지 않는다(비파괴).
    """
    line = _line_for_root_cause(finding, root_cause)
    if line is None:
        return None
    try:
        from model.code_index import CodeIndex
        from scanners.rag_enrich import code_context
    except Exception:
        return None
    try:
        index = CodeIndex.build(source_root)
    except Exception:
        return None
    probe = Candidate(
        id="root-cause-probe", run_id=finding.run_id, source_symbols=[f"{root_cause.file}:{line}"]
    )
    return code_context([probe], index).get(probe.id)


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
        root_cause = localize(finding, source_root=source_root)
        # 2-3: 계산한 root_cause를 Finding에 저장해 리포트/SARIF가 실제 값을 싣게 하고,
        # vc_generate_patch가 매번 재계산하지 않도록 한다(부록 B root cause 필드).
        finding.root_cause = root_cause
        save(finding)
        return root_cause

    @mcp.tool()
    @audited
    def vc_generate_patch(finding_id: str) -> Patch:
        """root cause 기반 patch 후보를 생성한다(원본 미변경, `approval=PENDING`).

        실제 합성·랭킹 로직은 P3 소유(`repair.patcher.generate_patch`) — P1은 finding → run →
        target → source_root 조회, root_cause 확보(2-3: `vc_localize_root_cause`가 이미
        `finding.root_cause`에 저장했으면 재사용, 없으면 `repair.locator.localize`로 계산 후
        저장), RunState 전이(VERIFIED/LOCALIZING/RETRY → PATCH_PROPOSED), Patch 저장,
        trajectory 기록만 배선한다.

        **LLM 합성 배선(배선 #7, P3 요청)**: `synthesize_fn=make_llm_synthesizer(_get_llm_client(),
        context_provider=_code_context_for)`를 넘긴다. `_get_llm_client()`는
        `build_patch_model_client()`를 프로세스당 1회 캐시(endpoint 없으면 `None` → template-only
        degrade, 안전 불변식 3 그대로). `_code_context_for`는 P4 `code_context()`를
        `(Finding, RootCause, Path)` 계약에 맞춘 어댑터로, root_cause 위치의 줄번호 스니펫을
        찾으면 그걸, 못 찾으면 `None`을 돌려 `llm_synth`의 전체 파일 폴백이 대신 쓰이게 한다.

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
        # 2-3: vc_localize_root_cause가 먼저 불려 저장해 둔 root_cause가 있으면 재사용하고,
        # 없으면(localize를 건너뛴 경우) 여기서 계산해 저장한다 — 중복 계산 제거.
        if finding.root_cause is not None:
            root_cause = finding.root_cause
        else:
            root_cause = localize(finding, source_root=source_root)
            finding.root_cause = root_cause
            save(finding)
        patch = generate_patch(
            run.id,
            finding,
            root_cause,
            source_root=source_root,
            synthesize_fn=make_llm_synthesizer(_get_llm_client(), context_provider=_code_context_for),
            attempt_no=attempt_no,
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

        catalog = _service().catalog
        worktree_manager = catalog.worktree_manager_for(run.target_id)
        worktree_path = worktree_manager.path_for(run.id)
        if not worktree_path.exists():
            worktree_path = worktree_manager.create(run.id)

        if already_applied:
            return patch

        apply_root = catalog.run_source_root_for(run.target_id, run.id)
        if not apply_root.is_dir():
            raise FileNotFoundError(f"run source directory does not exist: {apply_root}")
        try:
            assert_diff_within_worktree(patch.diff, apply_root)
        except ScopeViolationError as exc:
            raise PermissionError(str(exc)) from exc
        _git_apply(worktree_path, patch.diff, directory=_patch_directory_prefix(catalog, run.target_id))

        _advance_to_patch_applied(run)
        patch.approval = ApprovalStatus.APPROVED
        save(patch)
        # 2-3: 적용된 patch를 Finding에 연결한다(부록 B "patch candidates"). Finding 쪽엔
        # patch_id를 안 들고 있어 리포트가 Patch.finding_id 역참조로 우회하던 것을 보강.
        finding = get(Finding, patch.finding_id)
        if finding is not None and patch.id not in finding.patch_ids:
            finding.patch_ids = [*finding.patch_ids, patch.id]
            save(finding)
        record_trajectory_step(
            run.id,
            state=run.status,
            action={"tool": "vc_apply_patch", "patch_id": patch_id},
            result={"worktree_path": str(worktree_path), "apply_root": str(apply_root), "files": patch.files},
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
    def vc_export_patch(run_id: str) -> PatchExportResult:
        """적용된 patch의 diff를 `reset_run`이 worktree를 지우기 전에 보존한다(§3A-6, ⚠️ 실제 결함 수정).

        `.vibecutter/runs/<run_id>/security-fix.patch`로 저장한다(`vc_generate_report`와 같은
        `runs/<run_id>/` 관례). **원본 branch는 건드리지 않는다** — 이 파일을 자신의 저장소에
        `git apply`하는 건 사용자의 별도 행위다(기획서 10.1 "원본 미변경" 절대 원칙 유지).

        `vc_resume_audit`가 reset 직전에 호출하며, 여기서 예외가 나면(디스크 IO 등) 그대로
        전파돼 reset을 시도하지 않는다 — export 실패 후 reset하면 패치가 영영 사라진다.
        """
        check_not_paused()
        run = get(Run, run_id)
        if run is None:
            raise ValueError(f"run {run_id} not found")
        patch = _applied_patch_for_run(run_id)

        out_dir = DATA_DIR / "runs" / run_id
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "security-fix.patch"
        out_path.write_text(patch.diff, encoding="utf-8")

        record_trajectory_step(
            run.id,
            state=run.status,
            action={"tool": "vc_export_patch", "run_id": run_id},
            result={"patch_id": patch.id, "path": str(out_path)},
            next_state=run.status,
        )
        return PatchExportResult(run_id=run_id, patch_id=patch.id, path=str(out_path))

    @mcp.tool()
    @audited
    def vc_resume_audit(run_id: str) -> ResumeAuditResult:
        """사용자 승인 이후 재개: 남은 6게이트 → export → reset (§3A-7, 안전 불변식 4).

        **전제**: run이 `PATCH_APPLIED`여야 한다 — 사용자가 diff를 보고 `vc_apply_patch(patch_id,
        confirmed=True)`를 이미 호출했다는 뜻이다. driver(`mcp_server/driver.py`)의 자동 배치는
        여기까지 넘어오지 않는다(더 이상 `confirmed=True`를 자동으로 넘기지 않는다) — 재개
        주체는 항상 Host(사용자 승인 이후)다.

        `vc_build_and_test`→`vc_replay_attack`→`vc_validate_regression` 순서로 나머지 게이트를
        채우고(각 tool이 이미 `_finalize_validation`으로 verdict를 확정한다), verdict가
        FIXED/RETRY/미확정 무엇이든 **reset 전에 반드시 export**한다(§3A-6) — export가 실패하면
        예외가 그대로 전파돼 reset을 아예 시도하지 않는다.
        """
        check_not_paused()
        run = get(Run, run_id)
        if run is None:
            raise ValueError(f"run {run_id} not found")
        if run.status != RunState.PATCH_APPLIED:
            raise ValueError(
                "vc_resume_audit는 run이 PATCH_APPLIED 상태여야 호출할 수 있습니다"
                f"(현재 {run.status}) — 먼저 vc_apply_patch(patch_id, confirmed=True)를 호출하세요"
            )
        patch = _applied_patch_for_run(run_id)

        vc_build_and_test(patch.id)
        vc_replay_attack(patch.id)
        validation = vc_validate_regression(patch.id)

        export = vc_export_patch(run_id)
        reset_ok = _service().reset_run(run.target_id, run_id, approved=True)

        record_trajectory_step(
            run.id,
            state=run.status,
            action={"tool": "vc_resume_audit", "run_id": run_id},
            result={"patch_id": patch.id, "verdict": validation.verdict, "reset_ok": reset_ok},
            next_state=run.status,
        )
        return ResumeAuditResult(
            run_id=run_id,
            patch_id=patch.id,
            verdict=validation.verdict,
            export_path=export.path,
            reset_ok=reset_ok,
        )

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
        """부록 B Finding Report Schema 기준 HTML 리포트를 생성한다(REPORT.html, DoD C-7).

        `core.report.build_run_report(run_id)`로 finding+evidence+patch+validation을 조인하고
        `render_html()`로 self-contained HTML을 만들어 `.vibecutter/runs/{run_id}/report.html`에
        저장한다. SARIF export(`vc_export_sarif`)는 P4가 같은 데이터 소스로 별도 배선한다.
        """
        report = build_run_report(run_id)
        document = render_html(report)
        out_dir = DATA_DIR / "runs" / run_id
        out_dir.mkdir(parents=True, exist_ok=True)
        report_path = out_dir / "report.html"
        report_path.write_text(document, encoding="utf-8")
        return ReportResult(run_id=run_id, artifact_uri=f"file://{report_path}", format="html")

    @mcp.tool()
    @audited
    def vc_export_sarif(run_id: str) -> ReportResult:
        """SARIF 포맷으로 export한다.

        `vc_generate_report`와 동일한 `core.report.build_run_report(run_id)` 데이터 소스를
        SARIF 스키마로 변환하면 된다(P4 소유, 미배선).
        """
        raise NotImplementedError("Day3에 P4 SARIF export로 구현 — core.report.build_run_report가 입력 데이터")
