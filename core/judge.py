"""Deterministic Security Judge: 7.6절 6개 게이트(Build/Attack/Positive functionality/
Regression/Static/Scope)와 최종 verdict.

Day2 범위: 6개 게이트 함수 시그니처를 전부 고정하고, Attack gate만 실제로 동작시킨다
(나머지는 Day3, patch/worktree/test-runner가 준비된 뒤 채운다). 각 게이트는
`Validation`의 필드 하나씩을 채우는 bool 판정 함수다 — 실제 `Validation` row 조립·저장은
`vc_build_and_test`/`vc_replay_attack`/`vc_validate_regression`(mcp_server/tools_repair.py,
Day2~3 배선) 쪽 책임이고, 여기는 순수 판정 로직만 둔다.

**하드 가드**: 이 모듈을 포함해 어떤 코드도 `Finding.verification_state`를 직접 대입하지
않는다 — 오직 `core.evidence_store.update_finding_status()`만 이 필드를 바꾸고, 그 함수는
evidence_ids가 실제로 evidence_store에 존재해야만 통과시킨다(D1-P3.md 구멍 ①). Attack
gate도 같은 이유로 evidence가 실제로 남는 `verifiers.access_control.verify()`를 재호출할
뿐, verified 여부를 판단력으로 흉내 내지 않는다.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from contracts.schemas import Candidate, Finding, ObservationType, Patch, Run, RunState, Validation, VerificationResult
from core.evidence_store import get, write_artifact
from repair.validators import validate_patch
from scanners.aggregate import aggregate
from scanners.sast import run_semgrep
from scanners.vocab import candidate_severity
from verifiers.dispatch import verify_candidate
from verifiers.types import MAX_REQUESTS_DEFAULT

# `+++ b/<path>` 헤더에서 diff가 실제로 건드리는 파일 경로를 뽑는다. `repair.patcher`가
# 만드는 diff는 항상 기존 파일 수정이라 삭제(`+++ /dev/null`)는 대상에 없다 — patcher가
# 파일 삭제를 만들게 되면 이 정규식도 함께 넓혀야 한다.
_DIFF_NEW_PATH_RE = re.compile(r"^\+\+\+ b/(.+)$", re.MULTILINE)


class ScopeViolationError(ValueError):
    """diff가 worktree 밖 경로를 건드릴 때(10.1절 절대 원칙 위반)."""


def diff_touched_files(diff: str) -> list[str]:
    """unified diff의 `+++ b/<path>` 헤더에서 실제로 건드리는 파일 목록을 뽑는다."""
    return _DIFF_NEW_PATH_RE.findall(diff)


def assert_diff_within_worktree(diff: str, worktree_path: Path) -> None:
    """diff가 가리키는 모든 파일이 worktree_path 안에 있는지 확인한다(10.1절 절대 원칙).

    `vc_apply_patch`(적용 전 사전 강제)와 `check_scope`(적용 후 사후 검증) 양쪽이 공유한다.
    """
    root = worktree_path.resolve()
    for rel in diff_touched_files(diff):
        resolved = (worktree_path / rel).resolve()
        if resolved != root and root not in resolved.parents:
            raise ScopeViolationError(f"patch가 worktree 밖 경로를 건드립니다: {rel}")


def _service():
    """`mcp_server.tools_inventory._service()`와 동일한 팩토리를, core가 mcp_server에
    의존하지 않도록 여기서 독립적으로 재구성한다(레이어링: mcp_server → core, 역방향 금지)."""
    from runtime.target_service import TargetRuntimeService

    return TargetRuntimeService.from_repository_root(Path(__file__).resolve().parent.parent)


def _patch_and_worktree(run_id: str, patch_id: str) -> tuple[Patch, Run, Path, Path]:
    """build/regression/static 게이트가 공유하는 조회: patch/run 존재 확인 + P2가
    `vc_apply_patch`로 이미 만든 worktree/source-root 경로(없으면 아직 적용 전이라는 뜻)."""
    patch = get(Patch, patch_id)
    if patch is None:
        raise ValueError(f"patch {patch_id} not found")
    run = get(Run, run_id)
    if run is None:
        raise ValueError(f"run {run_id} not found")

    catalog = _service().catalog
    worktree_path = catalog.worktree_manager_for(run.target_id).path_for(run.id)
    if not worktree_path.is_dir():
        raise FileNotFoundError(
            f"run {run.id}에 대한 P2 worktree가 없습니다 — vc_apply_patch를 먼저 호출하세요"
        )
    run_source_root = catalog.run_source_root_for(run.target_id, run.id)
    if not run_source_root.is_dir():
        raise FileNotFoundError(
            f"run {run.id}에 대한 P2 source root가 없습니다 — vc_apply_patch를 먼저 호출하세요"
        )
    return patch, run, worktree_path, run_source_root


def check_attack(
    run_id: str,
    finding_id: str,
    *,
    max_requests: int = MAX_REQUESTS_DEFAULT,
    verifier: Callable[..., VerificationResult] | None = None,
) -> bool:
    """Attack gate: 기존 공격이 더 이상 보안 영향으로 이어지지 않으면 통과(True)한다.

    finding이 참조하는 원본 Candidate로 verifier를 다시 호출해 `verified=False`가
    나오는지 확인한다 — verifier가 실제로 요청을 다시 보내고 evidence를 다시 남기므로,
    "패치가 통했다"는 판단도 judge의 다른 게이트와 마찬가지로 evidence 기반이다.

    `verifier`가 None이면 `verifiers.dispatch.verify_candidate`에 위임한다 — candidate의
    `vuln_class`(idor/xss/injection, IDOR은 다시 `attack_params.idor_mode`로 read/write)를
    보고 알맞은 verifier를 자동 선택한다. `vc_replay_attack`처럼 자동 재검증 루프에서는
    사람이 tool을 골라줄 수 없으므로 필요하다. 명시적으로 넘기면(테스트 등) 그 값을 그대로
    쓴다. (예전엔 read/write IDOR 사이에서만 고르는 `_is_mutation_candidate` 분기를 직접
    들고 있어 XSS/Injection finding의 attack gate가 IDOR 파라미터를 찾다 터졌다 — dispatch로
    일원화해 3개 취약점군 모두 자동 재현된다.)

    이 함수가 재현하는 인스턴스는 verifier가 candidate의 `base_url`로 찌르는 그대로다 —
    patch 적용 후 이 gate를 호출하기 전에 호출부(`check_build`/`_repoint_to_patched_runtime`)가
    같은 포트에서 patched worktree 인스턴스가 응답하도록 원본을 stop하고 overlay를
    start해 둬야 한다(그렇지 않으면 원본을 재공격하는 셈이라 "패치가 막았나"를 볼 수 없다).
    """
    finding = get(Finding, finding_id)
    if finding is None:
        raise ValueError(f"finding {finding_id} not found")
    if finding.candidate_id is None:
        raise ValueError(f"finding {finding_id}에 candidate_id가 없어 attack gate를 재현할 수 없습니다")

    candidate = get(Candidate, finding.candidate_id)
    if candidate is None:
        raise ValueError(f"candidate {finding.candidate_id} not found")

    if verifier is None:
        verifier = verify_candidate

    result = verifier(run_id, candidate, max_requests=max_requests)
    return not result.verified


def _capture_command_log(run_id: str, producer: str, result) -> None:
    """실패한 build/regression 명령의 stdout/stderr를 evidence로 남긴다(7.3 container log redaction).

    지금까지 judge 게이트는 `CommandResult.status`만 보고 stdout/stderr를 버려서, RETRY
    사유(예: SQLite `+` 문자열 결합 오류로 검색이 깨진 사례, J-3 실주행에서 직접 겪음)를
    사람이 알 방법이 없었다 — SECURITY_POLICY.md 6절이 적어둔 "container/process 로그
    redaction 미구현" gap의 실제 원인은 redaction 누락이 아니라 **로그를 남기는 경로
    자체가 없었던 것**이다. `write_artifact`가 저장 전 이미 `redact()`를 거치므로
    (core/evidence_store.py), 그 경로에 그대로 실어 캡처와 redaction을 한 번에 해결한다.
    실패한 명령만 남긴다 — 전체 로그 보관이 아니라 RETRY 진단이 목적이다.
    """
    payload = (
        f"command_id={result.command_id} status={result.status} exit_code={result.exit_code}\n"
        f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}\n"
    )
    write_artifact(
        run_id,
        observation_type=ObservationType.LOG,
        producer=producer,
        data=payload.encode("utf-8", errors="replace"),
    )


def _target_kind(target: object) -> str:
    """target의 kind ("compose_project" | "running_local"). 미선언이면 "compose_project"(기존 기본).

    P1 확정값(2026-07-21): compose_project / running_local. 정확한 필드 위치는 P1이 P2 registry
    확인 후 확정 예정 — 그때까지 manifest.kind → target.kind 순으로 방어적 조회한다. 기본이
    compose_project라 기존 22개 target은 무영향(c1-05 gold 안전), running_local target이 생길
    때만 아래 분기가 활성화된다(그 target은 registry+kind가 main에 오기 전엔 존재 불가).
    """
    manifest = getattr(target, "manifest", None)
    return getattr(manifest, "kind", None) or getattr(target, "kind", None) or "compose_project"


def check_build(run_id: str, patch_id: str) -> bool | None:
    """Build gate: patch가 적용된 worktree가 실제로 build되는지 확인한다.

    Compose 기반 target(`manifest.docker_isolation`이 설정된 target)은 `catalog.run_overlay_for()`
    (P2, D3-P2.md)로 build context가 patched worktree를 가리키는 run-scoped Compose 문서를
    생성해 그 위에서 `build` command를 실행한다 — checked-in Compose의 build context가 원본
    source clone을 고정 참조하는 문제를 P2 overlay가 worktree로 재사영해서 우회한다.

    build 성공 뒤에는 원본 인스턴스를 내리고 patched overlay를 그 자리(같은 승인된 loopback
    포트)에 띄워 health가 날 때까지 기다린다(`_repoint_to_patched_runtime`) — 이게 안 되어
    있으면 뒤이은 `check_attack`/`check_positive_functionality`가 patched worktree가 아니라
    여전히 원본 인스턴스를 재공격해 "패치가 막았나"를 구조적으로 확인할 수 없다(candidate의
    base_url은 그대로 두고, 그 포트에서 응답하는 프로세스만 바꾸는 방식이라 verifier 쪽은
    수정할 필요가 없다).

    source-native target(Gradle/npm처럼 `working_dir` override 없이 그냥 소스 디렉터리에서
    도는 build)은 여전히 `runtime.test_runner.RunScopedTestRunner`(P2)가 test suite에 쓰는
    것과 같은 패턴 — manifest의 `source_dir`를 run source root 자신을 가리키는 `"."`로 바꿔서
    (`model_copy`) build command를 patched source root 안에서 직접 재실행한다. 현재 checked-in manifest
    22개가 전부 `docker_isolation`을 선언하므로 이 분기에는 아직 repoint가 없다 — 그런
    target이 생기면 같은 패턴(원본 stop → worktree 기준 start → health)을 추가해야 한다.
    """
    from runtime.lifecycle import LifecycleManager

    _, run, worktree_path, run_source_root = _patch_and_worktree(run_id, patch_id)
    catalog = _service().catalog
    target = catalog.get(run.target_id)
    if _target_kind(target) == "running_local":
        # 3A-5: 이미 떠 있는 서비스는 patched worktree를 build/restart 못 한다 → build 게이트 N/A(None).
        # compute_verdict가 None을 FIXED로 올리지 않으므로 running_local target은 최대 PATCH_PROPOSED에 머문다.
        # (못 돌린 게이트를 통과로 위조하지 않는다 = K-2 원칙)
        return None
    if target.manifest.docker_isolation is not None:
        overlay = catalog.run_overlay_for(run.target_id, run.id)
        overlay.prepare()
        result = overlay.execute("build")
        if result.status != "passed":
            _capture_command_log(run.id, "core.judge.check_build:build", result)
            return False
        return _repoint_to_patched_runtime(catalog, target, overlay)
    worktree_manifest = target.manifest.model_copy(update={"source_dir": "."})
    result = LifecycleManager(worktree_manifest, run_source_root).build()
    if result.status != "passed":
        _capture_command_log(run.id, "core.judge.check_build:build", result)
    return result.status == "passed"


def _repoint_to_patched_runtime(catalog, target, overlay) -> bool:
    """원본 인스턴스를 내리고 patched overlay를 승인된 loopback 포트에 띄운다.

    두 인스턴스가 같은 host port를 두고 경합할 수 없으므로(targets/README.md
    "Run-scoped patched runtime") 원본을 먼저 stop해야 overlay start가 그 포트를 받을 수
    있다. 원본이 이미 내려가 있어도 `docker compose down`은 안전하게 no-op이다.
    """
    from runtime.lifecycle import LifecycleManager

    # For a user-registered local target, the *original* (unpatched) instance is
    # defined by their own repository, not VibeCutter's — `catalog.repository_root`
    # is only correct for built-in targets (2026-07-22, U4 live discovery: this
    # always used `catalog.repository_root`, so stopping a local target's original
    # container silently ran in the wrong directory, found nothing to stop, and the
    # overlay's `start` then failed with "port is already allocated").
    original_root = (
        catalog.source_repository_for(target.manifest.id) if target.user_registered else catalog.repository_root
    )
    LifecycleManager(target.manifest, original_root).stop()
    start_result = overlay.execute("start")
    if start_result.status != "passed":
        _capture_command_log(overlay.run_id, "core.judge.check_build:start", start_result)
        return False
    return overlay.check_health().status == "ready"


def check_positive_functionality(run_id: str, patch_id: str) -> bool:
    """Positive functionality gate: 정상 권한 사용자 기능이 패치 후에도 성공하는지 확인한다.

    **P3 handoff(Plan B)**: 실제 재현·판정은 `repair.validators.validate_patch(run_id,
    patch_id)`에 위임한다 — P3가 attack gate 재확인 + positive functionality 확인을 묶어
    "judge 없이도 단독 실행 가능한" 실행기로 구현했다(D3-P3.md, `verifiers.access_control.verify`를
    judge가 소비하는 것과 같은 패턴: 실제 HTTP 재현/evidence 저장은 P3 모듈이, 여기 judge는
    그 결과를 bool로 받아 게이트 판정에만 쓴다). P3가 D3에 이 계약(bool, positive만) 그대로
    구현·재확인했으므로 Day2에 쓰던 지연 import를 걷어내고 `check_attack`과 같은 top-level
    import로 정리했다.

    patch_id → finding → candidate 역추적, 재현, evidence 저장은 전부 `validate_patch()`
    내부(`repair.validators._candidate_for_patch` + `run_security_validation`)가 한다.
    """
    return validate_patch(run_id, patch_id)


def check_regression(run_id: str, patch_id: str) -> bool:
    """Regression gate: 기존 test suite가 patch 적용 후(worktree 안에서)에도 통과하는지 확인한다.

    Compose 기반 target은 build gate와 동일하게 P2 run overlay를 통해 실행한다. 그렇지 않으면
    manifest의 checked-in Compose file 경로가 원본 source clone을 보거나, target worktree 안에서
    VibeCutter repo 상대 경로를 찾지 못할 수 있다. source-native target은 P2
    `RunScopedTestRunner`를 그대로 호출한다.

    test suite가 선언되지 않은 target은 `TestRunSummary.status == "not_configured"`이고
    `.passed`는 `False`다 — P2 계약대로 "없으면 통과로 치지 않는다"를 그대로 따른다.
    """
    _, run, _, _ = _patch_and_worktree(run_id, patch_id)
    catalog = _service().catalog
    target = catalog.get(run.target_id)
    if target.manifest.docker_isolation is not None:
        if not target.manifest.test_suites:
            return False
        overlay = catalog.run_overlay_for(run.target_id, run.id)
        overlay.prepare()
        for suite in target.manifest.test_suites:
            result = overlay.execute(suite.command_id)
            if result.status != "passed":
                _capture_command_log(run.id, f"core.judge.check_regression:{suite.command_id}", result)
                return False
        return True

    summary = catalog.test_runner_for(run.target_id).run(run.id)
    if not summary.passed:
        for result in summary.results:
            if result.status != "passed":
                _capture_command_log(run.id, f"core.judge.check_regression:{result.command_id}", result)
    return summary.passed


def _high_severity_count(candidates: list[Candidate]) -> int:
    """FP reject/우선순위(`scanners.aggregate.aggregate`) 적용 후 critical/high 후보 수."""
    kept = aggregate(candidates).kept
    return sum(1 for c in kept if candidate_severity(c) in ("critical", "high"))


def check_static(run_id: str, patch_id: str) -> bool:
    """Static gate: 패치가 새 high/critical severity SAST finding을 추가하지 않았는지 확인한다.

    원본 source(`catalog.source_root_for`, 패치 전 기준선)와 patched worktree 양쪽에 P4
    Semgrep(`scanners.sast.run_semgrep`)을 재실행해, FP reject/우선순위(`scanners.aggregate.aggregate`)
    적용 후 critical/high severity 후보 수를 비교한다 — patched 쪽이 늘지 않으면 통과.

    **알려진 한계**: `semgrep` 바이너리가 PATH에 없으면 `SemgrepUnavailableError`가 그대로
    전파된다(`vc_run_sast`와 동일한 제약, 로컬 미설치 환경 다수).
    """
    _, run, _, run_source_root = _patch_and_worktree(run_id, patch_id)
    catalog = _service().catalog
    source_root = catalog.source_root_for(run.target_id)

    baseline = run_semgrep(source_root, run_id=f"{run.id}-static-baseline")
    patched = run_semgrep(run_source_root, run_id=f"{run.id}-static-patched")
    return _high_severity_count(patched) <= _high_severity_count(baseline)


def check_scope(run_id: str, patch_id: str) -> bool:
    """Scope gate: 패치가 target worktree 밖 파일을 변경하지 않았는지 확인한다.

    10.1절 절대 원칙과 직결 — 6개 게이트 중 가장 엄격하게 구현한다. `vc_apply_patch`가 적용
    시점에 이미 `assert_diff_within_worktree()`로 같은 검사를 사전 강제하지만, 이 게이트는
    judge 6게이트의 일부로 사후에도 다시 확인한다(단일 지점 실패에 의존하지 않는 이중 확인).
    """
    patch = get(Patch, patch_id)
    if patch is None:
        raise ValueError(f"patch {patch_id} not found")
    run = get(Run, run_id)
    if run is None:
        raise ValueError(f"run {run_id} not found")

    run_source_root = _service().catalog.run_source_root_for(run.target_id, run.id)
    try:
        assert_diff_within_worktree(patch.diff, run_source_root)
    except ScopeViolationError:
        return False
    return True


_GATE_FIELDS = ("build", "attack", "positive_test", "regression", "static", "scope")


def compute_verdict(validation: Validation) -> str | None:
    """6개 게이트가 전부 채워졌을 때만 verdict를 낸다 — 하나라도 아직 `None`이면 미확정(`None`).

    전부 `True`면 `RunState.FIXED`, 하나라도 `False`면 `RunState.RETRY`. 재시도 횟수 상한
    (3회 실패 시 human review)은 이 함수가 아니라 `core/planner.py`(Day4)가 강제한다 —
    여기서는 `HUMAN_REVIEW`를 직접 내지 않는다(state_machine.py의 기존 원칙과 동일).
    """
    gates = [getattr(validation, field) for field in _GATE_FIELDS]
    if any(gate is None for gate in gates):
        return None
    return RunState.FIXED.value if all(gates) else RunState.RETRY.value
