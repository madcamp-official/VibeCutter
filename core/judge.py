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

from collections.abc import Callable

from contracts.schemas import Candidate, Finding, VerificationResult
from core.evidence_store import get
from verifiers.access_control import verify as verify_access_control
from verifiers.types import MAX_REQUESTS_DEFAULT


def check_attack(
    run_id: str,
    finding_id: str,
    *,
    max_requests: int = MAX_REQUESTS_DEFAULT,
    verifier: Callable[..., VerificationResult] = verify_access_control,
) -> bool:
    """Attack gate: 기존 재현 시퀀스가 더 이상 보안 영향으로 이어지지 않으면 통과(True)한다.

    finding이 참조하는 원본 Candidate로 verifier를 다시 호출해 `verified=False`가
    나오는지 확인한다 — verifier가 실제로 요청을 다시 보내고 evidence를 다시 남기므로,
    "패치가 통했다"는 판단도 judge의 다른 게이트와 마찬가지로 evidence 기반이다.

    Day2엔 실제 patch/worktree가 없어 "패치된 코드"가 아니라 "지금 코드베이스"를 다시
    찌른다 — 그래서 지금은 아직 취약한 코드에 대해 호출하면 gate가 정확히 실패(False)해야
    한다(패치 전이니 여전히 뚫려야 정상). Day3에 실제 patch loop가 붙으면 verifier가
    patched worktree의 실행 인스턴스를 대상으로 하도록 호출부(judge 사용처)에서 바꾼다 —
    이 함수 시그니처 자체는 바뀌지 않는다.

    verifier는 candidate.cwe에 따라 access_control 외에 injection/xss verifier로도
    바뀌어야 하지만(Day2엔 access_control만 구현됨), 그건 `verifier` 파라미터로 주입
    가능하게 열어뒀다 — 기본값만 access_control이다.
    """
    finding = get(Finding, finding_id)
    if finding is None:
        raise ValueError(f"finding {finding_id} not found")
    if finding.candidate_id is None:
        raise ValueError(f"finding {finding_id}에 candidate_id가 없어 attack gate를 재현할 수 없습니다")

    candidate = get(Candidate, finding.candidate_id)
    if candidate is None:
        raise ValueError(f"candidate {finding.candidate_id} not found")

    result = verifier(run_id, candidate, max_requests=max_requests)
    return not result.verified


def check_build(run_id: str, patch_id: str) -> bool:
    """Build gate: P2 adapter의 build 결과를 확인한다. Day3에 구현(P2 test runner 연동)."""
    raise NotImplementedError("Day3에 P2 build/worktree 연동 후 구현")


def check_positive_functionality(run_id: str, patch_id: str) -> bool:
    """Positive functionality gate: 정상 권한 사용자 기능이 패치 후에도 성공하는지 확인한다.

    Day3에 구현 — role fixture(P2)로 정상 사용자 플로우를 재현해야 한다.
    """
    raise NotImplementedError("Day3에 role fixture 연동 후 구현")


def check_regression(run_id: str, patch_id: str) -> bool:
    """Regression gate: 기존 test suite가 패치 후에도 통과하는지 확인한다.

    Day3에 구현 — `runtime.test_runner.RunScopedTestRunner`(P2)를 호출한다.
    """
    raise NotImplementedError("Day3에 P2 test runner 연동 후 구현")


def check_static(run_id: str, patch_id: str) -> bool:
    """Static gate: 패치가 새 high severity finding/secret을 만들지 않았는지 확인한다.

    Day3에 구현 — P4 Semgrep(`scanners.sast.run_semgrep`) 결과를 patch 적용 전/후로 재확인한다.
    """
    raise NotImplementedError("Day3에 P4 SAST 재실행 연동 후 구현")


def check_scope(run_id: str, patch_id: str) -> bool:
    """Scope gate: 패치가 target worktree 밖 파일을 변경하지 않았는지 확인한다.

    10.1절 절대 원칙과 직결 — 6개 게이트 중 가장 엄격하게 구현해야 한다(Day3).
    """
    raise NotImplementedError("Day3에 구현 — worktree 경로 밖 diff는 무조건 실패 처리")
