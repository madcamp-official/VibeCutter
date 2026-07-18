"""Run/Finding 상태 머신.

Run 파트는 기획서 5.2절 고정 순서를 전이 그래프로 강제한다. Finding 파트는 5.3절
"각 상태 전이는 deterministic judge의 조건으로만 발생한다"는 원칙을 코드 수준에서
강제한다 — evidence_ids 없이는 candidate/verified/rejected/fixed/human_review 사이를
전이할 수 없다. 이 모듈은 judge.py(Day2~3)가 구현을 채워 넣을 인터페이스이며, 다른
코드가 이 함수를 우회해 evidence 없이 상태를 승격시키지 못하게 하는 것이 목적이다.

상태 이름 자체는 `contracts.schemas`의 RunState/FindingStatus(공통 계약)를 그대로
쓴다 — 여기서는 enum을 다시 정의하지 않고 어떤 전이가 허용되는지만 정의한다.
"""

from __future__ import annotations

from collections.abc import Sequence

from contracts.schemas import FindingStatus, RunState

# 5.2절 화살표를 그대로 옮긴 허용 전이 그래프.
# RETRY는 문서에 되돌아갈 상태가 명시되어 있지 않아, patch 후보를 다시 만들어 재시도한다고
# 해석해 PATCH_PROPOSED로 되돌린다. 재시도 횟수 상한(3회 실패 시 human review)은
# core/planner.py(Day4)가 강제한다 — RETRY → HUMAN_REVIEW는 그 강제가 쓰는 유일한 목적지다
# (patch/verifier 판정이 아니라 재시도 소진이라는 프로세스 종료 사유라 RETRY의 기존
# 목적지 PATCH_PROPOSED만으로는 표현할 수 없었다. additive 변경 — 기존 RETRY→PATCH_PROPOSED
# 경로는 그대로 유지).
RUN_TRANSITIONS: dict[RunState, frozenset[RunState]] = {
    RunState.REGISTERED: frozenset({RunState.BUILDING}),
    RunState.BUILDING: frozenset({RunState.READY}),
    RunState.READY: frozenset({RunState.MAPPING}),
    RunState.MAPPING: frozenset({RunState.CANDIDATE_SCAN}),
    RunState.CANDIDATE_SCAN: frozenset({RunState.VERIFYING}),
    RunState.VERIFYING: frozenset({RunState.VERIFIED, RunState.REJECTED}),
    RunState.VERIFIED: frozenset({RunState.LOCALIZING}),
    RunState.REJECTED: frozenset(),  # 종료 — 다른 candidate 처리는 planner가 별도로 이어간다
    RunState.LOCALIZING: frozenset({RunState.PATCH_PROPOSED}),
    RunState.PATCH_PROPOSED: frozenset({RunState.WAITING_APPROVAL}),
    RunState.WAITING_APPROVAL: frozenset({RunState.PATCH_APPLIED}),
    RunState.PATCH_APPLIED: frozenset({RunState.VALIDATING}),
    RunState.VALIDATING: frozenset({RunState.FIXED, RunState.RETRY, RunState.HUMAN_REVIEW}),
    RunState.RETRY: frozenset({RunState.PATCH_PROPOSED, RunState.HUMAN_REVIEW}),
    RunState.FIXED: frozenset(),
    RunState.HUMAN_REVIEW: frozenset(),
}

TERMINAL_STATES: frozenset[RunState] = frozenset(
    {RunState.REJECTED, RunState.FIXED, RunState.HUMAN_REVIEW}
)


class InvalidTransitionError(ValueError):
    """허용되지 않은 상태 전이를 요청했을 때 발생한다."""

    def __init__(self, current: RunState | FindingStatus, target: RunState | FindingStatus):
        super().__init__(f"{current} -> {target} 전이는 허용되지 않습니다")
        self.current = current
        self.target = target


def can_transition(current: RunState, target: RunState) -> bool:
    return target in RUN_TRANSITIONS.get(current, frozenset())


def transition(current: RunState, target: RunState) -> RunState:
    """허용된 전이인지 검사 후 target을 반환한다. 실제 영속화는 evidence_store가 담당한다."""
    if not can_transition(current, target):
        raise InvalidTransitionError(current, target)
    return target


def is_terminal(state: RunState) -> bool:
    return state in TERMINAL_STATES


# --- Finding 상태 전이: judge-only 판정 (5.3절) ----------------------------------------
#
# CANDIDATE_SCAN에서 만든 후보는 VERIFYING의 judge 판정으로 VERIFIED/REJECTED로 갈라지고,
# VERIFIED는 patch 검증(VALIDATING)의 judge 판정으로 FIXED/HUMAN_REVIEW로 갈라진다 —
# RunState의 같은 두 분기점을 Finding 단위로 압축한 것과 동일한 구조다.

FINDING_TRANSITIONS: dict[FindingStatus, frozenset[FindingStatus]] = {
    FindingStatus.CANDIDATE: frozenset({FindingStatus.VERIFIED, FindingStatus.REJECTED}),
    FindingStatus.VERIFIED: frozenset({FindingStatus.FIXED, FindingStatus.HUMAN_REVIEW}),
    FindingStatus.REJECTED: frozenset(),
    FindingStatus.FIXED: frozenset(),
    FindingStatus.HUMAN_REVIEW: frozenset(),
}

FINDING_TERMINAL_STATES: frozenset[FindingStatus] = frozenset(
    {FindingStatus.REJECTED, FindingStatus.FIXED, FindingStatus.HUMAN_REVIEW}
)


class MissingEvidenceError(ValueError):
    """evidence_ids 없이 Finding 상태를 전이시키려 할 때 발생한다."""

    def __init__(self, current: FindingStatus, target: FindingStatus):
        super().__init__(f"{current} -> {target} 전이는 evidence_ids 없이 허용되지 않습니다")
        self.current = current
        self.target = target


def can_transition_finding(current: FindingStatus, target: FindingStatus) -> bool:
    return target in FINDING_TRANSITIONS.get(current, frozenset())


def transition_finding(
    current: FindingStatus,
    target: FindingStatus,
    *,
    evidence_ids: Sequence[str],
) -> FindingStatus:
    """evidence_ids가 최소 1개 이상 있어야만 Finding 상태 전이를 허용한다.

    이 함수는 의도적으로 LLM confidence나 서술형 이유를 입력으로 받지 않는다 — "LLM
    confidence는 우선순위에만 사용하고 최종 사실 판정에는 사용하지 않는다"는 5.3절 원칙을
    시그니처 수준에서 강제한다. 오직 core/judge.py만 이 함수를 호출해야 하며, 다른 코드는
    Finding.verification_state를 직접 대입하지 않고 항상 이 경로를 거쳐야 한다.
    """
    if not can_transition_finding(current, target):
        raise InvalidTransitionError(current, target)
    if not evidence_ids:
        raise MissingEvidenceError(current, target)
    return target


def is_finding_terminal(status: FindingStatus) -> bool:
    return status in FINDING_TERMINAL_STATES
