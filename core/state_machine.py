"""Run 상태 머신: 기획서 5.2절 고정 순서를 전이 그래프로 강제한다.

상태 이름 자체는 `contracts.schemas.RunState`(공통 계약)를 그대로 쓴다 — 여기서는
enum을 다시 정의하지 않고 어떤 전이가 허용되는지만 정의한다. Finding/Candidate 상태
(`FindingStatus`)를 deterministic judge만 판정하도록 강제하는 부분은 다음 체크리스트
항목(judge 인터페이스)에서 다룬다.
"""

from __future__ import annotations

from contracts.schemas import RunState

# 5.2절 화살표를 그대로 옮긴 허용 전이 그래프.
# RETRY는 문서에 되돌아갈 상태가 명시되어 있지 않아, patch 후보를 다시 만들어 재시도한다고
# 해석해 PATCH_PROPOSED로 되돌린다. 재시도 횟수 상한(예: 3회 실패 시 human review)은 이
# 그래프가 아니라 core/planner.py(Day4)가 별도로 강제한다.
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
    RunState.RETRY: frozenset({RunState.PATCH_PROPOSED}),
    RunState.FIXED: frozenset(),
    RunState.HUMAN_REVIEW: frozenset(),
}

TERMINAL_STATES: frozenset[RunState] = frozenset(
    {RunState.REJECTED, RunState.FIXED, RunState.HUMAN_REVIEW}
)


class InvalidTransitionError(ValueError):
    """허용되지 않은 상태 전이를 요청했을 때 발생한다."""

    def __init__(self, current: RunState, target: RunState):
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
