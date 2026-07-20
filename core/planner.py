"""patch 재시도 상한 (Day4).

`core/state_machine.py` 주석이 이미 "재시도 횟수 상한(예: 3회 실패 시 human review)은
이 그래프가 아니라 core/planner.py(Day4)가 별도로 강제한다"고 못박아 둔 항목을 채운다.
`repair/patcher.py`의 docstring("실패 시 planner가 RETRY(다음 attempt_no) → 3회 실패 시
HUMAN_REVIEW로 보낸다")과 SKILL 규칙("stop after 3 failed repair attempts and request
human review", 6.8절)이 이미 이 계약을 전제하고 있었다.

**이 상한은 프롬프트/Host의 판단이 아니라 tool 계층에서 하드 강제한다** — judge와 같은
원칙: `vc_generate_patch`(mcp_server/tools_repair.py)가 다음 attempt_no를 계산해 상한을
넘기면 이 모듈이 patch 생성 자체를 막고 Finding을 HUMAN_REVIEW로 강제 승격한다. Host가
이 규칙을 잊거나 무시해도 코드가 막는다(6.5절 `audit_local_target` 프롬프트는 안내만
하고, 실제 강제는 여기서 한다).
"""

from __future__ import annotations

import json

from contracts.schemas import Finding, FindingStatus, Patch, Run, RunState
from core.evidence_store import list_by_run, save, update_finding_status, write_artifact
from core.state_machine import transition
from core.trajectory import record_trajectory_step

MAX_PATCH_ATTEMPTS = 3


class RetryBudgetExhausted(RuntimeError):
    """이 finding에 대해 이미 `MAX_PATCH_ATTEMPTS`번 patch를 시도해 human review로 넘어갔다."""


def patch_attempt_count(run_id: str, finding_id: str) -> int:
    """이 finding에 대해 이미 생성된 Patch 수 — 다음 attempt_no(count + 1) 결정에 쓴다."""
    return sum(1 for p in list_by_run(Patch, run_id) if p.finding_id == finding_id)


def enforce_retry_budget(run: Run, finding: Finding, *, next_attempt_no: int) -> None:
    """`next_attempt_no`가 상한을 넘으면 Finding을 HUMAN_REVIEW로 강제 승격하고 거부한다.

    상한 이내면 아무 것도 하지 않는다 — 호출자(`vc_generate_patch`)가 평소대로
    `next_attempt_no`로 patch를 생성하면 된다. 상한을 넘으면 "3회 실패 소진" 사실을
    evidence artifact로 남기고(evidence 없이는 Finding 전이가 항상 거부되므로,
    `_finalize_validation`의 FIXED 승격과 같은 패턴), Run도 RETRY → HUMAN_REVIEW로
    전이한다(state_machine.py에 이 전이를 추가함 — 재시도 상한 소진은 patch/verifier
    판정이 아니라 프로세스 종료 사유라 RunState 그래프의 별도 목적지가 필요했다).
    """
    if next_attempt_no <= MAX_PATCH_ATTEMPTS:
        return

    summary = json.dumps(
        {
            "run_id": run.id,
            "finding_id": finding.id,
            "attempts": next_attempt_no - 1,
            "reason": f"patch 재시도 {MAX_PATCH_ATTEMPTS}회 소진",
        },
        ensure_ascii=False,
    ).encode("utf-8")
    artifact = write_artifact(
        run.id, observation_type="log", producer="core.planner:retry_exhausted", data=summary
    )
    update_finding_status(finding.id, FindingStatus.HUMAN_REVIEW, evidence_ids=[artifact.id])
    run.status = transition(run.status, RunState.HUMAN_REVIEW)
    save(run)
    # trajectory label(2-4, P4 학습 배치 전제): 재시도 소진 → human_review 학습 샘플.
    record_trajectory_step(
        run.id,
        state=run.status,
        action={"tool": "retry_budget", "finding_id": finding.id},
        result={"attempts": next_attempt_no - 1, "reason": "retry budget exhausted"},
        next_state=run.status,
        label="human_review",
        reward=0.0,
    )
    raise RetryBudgetExhausted(
        f"finding {finding.id}는 patch {MAX_PATCH_ATTEMPTS}회 실패로 human review로 넘어갔습니다"
    )
