"""core/planner.py 재시도 상한(Day4) 테스트.

`enforce_retry_budget()`이 상한 이내에서는 아무 것도 안 하고, 상한을 넘으면 Finding을
HUMAN_REVIEW로 강제 승격 + evidence를 남기고 `RetryBudgetExhausted`를 던지는지 확인한다.
`patch_attempt_count()`가 finding_id로 정확히 필터링하는 것과, `core/state_machine.py`의
RETRY→HUMAN_REVIEW 전이가 실제로 허용되는 것도 함께 확인한다.
"""

from __future__ import annotations

import unittest
from uuid import uuid4

from contracts.schemas import Finding, FindingStatus, Patch, Run, RunState
from core.evidence_store import get, save
from core.planner import MAX_PATCH_ATTEMPTS, RetryBudgetExhausted, enforce_retry_budget, patch_attempt_count
from core.state_machine import can_transition


def _run(status: RunState = RunState.RETRY) -> Run:
    run = Run(id=f"run-{uuid4().hex[:12]}", target_id="fake-target", status=status)
    save(run)
    return run


def _finding(run_id: str, status: FindingStatus = FindingStatus.VERIFIED) -> Finding:
    finding = Finding(id=f"finding-{uuid4().hex[:12]}", run_id=run_id, title="t", verification_state=status)
    save(finding)
    return finding


def _patch(run_id: str, finding_id: str) -> Patch:
    p = Patch(id=f"patch-{uuid4().hex[:12]}", finding_id=finding_id, run_id=run_id, diff="d")
    save(p)
    return p


class StateMachineRetryTransitionTests(unittest.TestCase):
    def test_retry_can_reach_human_review(self) -> None:
        self.assertTrue(can_transition(RunState.RETRY, RunState.HUMAN_REVIEW))

    def test_retry_can_still_reach_patch_proposed(self) -> None:
        # 기존 재시도 경로는 그대로 살아있어야 한다(additive 변경).
        self.assertTrue(can_transition(RunState.RETRY, RunState.PATCH_PROPOSED))


class PatchAttemptCountTests(unittest.TestCase):
    def test_counts_only_patches_for_this_finding(self) -> None:
        run = _run()
        finding = _finding(run.id)
        other_finding = _finding(run.id)
        _patch(run.id, finding.id)
        _patch(run.id, finding.id)
        _patch(run.id, other_finding.id)

        self.assertEqual(patch_attempt_count(run.id, finding.id), 2)
        self.assertEqual(patch_attempt_count(run.id, other_finding.id), 1)

    def test_zero_for_finding_with_no_patches(self) -> None:
        run = _run()
        finding = _finding(run.id)
        self.assertEqual(patch_attempt_count(run.id, finding.id), 0)


class EnforceRetryBudgetTests(unittest.TestCase):
    def test_within_budget_does_nothing(self) -> None:
        run = _run()
        finding = _finding(run.id)
        for attempt_no in range(1, MAX_PATCH_ATTEMPTS + 1):
            enforce_retry_budget(run, finding, next_attempt_no=attempt_no)  # no-op, no raise

        self.assertEqual(get(Run, run.id).status, RunState.RETRY)
        self.assertEqual(get(Finding, finding.id).verification_state, FindingStatus.VERIFIED)

    def test_exceeding_budget_promotes_to_human_review_and_raises(self) -> None:
        run = _run()
        finding = _finding(run.id)

        with self.assertRaises(RetryBudgetExhausted):
            enforce_retry_budget(run, finding, next_attempt_no=MAX_PATCH_ATTEMPTS + 1)

        self.assertEqual(get(Finding, finding.id).verification_state, FindingStatus.HUMAN_REVIEW)
        self.assertEqual(get(Run, run.id).status, RunState.HUMAN_REVIEW)

    def test_exceeding_budget_leaves_evidence(self) -> None:
        run = _run()
        finding = _finding(run.id)

        with self.assertRaises(RetryBudgetExhausted):
            enforce_retry_budget(run, finding, next_attempt_no=MAX_PATCH_ATTEMPTS + 1)

        # HUMAN_REVIEW 전이가 evidence_ids 없이 통과했다면 하드 가드가 깨진 것이다
        # (transition_finding()이 MissingEvidenceError를 던졌을 것) — 실제로 남았는지 확인.
        updated = get(Finding, finding.id)
        self.assertTrue(updated.evidence_ids)


if __name__ == "__main__":
    unittest.main()
