from __future__ import annotations

import unittest
from unittest.mock import patch
from uuid import uuid4

from contracts.schemas import Candidate, Finding, VerificationResult
from core.evidence_store import save
from core.judge import (
    check_attack,
    check_build,
    check_positive_functionality,
    check_regression,
    check_scope,
    check_static,
)


def _finding_with_candidate(run_id: str) -> tuple[Finding, Candidate]:
    candidate = Candidate(id=f"cand-{uuid4().hex[:12]}", run_id=run_id, cwe="CWE-639")
    save(candidate)
    finding = Finding(
        id=f"finding-{uuid4().hex[:12]}", run_id=run_id, candidate_id=candidate.id, title="t"
    )
    save(finding)
    return finding, candidate


class CheckAttackTests(unittest.TestCase):
    """Day2 범위: Attack gate만 실제로 동작해야 한다."""

    def test_passes_when_verifier_reports_no_longer_verified(self) -> None:
        run_id = f"run-{uuid4().hex[:12]}"
        finding, _ = _finding_with_candidate(run_id)

        def fake_verifier(run_id, candidate, *, max_requests=10):
            return VerificationResult(verified=False, evidence_ids=[], reason="patched")

        self.assertTrue(
            check_attack(run_id, finding.id, verifier=fake_verifier)
        )

    def test_fails_when_attack_still_succeeds(self) -> None:
        run_id = f"run-{uuid4().hex[:12]}"
        finding, _ = _finding_with_candidate(run_id)

        def fake_verifier(run_id, candidate, *, max_requests=10):
            return VerificationResult(verified=True, evidence_ids=["obs-x"], reason="still broken")

        self.assertFalse(
            check_attack(run_id, finding.id, verifier=fake_verifier)
        )

    def test_rejects_unknown_finding(self) -> None:
        with self.assertRaises(ValueError):
            check_attack("run-x", "finding-does-not-exist")

    def test_rejects_finding_without_candidate(self) -> None:
        run_id = f"run-{uuid4().hex[:12]}"
        finding = Finding(id=f"finding-{uuid4().hex[:12]}", run_id=run_id, title="no candidate")
        save(finding)
        with self.assertRaises(ValueError):
            check_attack(run_id, finding.id)


class RemainingGatesAreStubsTests(unittest.TestCase):
    """Day3 스텁 — 시그니처는 고정, 본문은 아직 미구현임을 명시적으로 확인."""

    def test_remaining_four_gates_raise_not_implemented(self) -> None:
        for gate in (check_build, check_regression, check_static, check_scope):
            with self.assertRaises(NotImplementedError):
                gate("run-x", "patch-x")


class CheckPositiveFunctionalityDelegatesToP3ValidatorsTests(unittest.TestCase):
    """P3 handoff(Plan B, D3-P3.md): check_positive_functionality는 이제 실제로 구현된
    `repair.validators.validate_patch()`에 top-level import로 위임한다(D3에 P3가 계약대로
    맞춰 구현 완료). `core.judge`가 `from repair.validators import validate_patch`로 이름을
    직접 바인딩해서 patch 대상은 origin(`repair.validators.validate_patch`)이 아니라
    `core.judge.validate_patch`여야 한다.
    """

    def test_delegates_to_repair_validators_validate_patch(self) -> None:
        with patch("core.judge.validate_patch", return_value=True) as mock_fn:
            self.assertTrue(check_positive_functionality("run-x", "patch-x"))
        mock_fn.assert_called_once_with("run-x", "patch-x")

    def test_propagates_false_from_validate_patch(self) -> None:
        with patch("core.judge.validate_patch", return_value=False):
            self.assertFalse(check_positive_functionality("run-x", "patch-x"))

    def test_unknown_patch_id_raises_value_error(self) -> None:
        # repair.validators.validate_patch가 이제 실제로 존재한다 — 존재하지 않는 patch_id는
        # (mock 없이) 그 실제 구현이 ValueError로 거부한다.
        with self.assertRaises(ValueError):
            check_positive_functionality("run-x", "patch-does-not-exist")


if __name__ == "__main__":
    unittest.main()
