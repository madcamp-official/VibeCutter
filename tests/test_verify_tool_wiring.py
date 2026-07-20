"""vc_verify_access_control MCP tool 실배선(Day2 섹션 2) 테스트.

실제 target/Docker 없이도 정책 검사 → 승인 게이트 → RunState 전이 → Candidate→Finding
승격 → verifier 결과 반영까지 검증한다. verifier 본문(`verifiers.access_control.verify`)은
D2-P3.md가 이미 WebGoat로 검증했으므로 여기서는 mock으로 대체하고, "P1이 배선한 부분"만
확인한다.
"""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch
from uuid import uuid4

from contracts.schemas import Candidate, Finding, FindingStatus, Run, RunState, VerificationResult
from core.evidence_store import get, save, write_artifact
from core.policy_engine import PolicyViolation
from mcp_server.tools_analysis import _prepare_verification

# policies/scope.yaml에 실제로 등록된 target_id (Day2 섹션 1에서 등록).
REGISTERED_TARGET_ID = "26s-w1-c1-03"


def _run(target_id: str = REGISTERED_TARGET_ID, status: RunState = RunState.CANDIDATE_SCAN) -> Run:
    run = Run(id=f"run-{uuid4().hex[:12]}", target_id=target_id, status=status)
    save(run)
    return run


def _candidate(run_id: str) -> Candidate:
    candidate = Candidate(id=f"cand-{uuid4().hex[:12]}", run_id=run_id, cwe="CWE-639")
    save(candidate)
    return candidate


class PrepareVerificationTests(unittest.TestCase):
    def test_rejects_without_approval(self) -> None:
        run = _run()
        candidate = _candidate(run.id)
        with self.assertRaises(PermissionError):
            _prepare_verification(run.id, candidate.id, approved=False, tool_name="t")

    def test_rejects_unregistered_target(self) -> None:
        run = _run(target_id="not-in-scope-yaml")
        candidate = _candidate(run.id)
        with self.assertRaises(PolicyViolation):
            _prepare_verification(run.id, candidate.id, approved=True, tool_name="t")

    def test_rejects_unknown_run_or_candidate(self) -> None:
        with self.assertRaises(ValueError):
            _prepare_verification("run-does-not-exist", "cand-x", approved=True, tool_name="t")
        run = _run()
        with self.assertRaises(ValueError):
            _prepare_verification(run.id, "cand-does-not-exist", approved=True, tool_name="t")

    def test_rejects_base_url_outside_allowed_hosts(self) -> None:
        # 부록 C-2 (1-1): verifier가 때릴 base_url의 host가 allowed_hosts 밖이면 거부.
        run = _run()  # 26s-w1-c1-03, allowed_hosts=[127.0.0.1]
        candidate = Candidate(
            id=f"cand-{uuid4().hex[:12]}",
            run_id=run.id,
            cwe="CWE-639",
            attack_params={"base_url": "http://10.0.0.5:8080"},
        )
        save(candidate)
        with self.assertRaises(PolicyViolation):
            _prepare_verification(run.id, candidate.id, approved=True, tool_name="t")
        # 정책 위반은 VERIFYING 전이 전에 거부돼야 한다.
        self.assertEqual(get(Run, run.id).status, RunState.CANDIDATE_SCAN)

    def test_allows_base_url_within_allowed_hosts(self) -> None:
        run = _run()
        candidate = Candidate(
            id=f"cand-{uuid4().hex[:12]}",
            run_id=run.id,
            cwe="CWE-639",
            attack_params={"base_url": "http://127.0.0.1:14005"},
        )
        save(candidate)
        _prepare_verification(run.id, candidate.id, approved=True, tool_name="t")
        self.assertEqual(get(Run, run.id).status, RunState.VERIFYING)

    def test_transitions_run_to_verifying_and_creates_finding(self) -> None:
        run = _run()
        candidate = _candidate(run.id)
        _, returned_candidate, finding = _prepare_verification(
            run.id, candidate.id, approved=True, tool_name="t"
        )
        self.assertEqual(returned_candidate.id, candidate.id)
        self.assertEqual(get(Run, run.id).status, RunState.VERIFYING)
        self.assertEqual(finding.candidate_id, candidate.id)
        self.assertEqual(finding.verification_state, FindingStatus.CANDIDATE)

    def test_second_call_reuses_same_finding_and_does_not_re_transition(self) -> None:
        run = _run()
        candidate = _candidate(run.id)
        _, _, finding_1 = _prepare_verification(run.id, candidate.id, approved=True, tool_name="t")
        _, _, finding_2 = _prepare_verification(run.id, candidate.id, approved=True, tool_name="t")
        self.assertEqual(finding_1.id, finding_2.id)
        self.assertEqual(get(Run, run.id).status, RunState.VERIFYING)


class VcVerifyAccessControlToolTests(unittest.TestCase):
    """실제 MCP call_tool 경로로 vc_verify_access_control 전체를 구동한다."""

    def _call(self, args: dict) -> object:
        from mcp_server.server import mcp

        return asyncio.run(mcp.call_tool("vc_verify_access_control", args))

    def test_verified_result_promotes_finding_and_records_evidence(self) -> None:
        run = _run()
        candidate = _candidate(run.id)
        obs = write_artifact(
            run.id, observation_type="http_exchange", producer="test", data=b"mock exchange"
        )
        fake_result = VerificationResult(
            verified=True, evidence_ids=[obs.id], reason="mocked: victim marker exposed"
        )
        with patch("mcp_server.tools_analysis.verify_access_control", return_value=fake_result):
            self._call(
                {
                    "run_id": run.id,
                    "candidate_id": candidate.id,
                    "max_requests": 5,
                    "approved": True,
                }
            )

        from core.evidence_store import list_by_run

        finding = next(f for f in list_by_run(Finding, run.id) if f.candidate_id == candidate.id)
        self.assertEqual(finding.verification_state, FindingStatus.VERIFIED)
        self.assertIn(obs.id, finding.evidence_ids)

    def test_rejected_result_does_not_promote_finding(self) -> None:
        run = _run()
        candidate = _candidate(run.id)
        obs = write_artifact(
            run.id, observation_type="http_exchange", producer="test", data=b"mock exchange"
        )
        fake_result = VerificationResult(
            verified=False, evidence_ids=[obs.id], reason="mocked: no access control violation"
        )
        with patch("mcp_server.tools_analysis.verify_access_control", return_value=fake_result):
            self._call(
                {
                    "run_id": run.id,
                    "candidate_id": candidate.id,
                    "max_requests": 5,
                    "approved": True,
                }
            )

        from core.evidence_store import list_by_run

        finding = next(f for f in list_by_run(Finding, run.id) if f.candidate_id == candidate.id)
        self.assertEqual(finding.verification_state, FindingStatus.REJECTED)

    def test_unapproved_call_is_rejected_before_verifier_runs(self) -> None:
        from mcp.server.fastmcp.exceptions import ToolError

        run = _run()
        candidate = _candidate(run.id)
        with patch("mcp_server.tools_analysis.verify_access_control") as mock_verify:
            with self.assertRaises(ToolError):
                self._call({"run_id": run.id, "candidate_id": candidate.id, "approved": False})
        mock_verify.assert_not_called()

    def test_verified_result_transitions_run_to_verified(self) -> None:
        run = _run()
        candidate = _candidate(run.id)
        obs = write_artifact(
            run.id, observation_type="http_exchange", producer="test", data=b"mock exchange"
        )
        fake_result = VerificationResult(
            verified=True, evidence_ids=[obs.id], reason="mocked: victim marker exposed"
        )
        with patch("mcp_server.tools_analysis.verify_access_control", return_value=fake_result):
            self._call(
                {"run_id": run.id, "candidate_id": candidate.id, "max_requests": 5, "approved": True}
            )

        self.assertEqual(get(Run, run.id).status, RunState.VERIFIED)

    def test_rejected_result_leaves_run_in_verifying(self) -> None:
        run = _run()
        candidate = _candidate(run.id)
        obs = write_artifact(
            run.id, observation_type="http_exchange", producer="test", data=b"mock exchange"
        )
        fake_result = VerificationResult(
            verified=False, evidence_ids=[obs.id], reason="mocked: no access control violation"
        )
        with patch("mcp_server.tools_analysis.verify_access_control", return_value=fake_result):
            self._call(
                {"run_id": run.id, "candidate_id": candidate.id, "max_requests": 5, "approved": True}
            )

        self.assertEqual(get(Run, run.id).status, RunState.VERIFYING)

    def _trajectory_labels(self, run_id: str) -> list:
        # record_trajectory_step은 evidence.db가 아니라 .vibecutter/trajectories/<run>.jsonl에
        # append한다 — P4 학습 배치가 읽는 그 파일에서 label을 확인한다.
        from core.trajectory import TRAJECTORY_DIR
        from model.trajectory import load_trajectories

        path = TRAJECTORY_DIR / f"{run_id}.jsonl"
        self.addCleanup(path.unlink, missing_ok=True)
        return [t.label for t in load_trajectories(path)] if path.exists() else []

    def test_verify_records_learnable_label_in_trajectory(self) -> None:
        """P4 학습 배치 전제(2-4): verify가 verified/rejected label을 trajectory에 남긴다 —
        이게 없으면 export_training_dataset()이 0줄이 된다(P2/P4 보고)."""
        for verified, expected in ((True, "verified"), (False, "rejected")):
            with self.subTest(verified=verified):
                run = _run()
                candidate = _candidate(run.id)
                obs = write_artifact(
                    run.id, observation_type="http_exchange", producer="test", data=b"mock"
                )
                fake = VerificationResult(verified=verified, evidence_ids=[obs.id], reason="m")
                with patch("mcp_server.tools_analysis.verify_access_control", return_value=fake):
                    self._call(
                        {"run_id": run.id, "candidate_id": candidate.id, "approved": True}
                    )
                self.assertIn(expected, self._trajectory_labels(run.id))

    def test_second_candidate_after_run_verified_is_rejected(self) -> None:
        from mcp.server.fastmcp.exceptions import ToolError

        run = _run()
        first_candidate = _candidate(run.id)
        second_candidate = _candidate(run.id)
        obs = write_artifact(
            run.id, observation_type="http_exchange", producer="test", data=b"mock exchange"
        )
        fake_result = VerificationResult(verified=True, evidence_ids=[obs.id], reason="mocked")
        with patch("mcp_server.tools_analysis.verify_access_control", return_value=fake_result):
            self._call(
                {
                    "run_id": run.id,
                    "candidate_id": first_candidate.id,
                    "max_requests": 5,
                    "approved": True,
                }
            )
        self.assertEqual(get(Run, run.id).status, RunState.VERIFIED)

        # run이 이미 VERIFIED로 확정된 뒤에는 같은 run으로 다른 candidate를 검증할 수 없다
        # (VERIFIED의 유일한 목적지는 LOCALIZING뿐 — VERIFYING으로 되돌아가는 전이가 없다).
        with patch("mcp_server.tools_analysis.verify_access_control", return_value=fake_result):
            with self.assertRaises(ToolError):
                self._call(
                    {
                        "run_id": run.id,
                        "candidate_id": second_candidate.id,
                        "max_requests": 5,
                        "approved": True,
                    }
                )


class VcVerifyInjectionXssToolTests(unittest.TestCase):
    """injection/xss verify tool이 access_control과 동일한 배선(policy/승인/RunState/Finding)을
    타는지 실제 MCP call_tool 경로로 확인한다. P3 verifier 본문(verifiers/injection.py,
    verifiers/xss.py)은 이미 실앱 4개로 검증됐으므로(D4-P3-verifier-validation.md) 여기서는
    mock으로 대체하고 "P1이 배선한 부분"만 본다."""

    # (tool 이름, tools_analysis의 mock 대상, candidate CWE)
    CASES = [
        ("vc_verify_injection", "mcp_server.tools_analysis.verify_injection", "CWE-89"),
        ("vc_verify_xss", "mcp_server.tools_analysis.verify_xss", "CWE-79"),
    ]

    def _call(self, tool: str, args: dict) -> object:
        from mcp_server.server import mcp

        return asyncio.run(mcp.call_tool(tool, args))

    def test_verified_result_promotes_finding_and_transitions_run(self) -> None:
        for tool, mockpath, cwe in self.CASES:
            with self.subTest(tool=tool):
                run = _run()
                candidate = _candidate(run.id)
                candidate.cwe = cwe
                save(candidate)
                obs = write_artifact(
                    run.id, observation_type="http_exchange", producer="test", data=b"mock"
                )
                fake = VerificationResult(verified=True, evidence_ids=[obs.id], reason="mocked")
                with patch(mockpath, return_value=fake):
                    self._call(
                        tool, {"run_id": run.id, "candidate_id": candidate.id, "approved": True}
                    )

                from core.evidence_store import list_by_run

                finding = next(
                    f for f in list_by_run(Finding, run.id) if f.candidate_id == candidate.id
                )
                self.assertEqual(finding.verification_state, FindingStatus.VERIFIED)
                self.assertIn(obs.id, finding.evidence_ids)
                self.assertEqual(get(Run, run.id).status, RunState.VERIFIED)

    def test_rejected_result_does_not_promote_and_keeps_verifying(self) -> None:
        for tool, mockpath, _cwe in self.CASES:
            with self.subTest(tool=tool):
                run = _run()
                candidate = _candidate(run.id)
                obs = write_artifact(
                    run.id, observation_type="http_exchange", producer="test", data=b"mock"
                )
                fake = VerificationResult(verified=False, evidence_ids=[obs.id], reason="mocked")
                with patch(mockpath, return_value=fake):
                    self._call(
                        tool, {"run_id": run.id, "candidate_id": candidate.id, "approved": True}
                    )

                from core.evidence_store import list_by_run

                finding = next(
                    f for f in list_by_run(Finding, run.id) if f.candidate_id == candidate.id
                )
                self.assertEqual(finding.verification_state, FindingStatus.REJECTED)
                self.assertEqual(get(Run, run.id).status, RunState.VERIFYING)

    def test_unapproved_call_is_rejected_before_verifier_runs(self) -> None:
        from mcp.server.fastmcp.exceptions import ToolError

        for tool, mockpath, _cwe in self.CASES:
            with self.subTest(tool=tool):
                run = _run()
                candidate = _candidate(run.id)
                with patch(mockpath) as mock_verify:
                    with self.assertRaises(ToolError):
                        self._call(
                            tool, {"run_id": run.id, "candidate_id": candidate.id, "approved": False}
                        )
                mock_verify.assert_not_called()
                # 승인 없이는 VERIFYING까지도 못 간다.
                self.assertEqual(get(Run, run.id).status, RunState.CANDIDATE_SCAN)


if __name__ == "__main__":
    unittest.main()
