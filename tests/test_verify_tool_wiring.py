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


class VcVerifyInjectionXssStubTests(unittest.TestCase):
    """verifier가 아직 없는 injection/xss도 policy/승인/상태 전이까지는 동일하게 배선됐는지 확인."""

    def _call(self, tool: str, args: dict) -> object:
        from mcp.server.fastmcp.exceptions import ToolError
        from mcp_server.server import mcp

        with self.assertRaises(ToolError) as ctx:
            asyncio.run(mcp.call_tool(tool, args))
        return ctx.exception

    def test_injection_stub_wires_policy_and_state_before_notimplemented(self) -> None:
        run = _run()
        candidate = _candidate(run.id)
        exc = self._call(
            "vc_verify_injection",
            {"run_id": run.id, "candidate_id": candidate.id, "approved": True},
        )
        self.assertIn("NotImplementedError", str(exc) + repr(exc.__cause__))
        self.assertEqual(get(Run, run.id).status, RunState.VERIFYING)

    def test_injection_stub_still_enforces_approval_gate(self) -> None:
        run = _run()
        candidate = _candidate(run.id)
        self._call(
            "vc_verify_injection",
            {"run_id": run.id, "candidate_id": candidate.id, "approved": False},
        )
        # 승인 없이는 VERIFYING까지도 못 간다.
        self.assertEqual(get(Run, run.id).status, RunState.CANDIDATE_SCAN)


if __name__ == "__main__":
    unittest.main()
