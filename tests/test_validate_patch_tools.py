"""vc_build_and_test/vc_replay_attack/vc_validate_regression MCP tool 배선 (Day3) 테스트.

실제 judge 게이트(core.judge.check_*)는 각자 별도 테스트(tests/test_judge.py)로 이미
검증했으므로 여기서는 mock으로 대체하고, P1이 배선한 부분(Validation row 공유, RunState
VALIDATING 전이, verdict 확정 시 Finding FIXED 승격/evidence 기록, RETRY 시 Finding 유지)만
확인한다.
"""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch
from uuid import uuid4

from contracts.schemas import Candidate, Finding, FindingStatus, Patch, Run, RunState
from core.evidence_store import get, save


def _setup(status: RunState = RunState.PATCH_APPLIED) -> tuple[Run, Finding, Patch]:
    run = Run(id=f"run-{uuid4().hex[:12]}", target_id="fake-target", status=status)
    save(run)
    candidate = Candidate(id=f"cand-{uuid4().hex[:12]}", run_id=run.id, cwe="CWE-639")
    save(candidate)
    finding = Finding(
        id=f"finding-{uuid4().hex[:12]}",
        run_id=run.id,
        candidate_id=candidate.id,
        title="t",
        verification_state=FindingStatus.VERIFIED,
        evidence_ids=["obs-seed"],
    )
    save(finding)
    p = Patch(id=f"patch-{uuid4().hex[:12]}", finding_id=finding.id, run_id=run.id, diff="d")
    save(p)
    return run, finding, p


def _call(name: str, args: dict) -> object:
    from mcp_server.server import mcp

    return asyncio.run(mcp.call_tool(name, args))


class GatePassingLeadsToFixedTests(unittest.TestCase):
    def test_all_six_gates_passing_marks_finding_fixed(self) -> None:
        run, finding, p = _setup()

        with (
            patch("mcp_server.tools_repair.check_build", return_value=True),
            patch("mcp_server.tools_repair.check_regression", return_value=True),
        ):
            _call("vc_build_and_test", {"patch_id": p.id})
        # 2/6 게이트만 채워졌으니 아직 미확정 — Run은 VALIDATING에 머문다.
        self.assertEqual(get(Run, run.id).status, RunState.VALIDATING)
        self.assertEqual(get(Finding, finding.id).verification_state, FindingStatus.VERIFIED)

        with patch("mcp_server.tools_repair.check_attack", return_value=True):
            _call("vc_replay_attack", {"patch_id": p.id})
        self.assertEqual(get(Run, run.id).status, RunState.VALIDATING)

        with (
            patch("mcp_server.tools_repair.check_positive_functionality", return_value=True),
            patch("mcp_server.tools_repair.check_static", return_value=True),
            patch("mcp_server.tools_repair.check_scope", return_value=True),
        ):
            _call("vc_validate_regression", {"patch_id": p.id})

        self.assertEqual(get(Run, run.id).status, RunState.FIXED)
        updated_finding = get(Finding, finding.id)
        self.assertEqual(updated_finding.verification_state, FindingStatus.FIXED)
        self.assertTrue(len(updated_finding.evidence_ids) >= 1)
        updated_patch = get(Patch, p.id)
        self.assertIsNotNone(updated_patch.validation_id)

    def test_one_failing_gate_leads_to_retry_and_finding_stays_verified(self) -> None:
        run, finding, p = _setup()

        with (
            patch("mcp_server.tools_repair.check_build", return_value=True),
            patch("mcp_server.tools_repair.check_regression", return_value=False),  # 실패
        ):
            _call("vc_build_and_test", {"patch_id": p.id})
        with patch("mcp_server.tools_repair.check_attack", return_value=True):
            _call("vc_replay_attack", {"patch_id": p.id})
        with (
            patch("mcp_server.tools_repair.check_positive_functionality", return_value=True),
            patch("mcp_server.tools_repair.check_static", return_value=True),
            patch("mcp_server.tools_repair.check_scope", return_value=True),
        ):
            _call("vc_validate_regression", {"patch_id": p.id})

        self.assertEqual(get(Run, run.id).status, RunState.RETRY)
        # RETRY는 Finding을 건드리지 않는다 — 다음 patch 재시도를 기다린다.
        self.assertEqual(get(Finding, finding.id).verification_state, FindingStatus.VERIFIED)

    def test_rejects_run_not_yet_patch_applied(self) -> None:
        run, finding, p = _setup(status=RunState.PATCH_PROPOSED)
        from mcp.server.fastmcp.exceptions import ToolError

        with self.assertRaises(ToolError):
            _call("vc_build_and_test", {"patch_id": p.id})
        self.assertEqual(get(Run, run.id).status, RunState.PATCH_PROPOSED)

    def test_unknown_patch_raises(self) -> None:
        from mcp.server.fastmcp.exceptions import ToolError

        with self.assertRaises(ToolError):
            _call("vc_replay_attack", {"patch_id": "patch-does-not-exist"})


if __name__ == "__main__":
    unittest.main()
