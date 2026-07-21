"""vc_resume_audit MCP tool 배선 (W-4, §3A-7) 테스트.

§3A-7: driver가 더 이상 confirmed=True를 자동으로 넘기지 않으므로, 사용자가
vc_apply_patch(confirmed=True)로 승인한 뒤 재개하는 지점이 이 tool이다. 실제 judge
게이트(core.judge.check_*)는 tests/test_judge.py가 이미 검증했으니 여기서는 mock으로
대체하고, P1이 배선한 오케스트레이션(6게이트 순서 → export → reset, 전제 상태 검사,
export 실패 시 reset 미실행)만 확인한다.
"""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import MagicMock, patch
from uuid import uuid4

from contracts.schemas import ApprovalStatus, Candidate, Finding, FindingStatus, Patch, Run, RunState
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
    p = Patch(
        id=f"patch-{uuid4().hex[:12]}", finding_id=finding.id, run_id=run.id, diff="d",
        approval=ApprovalStatus.APPROVED,
    )
    save(p)
    return run, finding, p


def _call(args: dict) -> dict:
    from mcp_server.server import mcp

    _content, structured = asyncio.run(mcp.call_tool("vc_resume_audit", args))
    return structured


def _all_gates_pass():
    return (
        patch("mcp_server.tools_repair.check_build", return_value=True),
        patch("mcp_server.tools_repair.check_attack", return_value=True),
        patch("mcp_server.tools_repair.check_positive_functionality", return_value=True),
        patch("mcp_server.tools_repair.check_regression", return_value=True),
        patch("mcp_server.tools_repair.check_static", return_value=True),
        patch("mcp_server.tools_repair.check_scope", return_value=True),
    )


class VcResumeAuditTests(unittest.TestCase):
    def test_rejects_run_not_patch_applied(self) -> None:
        run, _finding, p = _setup(status=RunState.PATCH_PROPOSED)
        from mcp.server.fastmcp.exceptions import ToolError

        with self.assertRaises(ToolError):
            _call({"run_id": run.id})

    def test_unknown_run_raises(self) -> None:
        from mcp.server.fastmcp.exceptions import ToolError

        with self.assertRaises(ToolError):
            _call({"run_id": "run-does-not-exist"})

    def test_all_gates_pass_runs_export_then_reset_and_returns_fixed(self) -> None:
        run, finding, p = _setup()
        fake_service = MagicMock()
        fake_service.reset_run.return_value = True

        gates = _all_gates_pass()
        with gates[0], gates[1], gates[2], gates[3], gates[4], gates[5], patch(
            "mcp_server.tools_repair._service", return_value=fake_service
        ):
            result = _call({"run_id": run.id})

        self.assertEqual(get(Run, run.id).status, RunState.FIXED)
        self.assertEqual(get(Finding, finding.id).verification_state, FindingStatus.FIXED)
        self.assertEqual(result["patch_id"], p.id)
        self.assertEqual(result["verdict"], "FIXED")
        self.assertTrue(result["reset_ok"])
        fake_service.reset_run.assert_called_once_with("fake-target", run.id, approved=True)

        from core.db import DATA_DIR

        out_path = DATA_DIR / "runs" / run.id / "security-fix.patch"
        self.assertTrue(out_path.is_file())
        out_path.unlink()

    def test_export_failure_prevents_reset(self) -> None:
        """§3A-6: export 실패 시 reset을 시도하지 않는다 — 실패하면 worktree/patch가 그대로
        보존돼야 사용자가 여전히 diff를 받아갈 길이 있다."""
        run, _finding, p = _setup()
        fake_service = MagicMock()

        gates = _all_gates_pass()
        with (
            gates[0], gates[1], gates[2], gates[3], gates[4], gates[5],
            patch("mcp_server.tools_repair._service", return_value=fake_service),
            # vc_resume_audit 자체의 조회(1회)는 통과시키고, vc_export_patch 내부의
            # 조회(2회째, reset 직전)만 실패시켜 "export 실패 → reset 미실행"을 겨냥한다.
            patch("mcp_server.tools_repair._applied_patch_for_run") as fake_lookup,
        ):
            fake_lookup.side_effect = [p, ValueError("export lookup failed")]
            from mcp.server.fastmcp.exceptions import ToolError

            with self.assertRaises(ToolError):
                _call({"run_id": run.id})

        fake_service.reset_run.assert_not_called()

    def test_retry_verdict_still_exports_and_resets(self) -> None:
        """FIXED가 아니어도(게이트 하나 실패) export/reset은 정리 차원에서 그대로 진행한다."""
        run, finding, p = _setup()
        fake_service = MagicMock()
        fake_service.reset_run.return_value = True

        with (
            patch("mcp_server.tools_repair.check_build", return_value=True),
            patch("mcp_server.tools_repair.check_attack", return_value=True),
            patch("mcp_server.tools_repair.check_positive_functionality", return_value=True),
            patch("mcp_server.tools_repair.check_regression", return_value=False),  # 실패
            patch("mcp_server.tools_repair.check_static", return_value=True),
            patch("mcp_server.tools_repair.check_scope", return_value=True),
            patch("mcp_server.tools_repair._service", return_value=fake_service),
        ):
            result = _call({"run_id": run.id})

        self.assertEqual(get(Run, run.id).status, RunState.RETRY)
        self.assertEqual(result["verdict"], "RETRY")
        fake_service.reset_run.assert_called_once_with("fake-target", run.id, approved=True)

        from core.db import DATA_DIR

        out_path = DATA_DIR / "runs" / run.id / "security-fix.patch"
        self.assertTrue(out_path.is_file())
        out_path.unlink()


if __name__ == "__main__":
    unittest.main()
