"""vc_generate_patch MCP tool 배선 테스트 (D3-P3.md 요청).

실제 합성·랭킹 로직(`repair.patcher.generate_patch`)과 root cause 계산(`repair.locator.localize`)은
P3 소유라 mock으로 대체하고, P1이 배선한 부분(source_root 조회, RunState 전이, Patch 저장,
trajectory 기록)만 검증한다.
"""

from __future__ import annotations

import asyncio
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

from contracts.schemas import ApprovalStatus, Finding, Patch, Run, RunState
from core.evidence_store import get, save
from core.trajectory import TRAJECTORY_DIR


def _run(status: RunState = RunState.VERIFIED) -> Run:
    run = Run(id=f"run-{uuid4().hex[:12]}", target_id="fake-target", status=status)
    save(run)
    return run


def _finding(run_id: str) -> Finding:
    finding = Finding(id=f"finding-{uuid4().hex[:12]}", run_id=run_id, title="t")
    save(finding)
    return finding


class VcGeneratePatchWiringTests(unittest.TestCase):
    def _call(self, args: dict) -> object:
        from mcp_server.server import mcp

        return asyncio.run(mcp.call_tool("vc_generate_patch", args))

    def _patched(self, fake_patch: Patch):
        fake_service = MagicMock()
        fake_service.catalog.source_root_for.return_value = Path(__file__).resolve().parent
        return (
            patch("mcp_server.tools_repair._service", return_value=fake_service),
            patch("mcp_server.tools_repair.localize", return_value=MagicMock(file="Foo.java")),
            patch("mcp_server.tools_repair.generate_patch", return_value=fake_patch),
        )

    def test_advances_verified_run_to_patch_proposed_and_stores_patch(self) -> None:
        run = _run(status=RunState.VERIFIED)
        finding = _finding(run.id)
        fake_patch = Patch(
            id=f"patch-{uuid4().hex[:12]}",
            finding_id=finding.id,
            run_id=run.id,
            diff="--- a\n+++ b\n",
            files=["Foo.java"],
            approval=ApprovalStatus.PENDING,
        )

        p1, p2, p3 = self._patched(fake_patch)
        with p1, p2, p3:
            self._call({"finding_id": finding.id})

        self.assertEqual(get(Run, run.id).status, RunState.PATCH_PROPOSED)
        self.assertIsNotNone(get(Patch, fake_patch.id))
        traj_path = TRAJECTORY_DIR / f"{run.id}.jsonl"
        self.assertTrue(traj_path.exists())
        self.assertIn("vc_generate_patch", traj_path.read_text(encoding="utf-8"))

    def test_repeat_call_on_patch_proposed_run_stays_patch_proposed(self) -> None:
        run = _run(status=RunState.PATCH_PROPOSED)
        finding = _finding(run.id)
        fake_patch = Patch(
            id=f"patch-{uuid4().hex[:12]}",
            finding_id=finding.id,
            run_id=run.id,
            diff="--- a\n+++ b\n",
            files=["Foo.java"],
        )

        p1, p2, p3 = self._patched(fake_patch)
        with p1, p2, p3:
            self._call({"finding_id": finding.id})

        self.assertEqual(get(Run, run.id).status, RunState.PATCH_PROPOSED)

    def test_rejects_run_in_wrong_state(self) -> None:
        run = _run(status=RunState.CANDIDATE_SCAN)
        finding = _finding(run.id)
        fake_patch = Patch(
            id=f"patch-{uuid4().hex[:12]}", finding_id=finding.id, run_id=run.id, diff="d"
        )

        from mcp.server.fastmcp.exceptions import ToolError

        p1, p2, p3 = self._patched(fake_patch)
        with p1, p2, p3, self.assertRaises(ToolError):
            self._call({"finding_id": finding.id})
        self.assertEqual(get(Run, run.id).status, RunState.CANDIDATE_SCAN)

    def test_no_candidate_synthesized_leaves_run_state_unchanged(self) -> None:
        run = _run(status=RunState.VERIFIED)
        finding = _finding(run.id)
        fake_service = MagicMock()
        fake_service.catalog.source_root_for.return_value = Path(__file__).resolve().parent

        from mcp.server.fastmcp.exceptions import ToolError

        with (
            patch("mcp_server.tools_repair._service", return_value=fake_service),
            patch("mcp_server.tools_repair.localize", return_value=MagicMock(file="Foo.java")),
            patch(
                "mcp_server.tools_repair.generate_patch",
                side_effect=ValueError("no candidate synthesized"),
            ),
            self.assertRaises(ToolError),
        ):
            self._call({"finding_id": finding.id})

        self.assertEqual(get(Run, run.id).status, RunState.VERIFIED)


if __name__ == "__main__":
    unittest.main()
