"""vc_export_patch MCP tool 배선 (W-4, §3A-6) 테스트.

§3A-6: `reset_run()`이 Compose 정리 후 worktree를 지워버려 사용자가 받아야 할 patch diff가
함께 사라지던 실제 결함을 고친다. 여기서는 파일이 정확한 경로/내용으로 보존되는지, 적용된
(approval=APPROVED) patch가 없을 때 거부하는지, 여러 patch 중 가장 최근 승인분을 고르는지만
확인한다 — reset과의 순서 보장(export 실패 시 reset 금지)은 `test_resume_audit.py`가 다룬다.
"""

from __future__ import annotations

import asyncio
import unittest
from uuid import uuid4

from contracts.schemas import ApprovalStatus, Patch, Run, RunState
from core.evidence_store import get, save


def _run(status: RunState = RunState.PATCH_APPLIED) -> Run:
    run = Run(id=f"run-{uuid4().hex[:12]}", target_id="fake-target", status=status)
    save(run)
    return run


def _patch(run_id: str, diff: str, *, approval: ApprovalStatus = ApprovalStatus.APPROVED) -> Patch:
    p = Patch(
        id=f"patch-{uuid4().hex[:12]}", finding_id="finding-x", run_id=run_id, diff=diff,
        approval=approval,
    )
    save(p)
    return p


def _call(args: dict) -> dict:
    from mcp_server.server import mcp

    _content, structured = asyncio.run(mcp.call_tool("vc_export_patch", args))
    return structured


class VcExportPatchTests(unittest.TestCase):
    def test_writes_diff_to_runs_directory(self) -> None:
        from core.db import DATA_DIR

        run = _run()
        p = _patch(run.id, "--- a/Foo.java\n+++ b/Foo.java\n@@ -1 +1 @@\n-x\n+y\n")

        result = _call({"run_id": run.id})

        out_path = DATA_DIR / "runs" / run.id / "security-fix.patch"
        self.assertTrue(out_path.is_file())
        self.assertEqual(out_path.read_text(encoding="utf-8"), p.diff)
        self.assertEqual(result["patch_id"], p.id)
        self.assertEqual(result["path"], str(out_path))
        out_path.unlink()

    def test_picks_most_recently_approved_patch_when_retried(self) -> None:
        run = _run()
        _patch(run.id, "old diff")
        newest = _patch(run.id, "new diff")

        result = _call({"run_id": run.id})

        self.assertEqual(result["patch_id"], newest.id)

    def test_pending_patch_is_ignored(self) -> None:
        run = _run()
        _patch(run.id, "never applied", approval=ApprovalStatus.PENDING)
        from mcp.server.fastmcp.exceptions import ToolError

        with self.assertRaises(ToolError):
            _call({"run_id": run.id})

    def test_no_approved_patch_raises(self) -> None:
        run = _run()
        from mcp.server.fastmcp.exceptions import ToolError

        with self.assertRaises(ToolError):
            _call({"run_id": run.id})

    def test_unknown_run_raises(self) -> None:
        from mcp.server.fastmcp.exceptions import ToolError

        with self.assertRaises(ToolError):
            _call({"run_id": "run-does-not-exist"})


if __name__ == "__main__":
    unittest.main()
