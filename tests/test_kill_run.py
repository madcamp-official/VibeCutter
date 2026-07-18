"""vc_kill_run MCP tool (Day4 rollback 경로) 테스트.

실제 P2 `TargetRuntimeService.reset_run()`은 Docker/worktree가 필요하므로 mock으로
대체하고, P1이 배선한 부분(approval 게이트, run 조회, reset_run 호출 인자, Run 상태
불변, reset 실패 시에도 에러 없이 ok=False 반환, kill switch와 무관하게 항상 호출
가능한 것)만 확인한다.
"""

from __future__ import annotations

import asyncio
import unittest
from unittest.mock import MagicMock, patch
from uuid import uuid4

from contracts.schemas import Run, RunState
from core.evidence_store import get, save
from core.kill_switch import clear_pause, request_pause
from core.trajectory import TRAJECTORY_DIR


def _run(target_id: str = "fake-target", status: RunState = RunState.PATCH_APPLIED) -> Run:
    run = Run(id=f"run-{uuid4().hex[:12]}", target_id=target_id, status=status)
    save(run)
    return run


def _fake_service(reset_ok: bool) -> MagicMock:
    fake_service = MagicMock()
    fake_service.reset_run.return_value = reset_ok
    return fake_service


class VcKillRunTests(unittest.TestCase):
    def tearDown(self) -> None:
        clear_pause()

    def _call(self, args: dict) -> object:
        from mcp_server.server import mcp

        return asyncio.run(mcp.call_tool("vc_kill_run", args))

    def test_rejects_without_approval(self) -> None:
        run = _run()
        from mcp.server.fastmcp.exceptions import ToolError

        with self.assertRaises(ToolError):
            self._call({"run_id": run.id, "approved": False})

    def test_rejects_unknown_run(self) -> None:
        from mcp.server.fastmcp.exceptions import ToolError

        with self.assertRaises(ToolError):
            self._call({"run_id": "run-does-not-exist", "approved": True})

    def test_calls_reset_run_with_target_and_run_id_and_leaves_run_state_unchanged(self) -> None:
        run = _run(target_id="26s-w1-c2-04", status=RunState.PATCH_APPLIED)
        fake_service = _fake_service(reset_ok=True)

        with patch("mcp_server.tools_repair._service", return_value=fake_service):
            self._call({"run_id": run.id, "approved": True})

        fake_service.reset_run.assert_called_once_with("26s-w1-c2-04", run.id, approved=True)
        # kill/rollback은 보안 판정이 아니다 — RunState 그래프를 건드리지 않는다.
        self.assertEqual(get(Run, run.id).status, RunState.PATCH_APPLIED)

    def test_reset_failure_is_reported_without_raising(self) -> None:
        run = _run()
        fake_service = _fake_service(reset_ok=False)

        with patch("mcp_server.tools_repair._service", return_value=fake_service):
            result = self._call({"run_id": run.id, "approved": True})

        # FastMCP tool 결과는 content list로 오므로 구조화 결과에서 ok=False만 확인한다.
        self.assertIn("false", str(result).lower())

    def test_records_trajectory_step(self) -> None:
        run = _run()
        fake_service = _fake_service(reset_ok=True)

        with patch("mcp_server.tools_repair._service", return_value=fake_service):
            self._call({"run_id": run.id, "approved": True})

        traj_path = TRAJECTORY_DIR / f"{run.id}.jsonl"
        self.assertIn("vc_kill_run", traj_path.read_text(encoding="utf-8"))

    def test_callable_even_while_kill_switch_paused(self) -> None:
        run = _run()
        fake_service = _fake_service(reset_ok=True)
        request_pause("전체 중단 상황에서도 정리는 가능해야 한다")

        with patch("mcp_server.tools_repair._service", return_value=fake_service):
            # KillSwitchEngaged가 나지 않아야 한다 — vc_kill_run은 pause 가드를 타지 않는다.
            self._call({"run_id": run.id, "approved": True})

        fake_service.reset_run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
