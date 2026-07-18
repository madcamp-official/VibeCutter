"""vc_apply_patch MCP tool 실배선 (Day3) 테스트.

실제 `git worktree add` + `git apply`를 임시 Git repository에서 구동해 end-to-end로
검증한다(원본 branch 미변경, worktree 밖 경로 거부, confirmed 게이트, 재시도 안전성).
`catalog.worktree_manager_for()`만 mock으로 대체해 실제 target Docker/manifest 없이도
worktree 메커니즘 자체는 진짜로 돈다.
"""

from __future__ import annotations

import asyncio
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch
from uuid import uuid4

from contracts.schemas import ApprovalStatus, Patch, Run, RunState
from core.evidence_store import get, save
from core.trajectory import TRAJECTORY_DIR
from runtime.worktree import WorktreeManager


def _git(*args: str, cwd: Path) -> None:
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True)


class VcApplyPatchWiringTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self.repo_root = Path(self._tmp.name) / "source-repo"
        self.repo_root.mkdir()
        _git("init", "-q", cwd=self.repo_root)
        _git("config", "user.email", "t@example.com", cwd=self.repo_root)
        _git("config", "user.name", "t", cwd=self.repo_root)
        (self.repo_root / "Foo.java").write_text("line1\nline2\nline3\n", encoding="utf-8")
        _git("add", "Foo.java", cwd=self.repo_root)
        _git("commit", "-q", "-m", "init", cwd=self.repo_root)
        self.artifact_root = Path(self._tmp.name) / "worktrees"
        self.worktree_manager = WorktreeManager(self.repo_root, artifact_root=self.artifact_root)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _fake_service(self) -> MagicMock:
        fake_service = MagicMock()
        fake_service.catalog.worktree_manager_for.return_value = self.worktree_manager
        # source_dir == repo root in these fixtures: no --directory prefix needed.
        fake_service.catalog.source_root_for.return_value = self.repo_root
        fake_service.catalog.source_repository_for.return_value = self.repo_root
        return fake_service

    def _run(self, status: RunState = RunState.PATCH_PROPOSED) -> Run:
        run = Run(id=f"run-{uuid4().hex[:12]}", target_id="fake-target", status=status)
        save(run)
        return run

    def _patch(self, run_id: str, diff: str) -> Patch:
        p = Patch(id=f"patch-{uuid4().hex[:12]}", finding_id="finding-x", run_id=run_id, diff=diff)
        save(p)
        return p

    def _call(self, args: dict) -> object:
        from mcp_server.server import mcp

        return asyncio.run(mcp.call_tool("vc_apply_patch", args))

    def test_rejects_without_confirmed(self) -> None:
        run = self._run()
        p = self._patch(run.id, "--- a/Foo.java\n+++ b/Foo.java\n")
        from mcp.server.fastmcp.exceptions import ToolError

        with self.assertRaises(ToolError):
            self._call({"patch_id": p.id, "confirmed": False})

    def test_applies_diff_in_worktree_and_advances_run_state(self) -> None:
        run = self._run()
        diff = (
            "--- a/Foo.java\n+++ b/Foo.java\n@@ -1,3 +1,3 @@\n"
            " line1\n-line2\n+CHANGED\n line3\n"
        )
        p = self._patch(run.id, diff)

        with patch("mcp_server.tools_repair._service", return_value=self._fake_service()):
            self._call({"patch_id": p.id, "confirmed": True})

        worktree_path = self.worktree_manager.path_for(run.id)
        self.assertEqual((worktree_path / "Foo.java").read_text(), "line1\nCHANGED\nline3\n")
        # 원본 소스 repo는 변하지 않았다(절대 원칙).
        self.assertEqual((self.repo_root / "Foo.java").read_text(), "line1\nline2\nline3\n")
        self.assertEqual(get(Run, run.id).status, RunState.PATCH_APPLIED)
        self.assertEqual(get(Patch, p.id).approval, ApprovalStatus.APPROVED)
        traj_path = TRAJECTORY_DIR / f"{run.id}.jsonl"
        self.assertIn("vc_apply_patch", traj_path.read_text(encoding="utf-8"))

    def test_applies_diff_when_source_dir_is_nested_under_repo_root(self) -> None:
        """26s-w1-c3-09 스타일: manifest source_dir(예: backend/server)가 git toplevel의
        하위 디렉터리인 target. patcher는 diff 경로를 source_dir 기준 상대경로로 내므로
        (예: src/Foo.java), 이를 worktree(git toplevel과 같은 레이아웃)에 적용하려면
        source_dir 접두사(backend/server/)를 보정해야 git apply가 실제 파일을 찾는다.
        """
        nested = self.repo_root / "backend" / "server" / "src"
        nested.mkdir(parents=True)
        (nested / "Foo.java").write_text("line1\nline2\nline3\n", encoding="utf-8")
        _git("add", "backend/server/src/Foo.java", cwd=self.repo_root)
        _git("commit", "-q", "-m", "add nested file", cwd=self.repo_root)

        run = self._run()
        # patcher가 낸 diff: source_dir(backend/server) 기준 상대경로, repo 루트 기준이 아님.
        diff = (
            "--- a/src/Foo.java\n+++ b/src/Foo.java\n@@ -1,3 +1,3 @@\n"
            " line1\n-line2\n+CHANGED\n line3\n"
        )
        p = self._patch(run.id, diff)

        fake_service = self._fake_service()
        fake_service.catalog.source_root_for.return_value = self.repo_root / "backend" / "server"
        fake_service.catalog.source_repository_for.return_value = self.repo_root

        with patch("mcp_server.tools_repair._service", return_value=fake_service):
            self._call({"patch_id": p.id, "confirmed": True})

        worktree_path = self.worktree_manager.path_for(run.id)
        self.assertEqual(
            (worktree_path / "backend" / "server" / "src" / "Foo.java").read_text(),
            "line1\nCHANGED\nline3\n",
        )
        self.assertEqual(get(Run, run.id).status, RunState.PATCH_APPLIED)

    def test_rejects_diff_that_escapes_worktree(self) -> None:
        run = self._run()
        diff = "--- a/../../etc/passwd\n+++ b/../../etc/passwd\n@@ -1,1 +1,1 @@\n-x\n+y\n"
        p = self._patch(run.id, diff)
        from mcp.server.fastmcp.exceptions import ToolError

        with patch("mcp_server.tools_repair._service", return_value=self._fake_service()):
            with self.assertRaises(ToolError):
                self._call({"patch_id": p.id, "confirmed": True})

        self.assertEqual(get(Run, run.id).status, RunState.PATCH_PROPOSED)
        self.assertEqual(get(Patch, p.id).approval, ApprovalStatus.PENDING)

    def test_rejects_run_not_in_patch_proposed_state(self) -> None:
        run = self._run(status=RunState.VERIFIED)
        p = self._patch(run.id, "--- a/Foo.java\n+++ b/Foo.java\n")
        from mcp.server.fastmcp.exceptions import ToolError

        with patch("mcp_server.tools_repair._service", return_value=self._fake_service()):
            with self.assertRaises(ToolError):
                self._call({"patch_id": p.id, "confirmed": True})

    def test_repeat_call_after_already_applied_is_a_safe_no_op(self) -> None:
        run = self._run()
        diff = (
            "--- a/Foo.java\n+++ b/Foo.java\n@@ -1,3 +1,3 @@\n"
            " line1\n-line2\n+CHANGED\n line3\n"
        )
        p = self._patch(run.id, diff)

        with patch("mcp_server.tools_repair._service", return_value=self._fake_service()):
            self._call({"patch_id": p.id, "confirmed": True})
            # 두 번째 호출: git apply를 다시 시도했다면 "이미 적용됨" 에러가 났을 것 —
            # already_applied 분기가 이를 건너뛰어야 한다.
            self._call({"patch_id": p.id, "confirmed": True})

        self.assertEqual(get(Run, run.id).status, RunState.PATCH_APPLIED)


if __name__ == "__main__":
    unittest.main()
