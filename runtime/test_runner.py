"""Regression runner restricted to P2-managed, run-scoped Git worktrees."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from .lifecycle import CommandResult, LifecycleManager
from .manifest import TargetManifest
from .worktree import WorktreeManager


class TestRunSummary(BaseModel):
    """P1 judge can map ``status == passed`` to its regression gate."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    worktree_path: str
    status: Literal["passed", "failed", "not_configured"]
    results: list[CommandResult]

    @property
    def passed(self) -> bool:
        return self.status == "passed"


class RunScopedTestRunner:
    """Run tests only in a worktree created under `.vibecutter/worktrees/<run_id>`."""

    def __init__(self, manifest: TargetManifest, repository_root: Path) -> None:
        self.manifest = manifest
        self.repository_root = repository_root.resolve()
        self.worktrees = WorktreeManager(self.repository_root)

    def run(self, run_id: str) -> TestRunSummary:
        worktree_path = self.worktrees.path_for(run_id)
        if not worktree_path.is_dir():
            raise FileNotFoundError(f"P2 worktree does not exist for run {run_id}")
        self._assert_git_worktree(worktree_path)
        if not self.manifest.test_suites:
            return TestRunSummary(
                run_id=run_id,
                worktree_path=str(worktree_path),
                status="not_configured",
                results=[],
            )
        results = LifecycleManager(self.manifest, worktree_path).run_test_suites()
        return TestRunSummary(
            run_id=run_id,
            worktree_path=str(worktree_path),
            status="passed" if all(result.status == "passed" for result in results) else "failed",
            results=results,
        )

    @staticmethod
    def _assert_git_worktree(worktree_path: Path) -> None:
        """Reject a manually created directory that merely shares a valid run_id path."""
        result = subprocess.run(
            ["git", "-C", str(worktree_path), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            check=False,
            shell=False,
            text=True,
        )
        if result.returncode != 0 or result.stdout.strip() != "true":
            raise ValueError("run path is not a Git worktree")
