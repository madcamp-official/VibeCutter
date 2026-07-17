from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from runtime.manifest import TargetManifest
from runtime.test_runner import RunScopedTestRunner
from runtime.worktree import WorktreeManager


def manifest_with_tests() -> TargetManifest:
    return TargetManifest.model_validate(
        {
            "id": "demo-api",
            "display_name": "Demo API",
            "adapter": "fastapi",
            "source_dir": ".",
            "base_url": "http://127.0.0.1:18080",
            "commands": {
                "build": {"argv": [sys.executable, "-c", "print('build')"]},
                "start": {"argv": [sys.executable, "-c", "print('start')"]},
                "stop": {"argv": [sys.executable, "-c", "print('stop')"]},
                "reset": {"argv": [sys.executable, "-c", "print('reset')"]},
                "test": {"argv": [sys.executable, "-c", "print('regression')"]},
            },
            "reset": {"command_id": "reset"},
            "test_suites": [{"name": "unit", "command_id": "test"}],
        }
    )


def _git(repository: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repository), *args], check=True, capture_output=True, text=True, shell=False)


class RunScopedTestRunnerTests(unittest.TestCase):
    def test_runs_only_in_p2_managed_git_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = Path(temp_dir)
            _git(repository, "init")
            _git(repository, "config", "user.email", "p2@example.test")
            _git(repository, "config", "user.name", "P2 Test")
            (repository / "tracked.txt").write_text("tracked", encoding="utf-8")
            _git(repository, "add", "tracked.txt")
            _git(repository, "commit", "-m", "initial")
            worktrees = WorktreeManager(repository)
            worktrees.create("run-1")
            try:
                summary = RunScopedTestRunner(manifest_with_tests(), repository).run("run-1")
            finally:
                worktrees.remove("run-1", approved=True)
        self.assertTrue(summary.passed)
        self.assertEqual(summary.status, "passed")
        self.assertEqual(summary.results[0].stdout.strip(), "regression")

    def test_rejects_missing_or_unmanaged_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = Path(temp_dir)
            runner = RunScopedTestRunner(manifest_with_tests(), repository)
            with self.assertRaises(FileNotFoundError):
                runner.run("missing-run")

    def test_empty_suite_is_not_a_regression_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repository = Path(temp_dir)
            _git(repository, "init")
            _git(repository, "config", "user.email", "p2@example.test")
            _git(repository, "config", "user.name", "P2 Test")
            (repository / "tracked.txt").write_text("tracked", encoding="utf-8")
            _git(repository, "add", "tracked.txt")
            _git(repository, "commit", "-m", "initial")
            worktrees = WorktreeManager(repository)
            worktrees.create("run-2")
            try:
                manifest = manifest_with_tests().model_copy(update={"test_suites": []})
                summary = RunScopedTestRunner(manifest, repository).run("run-2")
            finally:
                worktrees.remove("run-2", approved=True)
        self.assertFalse(summary.passed)
        self.assertEqual(summary.status, "not_configured")
