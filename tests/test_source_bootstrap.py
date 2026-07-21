from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from runtime.source_bootstrap import SourceBootstrapError, TargetSourceBootstrapper
from runtime.source_lock import SourceLock


class SourceBootstrapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.seed = self.root / "seed"
        self.seed.mkdir()
        self._git(self.seed, "init")
        self._git(self.seed, "config", "user.email", "p2@example.test")
        self._git(self.seed, "config", "user.name", "P2 Test")
        (self.seed / "app.txt").write_text("locked source", encoding="utf-8")
        self._git(self.seed, "add", "app.txt")
        self._git(self.seed, "commit", "-m", "initial")
        self.revision = self._git(self.seed, "rev-parse", "HEAD").stdout.strip()
        self.repository = "https://github.com/madcamp-official/demo-api.git"
        lock_path = self.root / "targets" / "source-lock.yaml"
        lock_path.parent.mkdir(parents=True)
        lock_path.write_text(
            yaml.safe_dump(
                {
                    "lock_version": 1,
                    "targets": {
                        "demo-api": {
                            "repository": self.repository,
                            "revision": self.revision,
                        }
                    },
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        self.lock = SourceLock.load(lock_path)
        self.commands: list[list[str]] = []

    @staticmethod
    def _git(repository: Path, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(repository), *args],
            capture_output=True,
            check=True,
            text=True,
            encoding="utf-8",
        )

    def _local_clone_runner(
        self, argv: list[str], timeout_seconds: int
    ) -> subprocess.CompletedProcess[str]:
        self.commands.append(list(argv))
        if "clone" in argv:
            self.assertIn("protocol.file.allow=never", argv)
            self.assertIn("core.longpaths=true", argv)
            checkout = Path(argv[-1])
            result = subprocess.run(
                [
                    "git",
                    "-c",
                    "protocol.file.allow=always",
                    "clone",
                    "--no-checkout",
                    str(self.seed),
                    str(checkout),
                ],
                capture_output=True,
                check=False,
                shell=False,
                text=True,
                encoding="utf-8",
                timeout=timeout_seconds,
            )
            if result.returncode == 0:
                self._git(checkout, "remote", "set-url", "origin", self.repository)
            return result
        return subprocess.run(
            argv,
            capture_output=True,
            check=False,
            shell=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
        )

    def test_bootstrap_requires_approval_and_creates_locked_detached_checkout(
        self,
    ) -> None:
        bootstrapper = TargetSourceBootstrapper(
            self.root, self.lock, run_git=self._local_clone_runner
        )
        with self.assertRaisesRegex(PermissionError, "explicit approval"):
            bootstrapper.bootstrap("demo-api", approved=False)

        result = bootstrapper.bootstrap("demo-api", approved=True)
        self.assertTrue(result.ready)
        self.assertEqual(result.observed_revision, self.revision)
        detached = subprocess.run(
            ["git", "-C", str(result.repository_path), "symbolic-ref", "-q", "HEAD"],
            capture_output=True,
            check=False,
            text=True,
            encoding="utf-8",
        )
        self.assertEqual(detached.returncode, 1)
        self.assertEqual(
            self._git(
                result.repository_path, "remote", "get-url", "origin"
            ).stdout.strip(),
            self.repository,
        )
        self.assertTrue(bootstrapper.bootstrap("demo-api", approved=True).ready)
        self.assertEqual(sum("clone" in command for command in self.commands), 1)

    def test_existing_dirty_checkout_is_rejected_without_mutation(self) -> None:
        bootstrapper = TargetSourceBootstrapper(
            self.root, self.lock, run_git=self._local_clone_runner
        )
        checkout = bootstrapper.bootstrap("demo-api", approved=True).repository_path
        (checkout / "app.txt").write_text("changed", encoding="utf-8")
        before = self._git(checkout, "rev-parse", "HEAD").stdout.strip()
        with self.assertRaisesRegex(SourceBootstrapError, "dirty"):
            bootstrapper.bootstrap("demo-api", approved=True)
        self.assertEqual(
            self._git(checkout, "rev-parse", "HEAD").stdout.strip(), before
        )
        self.assertEqual((checkout / "app.txt").read_text(encoding="utf-8"), "changed")

    def test_failed_clone_leaves_no_final_destination(self) -> None:
        def failing_runner(
            argv: list[str], _timeout: int
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(argv, 1, "", "failed")

        bootstrapper = TargetSourceBootstrapper(
            self.root, self.lock, run_git=failing_runner
        )
        with self.assertRaisesRegex(SourceBootstrapError, "clone failed"):
            bootstrapper.bootstrap("demo-api", approved=True)
        self.assertFalse(bootstrapper.path_for("demo-api").exists())

    def test_target_id_alone_controls_the_destination(self) -> None:
        bootstrapper = TargetSourceBootstrapper(self.root, self.lock)
        self.assertEqual(
            bootstrapper.path_for("demo-api"),
            (self.root / ".vibecutter" / "targets" / "sources" / "demo-api").resolve(),
        )
        with self.assertRaises(KeyError):
            bootstrapper.path_for("../escape")


if __name__ == "__main__":
    unittest.main()
