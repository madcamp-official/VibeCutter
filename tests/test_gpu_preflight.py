from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import yaml

from runtime.gpu_preflight import WorkerRuntimePreflightRunner, main


class WorkerRuntimePreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        (self.root / "targets" / "manifests").mkdir(parents=True)
        (self.root / "targets" / "runtime_batches").mkdir(parents=True)
        (self.root / "policies").mkdir()
        self.source = self.root / ".vibecutter" / "targets" / "sources" / "demo-api"
        (self.source / "app").mkdir(parents=True)
        (self.source / "app" / "README.md").write_text("demo", encoding="utf-8")
        self._git("init")
        self._git("config", "user.email", "test@example.invalid")
        self._git("config", "user.name", "Test")
        self._git("add", ".")
        self._git("commit", "-m", "locked source")
        self._git(
            "remote",
            "add",
            "origin",
            "https://github.com/madcamp-official/demo-api.git",
        )
        revision = self._git("rev-parse", "HEAD").stdout.strip()

        manifest = {
            "id": "demo-api",
            "display_name": "Demo API",
            "adapter": "fastapi",
            "source_dir": ".vibecutter/targets/sources/demo-api/app",
            "base_url": "http://127.0.0.1:18080",
            "commands": {
                command: {"argv": [sys.executable, "-c", "pass"]}
                for command in ("build", "start", "stop", "reset")
            },
            "reset": {"command_id": "reset"},
        }
        (self.root / "targets" / "manifests" / "demo-api.yaml").write_text(
            yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8"
        )
        (self.root / "targets" / "runtime_batches" / "gpu_3way.yaml").write_text(
            yaml.safe_dump(
                {
                    "queue_version": 1,
                    "workers": {
                        "gpu-1": {"targets": ["demo-api"]},
                        "gpu-2": {"targets": []},
                    },
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        # gpu-2 cannot be empty under the production queue contract.  Use a
        # second valid worker target only when testing assignment below.
        (self.root / "targets" / "runtime_batches" / "gpu_3way.yaml").write_text(
            yaml.safe_dump(
                {"queue_version": 1, "workers": {"gpu-1": {"targets": ["demo-api"]}}},
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        (self.root / "policies" / "scope.yaml").write_text(
            yaml.safe_dump(
                {
                    "targets": {
                        "demo-api": {"allowed_hosts": ["127.0.0.1"], "port": 18080}
                    }
                }
            ),
            encoding="utf-8",
        )
        (self.root / "targets" / "source-lock.yaml").write_text(
            yaml.safe_dump(
                {
                    "lock_version": 1,
                    "targets": {
                        "demo-api": {
                            "repository": "https://github.com/madcamp-official/demo-api.git",
                            "revision": revision,
                        }
                    },
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        self.docker_calls = 0

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(self.source), *args],
            capture_output=True,
            check=True,
            text=True,
            encoding="utf-8",
        )

    def _runner(
        self, *, docker=(True, "29.1.3"), port=(True, None)
    ) -> WorkerRuntimePreflightRunner:
        def docker_info():
            self.docker_calls += 1
            return docker

        return WorkerRuntimePreflightRunner(
            self.root,
            docker_info=docker_info,
            port_probe=lambda _host, _port, _expected: port,
        )

    def test_assigned_target_passes_all_local_checks(self) -> None:
        report = self._runner().run("gpu-1", expected_port_state="listening")
        self.assertTrue(report.ready)
        target = report.targets[0]
        self.assertTrue(target.source.ready)
        self.assertTrue(target.readiness.ready)
        self.assertEqual(target.docker_version, "29.1.3")
        self.assertEqual(target.expected_port_state, "listening")
        self.assertTrue(target.port_ready)
        self.assertEqual(target.warnings, ())

    def test_unassigned_target_is_rejected_before_docker_or_target_probes(self) -> None:
        runner = self._runner()
        with self.assertRaisesRegex(PermissionError, "not assigned"):
            runner.run("gpu-1", target_ids=["other-api"])
        self.assertEqual(self.docker_calls, 0)

    def test_unknown_worker_is_rejected_before_docker_or_target_probes(self) -> None:
        runner = self._runner()
        with self.assertRaisesRegex(KeyError, "not registered"):
            runner.run("gpu-x")
        self.assertEqual(self.docker_calls, 0)

    def test_source_revision_mismatch_fails_preflight(self) -> None:
        lock_path = self.root / "targets" / "source-lock.yaml"
        document = yaml.safe_load(lock_path.read_text(encoding="utf-8"))
        document["targets"]["demo-api"]["revision"] = "a" * 40
        lock_path.write_text(
            yaml.safe_dump(document, sort_keys=False), encoding="utf-8"
        )

        target = self._runner().run("gpu-1").targets[0]
        self.assertFalse(target.ready)
        self.assertEqual(target.source.status, "revision_mismatch")
        self.assertIn("source: revision_mismatch", target.issues)

    def test_docker_unavailability_fails_without_attempting_lifecycle_commands(
        self,
    ) -> None:
        target = self._runner(docker=(False, None)).run("gpu-1").targets[0]
        self.assertFalse(target.ready)
        self.assertIn("Docker daemon is unavailable", target.issues)

    def test_occupied_configured_port_fails_preflight(self) -> None:
        target = (
            self._runner(
                port=(
                    False,
                    "configured loopback port is unavailable: Address already in use",
                )
            )
            .run("gpu-1", expected_port_state="available")
            .targets[0]
        )
        self.assertFalse(target.ready)
        self.assertFalse(target.port_ready)
        self.assertIn("Address already in use", target.issues[-1])

    def test_missing_role_fixture_environment_is_reported_as_nonblocking_warning(
        self,
    ) -> None:
        manifest_path = self.root / "targets" / "manifests" / "demo-api.yaml"
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        manifest["role_fixtures"] = [
            {
                "name": "local_role_fixture",
                "description": "test-only role fixture",
                "secret_env_names": ["VIBECUTTER_TEST_MISSING_SECRET"],
            }
        ]
        manifest_path.write_text(
            yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8"
        )

        target = self._runner().run("gpu-1", expected_port_state="listening").targets[0]

        self.assertTrue(target.ready)
        self.assertEqual(target.issues, ())
        self.assertIn("role fixture environment not configured", target.warnings[0])

    def test_cli_serializes_nested_readiness_and_returns_report_status(self) -> None:
        runner = self._runner()
        report = runner.run("gpu-1", expected_port_state="listening")
        with (
            patch(
                "runtime.gpu_preflight.WorkerRuntimePreflightRunner.run",
                return_value=report,
            ),
            patch("sys.stdout", new_callable=StringIO) as stdout,
        ):
            exit_code = main(
                [
                    "--worker-id",
                    "gpu-1",
                    "--repository-root",
                    str(self.root),
                    "--expect-port-state",
                    "listening",
                ]
            )
        self.assertEqual(exit_code, 0)
        payload = yaml.safe_load(stdout.getvalue())
        self.assertEqual(payload["worker_id"], "gpu-1")
        self.assertTrue(payload["targets"][0]["readiness"]["ready"])


if __name__ == "__main__":
    unittest.main()
