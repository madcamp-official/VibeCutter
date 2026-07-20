from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import yaml

from core.policy_engine import PolicyViolation
from runtime.catalog import TargetCatalog
from runtime.lifecycle import CommandResult, HealthResult
from runtime.target_service import TargetOperationError, TargetRuntimeService


def manifest_data() -> dict:
    argv = [sys.executable, "-c", "print('ok')"]
    return {
        "id": "demo-api",
        "display_name": "Demo API",
        "adapter": "fastapi",
        "source_dir": ".",
        "base_url": "http://127.0.0.1:18080",
        "commands": {
            "build": {"argv": argv},
            "start": {"argv": argv},
            "stop": {"argv": argv},
            "reset": {"argv": argv},
            "prepare_fixture": {"argv": argv},
        },
        "reset": {"command_id": "reset"},
        "tool_versions": {"python": "3.11"},
    }


class TargetRuntimeServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.manifest_root = self.root / "targets" / "manifests"
        self.manifest_root.mkdir(parents=True)
        self.manifest_path = self.manifest_root / "demo.yaml"
        self.manifest_path.write_text(
            yaml.safe_dump(manifest_data(), sort_keys=False), encoding="utf-8"
        )
        self.scope_path = self.root / "scope.yaml"
        self.scope_path.write_text(
            yaml.safe_dump(
                {
                    "targets": {
                        "demo-api": {"allowed_hosts": ["127.0.0.1"], "port": 18080}
                    }
                }
            ),
            encoding="utf-8",
        )
        self.commands_path = self.root / "commands.yaml"
        self.commands_path.write_text(
            yaml.safe_dump(
                {
                    "commands": {
                        "build_target": {"args": {"target_id": "str"}},
                        "start_target": {"args": {"target_id": "str"}},
                        "reset_target": {"args": {"target_id": "str"}},
                        "provision_target": {"args": {"target_id": "str"}},
                    }
                }
            ),
            encoding="utf-8",
        )
        catalog = TargetCatalog(
            manifest_root=self.manifest_root, repository_root=self.root
        )
        catalog.load()
        self.saved_targets = []
        self.saved_runs = []
        self.service = TargetRuntimeService(
            catalog,
            scope_path=self.scope_path,
            commands_path=self.commands_path,
            save_target=self.saved_targets.append,
            save_run=self.saved_runs.append,
        )

        fixture_script = self.root / "write_fixture.py"
        fixture_script.write_text(
            "from pathlib import Path\n"
            "path = Path('.vibecutter/fixtures/demo-api.json')\n"
            "path.parent.mkdir(parents=True, exist_ok=True)\n"
            "path.write_text('{}', encoding='utf-8')\n",
            encoding="utf-8",
        )
        configured = manifest_data()
        configured["commands"]["prepare_fixture"] = {
            "argv": [sys.executable, "write_fixture.py"]
        }
        self.manifest_path.write_text(
            yaml.safe_dump(configured, sort_keys=False), encoding="utf-8"
        )
        provisioning_path = self.root / "targets" / "verifier_provisioning.yaml"
        provisioning_path.write_text(
            yaml.safe_dump(
                {
                    "targets": {
                        "demo-api": {
                            "strategy": "fixture_file",
                            "auth_mode": "none",
                            "fixture_command_id": "prepare_fixture",
                            "fixture_path": ".vibecutter/fixtures/demo-api.json",
                            "notes": "test fixture only",
                        }
                    }
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        self.service.catalog.load()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_register_requires_identical_checked_in_manifest_and_scope(self) -> None:
        checked_in = self.service.catalog.get("demo-api").manifest.model_dump(
            mode="json"
        )
        target = self.service.register(checked_in)
        self.assertEqual(target.id, "demo-api")
        self.assertEqual(len(self.saved_targets), 1)
        changed = dict(checked_in)
        changed["base_url"] = "http://127.0.0.1:18081"
        with self.assertRaises(PolicyViolation):
            self.service.register(changed)

    def test_build_uses_typed_policy_command_and_records_ready_run(self) -> None:
        run = self.service.build("demo-api")
        self.assertEqual(run.status.value, "READY")
        self.assertEqual(run.tool_versions, {"python": "3.11"})
        self.assertEqual(self.saved_runs[-1].id, run.id)

    def test_reset_requires_explicit_approval(self) -> None:
        with self.assertRaises(PermissionError):
            self.service.reset("demo-api", approved=False)
        self.assertTrue(self.service.reset("demo-api", approved=True))

    def test_reset_run_resets_generated_runtime_before_removing_worktree(self) -> None:
        overlay = MagicMock()
        overlay.execute.return_value = CommandResult(
            command_id="reset",
            status="passed",
            exit_code=0,
            duration_ms=1,
            stdout="",
            stderr="",
        )
        worktrees = MagicMock()
        self.service.catalog.run_overlay_for = MagicMock(return_value=overlay)  # type: ignore[method-assign]
        self.service.catalog.worktree_manager_for = MagicMock(return_value=worktrees)  # type: ignore[method-assign]

        self.assertTrue(self.service.reset_run("demo-api", "run-1", approved=True))
        overlay.execute.assert_called_once_with("reset")
        worktrees.remove.assert_called_once_with("run-1", approved=True)
        overlay.remove_artifact.assert_called_once_with()

    def test_reset_run_failure_keeps_worktree_for_retry(self) -> None:
        overlay = MagicMock()
        overlay.execute.return_value = CommandResult(
            command_id="reset",
            status="failed",
            exit_code=1,
            duration_ms=1,
            stdout="",
            stderr="failed",
        )
        worktrees = MagicMock()
        self.service.catalog.run_overlay_for = MagicMock(return_value=overlay)  # type: ignore[method-assign]
        self.service.catalog.worktree_manager_for = MagicMock(return_value=worktrees)  # type: ignore[method-assign]

        self.assertFalse(self.service.reset_run("demo-api", "run-1", approved=True))
        worktrees.remove.assert_not_called()

    def test_reset_run_allows_overlay_cleanup_after_worktree_was_pruned(self) -> None:
        overlay = MagicMock()
        overlay.execute.return_value = CommandResult(
            command_id="reset",
            status="passed",
            exit_code=0,
            duration_ms=1,
            stdout="",
            stderr="",
        )
        worktrees = MagicMock()
        worktrees.path_for.return_value = self.root / "missing-worktree"
        self.service.catalog.run_overlay_for = MagicMock(return_value=overlay)  # type: ignore[method-assign]
        self.service.catalog.worktree_manager_for = MagicMock(return_value=worktrees)  # type: ignore[method-assign]

        self.assertTrue(self.service.reset_run("demo-api", "run-1", approved=True))
        worktrees.remove.assert_not_called()
        overlay.remove_artifact.assert_called_once_with()

    def test_sweep_stale_run_overlays_resets_only_inactive_managed_artifacts(
        self,
    ) -> None:
        overlay_root = self.root / ".vibecutter" / "run-overlays" / "demo-api"
        for run_id in ("run-old", "run-live"):
            artifact = overlay_root / run_id
            artifact.mkdir(parents=True)
            (artifact / "compose.yaml").write_text(
                "name: test\nservices: {}\n", encoding="utf-8"
            )

        old_overlay = MagicMock()
        old_overlay.execute.return_value = CommandResult(
            command_id="reset",
            status="passed",
            exit_code=0,
            duration_ms=1,
            stdout="",
            stderr="",
        )
        worktrees = MagicMock()
        worktrees.path_for.side_effect = lambda run_id: (
            self.root / ".vibecutter" / "worktrees" / run_id
        )
        self.service.catalog.run_overlay_for = MagicMock(return_value=old_overlay)  # type: ignore[method-assign]
        self.service.catalog.worktree_manager_for = MagicMock(return_value=worktrees)  # type: ignore[method-assign]

        result = self.service.sweep_stale_run_overlays(
            "demo-api", active_run_ids={"run-live"}, approved=True
        )

        self.assertEqual(result.cleaned_run_ids, ("run-old",))
        self.assertEqual(result.failed_run_ids, ())
        self.assertEqual(result.skipped_active_run_ids, ("run-live",))
        self.service.catalog.run_overlay_for.assert_called_once_with(
            "demo-api", "run-old"
        )

    def test_sweep_stale_run_overlays_requires_approval(self) -> None:
        with self.assertRaises(PermissionError):
            self.service.sweep_stale_run_overlays("demo-api", approved=False)

    def test_reset_run_requires_explicit_approval_before_runtime_cleanup(self) -> None:
        with self.assertRaises(PermissionError):
            self.service.reset_run("demo-api", "run-1", approved=False)

    def test_verifier_provisioning_exposes_only_trusted_metadata(self) -> None:
        plan = self.service.verifier_provisioning("demo-api")
        self.assertEqual(plan.base_url, "http://127.0.0.1:18080")
        self.assertEqual(plan.auth_mode, "none")
        self.assertEqual(plan.fixture_command_id, "prepare_fixture")
        self.assertFalse(plan.fixture_available)

    def test_prepare_verifier_fixture_requires_approval_and_runs_fixed_command(
        self,
    ) -> None:
        with self.assertRaises(PermissionError):
            self.service.prepare_verifier_fixture("demo-api", approved=False)
        plan = self.service.prepare_verifier_fixture("demo-api", approved=True)
        self.assertTrue(plan.fixture_available)
        self.assertEqual(plan.fixture_path, ".vibecutter/fixtures/demo-api.json")

    @staticmethod
    def _passing_adapter() -> MagicMock:
        adapter = MagicMock()
        adapter.reset.return_value = CommandResult(
            command_id="reset",
            status="passed",
            exit_code=0,
            duration_ms=1,
            stdout="",
            stderr="",
        )
        adapter.start.return_value = CommandResult(
            command_id="start",
            status="passed",
            exit_code=0,
            duration_ms=1,
            stdout="",
            stderr="",
        )
        adapter.health.return_value = HealthResult(
            status="ready", attempts=1, observed_status=200, reason=None
        )
        return adapter

    def test_restore_baseline_after_write_requires_approval_before_reset(self) -> None:
        adapter_for = MagicMock()
        self.service.catalog.adapter_for = adapter_for  # type: ignore[method-assign]
        with self.assertRaises(PermissionError):
            self.service.restore_baseline_after_write("demo-api", approved=False)
        adapter_for.assert_not_called()

    def test_restore_baseline_after_write_restarts_and_refreshes_fixture(self) -> None:
        adapter = self._passing_adapter()
        self.service.catalog.adapter_for = MagicMock(return_value=adapter)  # type: ignore[method-assign]
        fixture_path = self.root / ".vibecutter" / "fixtures" / "demo-api.json"
        fixture_path.parent.mkdir(parents=True, exist_ok=True)
        fixture_path.write_text("stale", encoding="utf-8")

        result = self.service.restore_baseline_after_write("demo-api", approved=True)

        self.assertTrue(result.restored)
        self.assertTrue(result.fixture_prepared)
        self.assertEqual(fixture_path.read_text(encoding="utf-8"), "{}")
        adapter.reset.assert_called_once_with(approved=True)
        adapter.start.assert_called_once_with()
        adapter.health.assert_called_once_with()

    def test_restore_baseline_after_write_self_signup_needs_no_fixture(self) -> None:
        provisioning_path = self.root / "targets" / "verifier_provisioning.yaml"
        provisioning_path.write_text(
            yaml.safe_dump(
                {
                    "targets": {
                        "demo-api": {
                            "strategy": "self_signup",
                            "auth_mode": "bearer",
                            "notes": "ephemeral accounts only",
                        }
                    }
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        adapter = self._passing_adapter()
        self.service.catalog.adapter_for = MagicMock(return_value=adapter)  # type: ignore[method-assign]
        lifecycle_for = MagicMock()
        self.service.catalog.lifecycle_for = lifecycle_for  # type: ignore[method-assign]

        result = self.service.restore_baseline_after_write("demo-api", approved=True)

        self.assertTrue(result.restored)
        self.assertFalse(result.fixture_prepared)
        lifecycle_for.assert_not_called()

    def test_restore_baseline_after_write_rejects_missing_contract_before_mutation(
        self,
    ) -> None:
        (self.root / "targets" / "verifier_provisioning.yaml").write_text(
            "targets: {}\n", encoding="utf-8"
        )
        adapter_for = MagicMock()
        self.service.catalog.adapter_for = adapter_for  # type: ignore[method-assign]

        with self.assertRaisesRegex(
            TargetOperationError, "no P2-managed provisioning contract"
        ):
            self.service.restore_baseline_after_write("demo-api", approved=True)
        adapter_for.assert_not_called()

    def test_restore_baseline_after_write_reports_reset_failure_without_start(
        self,
    ) -> None:
        adapter = self._passing_adapter()
        adapter.reset.return_value = CommandResult(
            command_id="reset",
            status="failed",
            exit_code=1,
            duration_ms=1,
            stdout="",
            stderr="redacted",
        )
        self.service.catalog.adapter_for = MagicMock(return_value=adapter)  # type: ignore[method-assign]

        result = self.service.restore_baseline_after_write("demo-api", approved=True)

        self.assertEqual(result.status, "reset_failed")
        self.assertFalse(result.restored)
        adapter.start.assert_not_called()

    def test_port_mismatch_is_rejected_before_command_execution(self) -> None:
        self.scope_path.write_text(
            yaml.safe_dump(
                {
                    "targets": {
                        "demo-api": {"allowed_hosts": ["127.0.0.1"], "port": 9999}
                    }
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(PolicyViolation, "port must match"):
            self.service.build("demo-api")

    def test_build_failure_reports_manifest_target_id_instead_of_wrapper_attribute_error(
        self,
    ) -> None:
        failed = manifest_data()
        failed["commands"]["build"] = {
            "argv": [sys.executable, "-c", "raise SystemExit(7)"]
        }
        self.manifest_path.write_text(
            yaml.safe_dump(failed, sort_keys=False), encoding="utf-8"
        )
        self.service.catalog.load()

        with self.assertRaisesRegex(
            TargetOperationError, "build failed for target demo-api"
        ):
            self.service.build("demo-api")
