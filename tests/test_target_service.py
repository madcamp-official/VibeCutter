from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

import yaml

from core.policy_engine import PolicyViolation
from runtime.catalog import TargetCatalog
from runtime.target_service import TargetRuntimeService


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
        self.manifest_path.write_text(yaml.safe_dump(manifest_data(), sort_keys=False), encoding="utf-8")
        self.scope_path = self.root / "scope.yaml"
        self.scope_path.write_text(
            yaml.safe_dump({"targets": {"demo-api": {"allowed_hosts": ["127.0.0.1"], "port": 18080}}}),
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
                    }
                }
            ),
            encoding="utf-8",
        )
        catalog = TargetCatalog(manifest_root=self.manifest_root, repository_root=self.root)
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

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_register_requires_identical_checked_in_manifest_and_scope(self) -> None:
        target = self.service.register(manifest_data())
        self.assertEqual(target.id, "demo-api")
        self.assertEqual(len(self.saved_targets), 1)
        changed = manifest_data()
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

    def test_port_mismatch_is_rejected_before_command_execution(self) -> None:
        self.scope_path.write_text(
            yaml.safe_dump({"targets": {"demo-api": {"allowed_hosts": ["127.0.0.1"], "port": 9999}}}),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(PolicyViolation, "port must match"):
            self.service.build("demo-api")
