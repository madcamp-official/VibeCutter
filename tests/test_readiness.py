from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from runtime.manifest import TargetManifest
from runtime.readiness import TargetRuntimeInspector


def readiness_manifest() -> TargetManifest:
    return TargetManifest.model_validate(
        {
            "id": "ready-api",
            "display_name": "Ready API",
            "adapter": "fastapi",
            "source_dir": ".",
            "base_url": "http://127.0.0.1:18080",
            "commands": {
                "build": {"argv": [sys.executable, "-V"]},
                "start": {"argv": [sys.executable, "-V"]},
                "stop": {"argv": [sys.executable, "-V"]},
                "reset": {"argv": [sys.executable, "-V"]},
            },
            "reset": {"command_id": "reset"},
            "role_fixtures": [
                {"name": "user_a", "description": "Owner fixture", "secret_env_names": ["VIBECUTTER_ROLE_A_TOKEN"]}
            ],
            "log_paths": ["logs/app.log"],
        }
    )


class TargetReadinessTests(unittest.TestCase):
    def test_reports_missing_fixture_environment_without_secret_value(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(os.environ, {}, clear=True):
            report = TargetRuntimeInspector(readiness_manifest(), Path(temp_dir)).check_readiness()
        self.assertFalse(report.ready)
        self.assertEqual(report.fixtures[0].missing_env_names, ["VIBECUTTER_ROLE_A_TOKEN"])
        self.assertNotIn("TOKEN=", report.model_dump_json())

    def test_reports_present_log_metadata_and_ready_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ, {"VIBECUTTER_ROLE_A_TOKEN": "not-reported"}, clear=True
        ):
            log_path = Path(temp_dir) / "logs" / "app.log"
            log_path.parent.mkdir()
            log_path.write_text("safe metadata only", encoding="utf-8")
            report = TargetRuntimeInspector(readiness_manifest(), Path(temp_dir)).check_readiness()
        self.assertTrue(report.ready)
        self.assertEqual(report.logs[0].status, "present")
        self.assertEqual(report.logs[0].size_bytes, len("safe metadata only"))
        self.assertNotIn("not-reported", report.model_dump_json())

    def test_reports_unavailable_executable(self) -> None:
        manifest = readiness_manifest().model_copy(deep=True)
        manifest.commands["build"].argv[0] = "vibecutter-command-that-does-not-exist"
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ, {"VIBECUTTER_ROLE_A_TOKEN": "configured"}, clear=True
        ):
            report = TargetRuntimeInspector(manifest, Path(temp_dir)).check_readiness()
        self.assertFalse(report.ready)
        self.assertEqual(report.unavailable_executables, ["vibecutter-command-that-does-not-exist"])
