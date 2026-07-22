from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from runtime.manifest import TargetManifest
from runtime.lifecycle import VIBECUTTER_PYTHON
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

    def test_recognizes_the_trusted_runtime_python_token(self) -> None:
        manifest = readiness_manifest().model_copy(deep=True)
        manifest.commands["build"].argv[0] = VIBECUTTER_PYTHON
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ, {"VIBECUTTER_ROLE_A_TOKEN": "configured"}, clear=True
        ):
            log_path = Path(temp_dir) / "logs" / "app.log"
            log_path.parent.mkdir()
            log_path.write_text("safe", encoding="utf-8")
            report = TargetRuntimeInspector(manifest, Path(temp_dir)).check_readiness()
        self.assertTrue(report.ready)
        self.assertEqual(report.unavailable_executables, [])

    def test_relative_wrapper_script_checked_against_source_dir_not_path(self) -> None:
        """`./gradlew`처럼 프로젝트 루트의 래퍼 스크립트는 PATH가 아니라 source_dir 기준으로
        존재 여부를 확인해야 한다 — 실제 실행(LifecycleManager._run)이 cwd=source_dir로
        돌기 때문(2026-07-23 실사용자 monorepo 리포트: 항상 "unavailable executables: ./gradlew"
        오탐)."""
        manifest = readiness_manifest().model_copy(deep=True)
        manifest.commands["build"].argv[0] = "./gradlew"
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ, {"VIBECUTTER_ROLE_A_TOKEN": "configured"}, clear=True
        ):
            wrapper = Path(temp_dir) / "gradlew"
            wrapper.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
            wrapper.chmod(0o755)
            log_path = Path(temp_dir) / "logs" / "app.log"
            log_path.parent.mkdir()
            log_path.write_text("safe", encoding="utf-8")
            report = TargetRuntimeInspector(manifest, Path(temp_dir)).check_readiness()
        self.assertTrue(report.ready)
        self.assertEqual(report.unavailable_executables, [])

    def test_relative_wrapper_script_missing_is_still_reported_unavailable(self) -> None:
        manifest = readiness_manifest().model_copy(deep=True)
        manifest.commands["build"].argv[0] = "./gradlew"
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ, {"VIBECUTTER_ROLE_A_TOKEN": "configured"}, clear=True
        ):
            report = TargetRuntimeInspector(manifest, Path(temp_dir)).check_readiness()
        self.assertFalse(report.ready)
        self.assertEqual(report.unavailable_executables, ["./gradlew"])
