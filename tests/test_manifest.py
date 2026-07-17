from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from pydantic import ValidationError

from runtime.manifest import TargetManifest, load_manifest


def valid_manifest() -> dict:
    return {
        "manifest_version": 1,
        "id": "demo-api",
        "display_name": "Demo API",
        "adapter": "fastapi",
        "source_dir": ".",
        "base_url": "http://127.0.0.1:18080",
        "commands": {
            "build": {"argv": ["python", "-V"]},
            "start": {"argv": ["python", "-V"]},
            "stop": {"argv": ["python", "-V"]},
            "reset": {"argv": ["python", "-V"]},
            "test": {"argv": ["python", "-V"]},
        },
        "reset": {"command_id": "reset"},
        "test_suites": [{"name": "unit", "command_id": "test"}],
    }


class TargetManifestTests(unittest.TestCase):
    def test_valid_manifest_is_accepted(self) -> None:
        manifest = TargetManifest.model_validate(valid_manifest())
        self.assertEqual(manifest.id, "demo-api")
        self.assertEqual(manifest.base_url, "http://127.0.0.1:18080")

    def test_external_base_url_is_rejected(self) -> None:
        data = valid_manifest()
        data["base_url"] = "https://example.com"
        with self.assertRaises(ValidationError):
            TargetManifest.model_validate(data)

    def test_shell_syntax_and_path_escape_are_rejected(self) -> None:
        data = valid_manifest()
        data["source_dir"] = "../outside"
        data["commands"]["build"] = {"argv": ["sh", "-c", "echo a && echo b"]}
        with self.assertRaises(ValidationError):
            TargetManifest.model_validate(data)

    def test_command_working_directory_must_stay_within_repository(self) -> None:
        data = valid_manifest()
        data["commands"]["build"]["working_dir"] = "../outside"
        with self.assertRaises(ValidationError):
            TargetManifest.model_validate(data)

    def test_yaml_loader_reads_checked_in_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "target.yaml"
            path.write_text("""\
manifest_version: 1
id: demo-api
display_name: Demo API
adapter: node
source_dir: .
base_url: http://localhost:3000
commands:
  build: {argv: [node, --version]}
  start: {argv: [node, --version]}
  stop: {argv: [node, --version]}
  reset: {argv: [node, --version]}
reset: {command_id: reset}
""", encoding="utf-8")
            self.assertEqual(load_manifest(path).adapter.value, "node")
