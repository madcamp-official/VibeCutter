from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from runtime.manifest import TargetManifest
from runtime.registration import manifest_sha256, to_contract_target


class RegistrationTests(unittest.TestCase):
    def test_manifest_converts_to_p1_target_contract(self) -> None:
        manifest = TargetManifest.model_validate(
            {
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
                },
                "tool_versions": {"python": "3.11.9"},
                "reset": {"command_id": "reset"},
            }
        )
        target = to_contract_target(manifest, manifest_hash="a" * 64, source_commit="abc1234")
        self.assertEqual(target.id, "demo-api")
        self.assertEqual(target.adapter, "fastapi")
        self.assertEqual(target.allowed_hosts, ["127.0.0.1:18080"])
        self.assertEqual(manifest.tool_versions, {"python": "3.11.9"})

    def test_manifest_hash_is_stable_and_content_sensitive(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "target.yaml"
            path.write_text("id: demo-api\n", encoding="utf-8")
            first = manifest_sha256(path)
            self.assertEqual(first, manifest_sha256(path))
            path.write_text("id: other-api\n", encoding="utf-8")
            self.assertNotEqual(first, manifest_sha256(path))
