from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import subprocess
import warnings

from runtime.manifest import TargetManifest
from runtime.registry import LocalRegistry, commands_sha256, manifest_content_sha256


def _manifest(kind: str = "running_local") -> TargetManifest:
    return TargetManifest.model_validate(
        {
            "id": "local-demo",
            "display_name": "Local demo",
            "kind": kind,
            "adapter": "fastapi",
            "source_dir": ".",
            "base_url": "http://127.0.0.1:18080",
            "commands": {"reset": {"argv": ["python", "-V"]}},
            "reset": {"command_id": "reset"},
        }
    )


class LocalRegistryTests(unittest.TestCase):
    def _git_repo(self, root: Path) -> None:
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        (root / "README.md").write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "README.md"], check=True)
        subprocess.run(
            ["git", "-C", str(root), "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "baseline"],
            check=True,
        )

    def test_running_local_manifest_only_requires_reset(self) -> None:
        manifest = _manifest()
        self.assertEqual(manifest.kind, "running_local")
        self.assertNotIn("build", manifest.commands)

    def test_approve_persists_outside_repository_and_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "project"
            project.mkdir()
            self._git_repo(project)
            registry = LocalRegistry.load(Path(temp) / "registry")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                approved = registry.approve(_manifest(), source_path=project)
            self.assertEqual(registry.list_ids(), ("local-demo",))
            loaded = registry.get("local-demo")
            self.assertIsNotNone(loaded)
            assert loaded is not None
            self.assertEqual(loaded.source_path, project.resolve())
            self.assertEqual(approved.allowed_hosts, ["127.0.0.1"])
            self.assertEqual(loaded.manifest_sha256, manifest_content_sha256(_manifest()))
            self.assertEqual(loaded.commands_sha256, commands_sha256(_manifest()))
            self.assertEqual(loaded, approved)
            self.assertTrue((Path(temp) / "registry" / "local-demo" / "manifest.yaml").is_file())
            self.assertTrue((Path(temp) / "registry" / "local-demo" / "approval.yaml").is_file())
            self.assertEqual(registry.manifest_for("local-demo"), _manifest())

    def test_non_git_source_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "project"
            project.mkdir()
            with self.assertRaisesRegex(ValueError, "Git repository"):
                LocalRegistry.load(Path(temp) / "registry").approve(_manifest(), source_path=project)

    def test_manifest_and_command_hashes_change_when_approved_input_changes(self) -> None:
        first = _manifest()
        second = TargetManifest.model_validate(
            first.model_dump(mode="json") | {"display_name": "Changed"}
        )
        self.assertNotEqual(manifest_content_sha256(first), manifest_content_sha256(second))
        changed_commands = TargetManifest.model_validate(
            first.model_dump(mode="json")
            | {"commands": {"reset": {"argv": ["python", "--version"]}}}
        )
        self.assertNotEqual(commands_sha256(first), commands_sha256(changed_commands))

    def test_loopback_validation_remains_mandatory(self) -> None:
        with self.assertRaises(ValueError):
            TargetManifest.model_validate(
                _manifest().model_dump(mode="json")
                | {"base_url": "http://example.com:18080"}
            )
