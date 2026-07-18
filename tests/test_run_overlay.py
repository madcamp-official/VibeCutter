from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from runtime.manifest import TargetManifest
from runtime.run_overlay import RunComposeOverlay
from runtime.worktree import WorktreeManager


def _git(repository: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repository), *args], check=True, capture_output=True, text=True)


def _manifest() -> TargetManifest:
    return TargetManifest.model_validate(
        {
            "id": "demo-api",
            "display_name": "Demo API",
            "adapter": "fastapi",
            "source_dir": ".vibecutter/targets/sources/demo-api",
            "base_url": "http://127.0.0.1:18080",
            "commands": {
                "build": {"argv": ["docker", "compose", "-f", "targets/compose/demo-api.yaml", "build"], "working_dir": "."},
                "start": {"argv": ["docker", "compose", "-f", "targets/compose/demo-api.yaml", "up", "-d"], "working_dir": "."},
                "stop": {"argv": ["docker", "compose", "-f", "targets/compose/demo-api.yaml", "down"], "working_dir": "."},
                "reset": {"argv": ["docker", "compose", "-f", "targets/compose/demo-api.yaml", "down", "--volumes"], "working_dir": "."},
            },
            "reset": {"command_id": "reset"},
            "docker_isolation": {
                "compose_file": "targets/compose/demo-api.yaml",
                "internal_network": "vc-internal",
                "require_loopback_port_bindings": True,
            },
        }
    )


class RunComposeOverlayTests(unittest.TestCase):
    def test_generated_compose_uses_target_worktree_and_preserves_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / ".vibecutter" / "targets" / "sources" / "demo-api"
            source.mkdir(parents=True)
            _git(source, "init")
            _git(source, "config", "user.email", "p2@example.test")
            _git(source, "config", "user.name", "P2 Test")
            (source / "app.py").write_text("print('target')\n", encoding="utf-8")
            _git(source, "add", "app.py")
            _git(source, "commit", "-m", "initial")
            compose_dir = root / "targets" / "compose"
            dockerfiles = root / "targets" / "dockerfiles"
            compose_dir.mkdir(parents=True)
            dockerfiles.mkdir(parents=True)
            (dockerfiles / "demo.Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            (root / "targets" / "nginx.conf").write_text("server {}\n", encoding="utf-8")
            (compose_dir / "demo-api.yaml").write_text(
                """services:
  app:
    build:
      context: ../../.vibecutter/targets/sources/demo-api
      dockerfile: ../../../../targets/dockerfiles/demo.Dockerfile
    volumes: [../../targets/nginx.conf:/etc/nginx/conf.d/default.conf:ro]
    ports: [127.0.0.1:18080:8080]
    networks: [vc-internal]
networks:
  vc-internal:
    internal: true
""",
                encoding="utf-8",
            )
            worktrees = WorktreeManager(source, artifact_root=root / ".vibecutter" / "worktrees" / "demo-api")
            worktree = worktrees.create("run-1")
            try:
                # A run worktree must use repository bytes, not the host's
                # core.autocrlf setting: generated LF patch diffs otherwise
                # fail to apply on Windows CRLF checkouts.
                self.assertEqual((worktree / "app.py").read_bytes(), b"print('target')\n")
                overlay = RunComposeOverlay(_manifest(), root, source, worktree, "run-1")
                path = overlay.prepare()
                document = yaml.safe_load(path.read_text(encoding="utf-8"))
                self.assertEqual(Path(document["services"]["app"]["build"]["context"]), worktree)
                self.assertTrue(Path(document["services"]["app"]["build"]["dockerfile"]).samefile(dockerfiles / "demo.Dockerfile"))
                volume_source = document["services"]["app"]["volumes"][0].rsplit(":", 2)[0]
                self.assertTrue(Path(volume_source).samefile(root / "targets" / "nginx.conf"))
                self.assertTrue(overlay.inspect().compliant)
            finally:
                worktrees.remove("run-1", approved=True)
