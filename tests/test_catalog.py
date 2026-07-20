from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
import subprocess
import yaml

from runtime.catalog import TargetCatalog


def manifest_yaml(target_id: str) -> str:
    return f"""\
id: {target_id}
display_name: {target_id}
adapter: fastapi
source_dir: .
base_url: http://127.0.0.1:18080
commands:
  build: {{argv: [python, -V]}}
  start: {{argv: [python, -V]}}
  stop: {{argv: [python, -V]}}
  reset: {{argv: [python, -V]}}
reset: {{command_id: reset}}
tool_versions: {{python: 3.11.9}}
"""


def write_source_lock(
    root: Path, target_ids: list[str], revisions: dict[str, str] | None = None
) -> None:
    revisions = revisions or {}
    (root / "targets").mkdir(exist_ok=True)
    (root / "targets" / "source-lock.yaml").write_text(
        yaml.safe_dump(
            {
                "lock_version": 1,
                "targets": {
                    target_id: {
                        "repository": f"https://github.com/madcamp-official/{target_id}.git",
                        "revision": revisions.get(target_id, "a" * 40),
                    }
                    for target_id in target_ids
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )


class TargetCatalogTests(unittest.TestCase):
    def test_catalog_discovers_p1_contracts_by_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_root = root / "manifests"
            manifest_root.mkdir()
            (manifest_root / "beta.yaml").write_text(
                manifest_yaml("beta-api"), encoding="utf-8"
            )
            (manifest_root / "alpha.yaml").write_text(
                manifest_yaml("alpha-api"), encoding="utf-8"
            )
            catalog = TargetCatalog(
                manifest_root=manifest_root,
                repository_root=root,
                source_commit="deadbeef",
            )
            catalog.load()
            self.assertEqual(
                [item.contract_target.id for item in catalog.list()],
                ["alpha-api", "beta-api"],
            )
            self.assertEqual(
                catalog.get("beta-api").contract_target.source_commit, "deadbeef"
            )
            self.assertEqual(
                catalog.lifecycle_for("alpha-api").tool_versions, {"python": "3.11.9"}
            )

    def test_catalog_rejects_duplicate_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_root = root / "manifests"
            manifest_root.mkdir()
            (manifest_root / "first.yaml").write_text(
                manifest_yaml("same-api"), encoding="utf-8"
            )
            (manifest_root / "second.yaml").write_text(
                manifest_yaml("same-api"), encoding="utf-8"
            )
            catalog = TargetCatalog(manifest_root=manifest_root, repository_root=root)
            with self.assertRaisesRegex(ValueError, "duplicate target manifest id"):
                catalog.load()

    def test_unknown_target_id_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_root = root / "manifests"
            manifest_root.mkdir()
            (manifest_root / "known.yaml").write_text(
                manifest_yaml("known-api"), encoding="utf-8"
            )
            catalog = TargetCatalog(manifest_root=manifest_root, repository_root=root)
            catalog.load()
            with self.assertRaises(KeyError):
                catalog.get("unknown-api")

    def test_target_worktree_is_created_from_source_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_root = root / "manifests"
            manifest_root.mkdir()
            source = root / ".vibecutter" / "targets" / "sources" / "demo-api"
            source.mkdir(parents=True)
            subprocess.run(
                ["git", "-C", str(source), "init"],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["git", "-C", str(source), "config", "user.email", "p2@example.test"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(source), "config", "user.name", "P2 Test"], check=True
            )
            (source / "app.txt").write_text("target source", encoding="utf-8")
            subprocess.run(["git", "-C", str(source), "add", "app.txt"], check=True)
            subprocess.run(
                ["git", "-C", str(source), "commit", "-m", "initial"],
                check=True,
                capture_output=True,
            )
            revision = subprocess.run(
                ["git", "-C", str(source), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(source),
                    "remote",
                    "add",
                    "origin",
                    "https://github.com/madcamp-official/demo-api.git",
                ],
                check=True,
            )
            (manifest_root / "demo.yaml").write_text(
                manifest_yaml("demo-api").replace(
                    "source_dir: .", "source_dir: .vibecutter/targets/sources/demo-api"
                ),
                encoding="utf-8",
            )
            write_source_lock(root, ["demo-api"], {"demo-api": revision})
            catalog = TargetCatalog(manifest_root=manifest_root, repository_root=root)
            catalog.load()
            worktrees = catalog.worktree_manager_for("demo-api")
            worktree = worktrees.create("run-1")
            try:
                self.assertEqual(
                    catalog.source_repository_for("demo-api"), source.resolve()
                )
                self.assertEqual(
                    (worktree / "app.txt").read_text(encoding="utf-8"), "target source"
                )
                self.assertNotEqual(worktree.parents[1], root)
                self.assertEqual(
                    catalog.run_overlay_for("demo-api", "run-1").worktree_path, worktree
                )
            finally:
                worktrees.remove("run-1", approved=True)

    def test_run_source_root_tracks_manifest_subdirectory_inside_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_root = root / "manifests"
            manifest_root.mkdir()
            source = root / ".vibecutter" / "targets" / "sources" / "demo-api"
            backend = source / "backend"
            backend.mkdir(parents=True)
            subprocess.run(
                ["git", "-C", str(source), "init"],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["git", "-C", str(source), "config", "user.email", "p2@example.test"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(source), "config", "user.name", "P2 Test"], check=True
            )
            (backend / "app.txt").write_text("target source", encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(source), "add", "backend/app.txt"], check=True
            )
            subprocess.run(
                ["git", "-C", str(source), "commit", "-m", "initial"],
                check=True,
                capture_output=True,
            )
            revision = subprocess.run(
                ["git", "-C", str(source), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(source),
                    "remote",
                    "add",
                    "origin",
                    "https://github.com/madcamp-official/demo-api.git",
                ],
                check=True,
            )
            (manifest_root / "demo.yaml").write_text(
                manifest_yaml("demo-api").replace(
                    "source_dir: .",
                    "source_dir: .vibecutter/targets/sources/demo-api/backend",
                ),
                encoding="utf-8",
            )
            write_source_lock(root, ["demo-api"], {"demo-api": revision})
            catalog = TargetCatalog(manifest_root=manifest_root, repository_root=root)
            catalog.load()
            worktrees = catalog.worktree_manager_for("demo-api")
            worktree = worktrees.create("run-1")
            try:
                self.assertEqual(
                    catalog.source_repository_for("demo-api"), source.resolve()
                )
                self.assertEqual(
                    catalog.source_relative_path_for("demo-api"), Path("backend")
                )
                self.assertEqual(
                    catalog.run_source_root_for("demo-api", "run-1"),
                    worktree / "backend",
                )
            finally:
                worktrees.remove("run-1", approved=True)
