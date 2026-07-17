from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

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


class TargetCatalogTests(unittest.TestCase):
    def test_catalog_discovers_p1_contracts_by_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_root = root / "manifests"
            manifest_root.mkdir()
            (manifest_root / "beta.yaml").write_text(manifest_yaml("beta-api"), encoding="utf-8")
            (manifest_root / "alpha.yaml").write_text(manifest_yaml("alpha-api"), encoding="utf-8")
            catalog = TargetCatalog(manifest_root=manifest_root, repository_root=root, source_commit="deadbeef")
            catalog.load()
            self.assertEqual([item.contract_target.id for item in catalog.list()], ["alpha-api", "beta-api"])
            self.assertEqual(catalog.get("beta-api").contract_target.source_commit, "deadbeef")
            self.assertEqual(catalog.lifecycle_for("alpha-api").tool_versions, {"python": "3.11.9"})

    def test_catalog_rejects_duplicate_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_root = root / "manifests"
            manifest_root.mkdir()
            (manifest_root / "first.yaml").write_text(manifest_yaml("same-api"), encoding="utf-8")
            (manifest_root / "second.yaml").write_text(manifest_yaml("same-api"), encoding="utf-8")
            catalog = TargetCatalog(manifest_root=manifest_root, repository_root=root)
            with self.assertRaisesRegex(ValueError, "duplicate target manifest id"):
                catalog.load()

    def test_unknown_target_id_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            manifest_root = root / "manifests"
            manifest_root.mkdir()
            catalog = TargetCatalog(manifest_root=manifest_root, repository_root=root)
            catalog.load()
            with self.assertRaises(KeyError):
                catalog.get("unknown-api")
