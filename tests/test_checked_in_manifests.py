"""Regression coverage for the repository-owned P2 target catalog."""

from __future__ import annotations

import unittest
from pathlib import Path

from runtime.catalog import TargetCatalog


class CheckedInManifestTests(unittest.TestCase):
    def test_all_checked_in_manifests_load_under_the_role_fixture_contract(self) -> None:
        root = Path(__file__).resolve().parents[1]
        catalog = TargetCatalog(manifest_root=root / "targets" / "manifests", repository_root=root)
        catalog.load()

        targets = catalog.list()
        self.assertGreaterEqual(len(targets), 1)
        self.assertEqual(len({target.manifest.id for target in targets}), len(targets))

