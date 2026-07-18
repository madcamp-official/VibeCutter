from __future__ import annotations

import unittest
from pathlib import Path

from runtime.catalog import TargetCatalog
from runtime.lifecycle import VIBECUTTER_PYTHON


class ManifestPortabilityTests(unittest.TestCase):
    def test_checked_in_manifests_do_not_depend_on_the_windows_py_launcher(self) -> None:
        root = Path(__file__).resolve().parents[1]
        catalog = TargetCatalog(manifest_root=root / "targets" / "manifests", repository_root=root)
        catalog.load()

        for target in catalog.list():
            for command in target.manifest.commands.values():
                self.assertNotEqual(command.argv[0], "py", target.manifest.id)
                if command.argv[0] == VIBECUTTER_PYTHON:
                    self.assertGreater(len(command.argv), 1, target.manifest.id)
