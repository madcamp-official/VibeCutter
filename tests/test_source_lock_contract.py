from __future__ import annotations

import unittest
from pathlib import Path

from runtime.manifest import load_manifest
from runtime.source_lock import SourceLock


ROOT = Path(__file__).resolve().parents[1]


class CheckedInSourceLockContractTests(unittest.TestCase):
    def test_lock_covers_every_runtime_manifest_exactly(self) -> None:
        manifests = {
            load_manifest(path).id: load_manifest(path)
            for path in sorted((ROOT / "targets" / "manifests").glob("*.yaml"))
        }
        lock = SourceLock.load(
            ROOT / "targets" / "source-lock.yaml",
            expected_target_ids=set(manifests),
        )
        self.assertEqual(len(lock.target_ids), len(manifests))
        for target_id, manifest in manifests.items():
            expected_source_root = Path(".vibecutter/targets/sources") / target_id
            source_dir = Path(manifest.source_dir)
            self.assertTrue(
                source_dir == expected_source_root
                or expected_source_root in source_dir.parents,
                f"{target_id} source_dir must stay inside its locked managed clone",
            )


if __name__ == "__main__":
    unittest.main()
