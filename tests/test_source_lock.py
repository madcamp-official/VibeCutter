from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from runtime.source_lock import SourceLock


class SourceLockTests(unittest.TestCase):
    def _write(self, document: dict) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "source-lock.yaml"
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        return path

    @staticmethod
    def _document(*target_ids: str) -> dict:
        return {
            "lock_version": 1,
            "targets": {
                target_id: {
                    "repository": f"https://github.com/madcamp-official/{target_id}.git",
                    "revision": "a" * 40,
                }
                for target_id in target_ids
            },
        }

    def test_loads_canonical_exact_target_revisions(self) -> None:
        lock = SourceLock.load(
            self._write(self._document("demo-api", "other-api")),
            expected_target_ids={"demo-api", "other-api"},
        )
        self.assertEqual(lock.target_ids, ("demo-api", "other-api"))
        self.assertEqual(lock.get("demo-api").revision, "a" * 40)

    def test_rejects_unknown_fields_and_noncanonical_revision(self) -> None:
        document = self._document("demo-api")
        document["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "only lock_version and targets"):
            SourceLock.load(self._write(document))

        document = self._document("demo-api")
        document["targets"]["demo-api"]["revision"] = "A" * 40
        with self.assertRaisesRegex(ValueError, "40 lowercase hex"):
            SourceLock.load(self._write(document))

    def test_rejects_repository_that_does_not_match_target_id(self) -> None:
        document = self._document("demo-api")
        document["targets"]["demo-api"]["repository"] = (
            "https://github.com/madcamp-official/other-api.git"
        )
        with self.assertRaisesRegex(ValueError, "must be"):
            SourceLock.load(self._write(document))

    def test_rejects_missing_or_extra_manifest_coverage(self) -> None:
        path = self._write(self._document("demo-api", "extra-api"))
        with self.assertRaisesRegex(
            ValueError, "missing=.*other-api.*extra=.*extra-api"
        ):
            SourceLock.load(path, expected_target_ids={"demo-api", "other-api"})

    def test_unknown_target_lookup_is_rejected(self) -> None:
        lock = SourceLock.load(self._write(self._document("demo-api")))
        with self.assertRaisesRegex(KeyError, "not registered"):
            lock.get("other-api")


if __name__ == "__main__":
    unittest.main()
