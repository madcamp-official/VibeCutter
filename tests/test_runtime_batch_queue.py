from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from runtime.batch_queue import load_runtime_batch_queue


class RuntimeBatchQueueTests(unittest.TestCase):
    def _write(self, document: dict) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "queue.yaml"
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        return path

    def test_loads_exact_partition_of_allowlisted_targets(self) -> None:
        path = self._write(
            {"queue_version": 1, "workers": {"gpu-1": {"targets": ["one"]}, "gpu-2": {"targets": ["two"]}}}
        )
        queue = load_runtime_batch_queue(path, allowed_target_ids={"one", "two"})
        self.assertEqual(queue.targets_for("gpu-1"), ("one",))
        self.assertEqual(queue.target_ids, ("one", "two"))

    def test_rejects_duplicate_or_incomplete_assignments(self) -> None:
        path = self._write(
            {"queue_version": 1, "workers": {"gpu-1": {"targets": ["one", "two"]}, "gpu-2": {"targets": ["two"]}}}
        )
        with self.assertRaisesRegex(ValueError, "only one"):
            load_runtime_batch_queue(path, allowed_target_ids={"one", "two", "three"})

    def test_rejects_unknown_worker_lookup(self) -> None:
        path = self._write({"queue_version": 1, "workers": {"gpu-1": {"targets": ["one"]}}})
        queue = load_runtime_batch_queue(path, allowed_target_ids={"one"})
        with self.assertRaisesRegex(KeyError, "not registered"):
            queue.targets_for("gpu-2")
