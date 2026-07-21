from __future__ import annotations

from datetime import timedelta
import json
import tempfile
import unittest
from pathlib import Path

from runtime.target_lease import TargetLeaseError, TargetLeaseManager


class TargetLeaseTests(unittest.TestCase):
    def test_only_one_active_run_can_hold_a_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            manager = TargetLeaseManager(Path(temp))
            lease = manager.acquire("local-demo", "run-1", timeout_seconds=60)
            self.assertEqual(manager.get("local-demo"), lease)
            with self.assertRaises(TargetLeaseError):
                manager.acquire("local-demo", "run-2", timeout_seconds=60)

    def test_owner_can_release_and_another_run_can_acquire(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            manager = TargetLeaseManager(Path(temp))
            manager.acquire("local-demo", "run-1")
            self.assertTrue(manager.release("local-demo", "run-1"))
            self.assertIsNone(manager.get("local-demo"))
            self.assertEqual(manager.acquire("local-demo", "run-2").run_id, "run-2")

    def test_non_owner_cannot_release(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            manager = TargetLeaseManager(Path(temp))
            manager.acquire("local-demo", "run-1")
            with self.assertRaises(TargetLeaseError):
                manager.release("local-demo", "run-2")

    def test_expired_lease_can_be_reaped_and_reacquired(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            manager = TargetLeaseManager(Path(temp))
            lease = manager.acquire("local-demo", "run-1")
            expired = lease.__class__(
                lease.target_id,
                lease.run_id,
                lease.acquired_at - timedelta(seconds=10),
                lease.expires_at - timedelta(seconds=1_000_000),
            )
            (Path(temp) / "local-demo" / "lease.json").write_text(
                json.dumps({
                    "target_id": expired.target_id,
                    "run_id": expired.run_id,
                    "acquired_at": expired.acquired_at.isoformat(),
                    "expires_at": expired.expires_at.isoformat(),
                }),
                encoding="utf-8",
            )
            self.assertTrue(manager.reap_stale("local-demo"))
            self.assertEqual(manager.acquire("local-demo", "run-2").run_id, "run-2")

    def test_path_and_timeout_inputs_are_validated(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            manager = TargetLeaseManager(Path(temp))
            with self.assertRaises(ValueError):
                manager.acquire("../escape", "run-1")
            with self.assertRaises(ValueError):
                manager.acquire("local-demo", "run-1", timeout_seconds=0)


if __name__ == "__main__":
    unittest.main()
