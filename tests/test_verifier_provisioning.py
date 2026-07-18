from __future__ import annotations

import unittest
from pathlib import Path

from runtime.catalog import TargetCatalog
from runtime.provisioning import ProvisioningStrategy


class CheckedInVerifierProvisioningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[1]
        self.catalog = TargetCatalog(
            manifest_root=self.root / "targets" / "manifests",
            repository_root=self.root,
        )
        self.catalog.load()

    def test_fixture_file_target_declares_fixed_command_and_ignored_artifact(self) -> None:
        plan = self.catalog.verifier_provisioning_for("26s-w1-c2-04")
        self.assertEqual(plan.strategy, ProvisioningStrategy.FIXTURE_FILE)
        self.assertEqual(plan.auth_mode, "none")
        self.assertEqual(plan.fixture_command_id, "prepare_idor_fixture")
        self.assertEqual(plan.fixture_path, ".vibecutter/fixtures/26s-w1-c2-04-idor.json")

    def test_self_signup_target_never_declares_stored_fixture_credentials(self) -> None:
        plan = self.catalog.verifier_provisioning_for("26s-w1-c1-05")
        self.assertEqual(plan.strategy, ProvisioningStrategy.SELF_SIGNUP)
        self.assertEqual(plan.auth_mode, "bearer")
        self.assertIsNone(plan.fixture_command_id)
        self.assertIsNone(plan.fixture_path)

    def test_unconfigured_target_requires_p3_fixture_contract(self) -> None:
        plan = self.catalog.verifier_provisioning_for("26s-w1-c1-03")
        self.assertEqual(plan.strategy, ProvisioningStrategy.FIXTURE_CONTRACT_REQUIRED)
        self.assertFalse(plan.fixture_available)
