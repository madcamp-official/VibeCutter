from __future__ import annotations

import unittest
from pathlib import Path

import yaml

from datasets.inventory import Inventory
from runtime.manifest import load_manifest


ROOT = Path(__file__).resolve().parent.parent
MANIFEST_ROOT = ROOT / "targets" / "manifests"
OVERRIDES_PATH = ROOT / "targets" / "inventory_adapter_overrides.yaml"
P4_TO_P2_ADAPTER = {
    "node": "node",
    "fastapi": "fastapi",
    "spring": "spring-boot",
    "generic_docker": "generic-docker",
}


class InventoryManifestContractTests(unittest.TestCase):
    def test_checked_in_manifests_are_known_to_inventory(self) -> None:
        inventory = {app.id: app for app in Inventory.load().apps}
        manifests = {manifest.id: manifest for manifest in map(load_manifest, MANIFEST_ROOT.glob("*.yaml"))}
        self.assertFalse(set(manifests) - set(inventory))

    def test_adapter_differences_are_explicit_p2_overrides(self) -> None:
        inventory = {app.id: app for app in Inventory.load().apps}
        manifests = {manifest.id: manifest for manifest in map(load_manifest, MANIFEST_ROOT.glob("*.yaml"))}
        document = yaml.safe_load(OVERRIDES_PATH.read_text(encoding="utf-8"))
        overrides = document["overrides"]
        actual_differences = {
            target_id: (P4_TO_P2_ADAPTER[inventory[target_id].adapter], manifest.adapter.value)
            for target_id, manifest in manifests.items()
            if P4_TO_P2_ADAPTER[inventory[target_id].adapter] != manifest.adapter.value
        }
        documented_differences = {
            target_id: (P4_TO_P2_ADAPTER[entry["inventory_adapter"]], entry["manifest_adapter"])
            for target_id, entry in overrides.items()
        }
        self.assertEqual(actual_differences, documented_differences)
        for target_id, entry in overrides.items():
            self.assertIn(target_id, manifests)
            self.assertTrue(entry["reason"])
