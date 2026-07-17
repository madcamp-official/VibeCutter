from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

import yaml

from runtime.compose_isolation import ComposeIsolationInspector
from runtime.manifest import TargetManifest
from runtime.readiness import TargetRuntimeInspector


def manifest_for_compose() -> TargetManifest:
    return TargetManifest.model_validate(
        {
            "id": "compose-api",
            "display_name": "Compose API",
            "adapter": "fastapi",
            "source_dir": ".",
            "base_url": "http://127.0.0.1:18080",
            "commands": {
                "build": {"argv": [sys.executable, "-V"]},
                "start": {"argv": [sys.executable, "-V"]},
                "stop": {"argv": [sys.executable, "-V"]},
                "reset": {"argv": [sys.executable, "-V"]},
            },
            "reset": {"command_id": "reset"},
            "docker_isolation": {
                "compose_file": "compose.yaml",
                "internal_network": "vc-internal",
                "require_loopback_port_bindings": True,
            },
        }
    )


def compliant_compose() -> dict:
    return {
        "services": {
            "app": {
                "image": "example/app:latest",
                "ports": ["127.0.0.1:18080:8080"],
                "networks": ["vc-internal"],
            }
        },
        "networks": {"vc-internal": {"internal": True}},
    }


class ComposeIsolationTests(unittest.TestCase):
    def test_compliant_compose_passes_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "compose.yaml").write_text(yaml.safe_dump(compliant_compose()), encoding="utf-8")
            report = ComposeIsolationInspector(manifest_for_compose(), root).inspect()
            readiness = TargetRuntimeInspector(manifest_for_compose(), root).check_readiness()
        self.assertTrue(report.compliant)
        self.assertTrue(readiness.ready)

    def test_nat_disabled_bridge_allows_loopback_target_isolation(self) -> None:
        document = compliant_compose()
        document["networks"]["vc-internal"] = {
            "driver": "bridge",
            "driver_opts": {"com.docker.network.bridge.enable_ip_masquerade": "false"},
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "compose.yaml").write_text(yaml.safe_dump(document), encoding="utf-8")
            report = ComposeIsolationInspector(manifest_for_compose(), root).inspect()
        self.assertTrue(report.compliant)

    def test_non_loopback_privileged_compose_is_rejected(self) -> None:
        document = compliant_compose()
        document["services"]["app"]["ports"] = ["18080:8080"]
        document["services"]["app"]["privileged"] = True
        document["services"]["app"]["networks"] = ["default"]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "compose.yaml").write_text(yaml.safe_dump(document), encoding="utf-8")
            readiness = TargetRuntimeInspector(manifest_for_compose(), root).check_readiness()
        self.assertFalse(readiness.ready)
        self.assertEqual(readiness.docker_isolation.status, "non_compliant")
        self.assertTrue(any("non-loopback" in issue for issue in readiness.issues))

    def test_missing_compose_file_blocks_readiness(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            readiness = TargetRuntimeInspector(manifest_for_compose(), Path(temp_dir)).check_readiness()
        self.assertFalse(readiness.ready)
        self.assertEqual(readiness.docker_isolation.status, "missing_file")
