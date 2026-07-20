from __future__ import annotations

from pathlib import Path
import unittest

import yaml


class C105RuntimeContractTests(unittest.TestCase):
    def test_mysql_readiness_waits_for_application_account_database_access(self) -> None:
        root = Path(__file__).resolve().parents[1]
        compose = yaml.safe_load(
            (root / "targets" / "compose" / "26s-w1-c1-05.yaml").read_text(encoding="utf-8")
        )

        command = compose["services"]["database"]["healthcheck"]["test"]
        self.assertEqual(command[0], "CMD-SHELL")
        self.assertIn("$$MYSQL_USER", command[1])
        self.assertIn("$$MYSQL_PASSWORD", command[1])
        self.assertIn("$$MYSQL_DATABASE", command[1])
        self.assertIn("SELECT 1", command[1])
