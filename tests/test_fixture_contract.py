from __future__ import annotations

import importlib.util
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from surface.candidates import _fixture_resources
from verifiers.access_control import mutation_probe_from_fixture, probe_from_fixture


class FixtureContractTests(unittest.TestCase):
    def test_reader_accepts_normalized_auth_alias(self) -> None:
        fixture = {
            "base_url": "http://127.0.0.1:14017",
            "auth": {"mode": "none"},
            "resources": {
                "victim_vocabulary": {
                    "read_path": "/vocabs/1/words/",
                    "victim_marker": "victim-only",
                },
                "attacker_vocabulary": {
                    "baseline_path": "/vocabs/2/words/",
                    "marker": "attacker-only",
                },
            },
        }

        probe = probe_from_fixture(fixture)

        self.assertEqual(probe.auth_mode, "none")
        self.assertEqual(probe.attack_path, "/vocabs/1/words/")
        self.assertEqual(probe.baseline_path, "/vocabs/2/words/")

    def test_mutation_fixture_can_provide_explicit_observe_path(self) -> None:
        fixture = {
            "base_url": "http://127.0.0.1:14017",
            "auth": {"mode": "none"},
            "resources": {
                "vocabulary": {
                    "victim_marker": "victim-only",
                    "safe_mutation": {
                        "method": "PUT",
                        "path": "/vocabs/1/description/",
                        "observe_path": "/vocabs/?owner_id=10",
                        "json": {"description": "fixture mutation", "tags": "p2,p3"},
                    },
                }
            },
        }

        probe = mutation_probe_from_fixture(fixture)

        self.assertEqual(probe.observe_path, "/vocabs/?owner_id=10")
        self.assertEqual(probe.mutation_method, "PUT")
        self.assertEqual(probe.marker_field, "description")

    def test_candidate_bridge_accepts_normalized_resource_pair(self) -> None:
        fixture = {
            "base_url": "http://127.0.0.1:14017",
            "auth": {"mode": "none"},
            "resources": {
                "vocabulary": {
                    "kind": "vocabulary",
                    "attacker_id": 7,
                    "victim_id": 6,
                    "victim_marker": "victim-only",
                    "owner_marker": "attacker-only",
                }
            },
        }

        resources = _fixture_resources(fixture)

        self.assertEqual(
            resources,
            {
                "vocabulary": {
                    "attacker_id": 7,
                    "victim_id": 6,
                    "victim_marker": "victim-only",
                    "owner_marker": "attacker-only",
                }
            },
        )

    def test_c2_04_script_writes_legacy_and_normalized_fixture_without_secrets(self) -> None:
        script = Path(__file__).resolve().parents[1] / "targets" / "scripts" / "26s-w1-c2-04-idor-fixture.py"
        spec = importlib.util.spec_from_file_location("c2_04_fixture_script", script)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        counters = {"user": 3, "vocab": 5, "word": 90}
        words_by_vocab: dict[str, list[str]] = {}

        def fake_request(method: str, path: str, body: dict[str, object] | None = None):
            if method == "GET" and path == "/api/data":
                return 200, {"ok": True}
            if method == "POST" and path == "/users/":
                counters["user"] += 1
                return 201, {"id": counters["user"], "username": body["username"]}
            if method == "POST" and path == "/vocabs/":
                counters["vocab"] += 1
                return 201, {"id": counters["vocab"], "title": body["title"]}
            if method == "POST" and path.endswith("/words/"):
                counters["word"] += 1
                words_by_vocab.setdefault(path, []).append(str(body["word"]))
                return 201, {"id": counters["word"], "word": body["word"]}
            if method == "GET" and path.startswith("/vocabs/"):
                return 200, [{"word": word} for word in words_by_vocab.get(path, [])]
            raise AssertionError(f"unexpected fixture request: {method} {path}")

        with TemporaryDirectory() as td:
            fixture_path = Path(td) / "fixture.json"
            with (
                patch.object(module, "FIXTURE_PATH", fixture_path),
                patch.object(module, "request", side_effect=fake_request),
                redirect_stdout(io.StringIO()),
            ):
                module.main()

            data = json.loads(fixture_path.read_text(encoding="utf-8"))
            self.assertEqual(data["auth"]["mode"], "none")
            self.assertEqual(data["authentication"]["mode"], "none")
            self.assertIn("victim_vocabulary", data["resources"])
            self.assertIn("attacker_vocabulary", data["resources"])
            self.assertIn("vocabulary", data["resources"])
            self.assertEqual(data["resources"]["vocabulary"]["victim_id"], data["resources"]["victim_vocabulary"]["id"])
            self.assertEqual(data["resources"]["vocabulary"]["attacker_id"], data["resources"]["attacker_vocabulary"]["id"])
            self.assertIn("observe_path", data["resources"]["vocabulary"]["safe_mutation"])
            encoded = json.dumps(data, ensure_ascii=False).lower()
            self.assertNotIn("password", encoded)
            self.assertNotIn("bearer ", encoded)


if __name__ == "__main__":
    unittest.main()
