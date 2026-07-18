from __future__ import annotations

import unittest
from unittest.mock import patch

import httpx

from verifiers.access_control import IdorProbe, _replay_idor


class _Response:
    def __init__(self, status: int, payload: dict[str, object]) -> None:
        self.status_code = status
        self._payload = payload
        self.text = __import__("json").dumps(payload)

    def json(self) -> dict[str, object]:
        return self._payload


class _Client:
    calls: list[tuple[str, str, dict[str, object] | None]] = []

    def __init__(self, **_kwargs) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def post(self, url: str, *, json: dict[str, object] | None = None, headers=None):
        self.calls.append(("POST", url, json))
        if url.endswith("/signup"):
            return _Response(201, {"id": 1 if "owner" in str(json) else 2})
        if url.endswith("/login"):
            return _Response(200, {"access_token": "runtime-only-token"})
        if url.endswith("/workspaces"):
            return _Response(201, {"id": 11 if "owner" in str(json) else 22})
        raise AssertionError(url)

    def get(self, url: str, *, headers=None):
        self.calls.append(("GET", url, None))
        return _Response(200 if url.endswith("/22") else 403, {"name": "attacker"})


class BearerResourceReplayTests(unittest.TestCase):
    def test_login_and_resource_setup_use_only_runtime_credentials(self) -> None:
        probe = IdorProbe(
            base_url="http://127.0.0.1:14011",
            auth_mode="bearer",
            signup_path="/api/v1/auth/signup",
            signup_body_json='{"email":"{email}","password":"{password}","name":"{name}"}',
            login_path="/api/v1/auth/login",
            login_body_json='{"email":"{email}","password":"{password}"}',
            token_key="access_token",
            owner_setup_path="/api/v1/workspaces",
            owner_setup_body_json='{"name":"{marker}"}',
            path_template="/api/v1/workspaces/{id}",
            victim_marker="vcowner1",
            owner_marker="vcattacker1",
        )
        _Client.calls = []
        with patch("verifiers.access_control.httpx.Client", _Client):
            baseline, attack = _replay_idor(probe, max_requests=8)
        self.assertEqual(len(_Client.calls), 8)
        self.assertEqual(baseline["request"]["path"], "/api/v1/workspaces/22")
        self.assertEqual(attack["request"]["path"], "/api/v1/workspaces/11")

    def test_setup_flow_requires_eight_request_budget(self) -> None:
        probe = IdorProbe(
            base_url="http://127.0.0.1:14011", auth_mode="bearer", signup_path="/signup",
            path_template="/workspaces/{id}", victim_marker="owner", owner_marker="attacker",
            login_path="/login", owner_setup_path="/workspaces", owner_setup_body_json='{}',
        )
        with self.assertRaisesRegex(ValueError, "8회 필요"):
            _replay_idor(probe, max_requests=7)


if __name__ == "__main__":
    unittest.main()
