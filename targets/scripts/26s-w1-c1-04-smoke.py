"""Deterministic local smoke check for 26s-w1-c1-04's leaderboard API."""

from __future__ import annotations

import json
from urllib.request import Request, urlopen


BASE_URL = "http://127.0.0.1:14004"


def request(method: str, path: str, payload: dict | None = None) -> tuple[int, object]:
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"} if body is not None else {}
    with urlopen(Request(f"{BASE_URL}{path}", data=body, headers=headers, method=method), timeout=10) as response:
        return response.status, json.loads(response.read().decode())


status, created = request("POST", "/api/scores", {"nickname": "vc-smoke", "clearTimeMs": 12345, "hints": 1})
if status != 201 or created.get("nickname") != "vc-smoke":
    raise SystemExit("score submission failed")

status, leaderboard = request("GET", "/api/leaderboard")
if status != 200 or not any(entry.get("nickname") == "vc-smoke" for entry in leaderboard):
    raise SystemExit("leaderboard retrieval failed")

print("leaderboard smoke passed")
