from __future__ import annotations

import json
import urllib.error
import urllib.request


API_BASE = "http://127.0.0.1:14036"
UI_BASE = "http://127.0.0.1:14037"
USER_ID = 900000001
GAME_ID = 900000101


def request(method: str, url: str, body: dict[str, object] | None = None) -> tuple[int, object]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"} if data is not None else {}
    request_obj = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request_obj, timeout=10) as response:
            raw = response.read().decode("utf-8")
            try:
                return response.status, json.loads(raw)
            except json.JSONDecodeError:
                return response.status, raw
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")


def require_status(actual: int, expected: int, label: str) -> None:
    if actual != expected:
        raise AssertionError(f"{label}: expected HTTP {expected}, got {actual}")


def main() -> None:
    status, health = request("GET", f"{API_BASE}/api/health")
    require_status(status, 200, "API health")
    if not isinstance(health, dict) or health.get("status") != "ok":
        raise AssertionError("unexpected API health payload")

    status, saved = request(
        "PUT",
        f"{API_BASE}/api/tiers",
        {"userId": USER_ID, "entries": [{"universeId": GAME_ID, "tier": "A", "position": 0}]},
    )
    require_status(status, 200, "seeded user tier save")
    if not isinstance(saved, dict) or saved.get("ok") is not True or saved.get("saved") != 1:
        raise AssertionError("tier save did not persist exactly one fixture entry")

    status, page = request("GET", f"{UI_BASE}/")
    require_status(status, 200, "frontend root")
    if "root" not in str(page).lower():
        raise AssertionError("frontend root did not return the application document")

    status, proxied = request("GET", f"{UI_BASE}/api/health")
    require_status(status, 200, "frontend API proxy")
    if not isinstance(proxied, dict) or proxied.get("status") != "ok":
        raise AssertionError("frontend API proxy returned unexpected payload")

    print("26s-w1-c3-09 API/UI smoke passed")


if __name__ == "__main__":
    main()
