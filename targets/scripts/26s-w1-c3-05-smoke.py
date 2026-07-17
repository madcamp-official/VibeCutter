from __future__ import annotations

import json
import urllib.parse
import urllib.request


API_BASE = "http://127.0.0.1:14030/api"
UI_BASE = "http://127.0.0.1:14031"


def request(method: str, url: str, body: dict | None = None, token: str | None = None) -> tuple[int, dict | str]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as response:
        raw = response.read().decode("utf-8")
        try:
            return response.status, json.loads(raw)
        except json.JSONDecodeError:
            return response.status, raw


def require_status(actual: int, expected: int, label: str) -> None:
    if actual != expected:
        raise AssertionError(f"{label}: expected HTTP {expected}, got {actual}")


def main() -> None:
    status, health = request("GET", f"{API_BASE}/health")
    require_status(status, 200, "backend health")
    if health.get("status") != "ok":
        raise AssertionError(f"unexpected health payload: {health}")

    status, login = request(
        "POST",
        f"{API_BASE}/auth/login",
        {"username": "catlover123@example.com", "password": "12345678"},
    )
    require_status(status, 200, "seed user login")
    token = login.get("accessToken")
    if not token:
        raise AssertionError(f"login missing accessToken: {login}")

    status, me = request("GET", f"{API_BASE}/auth/me", token=token)
    require_status(status, 200, "auth me")
    if me.get("username") != "catlover123@example.com":
        raise AssertionError(f"unexpected user payload: {me}")

    status, cats = request("GET", f"{API_BASE}/cats", token=token)
    require_status(status, 200, "cats")
    if len(cats.get("cats", [])) < 3:
        raise AssertionError(f"seed cats missing: {cats}")

    params = urllib.parse.urlencode({"lat": "36.3727", "lng": "127.3602", "radius": "500", "includeUndiscovered": "true"})
    status, actors = request("GET", f"{API_BASE}/map/cat-actors?{params}", token=token)
    require_status(status, 200, "cat actors")
    if not actors.get("cats"):
        raise AssertionError(f"cat actors missing: {actors}")

    status, proxied_health = request("GET", f"{UI_BASE}/api/health")
    require_status(status, 200, "frontend api proxy")
    if proxied_health.get("status") != "ok":
        raise AssertionError(f"unexpected proxied health: {proxied_health}")

    print("26s-w1-c3-05 API smoke passed")


if __name__ == "__main__":
    main()
