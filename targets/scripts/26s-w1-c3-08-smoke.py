from __future__ import annotations

import json
import urllib.error
import urllib.request


API_BASE = "http://127.0.0.1:14034"
UI_BASE = "http://127.0.0.1:14035"


def request(method: str, url: str) -> tuple[int, dict | str]:
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            raw = response.read().decode("utf-8")
            try:
                return response.status, json.loads(raw)
            except json.JSONDecodeError:
                return response.status, raw
    except urllib.error.HTTPError as error:
        raw = error.read().decode("utf-8")
        try:
            return error.code, json.loads(raw)
        except json.JSONDecodeError:
            return error.code, raw


def require_status(actual: int, expected: int, label: str) -> None:
    if actual != expected:
        raise AssertionError(f"{label}: expected HTTP {expected}, got {actual}")


def main() -> None:
    status, health = request("GET", f"{API_BASE}/api/health")
    require_status(status, 200, "api health")
    if health.get("ok") is not True:
        raise AssertionError(f"unexpected health payload: {health}")

    status, server_time = request("GET", f"{API_BASE}/api/time")
    require_status(status, 200, "api time")
    if "serverNow" not in server_time or "defaultScheduledAt" not in server_time:
        raise AssertionError(f"unexpected time payload: {server_time}")

    status, protected = request("GET", f"{API_BASE}/api/messages/sent")
    require_status(status, 401, "unauthenticated messages boundary")
    if not isinstance(protected, dict) or "error" not in protected:
        raise AssertionError(f"unexpected protected payload: {protected}")

    status, login_page = request("GET", f"{UI_BASE}/login")
    require_status(status, 200, "web login page")
    if "매아리" not in str(login_page):
        raise AssertionError("login page did not render expected app text")

    status, proxied_health = request("GET", f"{UI_BASE}/api/health")
    require_status(status, 200, "web api proxy")
    if proxied_health.get("ok") is not True:
        raise AssertionError(f"unexpected proxied health payload: {proxied_health}")

    print("26s-w1-c3-08 health smoke passed")


if __name__ == "__main__":
    main()
