from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request


API_BASE = "http://127.0.0.1:14028/api"
UI_BASE = "http://127.0.0.1:14029"
DEVICE_ID = "p2-stockshorts-smoke"


def request(method: str, url: str, body: dict | None = None) -> tuple[int, dict | str]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Content-Type": "application/json",
            "X-Device-Id": DEVICE_ID,
        },
    )
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


def assert_status(actual: int, expected: int, label: str) -> None:
    if actual != expected:
        raise AssertionError(f"{label}: expected HTTP {expected}, got {actual}")


def main() -> None:
    status, device = request("POST", f"{API_BASE}/devices", {})
    assert_status(status, 201, "device registration")
    if not device.get("deviceId"):
        raise AssertionError(f"device registration missing deviceId: {device}")

    query = urllib.parse.quote("028050")
    status, companies = request("GET", f"{API_BASE}/companies?q={query}")
    assert_status(status, 200, "company search")
    company_list = companies.get("companies", [])
    if not company_list:
        raise AssertionError("company search returned no rows")
    company_id = company_list[0]["id"]

    status, subscription = request("POST", f"{API_BASE}/companies/{company_id}/subscriptions", {})
    assert_status(status, 201, "company subscription")
    if subscription.get("companyId") != company_id:
        raise AssertionError(f"unexpected subscription payload: {subscription}")

    status, sectors = request("GET", f"{API_BASE}/sectors")
    assert_status(status, 200, "sector groups")
    if not sectors.get("groups"):
        raise AssertionError("sector groups returned no rows")

    status, proxied_device = request("POST", f"{UI_BASE}/api/devices", {})
    assert_status(status, 201, "frontend api proxy")
    if not proxied_device.get("deviceId"):
        raise AssertionError(f"frontend proxy returned invalid payload: {proxied_device}")

    print("26s-w1-c3-04 API smoke passed")


if __name__ == "__main__":
    main()
