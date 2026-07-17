from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request


API_BASE = "http://127.0.0.1:14032"
UI_BASE = "http://127.0.0.1:14033"


def request(method: str, url: str, body: dict | None = None) -> tuple[int, dict | str]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"} if body is not None else {}
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
    unique = str(int(time.time()))
    user_id = f"p2{unique[-8:]}"
    nickname = f"p2{unique[-8:]}"
    password = "p2-local-password"

    params = urllib.parse.urlencode({"id": user_id})
    status, check = request("GET", f"{API_BASE}/auth/check-id?{params}")
    require_status(status, 200, "check id")
    if check.get("available") is not True:
        raise AssertionError(f"unexpected check-id payload: {check}")

    status, signup = request(
        "POST",
        f"{API_BASE}/auth/signup",
        {"id": user_id, "pw": password, "nickname": nickname},
    )
    require_status(status, 201, "signup")
    if signup.get("id") != user_id:
        raise AssertionError(f"unexpected signup payload: {signup}")

    status, login = request("POST", f"{API_BASE}/auth/login", {"id": user_id, "pw": password})
    require_status(status, 200, "login")
    if login.get("id") != user_id:
        raise AssertionError(f"unexpected login payload: {login}")

    status, account = request("GET", f"{API_BASE}/account?{params}")
    require_status(status, 200, "account")
    mock_account = account.get("mockAccount", {})
    if mock_account.get("nickname") != nickname or mock_account.get("totalAsset") != 1_000_000:
        raise AssertionError(f"unexpected account payload: {account}")

    status, stocks = request("GET", f"{API_BASE}/stock-list")
    require_status(status, 200, "stock list")
    if len(stocks.get("stocks", [])) < 10:
        raise AssertionError(f"seed stocks missing: {stocks}")

    status, proxied_check = request("GET", f"{UI_BASE}/api/auth/check-id?{urllib.parse.urlencode({'id': user_id + 'x'})}")
    require_status(status, 200, "frontend api proxy")
    if proxied_check.get("available") is not True:
        raise AssertionError(f"unexpected proxied check payload: {proxied_check}")

    print("26s-w1-c3-06 API smoke passed")


if __name__ == "__main__":
    main()
