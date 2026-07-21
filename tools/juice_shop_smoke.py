"""Deterministic read-only smoke check for the pinned Juice Shop target."""

from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


BASE_URL = "http://127.0.0.1:14020"


def main() -> int:
    request = Request(
        f"{BASE_URL}/rest/products/search?q=apple",
        headers={"User-Agent": "VibeCutter-JuiceShop-Smoke/1.0"},
    )
    try:
        with urlopen(request, timeout=10) as response:  # nosec B310: fixed loopback URL
            if response.status != 200:
                return 1
            payload = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, OSError, ValueError):
        return 1
    return 0 if isinstance(payload, dict) and payload.get("data") else 1


if __name__ == "__main__":
    raise SystemExit(main())
