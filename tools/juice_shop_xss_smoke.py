"""Read-only runtime smoke for the Juice Shop reflected-XSS search route.

This is deliberately a liveness/regression check, not a vulnerability verdict.
The Playwright XSS verifier owns the benign-marker execution check.
"""

from __future__ import annotations

from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


BASE_URL = "http://127.0.0.1:14020"


def _get(path: str) -> tuple[int, bytes]:
    request = Request(
        f"{BASE_URL}{path}",
        headers={"User-Agent": "VibeCutter-JuiceShop-XSS-Smoke/1.0"},
    )
    with urlopen(request, timeout=10) as response:  # nosec B310: fixed loopback URL
        return response.status, response.read()


def main() -> int:
    try:
        api_status, api_body = _get("/rest/products/search?q=apple")
        shell_status, shell_body = _get("/")
    except (HTTPError, URLError, TimeoutError, OSError):
        return 1

    # The fragment route (/#/search?q=...) is browser-side, so the server sees
    # only the SPA shell.  Browser execution is intentionally left to xss.py.
    api_ok = api_status == 200 and b'"data"' in api_body
    shell_ok = shell_status == 200 and b"<app-root" in shell_body
    return 0 if api_ok and shell_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
