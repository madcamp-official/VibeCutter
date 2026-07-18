from __future__ import annotations

import unittest

from core.redaction import redact


class RedactionTests(unittest.TestCase):
    def test_redacts_jsessionid(self) -> None:
        out = redact("Cookie: JSESSIONID=ABCDEF123456; Path=/")
        self.assertIn("JSESSIONID=<redacted>", out)
        self.assertNotIn("ABCDEF123456", out)

    def test_redacts_bearer_token(self) -> None:
        out = redact("Authorization: Bearer abc.def-123_XYZ")
        self.assertIn("Bearer <redacted>", out)
        self.assertNotIn("abc.def-123_XYZ", out)

    def test_redacts_password_field(self) -> None:
        out = redact('{"password": "hunter2", "matchingPassword": "hunter2"}')
        self.assertNotIn("hunter2", out)
        self.assertIn("<redacted>", out)

    def test_redacts_bare_jwt_without_bearer_prefix(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        out = redact(f"session token in log: {jwt}")
        self.assertNotIn(jwt, out)
        self.assertIn("<redacted-jwt>", out)

    def test_idempotent(self) -> None:
        text = 'JSESSIONID=abc; Authorization: Bearer tok123; "password": "secret"'
        once = redact(text)
        twice = redact(once)
        self.assertEqual(once, twice)

    def test_leaves_unrelated_text_untouched(self) -> None:
        out = redact("normal response body with no secrets")
        self.assertEqual(out, "normal response body with no secrets")


if __name__ == "__main__":
    unittest.main()
