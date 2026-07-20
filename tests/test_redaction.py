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

    def test_redacts_express_connect_sid(self) -> None:
        # Express 세션 쿠키: 값에 %(URL 인코딩)·.(서명) 섞임 → 통째로 가려야 한다.
        out = redact("Set-Cookie: connect.sid=s%3Aabc123.DEF456ghi; Path=/; HttpOnly")
        self.assertIn("connect.sid=<redacted>", out)
        self.assertNotIn("s%3Aabc123.DEF456ghi", out)

    def test_redacts_django_sessionid(self) -> None:
        out = redact("Cookie: sessionid=k7x9q2abc123def456; csrftoken=zzz")
        self.assertIn("sessionid=<redacted>", out)
        self.assertNotIn("k7x9q2abc123def456", out)

    def test_django_sessionid_does_not_double_process_jsessionid(self) -> None:
        # \b 가드: JSESSIONID는 전용 규칙만 타고, sessionid 규칙이 그 값을 다시 건드리지 않는다.
        out = redact("JSESSIONID=ABCDEF123456; Path=/")
        self.assertEqual(out, "JSESSIONID=<redacted>; Path=/")

    def test_redacts_opaque_access_token_field(self) -> None:
        # eyJ로 시작 안 하는 opaque access/refresh 토큰(self-signup 흐름).
        out = redact('{"accessToken":"a1b2c3d4e5opaque","refreshToken":"r9s8t7opaque"}')
        self.assertNotIn("a1b2c3d4e5opaque", out)
        self.assertNotIn("r9s8t7opaque", out)
        self.assertIn("<redacted>", out)

    def test_redacts_bare_token_field(self) -> None:
        out = redact('{"token": "plainOpaqueToken123"}')
        self.assertNotIn("plainOpaqueToken123", out)
        self.assertIn("<redacted>", out)

    def test_token_field_does_not_over_match_other_identifiers(self) -> None:
        # csrf_token의 꼬리 token은 \b가 막아 값이 그대로 남아야 한다(요청 범위 밖).
        out = redact('{"csrf_token": "keepThisValue"}')
        self.assertIn("keepThisValue", out)

    def test_idempotent(self) -> None:
        text = (
            'JSESSIONID=abc; connect.sid=s%3Axyz.sig; sessionid=django123; '
            'Authorization: Bearer tok123; "password": "secret"; "accessToken": "opaque1"'
        )
        once = redact(text)
        twice = redact(once)
        self.assertEqual(once, twice)

    def test_leaves_unrelated_text_untouched(self) -> None:
        out = redact("normal response body with no secrets")
        self.assertEqual(out, "normal response body with no secrets")


if __name__ == "__main__":
    unittest.main()
