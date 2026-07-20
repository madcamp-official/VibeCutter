"""Evidence artifact 저장 전 secret redaction.

cowork_rule.md 4절: "secret, token, 개인정보는 evidence, report, dataset 저장 전에
제거한다". D1-P3.md 구멍 ②(secret redaction이 어디에도 없어 JWT가 artifact에 평문으로
남는 것이 재현됨)에 대한 저장 계층 고정 방어 — `core.evidence_store.write_artifact()`가
이 모듈을 거친다.

패턴은 P3의 `verifiers/access_control.py`가 임시로 걸어둔 규칙(JSESSIONID/Bearer
토큰/password)을 저장 계층으로 승격한 것이다. 여기서 한 번 더 걸리므로 verifier 쪽의
임시 호출은 제거해도 안전하다(중복 적용해도 이미 `<redacted>`로 바뀐 텍스트는 패턴이
다시 매치하지 않아 idempotent).
"""

from __future__ import annotations

import re

_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    # 세션 쿠키(프레임워크별 이름): 값은 `;`/공백/따옴표 전까지. connect.sid/sessionid는
    # 값에 `%`(URL 인코딩), `.`(서명 구분자)이 섞여 있어 `[^;\s"]+`로 통째로 잡는다.
    (re.compile(r"(JSESSIONID=)[^;\s\"]+"), r"\1<redacted>"),
    (re.compile(r"(connect\.sid=)[^;\s\"]+"), r"\1<redacted>"),  # Express (cookie-session/express-session)
    # Django `sessionid`. `\b`가 앞을 막아 `JSESSIONID=`의 꼬리(...SESSIONID=)를 다시 잡지
    # 않는다(J가 word char라 그 뒤 S에는 word boundary가 없음) — JSESSIONID는 위 규칙 전담.
    (re.compile(r"(\bsessionid=)[^;\s\"]+", re.IGNORECASE), r"\1<redacted>"),
    (re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]+"), r"\1<redacted>"),
    (re.compile(r'("?(?:password|matchingPassword)"?\s*[=:]\s*"?)[^&"\s,}]+'), r"\1<redacted>"),
    # JSON/폼의 opaque 토큰 필드(eyJ로 시작 안 하는 self-signup access/refresh 토큰 등).
    # `\b`가 `csrf_token`처럼 다른 식별자 꼬리의 `token`을 잡지 않게 막는다(앞 `_`가 word char).
    (
        re.compile(
            r'("?\b(?:accessToken|access_token|refreshToken|refresh_token|token)"?\s*[=:]\s*"?)[^&"\s,}]+',
            re.IGNORECASE,
        ),
        r"\1<redacted>",
    ),
    # Authorization 헤더 없이 body/log에 그냥 박혀 있는 JWT(header.payload.signature)도 잡는다.
    (re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"), "<redacted-jwt>"),
]


def redact(text: str) -> str:
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text
