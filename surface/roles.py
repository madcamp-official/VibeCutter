"""'현재 인증 사용자' 참조 신호 — IDOR attack-surface 프리필터의 핵심 판정 (7.1절, Day1).

핵심 발견(실측 4개 앱): **id로 자원에 접근하는 handler가 '현재 사용자'를 전혀 참조하지 않으면,
소유권으로 스코프할 방법이 없으니 IDOR 강한 의심**이다.
  - c2-04 `read_words(vocabulary_id, db)` / c1-05 `getProfile(@PathVariable userId)` → 현재사용자 미참조 = 취약
  - c2-05 `get_profile(user=Depends(get_current_user))` / c3-08 `getMessageDetail(userId, ...)` → 현재사용자 참조 = 방어

정밀 인가분석이 아니라 빠른 프리필터다 — recall 우선(의심을 넓게 잡고) 최종 판정은 verifier가 한다.
"""

from __future__ import annotations

import re

# 스택별 '현재 인증 사용자' 관용구. 이 중 하나라도 handler에 있으면 소유권 스코프 가능으로 본다.
_CURRENT_USER_PATTERNS = (
    # Java / Spring
    r"\bauthentication\b",
    r"\bprincipal\b",
    r"@AuthenticationPrincipal",
    r"getCurrentUser",
    r"currentUserId",
    # Python (FastAPI / Flask / Django)
    r"current_user",
    r"get_current_user",
    r"request\.user",
    r"self\.request\.user",
    r"\bg\.user\b",
    # Node / Express
    r"req\.user",
    r"request\.user",
    r"res\.locals\.user",
)
_CU_RE = re.compile("|".join(_CURRENT_USER_PATTERNS), re.IGNORECASE)


def references_current_user(handler_text: str) -> bool:
    """handler 시그니처+본문에 인증 사용자 참조가 있으면 True(=소유권 스코프 가능)."""
    return bool(_CU_RE.search(handler_text))
