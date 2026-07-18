"""P3 verifier가 P1에게 제공하는 호출 계약.

`mcp_server/tools_analysis.py`의 `vc_verify_*` tool 본문은 P1이 배선하고(plan.md Day2:
"policy_engine 검사 → VERIFYING 전이 → P3가 구현한 verifier 함수 호출 → evidence_store
기록 → judge 판정"), 그 안에서 호출할 함수의 시그니처를 여기서 고정한다. verifier는 MCP
계층을 import하지 않는다 — 의존 방향은 항상 mcp_server → verifiers 한쪽이다.

7.3절: "Verifier의 목적은 공격 기술을 과시하는 것이 아니라 후보가 실제 보안 영향으로
이어지는지 최소한의 재현 시퀀스로 판정하는 것이다."
"""

from __future__ import annotations

from typing import Protocol

from contracts.schemas import Candidate, VerificationResult

# 부록 A `vc_verify_access_control` inputSchema가 명시한 상한.
# 10.2절 "Rate/impact limit: 요청 수, concurrency, body size" 통제에 해당한다.
MAX_REQUESTS_MIN = 1
MAX_REQUESTS_MAX = 20
MAX_REQUESTS_DEFAULT = 10

# `VerifierOutput`은 `contracts.schemas.VerificationResult`의 별칭이다. 예전에는 여기서
# 별도 클래스로 정의했는데, `mcp_server/tools_analysis.py`의 `VerifyResult`와 필드가
# 완전히 같은 채로 중복돼 있었다(D1-P3.md 지적, "결정은 P1이 해달라"). P1이 공통 계약으로
# 올렸고, 이 별칭 덕분에 `verifiers/access_control.py`를 포함한 기존 코드는 변경 없이
# `VerifierOutput` 이름 그대로 쓸 수 있다.
VerifierOutput = VerificationResult


class Verifier(Protocol):
    """취약점군별 verifier가 만족해야 하는 시그니처.

    `verifiers/{access_control,xss,injection}.py`가 각각 이 형태의 `verify()`를 노출하고,
    P1의 tool 본문이 candidate.cwe/vuln_class를 보고 알맞은 모듈로 분기한다.

    policy 검사(`require_target_allowed`/`require_host_allowed`)와 상태 전이는 호출자(P1)가
    한다 — verifier는 "이 후보가 실제 보안 영향으로 이어지는가"만 판정한다.
    """

    def verify(
        self,
        run_id: str,
        candidate: Candidate,
        *,
        max_requests: int = MAX_REQUESTS_DEFAULT,
    ) -> VerifierOutput: ...
