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

from pydantic import BaseModel, Field

from contracts.schemas import Candidate

# 부록 A `vc_verify_access_control` inputSchema가 명시한 상한.
# 10.2절 "Rate/impact limit: 요청 수, concurrency, body size" 통제에 해당한다.
MAX_REQUESTS_MIN = 1
MAX_REQUESTS_MAX = 20
MAX_REQUESTS_DEFAULT = 10


class VerifierOutput(BaseModel):
    """부록 A outputSchema와 동일한 3필드.

    `evidence_ids`에 기본값을 두지 않는다 — verified=false인 경우에도 부록 A는 이 필드를
    required로 명시하므로(빈 배열이라도 명시적으로), 구현부가 항상 채우도록 강제한다.

    **evidence_ids는 반드시 evidence_store에 실제로 기록된 Observation의 id여야 한다.**
    verifier가 먼저 `evidence_store.write_artifact(...)`로 Observation을 만들고, 그
    `.id`만 여기에 담는다. 문자열을 지어내면 안 된다 (D1-P3.md 구멍 ① 참고).
    """

    verified: bool
    evidence_ids: list[str]
    reason: str


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
