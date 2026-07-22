"""Kill switch + egress 동의 제어 tool (10.2절, U3/TEAM_CONTRACT §3A-10).

`vc_pause`/`vc_resume`은 다른 모든 tool의 승인 게이트보다 위에 있는 안전장치라 그 자체는
kill switch 가드(`core.kill_switch.check_not_paused`)를 타지 않는다 — pause된 상태에서
resume을 못 하면 정작 멈춰야 할 때 못 멈추는 역설이 생긴다. 같은 이유로 approval
파라미터도 없다: 언제든 누구나 즉시 멈출 수 있어야 한다.

`vc_consent_llm_egress`는 별개의 게이트다: "코드 일부가 외부 LLM으로 전송되는 것"에 대한
1회 동의를 기록한다(U3). 동의 전에는 LLM 합성/재랭킹 경로가 예외 없이 조용히 휴리스틱/
template로 degrade한다(`mcp_server/tools_repair.py::_get_llm_client`,
`mcp_server/tools_analysis.py::_rerank_hook_from_env`) — 즉 이 tool은 "막는" 게이트가
아니라 "더 잘 하게 해주는" 옵트인이다.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

from core.audit_log import audited
from core.egress_consent import grant_consent, revoke_consent
from core.kill_switch import clear_pause, is_paused, pause_reason, request_pause


class PauseStatus(BaseModel):
    paused: bool
    reason: str | None = None


class EgressConsentStatus(BaseModel):
    granted: bool
    granted_at: str | None = None
    actor: str | None = None


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    @audited
    def vc_pause(reason: str) -> PauseStatus:
        """global pause를 켠다 — 이후 모든 verify/scan/repair/mutation/judge tool 호출이 즉시 거부된다."""
        request_pause(reason)
        return PauseStatus(paused=True, reason=reason)

    @mcp.tool()
    @audited
    def vc_resume() -> PauseStatus:
        """global pause를 해제한다."""
        clear_pause()
        return PauseStatus(paused=is_paused(), reason=pause_reason())

    @mcp.tool()
    @audited
    def vc_consent_llm_egress(granted: bool) -> EgressConsentStatus:
        """"코드 일부(secret 제거)가 AI 모델로 전송돼 우선순위·수정안을 만든다"에 대한 동의를
        기록/철회한다(U3). **한 번만 있으면 된다** — 이미 동의한 상태에서 `granted=True`를
        다시 호출해도 최초 동의 시각은 그대로 유지된다(`vibecutter://consent/llm_egress`
        resource로 현재 상태를 먼저 확인해 중복으로 묻지 않을 수 있다).

        동의 전에는 vc_generate_patch의 LLM 패치 합성과 vc_run_sast/vc_run_sca/
        vc_scan_access_control의 LLM 재랭킹이 **엔드포인트가 없는 것과 동일하게** 조용히
        template/휴리스틱으로 degrade한다 — 예외로 막지 않는다. `granted=False`로 호출하면
        동의를 철회하고 즉시 같은 degrade 상태로 되돌린다.
        """
        from mcp_server.tools_repair import _reset_llm_client_cache

        if granted:
            record = grant_consent()
            _reset_llm_client_cache()
            return EgressConsentStatus(
                granted=True, granted_at=record["granted_at"], actor=record["actor"]
            )
        revoke_consent()
        _reset_llm_client_cache()
        return EgressConsentStatus(granted=False)
