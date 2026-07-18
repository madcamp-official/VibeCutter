"""Kill switch 제어 tool (10.2절).

`vc_pause`/`vc_resume`은 다른 모든 tool의 승인 게이트보다 위에 있는 안전장치라 그 자체는
kill switch 가드(`core.kill_switch.check_not_paused`)를 타지 않는다 — pause된 상태에서
resume을 못 하면 정작 멈춰야 할 때 못 멈추는 역설이 생긴다. 같은 이유로 approval
파라미터도 없다: 언제든 누구나 즉시 멈출 수 있어야 한다.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

from core.audit_log import audited
from core.kill_switch import clear_pause, is_paused, pause_reason, request_pause


class PauseStatus(BaseModel):
    paused: bool
    reason: str | None = None


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
