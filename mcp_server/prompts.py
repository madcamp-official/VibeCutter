"""MCP Prompts (6.5절): `audit_local_target`.

Prompt는 tool이 아니다 — 상태 머신을 대신 실행하는 코드가 아니라, Host(LLM)에게 이번
target 감사에서 어떤 순서로 어떤 tool을 부르고 언제 사용자 승인을 받아야 하는지
안내하는 메시지를 반환한다. 승인 게이트(`vc_apply_patch`의 `confirmed`), 재시도 상한
(`core.planner.enforce_retry_budget`), kill switch(`core.kill_switch`)는 이 프롬프트의
지시를 신뢰하지 않고 각 tool이 코드 레벨에서 이미 강제한다 — Host가 이 안내를 잊거나
무시해도 안전 장치는 그대로 동작한다. 프롬프트는 딱 한 곳, "무엇을 언제 부를지"만
안내한다.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.prompts import base

_STEPS = """target_id={target_id!r}에 대한 전체 보안 감사를 시작한다. 아래 순서를 지켜라:

1. vc_register_target / vc_check_readiness로 target이 등록·준비됐는지 확인한다.
   등록되지 않은 target_id는 정책 계층(policies/scope.yaml)이 모든 후속 tool에서
   자동으로 거부하니, 먼저 vibecutter://policies/scope resource로 허용된 target인지
   확인해도 좋다.
2. vc_build_target → vc_start_target으로 격리 환경에서 기동한다.
3. candidate를 만든다: vc_scan_access_control(IDOR/BOLA — attack-surface 프리필터를
   P2 provisioning과 결합해 검증 가능한 candidate를 만든다) / vc_run_sast / vc_run_sca를
   호출한다. 셋 다 target이 READY 상태여도 바로 부를 수 있다(내부적으로
   MAPPING→CANDIDATE_SCAN을 자동으로 거친다). vc_map_routes / vc_map_roles /
   vc_index_code / vc_run_secret_scan / vc_browser_crawl은 아직 구현되지 않았으니
   부르지 않는다. vc_scan_access_control이 candidate 없이 `blocked` 사유만 반환하면
   (예: provisioning 미비) 사용자에게 그 사유를 보고하고 다음 target으로 넘어간다 —
   억지로 candidate를 만들어내지 않는다.
4. 각 candidate를 vc_verify_access_control / vc_verify_injection / vc_verify_xss 중
   맞는 것으로 approved=True를 명시해 실제 재현 검증한다.
5. verified finding마다 vc_localize_root_cause → vc_generate_patch를 호출한다.
6. **patch diff를 사용자에게 보여주고 명시적 승인을 받은 뒤에만** vc_apply_patch를
   confirmed=True로 호출한다 — 절대 임의로 적용하지 않는다.
7. vc_build_and_test → vc_replay_attack → vc_validate_regression을 모두 실행해 verdict를 낸다.
8. verdict가 RETRY면 5번으로 돌아가 다시 시도한다. **재시도는 vc_generate_patch가 내부
   적으로 최대 3회까지만 허용하며, 초과하면 자동으로 Finding을 human review로 넘기고
   거부한다** — 이 시점부터는 재시도를 강행하지 말고 사용자에게 보고한다.
9. vc_generate_report로 최종 리포트를 만든다.

사용자가 중단을 요청하면 즉시 vc_pause를 호출하고 진행 중인 모든 tool 호출을 멈춰라.
target 밖 IP/URL이나 정책에 없는 target은 절대 다루지 않는다 — 이건 안내가 아니라
정책 계층이 이미 강제하는 절대 원칙이다."""


def register(mcp: FastMCP) -> None:
    @mcp.prompt()
    def audit_local_target(target_id: str) -> list[base.Message]:
        """승인된 target의 전체 탐지·검증 워크플로(6.5절)."""
        return [base.UserMessage(_STEPS.format(target_id=target_id))]
