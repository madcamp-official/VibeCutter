import sys
from pathlib import Path

# `python mcp_server/server.py`로 직접 실행하면 Python이 이 파일의 디렉터리(mcp_server/)만
# sys.path에 넣고 저장소 루트는 넣지 않아 `core`/`contracts` import가 깨진다. MCP Host가
# 보통 이 파일을 `python mcp_server/server.py` 형태로 subprocess 실행하므로, 여기서 저장소
# 루트를 명시적으로 추가해 `python -m mcp_server.server`로 실행하지 않아도 항상 동작하게 한다.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from mcp.server.fastmcp import FastMCP  # noqa: E402

from core.audit_log import audited  # noqa: E402
from mcp_server import (  # noqa: E402
    prompts,
    resources,
    tools_analysis,
    tools_control,
    tools_inventory,
    tools_repair,
)

_INSTRUCTIONS = """VibeCutter: 사용자가 소유·승인한 로컬/격리 웹앱을 감사(취약점 재현)·패치·
재검증하는 보안 에이전트 도구. 사용자가 "이 프로젝트/앱 검사해줘"처럼 한 문장으로만 요청해도,
아래 순서를 알아서 따라간다 — 레포에서 스스로 알아낼 수 있는 값은 되묻지 않고, 정말 필요한
승인만 예/아니오로 받는다(SKILL.md "표준 절차"/"질문 원칙"의 요약. 전체는 `register_local_project`
/`audit_local_target` MCP Prompt에도 동일하게 있다):

1. target_id가 없는 새 프로젝트면 vc_scaffold_manifest(source_path)로 build/start/stop/reset·
   포트·adapter 초안과 근거를 감지한다 → raw argv를 그대로 보여주지 말고 "앱을 검사하려면 평소
   시작 명령을 실행해도 될까요? [네/아니오] (자세히 보기)"처럼 쉬운 말로 승인만 구한 뒤
   vc_register_local_target(confirmed=True)로 등록한다. 이미 등록된 target이면 건너뛴다.
2. vc_check_readiness → vc_build_target → vc_start_target으로 격리 환경에서 기동한다.
3. 첫 LLM 호출 전 vibecutter://consent/llm_egress를 확인한다. 미동의면
   vc_consent_llm_egress(granted=True/False)로 1회만 묻는다 — 거부해도 감사는 막히지 않고
   휴리스틱/template로 계속된다.
4. vc_scan_access_control / vc_run_sast / vc_run_sca로 candidate를 만들고, 후보마다
   vc_materialize_worker_run → 맞는 검증 tool(vc_verify_access_control /
   vc_verify_mutation_access_control / vc_verify_injection / vc_verify_xss, approved=True)로
   실제 재현한다.
5. verified finding마다 vc_localize_root_cause → vc_generate_patch → "위 계획대로 고쳐도
   될까요? [네/아니오] (바뀌는 코드 보기)"처럼 쉬운 승인(diff는 요청 시에만 노출) → 승인 후
   vc_apply_patch(confirmed=True) → vc_resume_audit로 6게이트(build/attack/positive_test/
   regression/static/scope) 재검증까지 마친다. verdict가 RETRY면 자동으로 최대 3회까지
   재시도하고, 넘기면 human_review로 보고한다.
6. 채팅 보고는 항상 **①발견한 위험 ②수정 계획 ③(승인 시) 수정 결과** 딱 3항목만, 전부
   앱·데이터의 쉬운 말로 한다. CWE/OWASP 코드·게이트별 개별 판정·evidence ID·재시도 횟수는
   사용자가 "자세히 보여줘"라고 요청할 때만 보여준다.

이 서버가 프롬프트를 신뢰하지 않고 코드로 강제하는 것: 등록된 target 밖 URL/IP는 애초에
표현 불가(loopback만), confirmed=True 없는 patch 적용 불가, verified 판정은 evidence 기반
judge만 내림(LLM 서술만으로는 안 바뀜), patch는 원본이 아니라 run별 격리 worktree에만 적용,
재시도는 3회 상한, 사용자가 중단을 요청하면 vc_pause로 즉시 멈춘다. 자세한 안전 원칙은
SECURITY_POLICY.md/SKILL.md 참고."""

mcp = FastMCP("vibecutter", instructions=_INSTRUCTIONS)


@mcp.tool()
@audited
def vc_ping() -> str:
    """stdio 연결 스모크 테스트용."""
    return "pong"


resources.register(mcp)
tools_inventory.register(mcp)
tools_analysis.register(mcp)
tools_repair.register(mcp)
tools_control.register(mcp)
prompts.register(mcp)

if __name__ == "__main__":
    mcp.run(transport="stdio")
