"""MCP Prompts (6.5절): `register_local_project` + `audit_local_target` + 단계별 4종.

Prompt는 tool이 아니다 — 상태 머신을 대신 실행하는 코드가 아니라, Host(LLM)에게 이번
target 감사에서 어떤 순서로 어떤 tool을 부르고 언제 사용자 승인을 받아야 하는지
안내하는 메시지를 반환한다. 승인 게이트(`vc_apply_patch`의 `confirmed`), 재시도 상한
(`core.planner.enforce_retry_budget`), kill switch(`core.kill_switch`)는 이 프롬프트의
지시를 신뢰하지 않고 각 tool이 코드 레벨에서 이미 강제한다 — Host가 이 안내를 잊거나
무시해도 안전 장치는 그대로 동작한다. 프롬프트는 딱 한 곳, "무엇을 언제 부를지"만
안내한다.

`register_local_project`는 **아직 target_id가 없는** 새 로컬 프로젝트를 스캐폴딩(U1
`vc_scaffold_manifest`)→등록(`vc_register_local_target`)까지 안내한다. `audit_local_target`은
(이미 등록된) target의 전체 탐지·검증 흐름 하나를 안내하고, 나머지 4종(6.5절 표)은 그
흐름의 단계별 조각을 별도로 진입할 수 있게 한다: `verify_candidate`(특정 후보 최소 재현),
`repair_verified_finding`(root cause→patch), `retest_patch`(패치 후 공격+정상기능 회귀),
`triage_report`(발견 우선순위 정리). 모든 프롬프트는 **실제 등록된 tool 이름만** 참조한다
— 구현되지 않은 tool(vc_map_routes/vc_index_code/vc_browser_crawl 등)은 안내하지 않는다.

**"번역-not-dump" 승인 원칙(C2)**: 등록 argv와 patch diff, 두 승인 지점 모두 raw 산출물을
그대로 사용자에게 던지지 않는다 — 비전문가는 raw argv/diff를 의미 있게 승인할 수 없다(숨기면
blind 승인, 그대로 보이면 이해 못 함). 대신 **쉬운 말 설명**으로 예/아니오를 묻고, raw
산출물은 사용자가 명시적으로 "자세히 보기"/"코드 보기"를 요청할 때만 보여준다(SKILL.md
"출력 형식"의 ②수정 계획과 같은 지점). raw 값을 안 보여줘도 각 tool 호출 자체가
`@audited`라 감사 기록에는 항상 남는다 — "쉬운 말 승인"은 감사 가능성을 줄이지 않는다.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.prompts import base

_REGISTER_LOCAL_PROJECT = """source_path={source_path!r}에 있는, **아직 등록되지 않은** 로컬
프로젝트를 스캐폴딩→쉬운 말 승인→등록까지 안내한다. 이미 target_id가 있는(등록된) target을
감사하려면 이 프롬프트 대신 audit_local_target(target_id)을 쓴다:

1. vc_scaffold_manifest(source_path)로 build/start/stop/reset·포트·adapter 초안과 "어느
   파일에서 뽑았는지" 근거를 만든다. `manifest`가 None이면(확신 있는 초안을 못 만들었으면)
   `warnings`를 쉬운 말로 설명하고 부족한 값을 사용자에게 직접 물어본다 — 추측으로 채우지
   않는다.
2. **raw argv를 그대로 보여주지 말고 쉬운 말로 승인을 구한다.** 예: "앱을 검사하려면 앱을
   먼저 켜야 해요 — 평소 시작 명령을 그대로 실행해도 될까요? [네/아니오] (자세히 보기)".
   "자세히 보기"를 요청할 때만 `manifest.commands`의 실제 argv를 보여준다.
3. 승인을 받으면 vc_register_local_target(manifest, source_path, confirmed=True)를
   호출한다. `blockers`가 있으면(git 저장소 아님, built-in target_id와 충돌 등) 그 사유를
   쉬운 말로 설명하고 등록하지 않는다 — 임의로 우회하지 않는다. `warnings`(예: 포트 추측)는
   짧게 알리되 등록을 막지는 않는다.
4. 등록되면(`registered=True`) audit_local_target(target_id) 프롬프트로 이어가 실제 감사를
   시작한다.

raw argv를 사용자에게 안 보여줘도 vc_register_local_target 호출 자체가 감사 기록(audit log)에
남는다 — "쉬운 말 승인"은 감사 가능성을 줄이지 않는다."""


_STEPS = """target_id={target_id!r}에 대한 전체 보안 감사를 시작한다.

target_id가 아직 없는 새 프로젝트라면(사용자 소유 로컬 프로젝트를 처음 검사하는 경우) 이
프롬프트 대신 register_local_project(source_path)로 먼저 등록한다.

**시작 전에** vibecutter://consent/llm_egress resource로 LLM egress 동의 상태를 확인한다.
`granted`가 아직 false면, 스캔·패치 단계에서 코드 일부(secret 제거)가 우선순위 판단·수정안
생성을 위해 외부 AI 모델로 전송될 수 있음을 사용자에게 알리고 vc_consent_llm_egress(granted=
True/False)로 답을 받아 기록한다 — 이미 동의(또는 거부)한 적이 있으면 다시 묻지 않는다.
`False`를 선택해도 감사는 막히지 않는다: LLM 없이 휴리스틱 정렬·기본 패치로 계속 진행된다.

아래 순서를 지켜라:

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
4. 3번의 scan Run은 여러 후보를 모으는 부모일 뿐이다. **후보 하나당 하나의 검증 흐름만
   담을 수 있으므로**(검증된 Run은 되돌아갈 수 없다), 각 후보를 검증하기 전에
   vc_materialize_worker_run(scan_run_id, candidate_id)로 그 후보 전용 worker Run을 만든다.
   반환된 worker_run_id / worker_candidate_id를 이후 5~8번에서 쓴다. 원본 scan 후보는
   그대로 두고, 여러 후보는 **한 번에 하나씩 순차로** 처리한다(대상 앱이 고정 포트를 써서
   동시에 여러 patched 인스턴스를 띄울 수 없다).
5. 그 worker Run에서 후보를 vc_verify_access_control(읽기 IDOR) /
   vc_verify_mutation_access_control(쓰기 IDOR — 공격자가 피해자 자원을 실제로 바꿨는지
   before/after로 판정) / vc_verify_injection / vc_verify_xss 중 맞는 것으로 approved=True를
   명시해(run_id=worker_run_id, candidate_id=worker_candidate_id) 실제 재현 검증한다.
6. verified finding마다 vc_localize_root_cause → vc_generate_patch를 호출한다.
7. **patch diff를 그대로 보여주지 말고 쉬운 말로 승인을 구한다** — "위 계획대로 고쳐도
   될까요? [네/아니오] (바뀌는 코드 보기)"처럼(raw diff는 사용자가 "코드 보기"를 요청할
   때만). 승인받은 뒤에만 vc_apply_patch를 confirmed=True로 호출한다 — 절대 임의로
   적용하지 않는다.
8. 승인 후 vc_resume_audit(worker_run_id) 하나로 이어간다 — 내부에서
   vc_build_and_test → vc_replay_attack → vc_validate_regression으로 verdict를 내고,
   reset으로 patched overlay를 지우기 전에 diff를 .vibecutter/runs/<run_id>/security-fix.patch로
   먼저 보존한다(vc_export_patch). 세 게이트를 개별 tool로 직접 불러도 되지만, 그 경우
   reset 전에 vc_export_patch(worker_run_id)를 반드시 별도로 호출해야 patch가 남는다.
9. verdict가 RETRY면 6번으로 돌아가 다시 시도한다. **재시도는 vc_generate_patch가 내부
   적으로 최대 3회까지만 허용하며, 초과하면 자동으로 Finding을 human review로 넘기고
   거부한다** — 이 시점부터는 재시도를 강행하지 말고 사용자에게 보고한다.
10. 다음 후보가 있으면 4번으로 돌아가 새 worker Run을 만든다(scan Run을 재사용하지 않는다).
11. vc_generate_report로 최종 리포트를 만든다.

사용자가 중단을 요청하면 즉시 vc_pause를 호출하고 진행 중인 모든 tool 호출을 멈춰라.
target 밖 IP/URL이나 정책에 없는 target은 절대 다루지 않는다 — 이건 안내가 아니라
정책 계층이 이미 강제하는 절대 원칙이다."""


_VERIFY_CANDIDATE = """scan Run scan_run_id={scan_run_id!r}에서 나온 후보 candidate_id={candidate_id!r}
하나를 최소 재현으로 검증한다. 후보 수집(scan) 이후 단계만 다룬다:

1. vc_materialize_worker_run(scan_run_id, candidate_id)로 이 후보 전용 worker Run을 만든다.
   반환된 worker_run_id / worker_candidate_id를 이후 단계에서 쓴다. 원본 scan 후보는 건드리지
   않는다(검증된 Run은 되돌릴 수 없어 후보 하나당 worker Run 하나가 필요하다).
2. 후보의 취약점군에 맞는 검증 tool 하나만 고른다:
   - 읽기 IDOR/BOLA → vc_verify_access_control
   - 쓰기 IDOR(공격자가 피해자 자원을 실제로 바꿨는지 before/after 판정) →
     vc_verify_mutation_access_control
   - Injection → vc_verify_injection
   - XSS → vc_verify_xss
   run_id=worker_run_id, candidate_id=worker_candidate_id, approved=True를 명시해 호출한다.
3. 검증 결과가 verified면 그 finding은 실재하는 취약점이다 — 후속 수리는
   repair_verified_finding 프롬프트로 이어간다. rejected면 증거와 함께 그대로 보고하고
   억지로 재검증하지 않는다.

여러 후보는 **한 번에 하나씩 순차로** 처리한다(대상 앱이 고정 포트라 patched 인스턴스를
동시에 띄울 수 없다). target 밖 IP/URL은 정책 계층이 이미 거부하니 임의로 우회하지 않는다."""


_REPAIR_VERIFIED_FINDING = """검증된(verified) finding finding_id={finding_id!r}의 root cause를 찾고 패치를
제안한다. 이미 vc_verify_* 로 verified된 finding에만 쓴다:

(이 흐름을 audit_local_target 없이 단독으로 시작했다면, 2번 전에 vibecutter://consent/
llm_egress로 LLM egress 동의 상태를 확인한다 — 아직 미동의면 vc_consent_llm_egress로 먼저
묻는다. 동의 없이 진행해도 막히지 않고 template 기반 패치로 대체된다.)

1. vc_localize_root_cause(finding_id)로 결함 위치·원인을 특정한다.
2. vc_generate_patch(finding_id)로 최소 변경 패치를 생성한다(1의 결과를 저장해 재사용한다).
3. 생성된 patch를 **raw diff로 보여주지 말고 쉬운 말로 요약해 승인을 구한다** — "위
   계획대로 고쳐도 될까요? [네/아니오] (바뀌는 코드 보기)"처럼. "코드 보기"를 요청할
   때만 실제 diff를 보여준다.
4. 승인을 받은 뒤에만 vc_apply_patch(patch_id, confirmed=True)를 호출한다 — confirmed 없이는
   tool이 코드 레벨에서 거부한다. 절대 임의로 적용하지 않는다. raw diff를 안 보여줘도
   vc_apply_patch 호출 자체가 감사 기록(audit log)에 남는다.
5. 적용 후에는 retest_patch 프롬프트로 검증(공격 재현 + 정상 기능 회귀)을 이어간다 —
   vc_resume_audit(run_id) 하나로 6게이트+patch 보존+정리까지 한 번에 처리할 수도 있다.

**패치 재시도는 최대 3회까지만 허용되고**(vc_generate_patch 내부 강제), 초과하면 자동으로
Finding이 human review로 넘어간다 — 그 시점부터는 재시도를 강행하지 말고 사용자에게 보고한다."""


_RETEST_PATCH = """적용된 패치 patch_id={patch_id!r}가 취약점을 실제로 막았고 정상 기능을 깨지 않았는지
6게이트로 재검증한다. vc_apply_patch 이후에 쓴다. 가장 간단한 길은 vc_resume_audit(run_id)
하나로 아래 1~3번 + patch 보존(vc_export_patch) + reset을 한 번에 처리하는 것이다. 개별
tool로 직접 하려면:

1. vc_build_and_test(patch_id) — 패치된 코드가 빌드/기존 테스트를 통과하는지.
2. vc_replay_attack(patch_id) — 검증 때 성공했던 공격이 이제 실패하는지(취약점 차단 확인).
3. vc_validate_regression(patch_id) — 정상 기능이 유지되는지(overblocking/기능 손상 방지).
   세 tool의 결과가 합쳐져 최종 verdict가 난다.
4. verdict가 확정되면(FIXED든 RETRY든) **reset으로 patched overlay를 지우기 전에**
   vc_export_patch(run_id)로 diff를 .vibecutter/runs/<run_id>/security-fix.patch에 보존한다
   — 안 하면 reset 후 patch를 되찾을 방법이 없다.
5. verdict가 FIXED면 완료다. RETRY면 repair_verified_finding 프롬프트로 돌아가 다시
   패치한다 — 단 **재시도 상한 3회**를 넘기면 자동으로 human review로 넘어가니 강행하지 않는다.
6. verdict가 HUMAN_REVIEW면 자동 수리 범위를 벗어난 것이다 — 사용자에게 증거와 함께 보고한다.

셋 중 하나라도 건너뛰면 verdict가 불완전하다 — 세 tool을 모두 실행한다."""


_TRIAGE_REPORT = """Run run_id={run_id!r}에서 나온 발견들을 영향·재현성·수리 난이도 기준으로 정리하고
우선순위를 매긴다. 검증/수리가 끝난 뒤 보고 단계에 쓴다:

1. vibecutter://runs/{{run_id}}/state resource로 Run의 현재 상태를, vibecutter://runs/{{run_id}}/evidence
   resource로 수집된 관측/증거를 읽는다(이 둘은 저장된 실제 값이다 — 추측하지 않는다).
2. 각 finding을 세 축으로 정리한다:
   - 영향: 무엇이 노출/변경되는가(읽기 IDOR < 쓰기 IDOR/Injection 순으로 대체로 위험).
   - 재현성: verified 증거(evidence_ids)가 실재하는가 — 증거 없는 항목은 후순위로 내린다.
   - 수리 난이도: FIXED로 끝났는지, RETRY/HUMAN_REVIEW로 남았는지.
3. vc_generate_report(run_id)로 최종 리포트를 생성한다 — 위 우선순위를 사람이 읽을 수 있게
   요약한다. GitHub code scanning 등 표준 도구에 올리려면 vc_export_sarif(run_id)로 같은
   데이터를 SARIF 2.1.0으로도 낼 수 있다(둘 다 같은 조회 결과를 쓰므로 내용이 갈리지 않는다).
4. verified되지 않은 candidate나 증거 없는 항목을 "확정 취약점"으로 올리지 않는다 —
   evidence-first 원칙을 지킨다."""


def register(mcp: FastMCP) -> None:
    @mcp.prompt()
    def register_local_project(source_path: str) -> list[base.Message]:
        """아직 등록 안 된 로컬 프로젝트를 스캐폴딩→쉬운 말 승인→등록까지 안내한다(U1/C2)."""
        return [base.UserMessage(_REGISTER_LOCAL_PROJECT.format(source_path=source_path))]

    @mcp.prompt()
    def audit_local_target(target_id: str) -> list[base.Message]:
        """승인된 target의 전체 탐지·검증 워크플로(6.5절)."""
        return [base.UserMessage(_STEPS.format(target_id=target_id))]

    @mcp.prompt()
    def verify_candidate(scan_run_id: str, candidate_id: str) -> list[base.Message]:
        """특정 후보 하나를 worker Run으로 materialize해 최소 재현 검증한다(6.5절)."""
        return [
            base.UserMessage(
                _VERIFY_CANDIDATE.format(scan_run_id=scan_run_id, candidate_id=candidate_id)
            )
        ]

    @mcp.prompt()
    def repair_verified_finding(finding_id: str) -> list[base.Message]:
        """검증된 finding의 root cause 특정 → 패치 생성 → 승인 후 적용(6.5절)."""
        return [base.UserMessage(_REPAIR_VERIFIED_FINDING.format(finding_id=finding_id))]

    @mcp.prompt()
    def retest_patch(patch_id: str) -> list[base.Message]:
        """적용된 패치를 공격 재현 + 정상 기능 회귀로 재검증한다(6.5절)."""
        return [base.UserMessage(_RETEST_PATCH.format(patch_id=patch_id))]

    @mcp.prompt()
    def triage_report(run_id: str) -> list[base.Message]:
        """Run의 발견을 영향·재현성·난이도로 우선순위화해 리포트한다(6.5절)."""
        return [base.UserMessage(_TRIAGE_REPORT.format(run_id=run_id))]
