# SECURITY_POLICY — VibeCutter 안전 정책

> 이 문서는 "VibeCutter(MCP 서버)가 사용자 코드·계정·머신에 무엇을 할 수 있고 무엇을 절대
> 하지 않는지"를 한 곳에 정리한다. 인터페이스·계약의 최종 근거는 여전히
> `TEAM_CONTRACT.md`(특히 4절 "안전 불변식")이고, 이 문서는 그 불변식을 **사용자/감사자가
> 읽을 수 있는 말로 풀고, 코드 근거(파일·함수명)를 붙인 것**이다. 여기 적힌 어떤 정책도
> `TEAM_CONTRACT.md` 4절의 불변식을 약화하지 않는다 — 상충하면 코드와 `TEAM_CONTRACT.md`가
> 우선한다.

---

## 1. 이 문서가 다루는 범위

VibeCutter는 사용자가 소유하거나 명시적으로 권한을 받은 **로컬/격리 target**만 다룬다.
아래 정책은 전부 "그 target 하나"를 대상으로 한 동작에 적용된다 — 임의의 외부 서비스나
제3자 시스템은 애초에 입력으로 받지 않는다(2절, 3절).

---

## 2. 승인 모델 — 사용자 승인 없이는 상태를 바꾸는 어떤 동작도 실행되지 않는다

**원칙**: 코드·데이터를 바꾸거나(패치 적용), 외부로 코드 일부를 보내거나(LLM 질의),
사용자 머신에서 새 명령을 실행하는(target 등록·reset) 모든 지점에 **명시적 boolean 승인
파라미터**가 있고, 그 파라미터가 없으면 예외로 거부된다. Host(LLM)가 이 승인을 사용자
확인 없이 자동으로 넘기지 않는 것은 **Host의 책임**이지만, 파라미터 자체가 없으면 아예
실행되지 않는 것은 **코드가 강제**한다.

| 지점 | 승인 파라미터 | 승인 없을 때 | 강제 코드 |
|---|---|---|---|
| 패치를 코드에 적용 | `vc_apply_patch(patch_id, confirmed=True)` | `PermissionError` | `mcp_server/tools_repair.py` — `if not confirmed: raise PermissionError(...)` |
| 새 로컬 프로젝트 등록(argv 실행 허가) | `vc_register_local_target(manifest, source_path, confirmed=True)` | 미리보기만 반환, 아무것도 저장 안 됨 | `mcp_server/tools_inventory.py` |
| target 데이터 초기화 | `vc_reset_target(target_id, approved=True)` | `ApprovalRequired` | `runtime/target_service.py` |
| 취약점 재현 검증(공격 payload 실행) | `vc_verify_access_control` / `vc_verify_mutation_access_control` / `vc_verify_injection` / `vc_verify_xss` 전부 `approved=True` | `PermissionError` | `mcp_server/tools_analysis.py::_prepare_verification` |
| 코드 일부를 외부 LLM으로 전송 | `vc_consent_llm_egress(granted=True)` (1회) | 예외 없이 조용히 휴리스틱/template로 degrade | `core/egress_consent.py` |
| 실행 중인 run 강제 종료·정리 | `vc_kill_run(run_id, approved=True)` | `PermissionError` | `mcp_server/tools_repair.py` |

**자동/배치 실행에도 예외가 없다.** `run_target_audit`(자동 배치 드라이버)조차 patch 적용
직전 `PATCH_PROPOSED` 상태에서 멈추고, `confirmed=True`를 자동으로 대신 넘기지 않는다 —
"완전 자동" 우회 모드는 의도적으로 만들지 않았다(`TEAM_CONTRACT.md` §3A-7/§4).

**등록 승인이 실질적인 이유**: manifest의 `argv`는 그대로
`subprocess.run(argv, shell=False)`로 실행된다. 팀이 관리하는 built-in target은 "저장소에
커밋되고 PR로 리뷰됐다"는 근거로 신뢰했지만, 사용자가 자기 프로젝트를 등록하면 그 근거가
없다 — 그래서 등록 승인 화면은 **argv 전문**을 그대로 보여준다(요약·생략 없음). 이게
prompt injection으로 악성 argv가 끼어드는 confused-deputy 공격의 1차 방어선이다.

**보고 방식(비전문 사용자용)은 별도 계층이다**: 위 표의 raw argv/diff를 사용자에게 그대로
던지지 않고 쉬운 말로 번역해 예/아니오만 묻는 것은 `SKILL.md` "출력 형식"/"질문 원칙"과
`mcp_server/prompts.py`가 정한 **표현 계층**의 문제다 — 이 절의 코드 강제 승인 게이트
자체는 그 표현과 무관하게 항상 동일하게 동작한다.

---

## 3. loopback 불변식 — 등록된 target 밖으로는 구조적으로 나갈 수 없다

두 계층이 함께 강제한다.

**(1) 스키마 계층 — 등록 자체가 불가능**: `TargetManifest.base_url_must_be_loopback_http`
(`runtime/manifest.py`)이 `base_url`을 검증한다.

```python
if parsed.scheme != "http" or parsed.username or parsed.password or parsed.query or parsed.fragment:
    raise ValueError("base_url must be a plain http loopback URL")
if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
    raise ValueError("base_url host must be localhost, 127.0.0.1, or ::1")
if parsed.port is None:
    raise ValueError("base_url must include an explicit port")
```

`http` + `127.0.0.1`/`localhost`/`::1` + 명시적 포트가 아니면 **등록 시점에 거부**된다.
이 검증기는 완화·삭제 대상이 아니다(`TEAM_CONTRACT.md` 안전 불변식 1).

**(2) allowlist 계층 — 등록된 target만, 그 target의 host만**:
`core/policy_engine.py`의 `require_target_allowed`/`require_host_allowed`가 모든 tool
호출 진입점에서 두 번 확인한다 — ① `target_id`가 `policies/scope.yaml`(built-in) 또는
사용자 로컬 레지스트리에 있는가, ② 실제 요청을 보내려는 host가 그 target의
`allowed_hosts`에 있는가. `allowed_hosts`에는 **hostname만** 저장하고 port는 저장하지
않는다 — 실행 목적지 port는 오직 승인된 `base_url`의 명시 port로만 결정되므로, 어떤 tool
입력으로도 loopback의 다른 port를 임의로 고를 수 없다. 위반 시 `PolicyViolation`
(`PermissionError` 하위 클래스)으로 거부되고, 감사 로그에 자동 기록된다(4절 참고).

**결과**: VibeCutter는 외부 IP·도메인을 스캔하거나 공격하지 않는다. 다룰 수 있는 유일한
대상은 사용자가 명시적으로 등록을 승인한, loopback에서만 도는 target뿐이다.

---

## 4. argv 승인 — 임의 명령 실행 방지

manifest의 모든 명령(`build`/`start`/`stop`/`reset`/`test` 등)은 **고정된 인자 배열
(argv)**이지 shell 문자열이 아니다.

- `CommandSpec.argv_must_not_embed_shell`(`runtime/manifest.py`)이 `|`, `&&`, `;`,
  `` ` ``, `$(` 같은 shell 구문을 argv에 포함하면 스키마 검증 단계에서 거부한다.
- 실제 실행부(`runtime/lifecycle.py`)는 `subprocess.run(argv, shell=False, ...)`를
  하드코딩으로 쓴다 — `shell=False`이므로 문자열 보간·shell 해석이 애초에 일어나지
  않는다. 위 검증기는 이중 방어(defense-in-depth)다.
- git 관련 내부 호출(`runtime/source_bootstrap.py`, `runtime/worktree.py`)도 전부
  `shell=False`다.
- 이 argv가 **사용자 머신에서 실행되는 것을 사용자가 실제로 승인**하는 지점이 2절의
  "새 로컬 프로젝트 등록"이다 — argv 전문을 보여주고 `confirmed=True`를 받는다.

---

## 5. LLM 전송 범위 — 제3자 LLM API를 쓰지 않는다

**정확한 표현(2026-07-21 팀 확정, `TEAM_CONTRACT.md`)**:

> **제3자 LLM API를 쓰지 않는다.** 모델은 자체 서빙이며, 분석·evidence·패치는 전부
> 사용자 머신에서 처리된다. LLM 질의에 한해 코드 일부가 전송되며 secret은 redaction된다.

("모델·소스·취약점 데이터가 외부로 나가지 않는다"는 예전 표현은 사실과 달라 폐기했다 —
LLM 질의 한 건에 한해 코드 스니펫이 실제로 나간다. 아래가 정확한 범위다.)

### 5.1 무엇이 "자체 서빙"인가

`VIBECUTTER_LLM_ENDPOINTS`가 가리키는 서버는 **팀이 직접 운용하는 GPU 머신**(RTX 3090
×3, `docs/P4_MODEL_SERVING_RUNBOOK.md`)에서 vLLM(오픈소스 추론 서버)이 여는 OpenAI
호환 `/v1/chat/completions` 엔드포인트다. "OpenAI 호환"은 **와이어 프로토콜(요청/응답
JSON 형식)**이 같다는 뜻이지, OpenAI Inc.나 다른 상용 LLM 벤더의 서비스를 호출한다는
뜻이 아니다. 모델은 오픈웨이트 Qwen 계열(`qwen3-235b` primary, 예정된 72B fallback)이며,
학습·미세조정 없이 추론(inference)에만 쓴다. 저장소 어디에도 `openai.com`,
`anthropic.com`, 상용 벤더의 공개 API 호스트명을 호출하는 코드가 없다.

vLLM 서버는 `--host 127.0.0.1`로 바인딩돼 외부에 직접 노출되지 않고, 팀원은 SSH
터널(`LocalForward`)이나 Cloudflare Tunnel + Access 토큰으로만 접근한다. **Cloudflare
Access는 데이터 보호가 아니라 자원 보호 목적**이다 — 토큰이 유출되면 누구나 팀의 GPU를
쓸 수 있다는 위험을 막는 것이지, 이 자체가 "제3자에게 데이터를 보낸다"는 뜻은 아니다.
다만 **Cloudflare 엣지가 TLS를 종단**하므로, 아래 5.2의 스니펫이 그 경로를 지나가는
동안에는 Cloudflare가 평문을 볼 수 있는 위치에 있다 — 팀은 이 잔여 위험을 낮다고
판단하고 받아들이기로 했다(`TEAM_CONTRACT.md` "Cloudflare Tunnel — 판단" 절).

### 5.2 정확히 무엇이 나가는가

로컬에서 도는 것: MCP 서버 프로세스, target Docker 컨테이너, `.vibecutter/evidence.db`,
git worktree, 스캐너(SAST/SCA), verifier, judge 6게이트. **나가는 것은 하나뿐**:
`POST /v1/chat/completions` 호출.

그 요청 본문에 실리는 코드는 두 종류로 제한된다 — ① candidate 재랭킹용 코드 스니펫(약
21줄 × 최대 10개 후보), ② patch 합성 대상 파일의 관련 부분. 두 경로 모두 전송 직전
`core/redaction.py`의 `redact()`를 거친다(6절). evidence·평가 데이터·전체 소스 트리는
LLM 질의에 포함되지 않는다.

### 5.3 사용자 동의 게이트(2026-07-22 추가, U3)

위 전송은 `vc_consent_llm_egress(granted=True)`로 **1회 동의**해야 실제로 일어난다.
동의 전에는 예외로 막는 대신 "엔드포인트가 없는 것"과 동일하게 조용히 degrade한다 —
LLM 없이 휴리스틱 우선순위 정렬 + template 기반 패치로 계속 동작한다(기능이 잠기지
않는다). 동의 여부는 `.vibecutter/EGRESS_CONSENT`에 durable하게 기록되고,
`vibecutter://consent/llm_egress` resource로 언제든 조회할 수 있다.

### 5.4 실패 시 동작(fail-closed on network, fail-open to heuristic)

primary/fallback 엔드포인트가 모두 응답하지 않거나 `VIBECUTTER_LLM_DISABLE=1`이면,
네트워크를 아예 건드리지 않고 휴리스틱 정렬·template 패치로 떨어진다 — LLM이 죽었다고
검사·수정 기능 자체가 멈추지 않는다. 다만 **판정(`verified`/`fixed`)에는 애초에 LLM을
쓰지 않는다**(안전 불변식 3) — LLM 가용성은 우선순위·패치 품질에만 영향을 준다.

---

## 6. Redaction — 비밀 정보 제거 범위와 알려진 한계

`core/redaction.py`의 `redact()`가 다음 패턴을 제거한다:

- `JSESSIONID` 쿠키, Express `connect.sid`, Django `sessionid`
- `Bearer <token>` Authorization 헤더
- `password`/`matchingPassword` 필드값
- `accessToken`/`access_token`/`refreshToken`/`refresh_token`/`token` 필드값
- `Authorization` 헤더 밖에 있어도 매치되는 bare JWT(`eyJ...`)

적용 지점: evidence 저장(`core.evidence_store.write_artifact`), LLM 질의 프롬프트
조립(`model.serving.build_rerank_messages`, `repair.llm_synth.build_prompt`), HTML
리포트 렌더링(`core/report.py`의 `_esc()`), audit log(`core/audit_log.py`) — 예외 메시지에
git stderr나 토큰이 섞여 나올 경우까지 포함한다. **(2026-07-22 추가)** build/regression
게이트 실패 로그(`core/judge.py::check_build`/`check_regression`, `_capture_command_log`)
— 실패한 명령의 stdout/stderr를 `write_artifact`로 evidence(`ObservationType.LOG`)에
남겨 저장 전 자동으로 이 경로를 거친다(아래 "container/process 로그" 항목 참고).

**알려진 한계(정직하게 명시)**:

- 이 패턴 목록은 **좁게 설계**됐다 — 위 필드명·형식에 안 맞는 일반 API 키, DB 커넥션
  문자열의 비밀번호, 커스텀 이름의 secret은 잡지 못한다. "이 프로젝트가 쓰는 흔한 세션/
  토큰 형식"을 노린 목록이지 범용 secret 스캐너가 아니다.
- **patch diff export(`vc_export_patch`가 쓰는 `.patch` 파일)는 의도적으로 redaction하지
  않는다.** diff는 `git apply`로 실제 코드에 적용돼야 하는 바이트 정확한 산출물이고, 특히
  context/삭제 줄(` `/`-` 접두)은 원본 파일과 바이트 단위로 일치해야 `git apply`가 성공한다
  — 본문에 `<redacted>`를 끼워 넣으면 그 줄들이 더 이상 원본과 안 맞아 diff 자체가 깨진다.
  **(2026-07-22 P1 재검토)** 추가로 새로 도입되는 줄(`+` 접두)만 골라 redact하는 방안도
  검토했으나, 실제 위험은 대부분 "패치가 새로 넣는 코드"가 아니라 "취약한 원본 코드 근처에
  이미 있던 secret"이라 그 경우엔 도움이 안 되고, 반쪽짜리 보호를 "redaction 적용됨"으로
  잘못 표기할 위험이 있어 보류했다 — 대신 **HTML 리포트는 이미 redaction된 상태**(위
  "적용 지점" 참고, `core/report.py`가 `patch.diff`도 `_esc()`로 거른다)이므로 사람이 읽는
  경로는 커버돼 있고, 남은 것은 `git apply`용 원본 바이트 정확성이 필요한 export/`Patch.diff`
  필드뿐이다. 근본적인 완화책은 코드가 아니라 "대상 소스 코드 자체에 secret을 하드코딩하지
  않는다"는 위생 문제다 — 별도 접근이 필요하며 아직 미해결이다.
- **container/process 로그 redaction — (2026-07-22 구현 완료).** 이전에는 build/regression
  게이트(`core/judge.py`)가 실패한 명령의 stdout/stderr를 판정에만 쓰고 버려서, "로그가
  노출되는지"가 아니라 "로그를 남기는 경로 자체가 없어서" 실패 원인을 아무도 볼 수 없었다
  (J-3 라이브 실행 중 SQLite 문자열 결합 버그를 진단할 때 이 gap을 직접 겪음). 이제
  `check_build`/`check_regression`이 실패한 명령의 stdout/stderr를 `write_artifact()`로
  캡처한다 — 이 함수가 저장 전 항상 `redact()`를 거치므로 캡처와 redaction이 한 지점에서
  같이 강제된다. 성공한 명령의 로그는 남기지 않는다(진단이 목적이지 전체 로그 보관이 아님).
- **SARIF export(`eval/report_export.py::render_sarif`) — (2026-07-22 구현 완료, P4).**
  `message.text`(title+impact)에 `redact()`가 적용돼 secret이 제거된다. HTML 리포트와
  이제 동등하다.

patch diff redaction은 `REMAINING_PLAN.md`에 열린 작업으로 계속 추적한다.

---

## 7. Kill Switch — 언제든 즉시 중단

`core/kill_switch.py`는 in-memory 플래그가 아니라 **파일 존재**(`.vibecutter/PAUSE`)로
pause 상태를 판단한다 — MCP 서버 프로세스가 재시작되거나 다른 프로세스가 pause를 걸어도
살아남는다. `vc_pause(reason)`을 호출하면 그 순간부터 상태를 바꾸거나 target/verifier를
건드리는 모든 tool(verify/scan/repair/mutation/judge)이 `KillSwitchEngaged` 예외로 즉시
거부된다. `vc_resume()`으로 해제한다.

`vc_pause`/`vc_resume` 자신과 `vc_kill_run`(rollback/정리)은 이 가드를 타지 않는다 —
멈춰야 할 때 못 멈추거나, 정리를 못 해 상태가 지저분하게 남는 역설을 막기 위해서다.

---

## 8. 패치 적용 범위 제한 — worktree 밖은 건드릴 수 없다

패치는 **원본 브랜치가 아니라 run별 격리 git worktree에만** 적용된다. 이중으로
확인한다:

1. **적용 전(사전 강제)** — `assert_diff_within_worktree`(`core/judge.py`)가
   `vc_apply_patch` 실행 전에 diff가 건드리는 모든 파일이 그 worktree 경로 안에 있는지
   확인하고, 벗어나면 `ScopeViolationError`로 적용 자체를 막는다.
2. **적용 후(사후 검증)** — judge의 6게이트 중 `check_scope`가 같은 검사를 **다시**
   독립적으로 수행한다. 단일 지점 실패에 의존하지 않는 이중 확인이다.

원본 소스는 어떤 경로로도 변경되지 않는다 — `vc_apply_patch`는 항상 worktree 위에서만
동작한다.

---

## 9. Secret 취급 — manifest에는 이름만, 값은 `.env`에만

target manifest의 `role_fixtures`는 fixture 계정의 **메타데이터만** 담는다.
`RoleFixture.secret_env_names`는 `VIBECUTTER_`로 시작하는 **환경변수 이름**만 허용하고
(`runtime/manifest.py`의 `environment_names_only` 검증기), 실제 토큰·비밀번호 값은
manifest에 절대 쓸 수 없다 — 값은 커밋되지 않는 `.env` 파일에만 존재하고, 명령 실행
시점에 환경변수로만 주입된다.

---

## 10. 알려진 한계 (정직하게 명시)

이 문서는 "다 됐다"고 주장하지 않는다. 이 절은 지금 시점에 아직 안 끝난 것을 숨기지
않고 적는다(`REMAINING_PLAN.md`가 최신 상태를 추적한다):

- **모델 tier**: 의도한 구성은 primary=235B / fallback=72B이지만, 이 문서 작성 시점
  기준 fallback은 아직 코드 기본값이 예전 7B다(`model/endpoints.py`). `.env`에
  fallback 엔드포인트가 설정돼 있지 않으면 primary가 죽었을 때 fallback 없이 곧바로
  휴리스틱으로 떨어진다 — 5.4절의 "fail-open to heuristic" 동작 자체는 안전하지만, 의도한
  2단 fallback은 아직 완성되지 않았다.
- **patch diff redaction**: 6절에 적은 그대로, 구조적 제약(`git apply` 바이트 정확성)으로
  아직 미해결이다. **container/process 로그 redaction·SARIF redaction은 6절대로 구현 완료.**
- **`TargetSourceBootstrapper.bootstrap`(`runtime/source_bootstrap.py`)**: `approved`
  파라미터로 승인 게이트가 존재하지만, 이 문서 작성 시점에 이 메서드를 호출하는
  사용자 대상 MCP tool이 없다 — built-in target의 pinned source clone을 위한 골격으로
  보이며, 아직 실사용 경로에 배선되지 않았다.

이 한계들은 2~4절(승인 모델·loopback·argv)과 3절이 다루는 **핵심 안전 불변식에는
영향을 주지 않는다** — 전부 "부가 보호층이 아직 완성되지 않았다"는 것이지 "핵심 게이트가
뚫려 있다"는 뜻이 아니다.

---

## 11. 참고 문서

- `TEAM_CONTRACT.md` 4절 "안전 불변식" — 이 문서가 근거로 삼는 원 소스.
- `REMAINING_PLAN.md` — 이 문서가 언급한 미해결 항목들의 최신 진행 상황.
- `SKILL.md` — Host가 이 정책을 실제로 어떤 절차·질문·보고 형식으로 지켜야 하는지.
- `docs/P4_MODEL_SERVING_RUNBOOK.md` — 모델 서빙 인프라(GPU·vLLM·터널) 상세.
