# D5-P3 안전 감사 (Day4/5 — 스코프/금지명령/원본branch/secret 0건 검증)

> P3(Security/Agent), 브랜치 `security/agent`. **read-only 감사** — 이 문서 1개 외에는
> 코드/DB를 수정하지 않았다. 감사 대상은 메인 작업 트리
> `/Users/junseo/Projects/madcamp/VibeCutter`의 `.vibecutter/evidence.db`(누적 저장물)와
> git 상태다.
>
> plan-p3.md Day4 완료 기준: "audit log에서 **범위 밖 접속 0 / 금지 명령 0 / 원본 branch
> 변경 0 / secret 로그 0** 확인 (12.3절 목표 전부 0건)". 아래 4개 항목 **전부 PASS(0건)**.

## 감사 스냅샷 (읽은 대상)

| 대상 | 규모 | 읽은 방법 |
|---|---|---|
| `audit_log` 테이블 | 1,327 rows (ok 813 / error 514), 2026-07-18 09:51 ~ 07-20 05:01 | `sqlite3 "file:...evidence.db?mode=ro"` (read-only) |
| `run` 테이블 | 2,022 rows | 동일 |
| evidence artifacts | 637 개 (`.vibecutter/runs/*/artifacts/*.bin`) | `grep -rlE` (패턴 매치, 값 미출력) |
| trajectories | 495 개 (`.vibecutter/trajectories/*.jsonl`) | 동일 |
| 원본 소스 트리 | tracked 파일 전체 | `git status --porcelain`, `git diff --stat` |
| 정책 소스 | `policies/scope.yaml`(등록 target 20개), `policies/commands.yaml`(command_id 4개) | 직접 읽음 |

**참고 — 이번 세션 실앱 run** (다른 다수 row는 테스트 스위트가 남긴 것): c1-05
`run-897ad65c686f`(→ `26s-w1-c1-05`, FIXED), c2-04 `run-c100386ab19f`/`run-d441a526d3b1`/
`run-1327a6097641`(→ `26s-w1-c2-04`, VERIFYING). 네 run 모두 scope.yaml 등록 target 사용.

> **핵심 해석**: audit log에는 정책 게이트가 나쁜 입력을 **거부한 기록(result="error")**이
> 다수 있다. 이것은 위반이 아니라 방어가 **작동한** 증거다. "위반 0"의 판정 기준은
> *"금지된 행위가 성공(result="ok")했는가"* 이며, 그 답은 4개 항목 모두 **아니오**다.

---

## 항목 1 — 범위 밖 접속 0건 · **PASS**

**결과**: 미등록 host/IP/URL에 대한 접속이 **성공한 사례 0건**. 미등록 `target_id` 접근
시도는 정책 게이트(`core.policy_engine.require_target_allowed` / `require_host_allowed`)가
전부 거부했다.

**근거**:
- `audit_log`에서 `PolicyViolation`("...policies/scope.yaml에 등록되지 않았습니다") **54건**
  전부 `result="error"`. 대상 `target_id`는 모두 합성 테스트 ID뿐이었다:
  `not-in-scope-yaml`(50), `not-in-scope`(4). 실제 외부 host 아님.
- **성공한 스코프 우회 0건** 교차검증: `run` 테이블에서 scope.yaml 미등록 `target_id`
  (`fake-target`, `lab`, `local-xss-lab`, `not-in-scope`, `not-in-scope-yaml`)를 가진 run에
  대해 네트워크/게이트 tool(`vc_build_target`/`vc_start_target`/`vc_scan_access_control`/
  `vc_run_sast`/`vc_run_sca`/`vc_verify_*`)이 `result="ok"`로 실행된 건 **0건**
  (audit_log ⋈ run 조인 쿼리, 전부 빈 결과).
- 실앱 run 4개는 모두 등록 target(`26s-w1-c1-05`, `26s-w1-c2-04`) 사용, 관련 audit 에러 0건.
- scope.yaml의 모든 target `allowed_hosts`는 `127.0.0.1`만 — 외부 목적지 자체가 정책에 없음.

**검증 쿼리 예**: `SELECT ... FROM audit_log a JOIN run r ON a.target=r.id WHERE
a.tool IN (게이트tool들) AND a.result='ok' AND r.target_id IN (미등록 목록)` → 0 rows.

---

## 항목 2 — 금지 명령 0건 · **PASS**

**결과**: 정책이 거부해야 할 명령이 **실행된 사례 0건**. 모든 tool은 typed `command_id`
(`policies/commands.yaml`)로 제한되며 임의 shell 문자열 tool은 존재하지 않는다.

**근거**:
- `commands.yaml` 스키마 위반(미등록 command_id / 미정의 인자 / 필수 인자 누락 / 타입 불일치):
  **0건** (`error LIKE '%commands.yaml%' OR ...` → 0).
- **KillSwitch 우회 0건**: pause 상태에서 게이트 tool이 거부된 기록 `error='paused'` **4건**
  (`vc_materialize_worker_run`) — 킬 스위치가 실제로 tool을 막았음. pause/resume tool은
  각각 25회 정상 호출. (한계는 하단 참고 — pause "우회 성공"은 코드 설계상
  `check_not_paused()` 선행 호출로 보장되나 audit log에 pause-state 컬럼이 없어 직접
  질의로는 증명 불가.)
- **worktree 밖 경로 patch(경로 탈출) 0건 성공**: `assert_diff_within_worktree`
  (`core/judge.py:47`)가 `../../etc/passwd`, `Foo.java`, `src/Foo.java` 등을 건드리는
  `vc_apply_patch` 시도 **59건 전부 `result="error"`로 차단** — 성공 0.
- 승인 게이트도 전부 강제됨(우회 성공 0): `confirmed=True` 없는 `vc_apply_patch` 26건 거부,
  `approved=True` 없는 `vc_verify_*` 81건 거부, `approved=True` 없는 `vc_kill_run` 25건 거부.
- SKILL.md "절대 금지"(외부 스캔/파괴적 write/reverse connection)에 해당하는 tool 자체가
  MCP 서버에 없음 — 명령 표면이 typed command_id로만 노출됨.

---

## 항목 3 — 원본 branch 미변경 · **PASS**

**결과**: 원본 소스(security/agent 작업 트리)의 tracked 파일이 패치로 **변경된 것 0건**.
패치는 `.vibecutter/worktrees/`의 run-scoped worktree에만 적용됐다.

**근거**:
- `git status --porcelain`: 출력은 `?? docs/handoffs/D5-P3-verify-batch.md`(untracked 문서)
  뿐. tracked 소스 변경 없음.
- `git diff --stat` / `git diff HEAD --stat`: **빈 결과** → 수정/스테이징된 tracked 파일 0개.
- `.vibecutter/`(runs/worktrees 포함)는 `.gitignore`에 등록돼 있어 run 산출물이 git을
  건드리지 않음.
- 코드 경로: `vc_apply_patch`는 `worktree_manager.path_for(run.id)`가 만든 run-scoped
  detached worktree에만 `git apply`하며(`mcp_server/tools_repair.py:293-331`), 적용 전
  `assert_diff_within_worktree`로 worktree 밖 경로를 이중 차단(judge `check_scope` 게이트와
  동일 규칙). c1-05(run-897ad65c686f, FIXED)의 run-scoped worktree
  `.vibecutter/worktrees/26s-w1-c1-05`는 run 종료 후 정리되어 현재 비어 있음
  (`git worktree list`에도 없음).
- 참고: `git worktree list`에 보이는 `.claude/worktrees/agent-*` 2개는 **병렬 에이전트
  A/B**의 격리 worktree(다른 브랜치)이며 원본 security/agent 트리가 아니다 — 원본 소스와
  무관.

---

## 항목 4 — secret 로그 0건 (redaction 작동) · **PASS**

**결과**: evidence/trajectory/audit log에 토큰·비밀번호·JWT **원문 흔적 0건**. redaction
(`core/redaction.py`, `evidence_store.write_artifact` → `_redact_bytes`)이 저장 계층에서
실제로 작동한 증거를 확인. (본 리포트에는 실제 secret 값을 일절 기재하지 않으며, 아래는
패턴 매치 **건수**만이다.)

**근거 (원문 흔적 스캔 — 전부 0)**:

| 패턴 | evidence artifacts | trajectories | run-overlays | audit_log.error |
|---|---|---|---|---|
| RAW JWT (`eyJ....`) | 0 | 0 | 0 | 0 |
| RAW Bearer 토큰 (`Bearer <10+ 토큰문자>`) | 0 | 0 | 0 | 1* |
| RAW `JSESSIONID=<값>` | 0 | 0 | — | 0 |
| RAW `password/matchingPassword=<값>` | 0 | 0 | — | 0 |

\* audit_log의 Bearer 1건은 **오탐**: 문구 "bearer provision 실패: 응답에서 id/token을 찾지
못함"(id/token을 *찾지 못했다*는 진단 메시지)로, SQLite LIKE 대소문자 무시로 영어 단어
"bearer"가 매치된 것. **토큰 값 없음**(전체 길이 41자, redaction 마커 불필요).

**redaction 작동 증거**:
- `<redacted>`/`<redacted-jwt>` 마커가 evidence artifacts **50개**에 존재 → 저장 시점에
  실제로 secret이 지워짐.
- audit_log.error에 redaction 마커 **6건**(예: "git apply failed: Authorization: Bearer
  `<redacted>` rejected", "token leaked in body: `<redacted-jwt>`") — 예외 메시지에 섞인
  secret도 `@audited`가 `redact()`로 지운 뒤 기록.
- git tracked에 실제 `.env` 없음(`.env.example`만 tracked, 디스크에 `.env` 없음).

**검증 방법**: `.vibecutter/runs`·`/trajectories`·`/run-overlays`에 `grep -rlE`(파일 목록/
건수만), `audit_log.error`에 값 노출 없는 count-only sqlite 쿼리. 이번 세션 secret은 일회성
랜덤이라 값 자체는 폐기됐고, 목적인 **원문 잔존 여부·redaction 동작**을 확인함.

---

## 종합

| # | 항목 | 판정 | 한 줄 근거 |
|---|---|---|---|
| 1 | 범위 밖 접속 | **PASS (0)** | 미등록 target 시도 54건 전부 게이트 거부, 성공 우회 0건; 실앱 run 4개 모두 등록 target |
| 2 | 금지 명령 | **PASS (0)** | commands.yaml 위반 0, worktree 탈출 59건 차단, 승인/kill 게이트 우회 성공 0 |
| 3 | 원본 branch 변경 | **PASS (0)** | `git diff` 빈 결과, 패치는 run-scoped worktree에만, `.vibecutter/` gitignore |
| 4 | secret 로그 | **PASS (0)** | RAW JWT/Bearer/JSESSIONID/password 원문 0건, `<redacted>` 마커 50+ (redaction 작동) |

## 감사 중 발견한 리스크/한계

1. **audit_log에 `run_id`/`event_type` 전용 컬럼이 없음**. `target` 컬럼은 `_guess_target()`
   가 `target_id > run_id > finding_id > patch_id > candidate_id` 순으로 고른 **휴리스틱**
   값이라, tool마다 run 단위 집계가 정확하지 않고 finding/patch 조인이 필요하다. 감사
   자동화를 하려면 run_id·event_type 컬럼 추가를 권한다.
2. **KillSwitch 우회 "성공 0"은 직접 질의로 증명 불가**. audit log에 각 성공 호출 시점의
   pause 상태가 기록되지 않아, "pause 중에 게이트 tool이 성공했는가"를 로그만으로는 못
   본다. 현재는 (a) 관측된 refusal 4건 + (b) 코드 설계(`check_not_paused()` 선행 호출)로
   추론한 결과다.
3. **네트워크 egress가 직접 로깅되지 않음**. 스코프 보장은 정책 게이트가 네트워크 호출
   *전에* 거부한다는 것 + `allowed_hosts=127.0.0.1` 뿐이라는 사실에 의존한다. 게이트가
   미등록 target을 전부 막은 것은 확인했으나, 패킷/요청 수준의 독립 감사 기록은 없다.
4. **redaction은 패턴 기반**(JSESSIONID/Bearer/password/JWT). 다른 형태의 secret(예:
   OAuth code, 다른 shape의 API key)은 잡지 못한다. 이번 세션 secret은 커버되는 패턴이라
   원문 매치 0건이었으나 커버리지는 유한하다.
5. **바이너리 artifact는 설계상 미-redaction**(`_redact_bytes`가 non-UTF-8은 원본 저장 —
   스크린샷 등). 이미지에 렌더된 secret은 지워지지 않는다. 이번 감사에서 문제 artifact는
   없었으나 유의.
6. **DB는 테스트 스위트 run과 실앱 run이 섞인 누적 저장소**(2026-07-18~)라 error 다수가
   의도적 negative test다. 실앱 run은 제공된 4개 run_id로 구분해 확인했다.
7. **정책 소스(scope.yaml/commands.yaml)를 병렬 에이전트 A가 편집 중**이므로 본 감사는
   읽은 시점(20 target / 4 command_id)의 스냅샷 기준이다.
