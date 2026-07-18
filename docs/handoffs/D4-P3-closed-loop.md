# D4 / P3 Handoff (보충: Python 3.13 전환 + IDOR closed-loop 자동 FIXED 첫 완주)

> D4-P3.md(write-IDOR candidate) · D4-P3-xss-locator.md(XSS/locator)에 이은 같은 D4 범위의 보충
> 핸드오프다. 팀 관례상 D5 번호는 최종 통합 전까지 비워 두므로 접미사 보충으로 남긴다.
> **핵심**: 팀 공통 Python을 3.13으로 통일해 semgrep 블로커를 풀었고, 그 위에서 IDOR
> closed-loop이 **처음으로 6게이트 자동 `FIXED`까지 라이브 완주**했다. 라이브로 gap 3개를
> 실측해 그중 P3 것(bearer 재프로비저닝 409)을 고쳤다.

## 상태

완료(라이브 실증 + 커밋).

1. **Python 3.11/3.14 혼재 → 3.13 통일 완료.** semgrep 1.90.0이 3.14의 opentelemetry import로
   죽던 블로커 해소. 3.13에서도 최신 `setuptools>=81`이 `pkg_resources`를 제거해 semgrep이
   `ModuleNotFoundError`로 죽는 2차 함정이 있어 `setuptools<81` 상한이 필수(P1 `b6b0b71`이 main에
   같은 상한을 이미 넣어둔 것을 머지로 수용).
2. **IDOR closed-loop 자동 `FIXED` 첫 완주** — `26s-w1-c1-05`(Scrum Helper, Spring+JWT+MySQL),
   run `run-e32346b2a4b0`. 발견→verified(evidence)→locate→patch→apply(격리 worktree)→패치 재빌드→
   재공격 차단→정상기능 유지→회귀→static(semgrep)→scope **6게이트 전부 True → `VERDICT=FIXED`,
   Finding=`fixed`**. Day3 P0("IDOR 한 종류 발견·수정·재검증")를 사람 손 없이 회수했다.
3. **라이브 gap 3개 실측** — ①bearer 재프로비저닝 409(**P3, 고쳐서 커밋**) ②`VERIFYING→VERIFIED`
   미배선(P1) ③런타임 위생: MySQL grants 레이스 + 오버레이 포트 leak(P2).

## 변경 파일

- `verifiers/access_control.py` (커밋 `4eadf65`): **bearer 재프로비저닝 409 수정.** `_identity_values`에
  선택 `nonce` 추가 — 재현마다 fresh nonce로 계정 식별자(name/username/email)를 유니크하게 만든다.
  `marker`는 name/email의 **substring으로 남으므로** `idor_oracle`/positive-gate needle(`victim_marker`/
  `owner_marker`)은 그대로 매칭된다. `_replay_bearer`가 호출마다 `uuid4().hex[:8]` nonce를 생성해
  owner/attacker 양쪽에 넘긴다. `none`/`session_form` 경로는 kw-arg 기본값이라 무영향.
- `README.md` · `SKILL.md` (커밋 `5e450a6`): 설치 문구 `python3.11` → `python3.13`, 팀 공통 버전 명시.
- (머지로 수용, main `b6b0b71`) `requirements.txt`에 `setuptools<81`, `.python-version=3.13`,
  `core/judge.py` apply 경로 수정 — 이번 세션에서 이 상한이 **fresh 설치에 반드시 필요함을 실측**하고
  main과 계약을 맞췄다.

**공통 계약(`contracts/schemas.py`)·`core`·`mcp_server` 무변경.** access_control 변경은 함수 시그니처에
kw-arg 추가(additive)뿐 → evidence.db 초기화 불필요.

## 제공 인터페이스

- `verifiers.access_control._identity_values(marker, password, *, nonce="")` — nonce 주면 계정
  식별자를 `{marker}-{nonce}`로. bearer 재현이 attack/positive 게이트에서 각각 재프로비저닝해도 충돌 없음.
- **드라이버(참고, 미커밋)**: `scratchpad/idor_closed_loop.py` — 실제 MCP tool(`vc_scan_access_control`
  →`vc_verify_access_control`→`vc_localize_root_cause`→`vc_generate_patch`→`vc_apply_patch`→
  `vc_build_and_test`/`vc_replay_attack`/`vc_validate_regression`)을 순서대로 호출해 closed-loop을
  end-to-end로 몬다. `audit_local_target` 프롬프트가 안내하는 순서를 코드로 재현한 것 — 정식 배치
  드라이버/planner로 승격 후보(P1과 논의).

## 검증

| 항목 | 결과 |
| --- | --- |
| `semgrep --version` (3.13) | **1.90.0, exit 0** (3.14에선 opentelemetry로 죽던 것) |
| 클린룸: `python3.13 -m venv` + `pip install -r requirements.txt` | **setuptools 80.10.2 + 동작하는 semgrep** (팀원 재현 보장) |
| 프로젝트 SAST 배선(`scanners.sast`)으로 c1-05 backend 스캔 | **163 Candidate 생성** (3.14에선 import에서 죽던 경로) |
| 전체 회귀 스위트 | **207 tests OK** (access_control 수정 후 회귀 0) |
| **LIVE closed-loop `run-e32346b2a4b0` on c1-05** | **6게이트 전부 True → `VERDICT=FIXED`** |
| ├ verify(bearer) | verified — 공격자 JWT로 피해자 프로필 마커 유출, evidence 2건 저장 |
| ├ locate | `UserProfileController.getProfile:25`, controller_hotfix |
| ├ patch/apply | Principal 소유권 가드 diff → 격리 worktree 적용(원본 branch 불변) |
| ├ attack gate | **True** — 재공격 시 남의 프로필 차단(500), 마커 미유출 |
| ├ positive gate | **True** — 자기 프로필 여전히 200 (fresh-marker 수정으로 409 해소됨) |
| └ regression/static/scope | **True/True/True** — 기존 테스트 유지, semgrep 증가 없음, worktree 내부 |

**아직 검증 못 한 것**: 드라이버는 c1-05(Spring/bearer)로만 완주. 무인증(c2-04)/다른 인증 앱의 자동 FIXED는
미실행. 자동 FIXED는 현재 아래 P1/P2 우회를 드라이버가 대신 처리해야 성립(정식 orchestration 미배선).

## 다른 역할에 필요한 사항

### P1 — `VERIFYING → VERIFIED` Run 전이 미배선 (자동 loop 차단 요인)

- **증상**: `vc_verify_access_control`이 **Finding만 VERIFIED로 승격**하고 **Run은 VERIFYING에 그대로** 둔다.
  이어서 `vc_generate_patch`는 Run이 `VERIFIED/LOCALIZING/RETRY/PATCH_PROPOSED`여야 하는데(현재 VERIFYING)
  `ValueError: vc_generate_patch는 run이 … 상태여야`로 멈춘다. **드라이버가 `transition(run, VERIFIED)`를
  수동으로 넣어 우회**했다.
- D4-P3.md에 "(헤드업, 소규모) VERIFYING→VERIFIED 미배선"으로 이미 적었던 항목이 **자동 closed-loop을 실제로
  막는 지점**임이 라이브로 확인됐다.
- **요청**: verify tool(또는 스캔 tool이 `READY→MAPPING→CANDIDATE_SCAN`을 멱등 전이하는 것과 같은 패턴)이
  verified finding이 나오면 Run을 `VERIFYING→VERIFIED`로 전이하게 배선. 그러면 Host/드라이버가 상태를 손으로
  옮기지 않아도 `vc_generate_patch`로 이어진다.

### P2 — 런타임 위생 2건 (D3-밤 배치 안정성에 직접 영향)

라이브 반복 실행에서 c1-05 앱이 계속 안 뜨는 원인을 추적한 결과, **P3 로직 문제가 아니라 런타임 위생 2건**이었다.

1. **MySQL healthcheck가 grants 완료 전에 healthy를 보고** — 매니페스트 healthcheck(`mysqladmin ping`)는
   mysqld가 뜨면 통과하지만, 그 시점에 **앱 유저/권한 생성(init 스크립트)이 아직 안 끝났다**. fresh volume에서
   앱(Hibernate)이 그 창에 접속 시도 → 접속 실패 → `Unable to determine Dialect / JdbcEnvironment` 크래시 →
   앱 컨테이너 `Exited(1)`. **타이밍 의존이라 간헐적**(첫 run은 운으로 통과, 이후 반복 실패). `depends_on:
   condition: service_healthy`가 있어도 healthcheck 자체가 "너무 이르게" 초록이라 안 막힌다.
   → **제안**: healthcheck를 앱 유저 인증까지 확인하도록(예: `mysqladmin ping -u<app_user> -p<pw>` 또는 init
   완료 sentinel), 또는 앱 쪽 DB 접속 재시도, 또는 start에 grants 여유 버퍼. (P3 드라이버는 "DB만 먼저 띄워
   healthy 확인 → 버퍼 → 앱" 순서로 우회했다.)
2. **완료된 run의 run-scoped 오버레이가 teardown되지 않고 포트를 점유** — 앞선 성공 run의 STAGE 6
   `_repoint_to_patched_runtime`이 만든 오버레이(`vc-<hash>-*`)가 정리 안 되고 **:14006/:14007을 15분+ 계속
   점유** → 다음 run의 앱이 포트 바인딩 실패로 `Created`에 멈춤. `docker compose down --volumes`(원본 프로젝트)
   로는 이 오버레이가 안 지워진다(프로젝트명이 다름).
   → **제안**: run 종료 시 `reset_run(target_id, run_id, approved=True)`로 오버레이 확실히 teardown(배치 루프가
   run마다 호출), + stale 오버레이 sweep. **배치가 앱마다 이 두 문제에 걸리면 D3-밤 audit이 대량 실패**한다.

### P4 — 신규 `verified→fixed` trajectory (실제 closed-loop 학습 샘플)

- `run-e32346b2a4b0` = **evidence 기반 verified + 6게이트 fixed까지 완주한 실제 closed-loop trajectory**.
  라벨: c1-05, IDOR/CWE-639, Spring/bearer. verify evidence(http_exchange 2건) + validation(post-patch
  http_exchange) + 6게이트 결과가 조인돼 있다. **base vs full 학습의 진짜 재료** — 그동안 mock/부분이던 걸
  실물로 대체 가능.

### 전원 — Python 3.13 + `setuptools<81`

- 팀 공통 실행 버전 **3.13**. macOS는 `brew install python@3.13`. `.venv` 재생성 후
  `pip install -r requirements.txt`. **`setuptools<81`이 없으면 fresh 설치에서 semgrep이 `pkg_resources`로
  죽는다**(requirements에 상한 포함됨). README/SKILL 갱신 반영.

## 결정·가정·리스크

- **자동 `FIXED`는 P3 로직 자체로는 이미 완성** — 이번에 초록불을 낸 건 verifier/locator/patcher/validators
  (P3)가 아니라 그 주변 **orchestration(P1: Run 전이) + 런타임 위생(P2: DB/포트)** 우회를 드라이버가 대신
  처리했기 때문. 즉 **남은 마찰은 P3 밖**이며, 위 P1/P2 항목이 배선되면 Host가 프롬프트만으로 자동 FIXED에
  도달한다.
- **패치는 오프라인 템플릿(v1)** — `ResponseStatusException`을 써서 차단 시 403이 아니라 앱 `GlobalException
  Handler` 때문에 500이 난다. 그래도 **6게이트는 전부 통과**(attack=차단, positive=자기자원 유지, regression=
  유지). house-style 403은 LLM `synthesize_fn`(GPU) 몫 — FIXED 판정에 "예쁜 에러"는 불필요, 6게이트만 필요.
- **bearer nonce 수정의 안전성** — nonce는 계정 식별자만 유니크하게 하고 `marker`(oracle needle)는 순수하게
  유지 → attack oracle(`victim_marker in attack & not in baseline`)·positive oracle(`owner_marker in
  baseline`) 판정 로직 불변. 207 회귀 통과로 확인.
- **격리·안전** — 로컬 격리 c1-05에 일회성 DB/JWT secret(임시값, 파일 미저장, reset --volumes로 폐기),
  패치는 run-scoped worktree에만(원본 branch 불변), evidence에 토큰/비번 미기록.
- **드라이버는 scratchpad 산출물**(미커밋) — 정식 배치 드라이버/planner로 승격은 P1과 논의. 지금은 재현용.
