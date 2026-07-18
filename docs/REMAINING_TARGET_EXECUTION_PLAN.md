# Remaining Target Execution Plan

## 이 배분의 의미

P1/P2/P3의 기존 코드 소유권은 바꾸지 않는다.

| 공통 기능 | 소유자 |
| --- | --- |
| Host orchestration, 상태 전이, evidence, judge, kill switch | P1 |
| manifest, build/start/reset, provisioning, worktree/Compose overlay | P2 |
| attack surface, suspect→Candidate, verifier, locator/patcher/validator | P3 |

아래의 `P1 5 / P2 5 / P3 8`은 기능을 다시 나눈 것이 아니라, **P3가 혼자 수행하던
레포별 후보 선별·검증 실행을 세 명이 나눠 맡는 audit queue**다. 각 작업자는 자기 배정 target에
같은 공통 파이프라인을 실행한다. P2도 fixture 제공에서 멈추지 않고 자기 5개에서
Candidate·evidence 또는 범위가 명시된 clean/blocked 결과를 만든다.

`verified`와 `fixed` 판정은 작업자와 관계없이 P1 evidence store와 deterministic judge만 수행한다.

## 최신 main 반영 상태

- P1: `audit_local_target(target_id)` Host prompt, run kill/rollback, patched worktree overlay build,
  3회 patch 재시도 상한을 구현했다.
- P2: 22개 executable manifest, target lifecycle, provisioning contract,
  run-scoped worktree/Compose overlay/reset/regression을 제공한다.
- P3: `candidates_for_target()` 단일 진입점으로 `find_idor_suspects()`와 strategy-aware
  `build_candidates()`를 묶었다. P1은 target source와 P2 provisioning만 넘기면 typed Candidate 또는
  provisioning blocker를 받을 수 있다.
- P1: 최신 main의 `vc_scan_access_control`이 위 bridge를 실제 배선한다. run이 `READY`이면
  `MAPPING → CANDIDATE_SCAN`을 거쳐 Candidate를 evidence store에 저장하고, fixture 계약이 없으면
  blocked 사유를 trajectory에 저장한다. `vc_map_*` 도구는 여전히 스텁이지만 access-control batch를
  시작하는 데에는 더 이상 blocker가 아니다.
- Access-control(IDOR) verifier는 동작한다. XSS/Injection verifier는 아직 미구현이므로 해당
  후보는 unsupported blocker와 필요한 verifier contract를 기록한다.

## 실행 범위

Notion 체크는 우선순위 신호로 사용하되, P2가 manifest·loopback runtime·readiness로 실행 가능하다고
판정한 W1 target은 미체크여도 진행 후보에 포함한다.

- reference: `c1-05`(수동 closed-loop), `c2-04`(read/write IDOR), `c2-05`(clean),
  `c3-08`(검토 표면 방어됨)
- active audit queue: reference 4개를 제외한 18개
- W2·기타 inventory는 P2 manifest/runtime contract가 생기기 전까지 backlog

## 공통 target 완료 기준

각 작업자는 배정 target마다 다음 중 하나를 남겨야 한다.

1. typed Candidate → verifier → `verified`/`rejected` evidence
2. 확인한 취약점 범위, scanner/prefilter 결과와 함께 남긴 scoped clean 결과
3. 인증·seed·미지원 verifier 등 재현 가능한 blocked 결과와 필요한 다음 계약

단순 build/health PASS, fixture 준비, suspect 개수만으로는 audit 완료가 아니다. verified finding이
생기면 P1 승인·judge 흐름에 따라 locator→patch→P2 patched runtime→P3 replay/positive→최종
verdict까지 진행한다.

## 실행 배분

### P1 audit queue — 5개

P1은 공통 orchestration을 소유하는 동시에 아래 5개를 그 흐름의 첫 batch로 실행한다.

| target_id | stack | 현재 prefilter 참고 |
| --- | --- | ---: |
| `26s-w1-c3-09` | Spring | IDOR suspect 8 |
| `26s-w1-c3-03` | Node | IDOR suspect 2 |
| `26s-w1-c3-04` | Node | IDOR suspect 16 |
| `26s-w1-c3-05` | Node | IDOR suspect 3 |
| `26s-w1-c2-08` | Django/generic | IDOR suspect 0 |

### P2 audit queue — 5개

P2는 기존 runtime/provisioning 소유권을 유지하면서 아래 5개의 audit operator가 된다.

| 우선순위 | target_id | prefilter | P2 실행 계획 |
| ---: | --- | ---: | --- |
| 1 | `26s-w1-c2-01` | 12 | ephemeral DB password로 기동 후 signup→login two-role 계약 확인. 현재 bearer verifier는 가입 응답 토큰형만 지원하므로 login-path 확장 또는 fixture contract 뒤 Candidate/verify |
| 2 | `26s-w1-c2-02` | 1 | **실행 완료(후속 계약 대기)**: `run-7ec9f46e4519` build PASS, access-control scan Candidate 0 / `fixture_contract_required` blocked. 현재 후보는 path-id 없는 leaderboard aggregate라 live fixture 뒤 scoped clean 또는 evidence로 확정 |
| 3 | `26s-w1-c1-06` | 1 | **실행 완료(후속 계약 대기)**: `run-a1498e9a2489` build PASS, Candidate 0 / `fixture_contract_required` blocked. `/api/demo/settle`은 unprotected demo endpoint라 P3가 auth-none 또는 bearer resource verifier 계약을 지정해야 함 |
| 4 | `26s-w1-c1-07` | 5 | Google OAuth + process-local memory session이라 DB seed만으로 재현 불가. trusted test-login/session-fixture 계약이 생기기 전까지 blocked 근거를 남김 |
| 5 | `26s-w1-c1-03` | 0 | SAST/SCA와 검토 범위를 결합한 scoped clean 또는 다른 class Candidate 기록 |

위 수치는 최신 main의 `find_idor_suspects()`를 P2 로컬 source에 읽기 전용으로 실행한 결과다.
아직 evidence/judge를 통과한 결과가 아니므로 완료 수치로 사용하지 않는다.

### P3 audit queue — 8개

P3는 공용 보안 엔진을 유지하면서 더 많은 8개 target의 audit operator가 된다.

| batch | target_id | stack | 현재 prefilter 참고 |
| --- | --- | --- | ---: |
| A | `26s-w1-c2-03` | FastAPI | 12 |
| A | `26s-w1-c3-06` | FastAPI | 0 |
| A | `26s-w1-c1-02` | Node | 2 |
| A | `26s-w1-c1-04` | Node | 0 |
| B | `26s-w1-c1-01` | generic/mixed | 3 |
| B | `26s-w1-c2-06` | Django/generic | 0 |
| B | `26s-w1-c2-07` | Node/Next | 0 |
| B | `26s-w1-c3-02` | Django/generic | 21 |

## target별 공통 실행 순서

```text
P1 Host orchestration / audit operator
  → P2 register·build·start·provisioning
  → P3 mapping·suspect→Candidate
  → P3 verifier 실행
  → P1 evidence 저장·deterministic verdict
  → verified인 경우 P3 locate·patch 후보
  → 사용자 승인 후 P2 worktree overlay build/start/regression
  → P3 replay·positive validation
  → P1 FIXED / RETRY / HUMAN_REVIEW
  → P4 trajectory/report 입력
```

작업자가 P1/P2/P3 중 누구든 위 제공자를 바꾸지 않는다. 작업자는 자기 target의 입력 준비,
tool 호출 진행, 결과·blocker 기록을 맡는다.

## 바로 다음 작업

1. P2는 `c2-02`의 `fixture_contract_required`를 보존한다. P3의 선언형 bearer 계약이 들어오면
   self-signup provisioning override를 추가해 live scope 확인을 재개한다.
2. P2는 `c2-01`에 process-local DB password를 주입해 build/start하고, `/api/v1/auth/signup`
   → `/api/v1/auth/login`의 two-role 계약과 resource 생성 경로를 확인한다. 값·token은 파일·evidence에
   저장하지 않는다. 기존 Docker volume을 비우는 reset은 별도 승인 뒤에만 실행한다.
3. P3 bearer bridge에 선언형 signup payload와 선택 login(`login_path` 등) 계약이 추가되면
   `c2-01`을 첫 P2 audit target으로 실행하고 Candidate/evidence/blocked 결과를 handoff에 기록한다.
4. 같은 계약으로 `c2-02`와 `c1-06`을 재개한다. `c1-07`은 trusted test-login/session fixture,
   `c1-03`은 existing-account fixture와 SAST/SCA clean scope를 별도로 준비한다.

## Handoff 최소 필드

- `target_id`, run ID, source commit, audit operator
- provisioning strategy/auth mode/base URL/fixture artifact 상태(secret 값 제외)
- scanner/prefilter 범위, suspect 수와 선택 endpoint
- Candidate/evidence/validation ID 또는 scoped clean·blocked 근거
- patch가 있으면 worktree ID, 승인 상태, reset 여부
- 다음 역할에 필요한 한 가지 입력

## 팀 동기화 메시지

### P1에게

최신 main의 `vc_scan_access_control` 배선을 확인했습니다. P2는 `c2-02`부터 실제 tool 호출로
Candidate 또는 provisioning blocker를 trajectory에 남기겠습니다. P1은 이 경로의 결과가 report/judge
단계에서 누락되지 않는지만 통합 시 확인해 주세요.

### P3에게

P2의 첫 두 대상은 현재 bearer verifier가 가정한 고정 `{name,email,password}` signup body와 다릅니다.
`c2-01`은 `POST /api/v1/auth/signup`이 id만 반환하고 `POST /api/v1/auth/login`의 `access_token`이
필요하며, `c2-02`는 `POST /api/auth/signup`이 `{username,password}` body와 `accessToken`을 사용합니다.
target별 하드코딩 대신 bearer probe에 선언형 `signup_payload`과 선택 `login_path`/`login_payload` 계약을
추가해 주세요. P2는 각 target의 endpoint·field·token key를 제공하고, 그 커밋 뒤 self-signup runtime으로
Candidate→verify batch를 돌리겠습니다. 추가로 `c1-06`은 `/api/auth/signup`의
`{email,password,nickname}` body에서 `token`을 즉시 반환하고, prefilter endpoint `/api/demo/settle`은
인증 미들웨어가 없습니다. 이 endpoint를 auth-none 상태 변경 검증으로 다룰지, 두 계정/resource fixture가
필요한 IDOR verifier로 다룰지 P3 contract를 지정해 주세요.
