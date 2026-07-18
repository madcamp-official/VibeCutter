# D3 / P2 Status Update

> 이 문서는 Day3 구현 후 수행한 runtime 감사와 협업 상태 갱신이다. Day5 통합 freeze 또는
> 최종 재현 작업이 끝났다는 뜻이 아니며, Day5 handoff 번호는 실제 최종 통합까지 비워 둔다.

## 상태

진행 중 — P2의 manifest/catalog, target-source worktree, run-scoped Compose overlay,
rollback/reset, regression runner는 구현·검증됐다. 최신 main에서 P1이 overlay build,
kill/rollback, retry budget과 `audit_local_target` Host prompt를 연결했다. P2의 다음 단계는
인프라 지원에서 멈추지 않고 배정된 5개 target의 audit operator로 Candidate/evidence 또는
scoped clean/blocked 결과를 만드는 것이다.

## 변경 파일

- `docs/P2_TARGET_RUNTIME_RUNBOOK.md`: P3 live 검증 완료, 자동 closed-loop 호출 순서,
  static Compose port 충돌 조건, GPU 역할 경계를 최신화.
- `docs/handoffs/D3-P2-status-update.md`: 현재 P2 상태·검증·역할별 의존성을 기록.
- `docs/REMAINING_TARGET_EXECUTION_PLAN.md`: Notion 체크를 우선순위로 사용하되 P2 viability가 확인된
  W1 target도 진행 후보로 삼는 P1 5 / P2 5 / P3 8 batch 배분을 기록.
- `runtime/provisioning.py`, `targets/verifier_provisioning.yaml`: P2 verifier provisioning contract.
  `c2-04` fixture-file/unauthenticated, `c1-05` self-signup/bearer, 나머지 fixture contract 필요를
  typed metadata로 노출.
- `docs/VERIFIER_BATCH_INTERFACE.md`: P2 provisioning → P3 Candidate bridge → P1 orchestration →
  P2 patched runtime → P3 replay → P1 judge → P4 trajectory의 호출 순서를 확정.
- 최신 main 반영: P1 `audit_local_target` prompt·kill switch·rollback·retry budget과
  P3 `candidates_for_target()` 단일 Candidate bridge를 확인하고, 기능 소유권과 target audit 실행
  분담을 분리해 기록.
- `runtime/lifecycle.py`, `tests/test_lifecycle.py`: Windows CP949 기본 디코딩 때문에 Docker UTF-8
  build output이 `stdout=None` Pydantic 오류로 바뀌던 P2 lifecycle 결함을 UTF-8/replacement decoding과
  회귀 테스트로 수정.

## 제공 인터페이스

- 입력: policy-allowed `target_id`, trusted `run_id`, patch 승인 뒤 생성된 target-source worktree,
  destructive lifecycle에는 explicit approval.
- 출력: `catalog.run_overlay_for(target_id, run_id).prepare()`의 generated Compose,
  `overlay.execute("build"|"start")`, health 결과, `catalog.test_runner_for(target_id).run(run_id)`,
  `TargetRuntimeService.reset_run(target_id, run_id, approved=True)`.
- 실패/예외: worktree·Compose isolation·approval이 하나라도 만족되지 않으면 실행을 거부한다.
  reset 실패 시 worktree는 보존한다.

### Verifier provisioning / batch bridge (이번 갱신)

- P2 → P3: `vc_get_verifier_provisioning(target_id)`는 loopback `base_url`, `auth_mode`,
  역할 fixture 이름과 준비 전략을 반환한다. `26s-w1-c2-04`는 승인된
  `vc_prepare_verifier_fixture(target_id, approved=True)`로 두 로컬 사용자/리소스 fixture를
  준비하고, `26s-w1-c1-05`는 P3 verifier가 self-signup으로 일회성 두 계정을 만든다.
- P3 → P1: `IdorSuspect`를 그대로 문자열 finding으로 남기지 말고, P2 provisioning의
  `base_url`·인증 방식·공격 파라미터를 넣은 typed `Candidate`로 변환한다. fixture가 없거나
  계약이 미정이면 Candidate를 만들지 않고 blocked로 남긴다.
- P1: `audit_local_target` Host prompt가 P2 provisioning → P3 scan/verify → evidence store →
  report 호출 순서를 안내한다. prompt는 실행 함수가 아니며, patch build와 kill/reset,
  retry budget은 각 tool 계층에서 강제된다.
- 상세 계약·순서는 `docs/VERIFIER_BATCH_INTERFACE.md`가 단일 기준이다.

## 검증

- 최신 main 통합 후 전체 회귀 175건 PASS. 이 중 P2 관련 항목은 checked-in manifests, catalog, overlay,
  worktree test runner, target service, portability, lifecycle, readiness, apply-patch 연동을
  포함하며, 새 provisioning registry/MCP tool/fixture approval 경로도 포함한다.
- `vc_get_verifier_provisioning(26s-w1-c2-04)` 실제 MCP read 호출이
  loopback base URL, `fixture_file`, fixture artifact 상태를 정확히 반환함을 확인했다.
- 22개 checked-in runtime manifest를 read-only audit했다. 16개는 `ready=True`이고,
  6개(`c1-03`, `c1-05`, `c1-06`, `c1-07`, `c2-01`, `c2-02`)는 필요한 role-fixture 환경변수가
  아직 주입되지 않아 `ready=False`다. source/Compose/실행 파일 오류는 없으며, 이 변수는 P3의
  authenticated replay 계약 또는 명시적인 fixture 준비가 있어야 주입한다.
- `.vibecutter/targets/sources/`의 관리 source clone은 모두 Git clean이다. active
  `c2-04` run worktree `d2-c2-overlay`와 generated overlay는 보존했다. `c3-09` static-preflight
  overlay도 artifact로만 남아 있으며 running service는 없다.
- `26s-w1-c2-04`: API `127.0.0.1:14017`, UI `127.0.0.1:14018`이 healthy이고 IDOR fixture가 존재함을
  재확인. P3의 read/write IDOR live evidence는 D3-P3에 기록돼 있다.
- `26s-w1-c3-09`: catalog readiness PASS 및 detached-worktree generated Compose static preflight PASS.
  build/start/reset/smoke는 명시 승인 없이 실행하지 않았다.
- P3의 `c1-05` closed-loop는 disposable clone에서 수동으로 성공했다. 이는 P2 overlay를 경유한
  자동 run의 증명은 아니다.

## 다른 역할에 필요한 사항

- P1: 최신 main의 `vc_scan_access_control`은 P3 bridge를 배선하고 `READY → MAPPING → CANDIDATE_SCAN`
  전이, Candidate 저장, blocked trajectory 기록을 수행한다. overlay build, kill/reset, retry budget과
  함께 report/judge 단계가 실제 batch 결과를 끝까지 소비하는지만 통합 시 확인할 것.
- P3: 공용 verifier/candidate 모듈을 유지하면서 P3 배정 8개를 실행하고, P2/P1 실행 중 발견되는
  공용 verifier·인증 모드 문제만 모듈 소유자로서 보완할 것.
- P4: P1 judge가 확정한 verified/fixed evidence만 trajectory에 수집할 것. GPU 학습은 이 라벨된
  closed-loop 결과가 충분히 쌓인 뒤 시작한다.

## 결정·가정·리스크

- P2는 `c2-04`를 유지하지만, P3의 live verifier 완료를 기다리는 상태는 아니다. reset은 새 승인된
  run 또는 운영자 지시가 있을 때만 실행한다.
- `c3-08` OAuth 대상의 DB seed/session fixture는 P3가 실제 검증 계약을 요청할 때만 만든다.
- Notion 체크는 우선순위 신호이며 배제 규칙은 아니다. P2가 source/manifest/runtime viability를
  확인한 W1 대상은 현재 5/5/8 배분 안에서 진행할 수 있다.
- 5/5/8은 역할 재분배가 아니라 target별 audit 실행량 분담이다. P2 배정은 `c2-01`(suspect 12) →
  `c2-02`(1) → `c1-06`(1) → `c1-07`(5) → `c1-03`(0) 순서로 실행하며, fixture 준비만으로
  완료 처리하지 않는다.
- `c2-01`의 source 계약을 재점검했다. `/api/v1/auth/signup`은 user id만 반환하고,
  `/api/v1/auth/login`이 `access_token`을 반환한다. 현재 P3 bearer verifier는 signup response에서
  token을 찾는 `c1-05` 형태만 지원하므로, local process DB password로 runtime을 준비한 뒤에도
  P3의 login-path bearer 확장 또는 동등한 fixture contract가 있어야 Candidate 검증을 시작할 수 있다.
- `c2-01` MCP register/build는 통과했지만 기존 Docker database volume이 이전 비밀번호로 초기화되어
  schema migration이 `InvalidPasswordError`로 실패했다. 새 process-local 비밀번호로 재현하려면
  `vc_reset_target(..., approved=True)`가 필요하며, 승인 전에는 해당 local volume을 보존한다.
- 사용자 승인 후 `c2-01`의 전용 Compose database/redis volume을 `vc_reset_target(..., approved=True)`로
  초기화했다. 새 process-local DB password로 `run-abc76bd16b75` build PASS, start healthy,
  `vc_check_readiness` ready, `python_regression` PASS를 확인했다. 현재 API는 loopback
  `http://127.0.0.1:14011`에서 실행 중이다. access-control scan은 아직 P3 fixture contract가 없어
  Candidate 0 / `fixture_contract_required` blocked를 정상 기록했다.
- `c2-02` source preflight: `/api/auth/signup`은 `{username,password}`와 `accessToken`을 반환한다.
  프리필터 1건은 path-id가 없는 authenticated leaderboard aggregate(`GET /`)라 현재는 false positive
  후보로 분류했다. runtime reset/기동 뒤 scoped clean 또는 evidence로 확정한다.
- `c2-02` 실행 batch: `run-7ec9f46e4519`에서 manifest register와 Docker build가 PASS했고,
  `vc_scan_access_control`은 `READY → MAPPING → CANDIDATE_SCAN`으로 전이했다. Candidate는 0개이며
  `.vibecutter/trajectories/run-7ec9f46e4519.jsonl`에 `fixture_contract_required` / `인증/seed 방식 미확정`
  blocked 사유가 남았다. 이는 endpoint만 보고 임의 요청을 보내지 않은 정상 결과다. P3의 선언형 bearer
  계약 뒤 P2가 self-signup provisioning override를 추가하면 같은 target을 live scope로 재개한다.
- `c1-06` source/batch: `/api/auth/signup`은 `{email,password,nickname}`에서 `token`을 즉시 반환한다.
  `run-a1498e9a2489`의 manifest register/Docker build는 PASS했고, access-control scan은 Candidate 0과
  `fixture_contract_required` blocked를 trajectory에 남겼다. 유일한 prefilter는 `/api/demo/settle`이며
  `promiseId`를 받지만 인증 미들웨어가 없다. P3가 auth-none state-change 또는 two-role resource verifier
  중 적용할 contract를 지정하면 P2가 같은 local runtime으로 재개한다.
- `c1-07` source preflight: 유일한 login은 Google ID-token을 검증하는 `/api/auth/google`이며 성공 시
  `mp_session` opaque cookie를 서버 메모리 `Map`에 생성한다. seed는 game/score data만 만들고 user를
  만들지 않는다. 따라서 DB seed만으로는 role fixture를 만들 수 없고, P2가 임의 OAuth 우회나 세션 주입을
  하지 않는다. trusted local test-login 또는 session-fixture 계약이 생기기 전에는 이 target을
  `fixture_contract_required` blocked로 남긴다.
- `c1-07` 실행 batch: Docker build 중 UTF-8 출력이 Windows CP949 decoding을 깨는 P2 lifecycle 결함을
  발견·수정한 뒤 `run-d1cc7c5befa7` build PASS와 access-control scan을 확인했다. Candidate 0,
  `fixture_contract_required` blocked가 trajectory에 남았다.
- `c1-03` 실행 batch: `run-b5a3643a31b9`에서 Spring Docker build PASS, Candidate 0,
  `fixture_contract_required` blocked가 trajectory에 남았다. IDOR prefilter도 0건이다. 현재 local에
  `semgrep`/`osv-scanner`가 없어 P4 static gate 없이 scoped clean을 확정하지 않는다.

## P1/P3 전달 메시지

### P1

최신 main의 `vc_scan_access_control` 배선(bridge 호출, `READY → MAPPING → CANDIDATE_SCAN`, Candidate 저장,
blocked trajectory 기록)을 확인했다. P2는 `c2-02`부터 실제 batch 결과를 남긴다. P1은 이 결과가 report/judge
단계에서 누락되지 않는지만 통합 시 확인해 달라.

### P3

P2 첫 두 target은 고정 `{name,email,password}` signup 가정과 다르다. `c2-01`은 signup 뒤
`/api/v1/auth/login`으로 `access_token`을 받고, `c2-02`는 `{username,password}` signup에서
`accessToken`을 받는다. target별 하드코딩 대신 bearer probe에 선언형 `signup_payload`과 선택
`login_path`/`login_payload` 계약을 추가해 달라. P2는 endpoint·field·token key를 제공하고,
그 뒤 self-signup runtime으로 Candidate→verify를 실행한다.
추가로 `c1-06`은 signup payload `{email,password,nickname}`, token key `token`이며 `/api/demo/settle`
후보는 인증 없이 `promiseId`를 받는다. 이 endpoint의 intended verifier mode(auth-none state change vs
two-role resource replay)를 contract로 지정해 달라.

`c2-01`은 이제 loopback runtime이 실제 준비됐다(`run-abc76bd16b75`, health/readiness/regression PASS).
선언형 bearer bridge에는 `signup_path=/api/v1/auth/signup`, signup body fields
`email,password,name`, `login_path=/api/v1/auth/login`, token key `access_token`을 넣으면 된다.
P2는 endpoint의 ID 기반 workspace/map/block/comment resource 생성 경로를 확인했으며, verifier가
요청할 typed candidate/fixture schema에 맞춰 두 역할 provisioning을 이어서 제공한다.
- Semgrep의 Python 3.14 호환 실패는 P2 runtime 문제가 아니다. 팀의 실행 기준을 3.11 또는 3.12로
  통일해야 P4 static gate와 P1 final judge가 안정적으로 동작한다.
