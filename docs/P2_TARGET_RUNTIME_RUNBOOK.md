# P2 Target Runtime Runbook

이 문서는 P2 runtime 계약이다. P2가 target audit operator로 일할 때는 공통 verifier/judge를
사용해 취약점 재현과 evidence 생성도 수행할 수 있지만, runtime 계층 자체의 책임은 승인된
manifest의 격리 build/start/reset/worktree 제공으로 제한한다. `verified`/`fixed` 최종 판정은
항상 evidence와 deterministic judge를 거친다.

## 현행 범위 — audit 업무 분담 폐지, runtime 배치 유지

사용자/팀 최신 결정으로 P1/P2/P3가 target을 나눠 audit operator로 수행하던 `P1 5 / P2 5 / P3 8`
분담 계획은 폐지한다. 이후 repo별 후보 선별·검증 실행은 다시 P3가 전담하고, P2는 필요한 순간에만
runtime/provisioning/fixture/worktree/overlay/reset/test-runner 지원을 제공한다.

따라서 P2는 더 이상 `c2-01`, `c2-02`, `c1-06`, `c1-07`, `c1-03`을 독립 audit queue로 계속
밀지 않는다. 기존에 남긴 build/health/Candidate/blocked/evidence 기록은 당시 실행 이력으로만
보존하고, 새 audit 완료 판정에는 P3가 공통 파이프라인으로 만든 Candidate/evidence와 P1 judge 결과를
사용한다.

`targets/runtime_batches/gpu_3way.yaml`의 GPU-1/2/3 7/7/6 분할은 **runtime placement**다.
P1/P2/P3가 target을 나눠 공격한다는 뜻이 아니며, audit 실행 소유자는 계속 P3다. queue loader는
20개 allowlist target의 누락·중복을 막지만 원격 SSH dispatcher나 worker scheduler는 아니다.

P3가 특정 target에서 막히면 P2는 아래 입력을 받아 최소 범위로 지원한다.

- `target_id`, 필요한 runtime 상태(build/start/reset/run overlay)
- 필요한 fixture 종류(`fixture_file`, `self_signup`, session/test-login, `safe_mutation` 등)
- secret을 제외한 role/resource/endpoint schema
- reset 또는 fixture prepare처럼 mutation 단계가 필요한지 여부

## Clean-room 후보

- **P3 live-verifier 증명 대상:** `26s-w1-c2-04` — P3의 read/write IDOR live 검증은
  완료됐다(`docs/handoffs/D3-P3.md`). 배치 종료 뒤 container/volume은 정리됐으며, 재현 시
  승인된 fixture prepare → build/start 순서로 fresh instance를 만든다.
- **패치 closed-loop 후보:** `26s-w1-c1-05` — P2 worktree overlay를 경유한 자동
  verify→apply→rebuild→replay→validation이 `verified → fixed`를 완주했고, 종료 뒤
  `reset_run=True`와 포트·overlay·worktree 잔여 0을 확인했다. token/credential은 메모리의
  일회성 self-signup 값만 사용한다.
- **holdout/demo runtime:** `26s-w1-c3-09` — local MySQL volume을 `down --volumes`로 제거하는
  reset command, loopback-only Compose, local seed 기반 smoke command를 가진다. 이 선택은
  실행 환경 기준이며 보안 검증 또는 취약점 존재를 뜻하지 않는다.

`c3-09` preflight는 `docker compose config --quiet`와
`catalog.readiness_for("26s-w1-c3-09")`로 확인한다. 2026-07-20 GPU 실측에서 공식
`gradle:9.5.1-jdk17` builder로 Spring build를 통과했고 DB/server/frontend healthy,
API와 frontend HTTP 200을 확인했다.

patched build 전에는 `catalog.worktree_manager_for(target_id).create(run_id)`와
`catalog.run_overlay_for(target_id, run_id).prepare()`를 호출한 뒤 generated Compose에
`docker compose config --quiet` 및 overlay isolation 검사를 수행한다. `c3-09`에서 이
worktree-only static preflight를 통과했고, 검증용 worktree는 즉시 제거했다.

## 자동 closed-loop 연결 상태

P2의 run-scoped Compose overlay, patched source-root projection, worktree regression runner,
`reset_run()`은 구현되어 있다. P1 judge의 `check_build()`와 `check_regression()`은 Compose 기반
target에서 `catalog.run_overlay_for(target_id, run_id)`를 사용하므로, checked-in Compose가 원본
source clone을 보지 않고 run-scoped worktree build context를 보게 된다.

최신 main의 `mcp_server.driver.run_target_audit()`는 batch 시작 sweep, target build/start,
scan parent Run, candidate별 worker Run, target별 순차 verify/repair, patch overlay 생성 worker의
종료 reset을 연결한다. 따라서 이전 handoff의 “P1 orchestration 배선 대기”는 해소됐다.

Patch diff는 `catalog.source_root_for(target_id)` 기준 상대 경로여야 한다. `source_dir`가 target
Git repository의 하위 디렉터리(예: `backend`, `main`, `backend/server`)인 경우에도
`vc_apply_patch`는 `catalog.run_source_root_for(target_id, run_id)`에서 `git apply`를 실행한다.
따라서 P3 patcher는 repo-root 기준 `backend/src/...`가 아니라 source-root 기준 `src/...` diff를
생성해야 한다.

P1의 승인된 patch run은 아래 순서로 P2 인터페이스를 호출해야 한다.

1. `catalog.worktree_manager_for(target_id).create(run_id)`로 target Git worktree를 확보한다.
2. `catalog.run_overlay_for(target_id, run_id).prepare()`로 generated Compose와 isolation 검사를
   만든다.
3. `overlay.execute("build")` → `overlay.execute("start")` → health를 실행한다.
4. P3가 그 patched instance에 attack replay/정상 기능 검증을 수행하고, regression은
   Compose target이면 `overlay.execute(<test command_id>)`, source-native target이면
   `catalog.test_runner_for(target_id).run(run_id)`로 실행한다.
5. 종료·kill switch는 `TargetRuntimeService.reset_run(target_id, run_id, approved=True)`로만 한다.

generated Compose는 원본의 loopback port mapping을 보존한다. baseline instance가 같은 포트를
점유한 상태에서는 patched instance를 동시에 start할 수 없다. baseline을 승인된 reset으로 내리거나,
공통 manifest 계약을 변경해 별도 port projection을 도입하기 전에는 동시 실행을 가정하지 않는다.

write verifier가 shared baseline DB를 변경한 경우 `reset_run()`은 그 데이터를 원복하지 않는다.
`reset_run()`은 patched worktree/overlay 전용이므로, write worker 종료 뒤에는 별도 승인을 받아
manifest reset을 실행하고 fixture를 다시 준비해야 한다.

## Source bootstrap 및 verifier coverage

- `.vibecutter/targets/sources/`는 외부 target clone과 runtime artifact가 놓이는 로컬 경로다.
  `.vibecutter/` 전체는 gitignore에 유지하며 source 전문·credential·DB·trajectory를 main에
  커밋하지 않는다.
- 현재 P2 workspace에는 manifest 22개의 managed Git source가 있고, GPU queue의 20개 target은
  세 서버에 bootstrap돼 build/start/health를 통과한 이력이 있다. 새 host에서는 repository와
  revision을 별도로 bootstrap해야 한다.
- 20개 코딩캠프 target은 모두 허가된 scan/verify 범위다. Injection/XSS candidate 0은 권한 거부가
  아니라 검사한 앱에서 prefilter 패턴을 찾지 못한 결과다.
- repeatable role-based provisioning은 `c1-05`, `c1-06`, `c2-01`, `c2-02` self-signup과
  `c2-04` fixture-file까지 5개다. 나머지는 P3가 실제 endpoint/resource/role boundary를 찾은 뒤
  P2가 안전한 seed/reset 계약을 추가한다.

## 승인된 clean-room 순서

1. P1 policy에서 target과 reset command가 허용됐는지 확인한다.
2. 사용자 또는 P1 mutation gate의 명시 승인 후에만 `TargetRuntimeService.reset(target_id,
   approved=True)`를 호출한다. reset은 manifest의 fixed `docker compose down --volumes`만 실행한다.
3. P2 lifecycle로 fixed `build` → `start` → `check_readiness`를 실행한다.
4. manifest가 선언한 smoke/regression suite만 실행한다. 임의 shell command, URL, IP는 추가하지 않는다.
5. 결과가 필요하면 P1/P3가 evidence/audit trail에 연결한다.

## Patched run rollback

P1이 승인된 diff를 target-source worktree에 적용한 run은 generated Compose overlay만 사용한다.
run 종료는 `TargetRuntimeService.reset_run(target_id, run_id, approved=True)`로 수행한다.

- approval 없이는 reset하지 않는다.
- generated Compose reset이 성공한 경우에만 해당 run worktree를 제거한다.
- reset 실패 시 worktree를 보존해 원인 확인 또는 재시도가 가능하다.
- 원본 source clone과 원본 branch는 이 절차로 변경하지 않는다.

## 인프라 제약

- manifest의 Python helper는 `"{vibecutter_python}"` token을 사용한다. 이는 VibeCutter를
  실행 중인 interpreter로만 해석되며 Windows `py` launcher에 의존하지 않는다.
- secret/token/password는 manifest, fixture metadata, handoff, audit artifact에 저장하지 않는다.
- fixture-file artifact는 reset/run-bound metadata다. 스크립트 또는 target reset 뒤에는 기존
  `.vibecutter/fixtures/*.json`을 완료 근거로 쓰지 말고, 승인된
  `vc_prepare_verifier_fixture(target_id, approved=True)`로 다시 생성한다.
- 새 fixture consumer는 `auth.mode`와 `resources.<kind>.attacker_id/victim_id/...` 정규화 필드를
  우선 사용한다. 기존 `authentication` 및 victim/attacker 분리 필드는 하위호환 목적으로 유지한다.
- 세 GPU 서버는 RTX 3090 24GB이며 P2 runtime 20개가 7/7/6으로 배치돼 있다. 서버 접속 정보나
  자격 증명은 이 runbook에 기록하지 않는다.
- 팀 로컬 스캐너/runtime 기준은 Python 3.13이다. GPU vLLM 환경은 서버 기본 호환성 때문에
  Python 3.10을 사용하며, 두 환경을 같은 venv로 취급하지 않는다.

## P2 종료 전 체크리스트

1. clean host source bootstrap/revision 계약을 남긴다.
2. P3 audit 전에 해당 target이 배정된 GPU에서 source/readiness/port를 확인한다.
3. write fixture 요청은 safe method/path/body, observe path, rollback이 모두 있을 때만 받는다.
4. patch worker 종료에는 `reset_run`, shared baseline mutation 뒤에는 승인된 manifest reset과
   fixture 재준비를 적용한다.
5. 최종 실앱 run에서 report 생성과 teardown 후 port·overlay·worktree 잔여 0을 확인한다.
