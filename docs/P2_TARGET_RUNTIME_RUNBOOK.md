# P2 Target Runtime Runbook

이 문서는 P2 runtime 계약이다. P2가 target audit operator로 일할 때는 공통 verifier/judge를
사용해 취약점 재현과 evidence 생성도 수행할 수 있지만, runtime 계층 자체의 책임은 승인된
manifest의 격리 build/start/reset/worktree 제공으로 제한한다. `verified`/`fixed` 최종 판정은
항상 evidence와 deterministic judge를 거친다.

## Clean-room 후보

- **P3 live-verifier 증명 대상:** `26s-w1-c2-04` — P3의 read/write IDOR live 검증은
  완료됐다(`docs/handoffs/D3-P3.md`). 현재 인스턴스와 fixture는 재현·통합 리허설에 다시
  쓸 수 있으므로, P1의 승인된 run 또는 운영자 지시 없이 다른 작업자가 reset하지 않는다.
- **패치 closed-loop 후보:** `26s-w1-c1-05` — P3가 disposable clone에서 수동
  apply→rebuild→replay를 실증했다. 아직 P2 worktree overlay를 경유하는 자동 run은 없으며,
  인증 fixture 계약을 P3가 확정하기 전에는 P2가 token/credential fixture를 만들지 않는다.
- **holdout/demo runtime:** `26s-w1-c3-09` — local MySQL volume을 `down --volumes`로 제거하는
  reset command, loopback-only Compose, local seed 기반 smoke command를 가진다. 이 선택은
  실행 환경 기준이며 보안 검증 또는 취약점 존재를 뜻하지 않는다.

`c3-09` preflight는 `docker compose config --quiet`와
`catalog.readiness_for("26s-w1-c3-09")`로 확인한다. 2026-07-18 기준 readiness는
`ready=True`이고 실행 파일 누락이 없다.

patched build 전에는 `catalog.worktree_manager_for(target_id).create(run_id)`와
`catalog.run_overlay_for(target_id, run_id).prepare()`를 호출한 뒤 generated Compose에
`docker compose config --quiet` 및 overlay isolation 검사를 수행한다. `c3-09`에서 이
worktree-only static preflight를 통과했고, 검증용 worktree는 즉시 제거했다.

## 자동 closed-loop 연결 상태

P2의 run-scoped Compose overlay, patched source-root projection, worktree regression runner,
`reset_run()`은 구현되어 있다. P1 judge의 `check_build()`와 `check_regression()`은 Compose 기반
target에서 `catalog.run_overlay_for(target_id, run_id)`를 사용하므로, checked-in Compose가 원본
source clone을 보지 않고 run-scoped worktree build context를 보게 된다.

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
- GPU 서버 접근 가능 여부는 P4의 model-serving/학습 준비 조건이다. 서버 접속 정보나 자격 증명은
  이 runbook에 기록하지 않으며, Python 3.11 또는 3.12 기반의 Semgrep·모델 환경을 P4가 한 서버에서
  먼저 통일한 뒤 다른 GPU로 확장한다.
