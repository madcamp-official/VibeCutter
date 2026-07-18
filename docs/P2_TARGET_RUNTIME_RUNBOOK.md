# P2 Target Runtime Runbook

P2는 승인된 manifest의 격리 build/start/reset/worktree만 제공한다. 취약점 재현,
evidence 저장, `verified`/`fixed` 판정은 P3/P1 소유다.

## Clean-room 후보

- **P3 live verifier:** `26s-w1-c2-04` — 현재 P3가 사용할 수 있는 instance/fixture가 있으므로
  다른 작업자가 reset하지 않는다.
- **holdout/demo runtime:** `26s-w1-c3-09` — local MySQL volume을 `down --volumes`로 제거하는
  reset command, loopback-only Compose, local seed 기반 smoke command를 가진다. 이 선택은
  실행 환경 기준이며 보안 검증 또는 취약점 존재를 뜻하지 않는다.

`c3-09` preflight는 `docker compose config --quiet`와
`catalog.readiness_for("26s-w1-c3-09")`로 확인한다. 2026-07-18 기준 readiness는
`ready=True`이고 실행 파일 누락이 없다.

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
