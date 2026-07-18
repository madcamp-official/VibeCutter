# D3 / P2 Status Update

> 이 문서는 Day3 구현 후 수행한 runtime 감사와 협업 상태 갱신이다. Day5 통합 freeze 또는
> 최종 재현 작업이 끝났다는 뜻이 아니며, Day5 handoff 번호는 실제 최종 통합까지 비워 둔다.

## 상태

진행 중 — P2의 manifest/catalog, target-source worktree, run-scoped Compose overlay,
rollback/reset, regression runner는 구현·검증됐다. 이제 남은 P2 관련 병목은 기능 부재가 아니라
P1 judge가 이 인터페이스를 실제 patched run에 호출하도록 연결하는 일이다.

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
- P1: target 목록을 읽어 P2 provisioning → P3 scan/verify → evidence store → report 순서로
  호출한다. patch가 있으면 P2 run-scoped overlay로 patched worktree를 build/start하고,
  kill switch는 `reset_run()`으로 정리한다.
- 상세 계약·순서는 `docs/VERIFIER_BATCH_INTERFACE.md`가 단일 기준이다.

## 검증

- 전체 회귀 139건 PASS. 이 중 P2 관련 항목은 checked-in manifests, catalog, overlay,
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

- P1: Compose 기반 `check_build()`/start 경로에서 static manifest 실행 대신 P2 overlay를 호출해
  patched worktree를 build/start하도록 배선할 것. P1의 kill switch에는 `reset_run()`을 연결할 것.
  기존 baseline container와 run overlay는 같은 loopback port를 쓰므로 실행 순서도 명시할 것.
- P3: `find_idor_suspects()` 결과를 위 Candidate 계약으로 변환하고 `c2-04` fixture와 `c1-05`
  self-signup 경로에서 verifier가 직접 소비하도록 연결할 것. P3는 patched base URL을 대상으로
  attack/positive evidence를 기록한다.
- P4: P1 judge가 확정한 verified/fixed evidence만 trajectory에 수집할 것. GPU 학습은 이 라벨된
  closed-loop 결과가 충분히 쌓인 뒤 시작한다.

## 결정·가정·리스크

- P2는 `c2-04`를 유지하지만, P3의 live verifier 완료를 기다리는 상태는 아니다. reset은 새 승인된
  run 또는 운영자 지시가 있을 때만 실행한다.
- `c3-08` OAuth 대상의 DB seed/session fixture는 P3가 실제 검증 계약을 요청할 때만 만든다.
- Notion 체크는 우선순위 신호이며 배제 규칙은 아니다. P2가 source/manifest/runtime viability를
  확인한 W1 대상은 현재 5/5/8 배분 안에서 진행할 수 있다.
- Semgrep의 Python 3.14 호환 실패는 P2 runtime 문제가 아니다. 팀의 실행 기준을 3.11 또는 3.12로
  통일해야 P4 static gate와 P1 final judge가 안정적으로 동작한다.
