# TEAM_CONTRACT §3A 구현 추적

상위 계약은 [`TEAM_CONTRACT.md`](../TEAM_CONTRACT.md)의 §3A다. 이 문서는 계약을 다시
정의하지 않고, **현재 코드·테스트로 아직 닫히지 않은 구현 항목**만 추적한다.

## 완료 판정

- `[x]`는 `origin/main`에서 코드와 관련 테스트를 직접 확인한 항목이다.
- `[ ]`는 계약은 확정됐지만 구현 또는 E2E 검증이 남은 항목이다.
- built-in demo target은 fallback으로 유지한다. 사용자 registry와 충돌 시 등록을 거부하며,
  자동으로 built-in target으로 대체 실행하지 않는다.

## 이미 확인된 항목

- [x] **P1 / §3A-1** `vc_register_local_target` preview·명시 승인 인터페이스.
- [x] **P1 / §3A-3** built-in `target_id` 충돌은 등록 preview의 blocker로 거부.
- [~] **P1 / §3A-4** dirty Git repo 차단 로직은 구현됐으나, registration preview도
  `git rev-parse --show-toplevel == source_path`를 강제해야 한다. 현재 하위 디렉터리가
  상위 Git repo에 포함되면 Git root처럼 인식될 수 있다.
- [x] **P2 / §3A-6 사실 확인** `reset_run()`은 run Compose 정리 뒤 worktree를 제거한다.
- [x] **P3·P2 / §3A-9 기반 API** `restore_baseline_after_write()`가 존재한다.

## 우선 구현 목록

### P2 — registry와 runtime

- [~] **§3A-2 승인 manifest snapshot**: registry는 `<target_id>/manifest.yaml`과
  `approval.yaml` 구조로 바꾸고, catalog가 snapshot만 읽도록 연결한다. hash만 보관하는
  P2 registry 내부 저장·복원은 구현됐지만 catalog 연결은 남아 있다.
- [~] **§3A-2 host/port 계약**: registry가 `allowed_hosts=["127.0.0.1"]`처럼 hostname만
  저장하도록 구현했다. port를 승인 snapshot의 `base_url`에 고정하는 lifecycle/health
  검증은 catalog 통합 시 닫아야 한다.
- [~] **§3A-8 target별 active-run lease**: P2 runtime에 원자적 acquire/release/reap
  primitive와 단위 테스트를 추가했다. P1 orchestration의 acquire/finally-release 연결은
  아직 남아 있다.
- [ ] **R-4/R-5 catalog 이중 출처**: built-in은 기존 source lock/bootstrap을 유지하고,
  user target은 승인된 source path·snapshot을 사용한다. 외부 user Git repo에서
  lifecycle/overlay/worktree가 동작하는 E2E 테스트가 필요하다.

### P1 — 사용자 흐름과 산출물

- [ ] **§3A-1/4 Git root preflight 보정**: `source_path`가 Git worktree 안의 임의 하위
  디렉터리가 아니라 실제 Git top-level과 일치하는지 확인한다. 이 규칙은 P2 registry의
  worktree 생성 전제와 같아야 한다. 관련 non-Git test는 사용자 home 자체가 Git repo인
  환경에서도 안정적으로 실행되게 고친다.
- [ ] **§3A-6 `vc_export_patch(run_id)`**: reset 전에 patch diff를
  `.vibecutter/runs/<run_id>/security-fix.patch`로 보존하고 반환한다.
- [ ] **§3A-7 승인 후 재개**: driver가 `confirmed=True`를 자동으로 넘기지 않는다.
  `PATCH_PROPOSED`/`WAITING_APPROVAL`에서 멈추고 Host의 명시 승인으로 apply·validation을 재개한다.
- [ ] **§3A-10 report redaction**: HTML, SARIF, patch diff, container log의 사용자 대면
  출력에 redaction을 적용하고 테스트한다.

### P3 — 판정과 재기동

- [ ] **§3A-5 `running_local` FIXED 조건**: build + patched-worktree restart + health가
  모두 가능한 target만 `FIXED`까지 진행한다. 하나라도 없으면 scan/verify·최대
  `PATCH_PROPOSED`까지만 허용한다.
- [ ] **§3A-9 write 원복 호출 검증**: write verifier가 실제 호출 뒤 항상
  `restore_baseline_after_write()`를 수행하는 E2E 테스트를 추가한다.

### P1·P4 — 외부 LLM 경계

- [ ] **§3A-10 egress 동의**: 등록 시 또는 첫 LLM 호출 전에 코드 일부가 LLM 질의로
  전송됨을 한 번 표시하고 기록한다. egress 실패/거부 시 template·heuristic으로 안전하게
  degrade하는 결과도 사용자에게 표시한다.

## E2E 종료 조건

- [ ] clean Git user project 등록 → registry snapshot 생성 → registry target policy 통과
- [ ] scan/verify → `PATCH_PROPOSED`에서 사용자 승인 대기
- [ ] 승인 후 patched worktree에서 6게이트 → `FIXED`
- [ ] patch file export 확인 → reset 뒤에도 artifact 보존 확인
- [ ] write verifier가 있으면 shared baseline restore 및 target lease 해제 확인
