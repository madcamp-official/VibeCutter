# D8 / P2 Handoff

## 상태
진행 중 — P2 내부 runtime primitive 완료, P1 orchestration 연결 대기

## 변경 파일

- `runtime/registry.py`: 승인 manifest snapshot(`manifest.yaml`/`approval.yaml`) 저장·복원,
  legacy JSON 읽기 호환, `allowed_hosts` hostname-only 저장, `manifest_for()` helper
- `runtime/target_lease.py`: target당 단일 active run lease의 acquire/release/reap
- `tests/test_registry.py`: snapshot artifact·hostname-only 회귀 검증
- `tests/test_target_lease.py`: 충돌·소유자·만료·입력 검증
- `runtime/catalog.py`: built-in source-lock과 user registry snapshot/source path 이중 출처
  discovery 및 user source root 분기
- `tests/test_catalog.py`: source-lock 없는 user target discovery/source repository 검증
- `P2_new_plan.md`: R-1/R-6를 내부 구현 완료·통합 대기 상태로 갱신
- `docs/CONTRACT_IMPLEMENTATION_TODO.md`: §3A 진행 상태 갱신

## 제공 인터페이스

- `LocalRegistry.manifest_for(target_id) -> TargetManifest`
  - 승인 당시 `<registry>/<target_id>/manifest.yaml`만 읽음
  - 사용자 원본 manifest를 재조회하지 않음
- `TargetLeaseManager(root=None)`
  - `acquire(target_id, run_id, ttl_seconds=900) -> TargetLease` (즉시 실패, TTL 기준)
  - `renew(target_id, run_id, ttl_seconds=900) -> TargetLease`
  - `get(target_id) -> TargetLease | None`
  - `release(target_id, run_id) -> bool`
  - `reap_stale(target_id) -> bool`
- `runtime.metadata.RuntimeMetadata` / `append_runtime_metadata()`
  - P4 join용 secret-free run JSONL
  - lease 소유 run/만료 시각은 선택 필드로만 기록

## 실패/예외

- active lease가 있으면 `TargetBusyError` (`RuntimeError` 계열)
- 다른 run이 release/renew하면 `TargetBusyError`
- 만료 lease는 새 acquire 전 회수 가능
- 잘못된 target/run slug 또는 양수 아닌 `ttl_seconds`는 `ValueError`
- snapshot이 없는 legacy entry에서 `manifest_for()`를 호출하면 재승인 요구 `ValueError`

## 검증

- `py -3.13 -m unittest tests.test_catalog tests.test_registry tests.test_target_lease`
  - 16/16 통과
- snapshot과 lease primitive는 P2 runtime/catalog에 연결됨
- lease의 P1 driver acquire/finally-release 호출과 user Compose patched-runtime 재기동은 아직 미연결

## 다른 역할에 필요한 사항

- P1: catalog가 `LocalRegistry.manifest_for()`를 소비할지 확인해 주세요.
- P1: audit 시작 전 `acquire(target_id, run_id)` 및 reset/kill/failure의 `finally`에서
  `release(target_id, run_id)`를 호출할 위치를 확정해 주세요.
- P3: `running_local` patched-worktree restart 조건은 §3A-5 그대로 유지합니다.

## 결정·가정·리스크

- `allowed_hosts`는 `["127.0.0.1"]`처럼 hostname만 저장하고, port는 승인 snapshot의
  `base_url`에서만 결정합니다.
- user registry snapshot과 built-in source-lock은 별도 경로입니다.
- lease 파일은 `~/.vibecutter/leases/<target_id>/lease.json`에 저장되며 evidence DB와
  섞지 않습니다.
