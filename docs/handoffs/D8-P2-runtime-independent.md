# D8 / P2 Handoff

## 상태
진행 중 — P2 runtime primitive와 P1 orchestration lease 배선 완료. Juice Shop source/build/reset은 통과했으나 Windows Docker Desktop의 `internal: true` 네트워크에서 host health/smoke가 timeout되어 운영 Linux 재검증 대기

## 변경 파일

- `runtime/registry.py`: 승인 manifest snapshot(`manifest.yaml`/`approval.yaml`) 저장·복원,
  legacy JSON 읽기 호환, `allowed_hosts` hostname-only 저장, `manifest_for()` helper
- `runtime/target_lease.py`: target당 단일 active run lease의 acquire/release/reap
- `tests/test_registry.py`: snapshot artifact·hostname-only 회귀 검증
- `tests/test_target_lease.py`: 충돌·소유자·만료·입력 검증
- `runtime/catalog.py`: built-in source-lock과 user registry snapshot/source path 이중 출처
  discovery 및 user source root 분기
- `runtime/run_overlay.py`: patched Compose의 build context와 source Dockerfile을 모두
  run worktree로 재지정해 패치가 실제 이미지 빌드에 반영되도록 보강
- `targets/source-lock.yaml`, `targets/manifests/juice-shop.yaml` 및
  `targets/compose/juice-shop.yaml`: P3 SQLi 계약용 Juice Shop pinned source와
  loopback/read-only smoke runtime 등록
- `tools/juice_shop_smoke.py`: 고정 loopback search endpoint의 비파괴 regression smoke
- `runtime/source_bootstrap.py`: Windows 긴 경로 checkout 오판을 막기 위한 `core.longpaths=true` clone/checkout 옵션
- `targets/dockerfiles/juice-shop.Dockerfile`: pinned upstream Dockerfile의 EOL Buster base를 Bookworm으로 치환한 빌드 호환 overlay
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

- `py -3.13 -m unittest tests.test_run_overlay tests.test_runtime_metadata tests.test_target_lease tests.test_catalog tests.test_registry`
  - 23/23 통과
- snapshot과 lease primitive는 P2 runtime/catalog에 연결됨
- lease의 P1 driver acquire/finally-release 호출과 user Compose patched-runtime 재기동은 아직 미연결
- pinned source bootstrap: `ready`, revision `1867b926c5f50e4e692dc9c8f61821413cebe0cd`
- `docker compose ... build`: 통과. upstream Buster mirror EOL로 Bookworm overlay 필요
- lifecycle `start`와 `reset(approved=True)`: 통과, reset 후 Juice Shop container/network 잔여 없음
- lifecycle `health`/`search_smoke`: Windows Docker Desktop에서 `internal: true` network의 published loopback port가 host에서 연결 거부되어 timeout. 동일 image를 default bridge로 직접 실행하면 search HTTP 200으로 앱 자체 기동은 확인
- CAMP-1 (`172.10.5.178`)에서 최신 main pull 및 source bootstrap은 성공. Linux Docker build는 `npm install --omit=dev --unsafe-perm` 단계에서 502.8초 동안 진전 없이 대기해 중단했으며, 이는 앱 코드 실패가 아니라 CAMP↔npm registry 경로/의존성 설치 지연으로 분류한다. 중단 후 Juice Shop active container와 14006/14007/14020 포트는 없었다. 서버에는 이전 target의 exited container 기록이 남아 있으나 이번 실행에서 생성하지 않았다.

## 다른 역할에 필요한 사항

- P1: `LocalRegistry.manifest_for()` 소비와 batch-level lease acquire/worker renew/finally-release
  배선을 main에 반영했습니다. fresh run에서 metadata까지 연결해 주세요.
- P4/P1: observed LLM recorder 결과를 rerank trajectory `result`에 저장하는 T-2 배선을
  main에 반영해 주세요.
- P3: `running_local` patched-worktree restart 조건은 §3A-5 그대로 유지합니다.
- P3: CAMP-1 Docker build가 npm registry 지연으로 중단되었으므로 J-3 실행 전 의존성 cache/registry 경로를 확인해 주세요.

## 결정·가정·리스크

- `allowed_hosts`는 `["127.0.0.1"]`처럼 hostname만 저장하고, port는 승인 snapshot의
  `base_url`에서만 결정합니다.
- user registry snapshot과 built-in source-lock은 별도 경로입니다.
- lease 파일은 `~/.vibecutter/leases/<target_id>/lease.json`에 저장되며 evidence DB와
  섞지 않습니다.

## 사용자 확정 운영 결정 (2026-07-22)

- 72B fallback 준비 전에는 235B primary 단독 운영.
- 235B 장애 시 안전한 휴리스틱 degrade 허용. 해당 run은 LLM 사용 표본에서 별도 표시/제외.
- Juice Shop은 발표 target에서 제외하고 Injection 후보·verifier·LLM patch 경로의 엔지니어링
  검증용으로만 유지.
- Juice Shop runtime smoke/검증은 CAMP default-bridge를 기준으로 하며, 기존 pinned source와
  Compose 계약은 build/static/scope/patch 재현성을 위해 보존.
- 발표 순서는 c1-05 → c2-04, c3-09는 holdout/clean-room으로 유지.

## D9 독립 검증 (2026-07-22)

- runtime/registry/metadata/lease/catalog/overlay/source-bootstrap/lifecycle/Compose-isolation/source-lock
  회귀: **52 passed, 5 subtests passed** (기존 `utcnow()` deprecation warning 11건).
- 로컬 default-bridge Juice Shop smoke: `/` 및 pinned search 계약을 `tools/juice_shop_smoke.py`로
  실행해 **exit 0**. 임시 `p2-juice-runbook-smoke` container는 종료·삭제했고 14020은 listener가
  남지 않았다(TCP TIME_WAIT만 일시 관찰).
- 전체 registry policy 모음은 1건이 환경 간섭으로 실패했다. OS 임시 디렉터리가 상위 사용자
  Git 저장소로 해석되어 non-Git 차단 테스트가 dirty-repo 경로를 탔다. P2 코드 변경으로 우회하지
  않고 해당 테스트 하네스 이슈로 기록한다.

## D9 후속 수정 (2026-07-22)

- 위 현상은 단순 테스트 간섭이 아니라 등록 preflight가 상위 Git 저장소의 하위 디렉터리를
  독립 프로젝트로 오인할 수 있는 실제 계약 결함으로 확인했다.
- `mcp_server/tools_inventory.py::_git_state()`가 `git rev-parse --show-toplevel` 결과와
  `source_path`를 비교하도록 최소 보정했다. 상위 저장소 하위 경로는 명확한 blocker로 거부하고,
  독립 프로젝트에는 `git init` 안내를 유지한다.
- registry policy 및 P2 runtime 회귀: **68 passed, 5 subtests passed** (기존 deprecation warning만 남음).
