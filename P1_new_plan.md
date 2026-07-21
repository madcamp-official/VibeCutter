# P1 (이지민) — 2일 스프린트 계획

> 상위 문서: **[TEAM_CONTRACT.md](TEAM_CONTRACT.md)** — 충돌 시 그쪽이 이긴다.

## 내 역할 한 줄

**MCP 표면과 통합의 소유자.** tool/prompt/진입점, 정책 조회, 브랜치 병합, 최종 리허설.

## 내 파일 (배타적)

`mcp_server/**`, `core/policy_engine.py`, `core/report.py`, `core/orchestrator.py`, `core/state_machine.py`, `tests/**`

**남의 파일은 안 고친다.** `runtime/`(P2), `repair/`·`verifiers/`(P3), `model/`·`scanners/`(P4).

---

## ▶ 지금 해야 할 일 (2026-07-21 14:40 갱신 · 위에서부터)

**다른 사람을 막고 있는 순서**로 정렬했다. 1·2번은 P2가 3시간+ 대기 중이다.

| # | 항목 | 막고 있는 사람 | 상태 |
|---|---|---|---|
| ~~W-1~~ | `source_lock.py` external_allowlist | P2 | ✅ **완료** |
| ~~W-2~~ | P2 registry 병합 + `kind` 노출 | P2·P3 | ✅ **완료** |
| ~~W-3~~ | `Validation.build_ok: bool \| None` coerce 금지 | P3 | ✅ **완료(P3가 이미 구현)** |
| ~~W-8~~ | **lease 배선** (acquire/renew/release) | P2 | ✅ **완료** |
| ~~W-9~~ | **runtime metadata JSONL 배선** | P2 | ✅ **완료** |
| **W-4** | `vc_export_patch` + `vc_resume_audit` + driver 자동승인 제거 | P2 | 중 |
| ~~W-5~~ | R-3b `synthesize_fn` + `context_provider` 배선 | P3 | ✅ **완료** |
| **W-10** | rerank를 `observed_chat_fn_from_env()`로 교체 (T-2) | — | ⏳ P4 main 반영 대기 |
| **W-6** | `core/report.py` redaction (§3A-10) | — | 소 |
| **W-7** | `vc_export_sarif` 배선 | P4 | 소 |

> ⚠️ **스프린트 최대 리스크 — 235B endpoint 순환 대기 (2026-07-21 확인)**
> `.env`에 `VIBECUTTER_LLM_*`가 **0건**이고 `python -m model.endpoints`는 두 tier 모두 `[DOWN]`이다.
> P4는 P2에게 터널 URL을 요청하고(05:23·05:28), P2는 P1에게 "URL을 .env에 넣고 probe하라"고 요청했는데 **P1에게 URL이 없다.**
> `cloudflared` 노출은 **P2_new_plan G-1(P2 소유)**이다. 터널이 실제로 생기기 전에는 아무도 probe를 초록으로 만들 수 없고, **데모 2가 여기 걸려 있다.**

- [ ] **W-1. `source_lock.py` external_allowlist** — **최우선. 이미 승인받은 미이행 건**(03:09 설계 확정 → 03:12 anjonghwa 승인 → 권한 문제로 미적용)
  - 현재 `source_lock.py:14`가 `https://github.com/madcamp-official/{target_id}.git` **exact match**를 강제해 외부 repo가 구조적으로 불가
  - `external_allowlist` optional 최상위 필드 추가 → 거기 있는 URL은 통과. **없으면 기존 동작 100% 동일**(하위호환)
  - P2가 준 값: `https://github.com/juice-shop/juice-shop.git` @ `1867b926c5f50e4e692dc9c8f61821413cebe0cd`, target_id=`juice-shop`
  - ⚠️ `runtime/source_lock.py`는 **P2 소유 파일**이다. 03:12에 명시 승인을 받았으므로 진행하되, 완료 즉시 P2에 공지
  - ⚠️ `tests/test_source_lock_contract.py`의 target count는 **건드리지 않는다** — P2가 manifest를 추가할 때 함께 올린다(먼저 바꾸면 P2 커밋 전에 깨진다)

- [ ] **W-2. `codex/p2-local-registry`(8c6ed5c) 병합 + `kind` 노출**
  - P1 소비 코드는 **이미 main에 있다**(13706de). Protocol 기반이라 registry가 오면 **자동으로 붙는다**
  - 병합 후 확인: `LocalRegistry.load()` 실제 인스턴스로 `require_target_allowed`가 통과하는지
  - **P3 요청(05:07)**: `kind`가 judge까지 도달해야 한다. 지금은 policy_engine만 lazy-load라 judge가 못 본다 → catalog가 registry의 `manifest_for()`로 snapshot을 읽어 `kind`를 노출하는 경로를 P2와 확정
  - `manifest_for()`는 P2가 이미 구현했다(§3A-2 충족). **P1은 snapshot 파일을 직접 읽지 않는다**

- [x] **W-3. `Validation.build_ok: bool | None` coerce 금지** — **이미 완료돼 있었다.** P3가 `226a482`("running_local build 게이트 N/A 판정")에서 내 W-8 작업보다 먼저 `core/judge.py:check_build`에 직접 구현해 브랜치에 이미 들어와 있었다(내가 몰랐던 것뿐 — 05:08 약속 그대로 이행됨)
  - `check_build`가 `_target_kind(target) == "running_local"`이면 `_patch_and_worktree` 조회 직후 곧바로 `None`을 반환한다(overlay/LifecycleManager 어느 쪽도 건드리지 않고) — running_local에서 build를 못 돌리면 `None`을 **그대로 저장**한다. `False`로 바꾸면 RETRY가 되고, `True`로 바꾸면 안 돌린 게이트를 통과로 위조하는 것
  - `mcp_server/tools_repair.py:vc_build_and_test`의 `validation.build = check_build(...)`는 코어스 없이 그 값을 그대로 대입 — 확인 완료
  - `compute_verdict()`가 `None` 하나면 verdict를 안 내므로 **FIXED가 구조적으로 불가**해진다 — 이게 §3A-5의 강제 수단이다(추가 방어 불필요). 일반 케이스는 `ComputeVerdictTests.test_none_while_any_gate_is_unset`가 이미 고정하고 있었음
  - **빠져 있던 것**: `check_build`가 running_local에서 실제로 `None`을 내고 build를 아예 시도하지 않는지 확인하는 전용 테스트가 없었다 → `tests/test_judge.py::CheckBuildTests::test_running_local_returns_none_without_attempting_build` 추가(`LifecycleManager`/`run_overlay_for` 미호출까지 확인). `test_judge.py` 31건 전체 통과, 전체 스위트 542 passed(juice-shop/inventory 1건 제외 — 무관·기존 블로커)

- [ ] **W-4. 승인 흐름 정리** (§3A-6/3A-7, P2 회신 4·5번)
  - [ ] `vc_audit_target(target_id, mode="propose")` 노출 — 기본은 `PATCH_PROPOSED` 정지
  - [ ] `vc_export_patch(run_id)` 신규 — `.vibecutter/runs/<run_id>/security-fix.patch`. **reset보다 먼저, 실패 시 reset 금지**
  - [ ] `vc_resume_audit(run_id)` 신규 — 전제 `PATCH_APPLIED`. 6게이트 → export → reset
  - [ ] `driver.py:145`의 자동 `confirmed=True` **제거**
  - [ ] driver 진입 직후 `acquire_target_lease`, `finally`에서 `release_target_lease` (P2 구현 대기)

- [x] **W-8. lease 배선** (P2 긴급 요청 3번, §3A-8) — **완료(2026-07-21)**. `mcp_server/driver.py:run_target_audit`
  ```
  run_target_audit(target_id)
    ├─ require_target_allowed(target_id)          ← lease보다 먼저(미등록 target은 lease조차 안 잡음)
    ├─ acquire(target_id, scan_run_id)             ← 배치 진입 직후, build/start보다 먼저
    ├─ try: sweep → build → start → scan → [worker마다 renew()]
    └─ finally: release(target_id, scan_run_id)
  ```
  - **배치 전체 단위**다(worker 단위 아님) — `scan_run_id`를 `uuid4`로 미리 뽑아 lease에 쓰고, 나중에 실제 `Run(id=scan_run_id, ...)`로 재사용해 lease 소유자와 scan Run id를 일치시켰다
  - `renew()`가 필요한 이유: c1-05 실측이 후보 1개에 **136초**라 후보 10개면 TTL 900초를 넘긴다. 살아 있으면 갱신, 죽으면 900초 뒤 자동 회수
  - `TargetBusyError`(`RuntimeError` 상속)는 그대로 전파한다 — audit log의 `PermissionError` 집계를 오염시키지 않는다. 다른 배치가 이미 쥐고 있으면 build조차 시도하지 않고 즉시 실패
  - `lease_manager` 파라미터 주입 가능(기본 `~/.vibecutter/leases`) — `service`/`invoke`와 같은 DI 패턴, 테스트는 임시 디렉터리로 격리
  - 테스트: `tests/test_driver.py::TargetLeaseWiringTests` 5건(release/held-before-build/renew-per-worker/busy-target/finally-release-on-unexpected-error) 신규 + 기존 11건 전부 `lease_manager` 주입으로 갱신, 16건 전체 통과

> ⚠️ **W-8과 무관한 새 블로커 발견(2026-07-21) — `datasets/inventory.yaml`에 juice-shop 누락**
> `8b794b5`(P2, "register pinned Juice Shop SQLi runtime")가 `targets/manifests/juice-shop.yaml` + `source-lock.yaml`은 정확히 채웠지만(W-1에서 요청한 그대로), **P4 소유 `datasets/inventory.yaml`에는 juice-shop 항목을 추가하지 않았다.** `tests/test_inventory_manifest_contract.py`(체크인된 모든 manifest가 inventory에도 있어야 한다는 계약, P4 소유)가 지금 브랜치에서 **1 failure + 1 error**로 깨져 있다 — 내 W-8 변경과 무관, 순수하게 이 커밋 이후 상태다. **P2/P4 조율 필요**: `datasets/inventory.yaml`에 `juice-shop`(focus=injection) 항목 추가.

- [x] **W-9. runtime metadata JSONL 배선** (P2 긴급 요청 2번) — **완료(2026-07-21)**. `mcp_server/driver.py:_record_runtime_metadata`, 배치 종료 시점(`finally` 직전)에 1건 기록
  - P1이 채운 것: `run_id`(=scan_run_id)·`target_id`·`base_url`(`catalog.get().manifest.base_url`)·`source_commit`(`catalog.get().contract_target.source_commit`)·`health`(`adapter_for().health()` 재확인)·`readiness`(`check_readiness().ready`)·`reset_result`(이 배치 worker들이 만든 overlay가 전부 정리됐는지 — overlay를 하나도 안 만들었으면 `None`, 지어내지 않음)·`lease_run_id`·`lease_expires_at`(마지막 `acquire`/`renew` 결과)
  - ⏳ `llm_endpoint_state` — **W-10(P4 recorder) 이후.** 같은 출처를 써야 eval 표본 필터와 어긋나지 않는다(스키마 기본값 `"unknown"` 그대로 둠)
  - ❓ `gpu_worker`·`remaining_containers/worktrees/ports` — **P2에게 출처를 물었다.** 여전히 스키마 기본값(`None`/빈 리스트) 그대로 — 모르는 값을 지어내지 않는다
  - 기록 자체가 실패해도(catalog 조회 예외, IO 등) 로깅만 하고 감사 배치는 완주한다 — worker/scanner 예외 격리와 같은 원칙
  - 테스트: `tests/test_driver.py::RuntimeMetadataWiringTests` 4건(P1 필드 기록·reset_result true/None·실패해도 배치 완주) 신규. 전체 스위트 546 passed(juice-shop/inventory 1건 제외 — 무관·기존 블로커)

- [x] **W-5. R-3b `synthesize_fn` + `context_provider` 배선** — **완료(2026-07-21, 배선 #7)**. `mcp_server/tools_repair.py`
  ```python
  patch = generate_patch(
      ..., synthesize_fn=make_llm_synthesizer(_get_llm_client(), context_provider=_code_context_for),
  )
  ```
  - `_get_llm_client()`: `build_patch_model_client()` 프로세스당 1회 캐시(`None`도 캐시 — endpoint DOWN을 매번 재확인하지 않는다). `_reset_llm_client_cache()`로 테스트/장수명 서버에서 비울 수 있다
  - `_code_context_for(finding, root_cause, source_root)`: P4 `code_context()` 어댑터. `context_provider` 계약은 `(Finding, RootCause, Path) -> str | None`인데 `code_context()`는 `(candidates, index) -> {id: 스니펫}`이라 **`root_cause.file:line` 하나짜리 probe `Candidate`를 만들어** 그대로 넘긴다. 이러면 rerank(`_rag_enrich`)와 패치 합성이 **같은 CodeIndex·같은 스니펫 형식**을 공유한다(계약 3.4)
  - `RootCause`엔 줄번호가 없어(`file`/`symbol`/`rationale`만) `_line_for_root_cause()`가 `finding.source_symbols`(SAST `파일:줄`)에서 같은 파일의 줄을 복원한다. 못 찾으면(SAST가 이 파일을 안 짚었을 때) `None` → `llm_synth`가 root_cause 파일 전체(줄번호 부착)로 폴백 — 인덱싱 실패가 패치 합성을 죽이지 않는다
  - 테스트: `tests/test_tools_repair_llm_wiring.py` 10건(줄 복원 4·code_context 어댑터 3·캐시 3), 전체 스위트 535 passed
  - endpoint가 아직 전부 DOWN이라(⚠️ 위 리스크 박스) J-3 실행은 **터널이 뜬 뒤** P3가 완주 1회 돌릴 수 있다 — 배선 자체는 지금 template-only로도 안전하게 degrade한다

- [ ] **W-10. rerank를 `observed_chat_fn_from_env()`로 교체** (P4 T-1 → T-2) — ⏳ **P4가 main에 올려야 시작**(현재 `p4` 브랜치 미커밋, main에 0건)
  - `(chat_fn, recorder)`를 받아 `aggregate` 직후 `recorder().as_metadata()`를 trajectory step `result`에 병합
  - `contracts` freeze를 안 건드린다(전부 `result` dict)
  - **W-9의 `llm_endpoint_state`와 같은 출처를 쓴다** — 두 곳이 갈라지면 ablation 표본 필터와 runtime metadata가 어긋난다

- [ ] **W-6. `core/report.py` redaction** — 확인된 결함: `redact()` 호출 **0건**. evidence 8건·audit 3건과 대조. HTML 리포트로 secret이 샐 수 있다

- [ ] **W-7. `vc_export_sarif` 배선** — 렌더러(`eval/report_export.render_sarif`)는 P4 것이고 이미 동작 검증됨. tool 본문 2줄

### ✅ P0 병합 — 완료 (우리 없이 진행됨)

D1 오전 예정이던 병합을 P3·P4가 먼저 집행했다. `main` = **935e362**에 RAG·llm_synth·locator·patch_client·P1 R1이 전부 들어갔다.
남은 미반영: `codex/p2-local-registry`(8c6ed5c) → W-2, `security/agent`(2e30ade, P3 결합검증분) → P3 소관.

---

## P1 — 정책을 로컬 레지스트리로 (P2와 짝) — ✅ **P1 몫 완료 (2026-07-21)**

**의존**: P2의 `runtime/registry.py`(계약 3.1). D1 오전에 시그니처만 확정되면 **P2 구현 완료 전에도** 내 쪽을 목으로 짤 수 있다.
→ 실제로 그렇게 진행했다. **P1 쪽은 전부 끝났고, `confirmed=True` 저장 경로만 P2 대기 중**이다.

- [x] **R1-1. `core/policy_engine.py` 이중 출처 전환** — **완료**
  - `require_target_allowed(target_id, *, path=, registry=)`가 ① `policies/scope.yaml`(built-in 20개) → ② 사용자 로컬 레지스트리 순으로 조회. `is_target_allowed`·`require_host_allowed`도 동일
  - **P2의 `runtime.registry`를 import 하지 않는다** — `_ApprovedTargetLike`/`_RegistryLike` Protocol에만 의존. 레지스트리가 아직 main에 없어도 이 모듈과 테스트가 정상 동작하고, 없으면 **built-in만으로 판정하며 계속**한다(정책 게이트가 판단 자체를 못 하고 죽는 것보다 낫다)
  - `_default_registry()` 지연 로드 + 캐시, `reset_registry_cache()`로 등록 직후 즉시 반영
  - 두 출처를 **같은 모양의 dict**로 정규화 → `require_host_allowed`는 출처를 몰라도 된다
  - **built-in 우선 순서 확정**: 사용자가 실수로 같은 target_id를 등록해도 팀이 체크인한 정의가 이긴다 (c1-05 gold 보호)
  - 거부 메시지에 다음 행동을 담았다 — "자기 프로젝트라면 vc_register_local_target으로 먼저 승인하세요"

- [x] **R1-2. `vc_register_local_target` tool 신규** (`mcp_server/tools_inventory.py`) — **완료**
  - 2단계 승인. `confirmed=False`(기본)면 **아무것도 저장하지 않고** `RegistrationPreview`만 반환
  - preview에 **argv 전문**을 담는다(`{"build": ["docker","compose","build"], ...}`) — 요약·생략 없음. 이 표시가 "우리 저장소에 커밋되고 PR 리뷰됨"을 대체하는 승인 근거다(안전 불변식 2)
  - `TargetManifest.model_validate()`를 **먼저** 통과시킨다 → loopback이 구조적으로 강제된다. 실측 확인: `https://victim.example.com` → `ValueError: base_url must be a plain http loopback URL`
  - `_git_state()` 사전조건 검사 추가 (R1-5)
  - `confirmed=True` 경로는 **P2의 `runtime/registry.py` 대기 중** — 없으면 blocker 메시지로 명확히 알린다(조용히 실패하지 않음)

- [x] **R1-3. 기존 `vc_register_target` docstring 정정** — **완료**. "새 target을 만들지 않는다. 체크인 manifest와 byte 단위 동일성만 확인하는 **built-in demo 전용** tool"이라고 명시하고 `vc_register_local_target`으로 안내. 삭제하지 않음

- [x] **R1-4. 테스트 11건 신규** (`tests/test_local_registry_policy.py`) — **완료**
  - 이중 출처 7건: built-in 유지 / 사용자 target 통과 / 둘 다 없으면 거부 / **id 충돌 시 built-in 승리** / host 검사 / `is_target_allowed` / 레지스트리 부재 시 degrade
  - git 사전조건 4건: 비-git 차단 / 커밋 없음 차단 / 정상 통과 / dirty는 경고만
  - 가짜 레지스트리를 주입해 **P2 구현 없이** P1 계약을 고정
  - **전체 회귀 488건 통과** (기존 463 → 488)

- [x] **R1-5. [신규] git 사전조건 검사** — **완료**. 계획에 없었으나 코드 훑기에서 발견해 추가
  - `runtime/worktree.py:57`이 대상 소스에 `git worktree add --detach`를 하고 패치 apply·6게이트 전체가 그 worktree 위에서 돈다 → **사용자 프로젝트가 git repo가 아니면 패치 경로가 통째로 불가**
  - 비-git이면 `git init && git add -A && git commit -m init` 안내와 함께 **명확한 사유로 차단**(추측으로 진행 금지). 커밋 없는 repo도 차단, dirty worktree는 경고만
  - 확인된 좋은 점: `catalog.py:243`이 `artifact_root`를 우리 저장소 아래로 명시 지정한다 → **사용자 프로젝트 디렉터리에는 우리가 아무 파일도 만들지 않는다**

### R1에서 P2에게 넘길 발견

- [ ] **R1-X. `adapter` 열거형 확장 필요** — `AdapterKind`가 `spring-boot | fastapi | node | generic-docker` 넷뿐이다. 사용자 프로젝트가 여기 안 맞으면 **manifest 검증 단계에서 막힌다**. P2의 R-3(kind 추가)와 함께 검토 요청 → Discord로 전달

---

## P2 — 단일 진입점 + 승인 흐름 (P2 지적 ①②, 내 단독)

현재 `run_target_audit()`는 Python 함수일 뿐 tool이 아니다. 그리고 `driver.py:145`가 `confirmed=True`를 자동으로 넘겨 **안전 불변식 4를 위반**한다.

- [ ] **E-1. `vc_audit_target` tool 노출** (`mcp_server/tools_control.py` 또는 신규)
  ```python
  def vc_audit_target(target_id: str, mode: str = "propose") -> AuditReport
  ```
  - `mode="propose"` (**기본**): scan → verify → localize → **generate_patch까지 하고 `PATCH_PROPOSED`에서 정지**
  - `mode="batch_approved"`: apply·6게이트까지 자동. **audit log에 mode를 반드시 기록**
  - 기본이 `propose`인 게 핵심이다. SKILL 규칙 `never invoke patch application without explicit user confirmation`

- [ ] **E-2. `driver.run_target_audit()`에 `mode` 전달** — `mode="propose"`면 `vc_apply_patch` 이후를 건너뛴다
  ⚠️ `driver.py`는 내 파일이다. 단 `require_target_allowed` 호출부는 **안 고쳐도 된다** — policy_engine이 바뀌면 자동으로 따라온다

- [ ] **E-3. `audit_local_target` prompt 갱신** — 새 흐름(등록 → propose → 사용자 승인 → apply)을 반영

- [ ] **E-4. 승인 후 재개 경로** — 사용자가 diff를 보고 승인하면 `vc_apply_patch` → 6게이트가 이어지는지 E2E 확인

---

## P3 — LLM 패치 배선 (P3·P4 산출물 소비)

**의존**: M-2(llm_synth가 main에), P4의 `build_patch_model_client()`

- [ ] **L-1. `tools_repair.py:298` 배선**
  ```python
  from repair.llm_synth import make_llm_synthesizer
  patch = generate_patch(..., synthesize_fn=make_llm_synthesizer(_get_llm_client()), ...)
  ```
- [ ] **L-2. `_get_llm_client()` lazy init + memoize** — 이미 P3와 합의됨(2026-07-21 02:26)
  - 모듈 싱글턴 ❌ — import 시 env 읽기·health probe가 CI/오프라인 import를 오염시킨다
  - 실패 시 `None` → 어댑터 no-op → **template-only degrade**
- [ ] **L-3. `vc_export_sarif` 구현** — `build_run_report` → `eval.report_export.render_sarif`. P4가 렌더러 소유, 나는 tool 배선만. 2줄 수준

---

## P4 — 통합·리허설 (D2)

- [ ] **F-1. D2 10:00 병합 #3 후 기능 동결 선언**
- [ ] **F-2. 데모 1 E2E**: 사용자 프로젝트 등록 → 검사 (P2와 짝)
- [ ] **F-3. 데모 2 E2E**: Juice Shop SQLi → LLM 패치 (P3·P4와 짝)
- [ ] **F-4. fallback 확인**: c1-05 gold가 여전히 도는지. **이게 깨지면 최우선 복구**
- [ ] **F-5. 문서**: `SECURITY_POLICY.md`(승인 모델·loopback 불변식·argv 승인·CF 전송 범위), `RUNBOOK.md`(P2·P4 섹션 취합), `MCP_SPEC.md`

---

## 하지 말 것

- ❌ `runtime/`·`repair/`·`verifiers/`·`model/`·`scanners/` 직접 수정 — 요청하고 소유자가 고친다
- ❌ `contracts/schemas.py` 변경 — D1 오전 이후 freeze
- ❌ loopback 검증기 완화
- ❌ 판정 경로(`core/judge.py`)에 LLM 주입
- ❌ c1-05 gold 경로를 깨는 변경

## 보고

D1 10:00 / 18:00, D2 10:00 병합 직후 **규칙 3 형식**으로 Discord 공지. 병합 결과는 내가 유일한 발신자다.
