# P2 — 2일 스프린트 계획

> 상위 문서: **[TEAM_CONTRACT.md](TEAM_CONTRACT.md)** — 충돌 시 그쪽이 이긴다.

## 내 역할 한 줄

**런타임과 등록의 소유자.** 중앙 allowlist를 사용자 로컬 레지스트리로 전환하고, LLM 관문(VM)을 연다.

## 내 파일 (배타적)

`runtime/**`, `targets/**`, `policies/**`, VM/Cloudflare 인프라

**남의 파일은 안 고친다.** `core/policy_engine.py`는 **P1 것**이다 — 나는 `runtime/registry.py`를 제공하고 P1이 그걸 호출한다.

---

## P0 — LLM 관문 (VM은 딱 이것만)

**VM은 LLM에 닿기 위한 관문 수준으로만 쓴다.** target도 evidence도 MCP도 VM에 두지 않는다.
사용자 머신에서 도는 것: MCP, Docker target, evidence.db, worktree, 스캐너, verifier, 6게이트.
나가는 것: `POST /v1/chat/completions` **하나뿐**.

- [ ] **G-1. `cloudflared`로 235B 노출**
  - VM에서 `192.168.0.226:8080` → `https://<name>.trycloudflare.com` (또는 고정 도메인)
  - `GET /health`는 인증 없이 열어둔다(도달성 probe용 — `model.endpoints.liveness_check`가 씀)
  - `/v1/*`는 `Authorization: Bearer` 필수
- [ ] **G-2. Cloudflare Access 적용** — **데이터가 아니라 자원 문제다.** 토큰 하나가 유일 방어면 새는 순간 누구나 우리 GPU를 쓴다. 7.7 tok/s라 동시 사용 몇 명이면 데모가 죽는다
- [ ] **G-3. P4에게 전달**: 최종 URL, 모델 ID(`qwen3-235b`), timeout 권장치, `/health` 경로
  ⚠️ **용어**: 이 모델은 **72B가 아니라 qwen3-235b**다. D7 runtime plan·평가 표 필드 정정 필요
- [ ] **G-4. 부하 확인** — 4명이 동시에 쓰면 어떻게 되는지 1회 측정. 순차 대기가 필요하면 P4에게 알린다

---

## P1 — 로컬 승인 레지스트리 (이번 스프린트의 핵심)

**계약 3.1의 시그니처를 그대로 구현한다.** D1 오전에 확정되면 이후 안 바꾼다 — P1이 이걸 목으로 짜고 있다.

- [~] **R-1. `runtime/registry.py` snapshot 구현 / catalog 연결 대기**
  - 저장 위치 `~/.vibecutter/registry/` — **repo의 `.vibecutter/`(evidence.db)와 분리**
  - `manifest_sha256`은 **이미 있다** — `runtime/registration.py:13`. 새로 만들지 말 것
  - `commands_sha256`: manifest의 `commands` 전체(argv 포함)를 정규화해 해시. **argv가 바뀌면 재승인 강제**가 목적
  - **§3A-2:** hash만 저장하지 않는다. `~/.vibecutter/registry/<target_id>/manifest.yaml`에
    승인 당시 manifest snapshot을, `approval.yaml`에 source path·hash·승인 시각을 저장한다.
    catalog는 사용자 원본 파일이 아니라 이 snapshot만 소비한다
  - `allowed_hosts`는 hostname만 저장한다(예: `["127.0.0.1"]`). port는 승인된 `base_url`의
    명시 port로만 결정한다
  - `approve()`는 **승인 여부를 판단하지 않는다.** 사용자 승인은 P1의 tool이 받고 나는 기록만 한다
  - `base_url`은 `TargetManifest` 검증기를 **반드시** 통과시킨 뒤 저장 — loopback 불변식의 집행 지점

- [ ] **R-2. 사용자 프로젝트 사전조건 검사** (`registry.approve()` 안)
  - ⚠️ **git 저장소여야 한다.** `runtime/worktree.py:43`이 대상 소스에 `git worktree add`를 하고, 패치 apply·6게이트 전체가 그 위에서 돈다
  - git이 아니면 **명확한 사유로 거부**한다(추측으로 진행 금지). `git init` 안내 문구 제공
  - **§3A-4:** closed-loop 등록/실행은 dirty worktree를 거부한다. 실행 중인 코드와
    worktree의 마지막 commit이 달라져 verify·patch 정합성이 깨지기 때문이다
  - patch를 만들지 않는 scan/verify 전용만 `for_closed_loop=False`로 경고 허용한다

- [ ] **R-3. `TargetManifest`에 `kind` 추가** (`runtime/manifest.py`)
  - `kind: Literal["compose_project", "running_local"] = "compose_project"` (기본값이 기존 동작 = 하위호환)
  - **`referenced_commands_must_exist` 완화**: 현재 `{"build","start","stop",reset}`을 전부 요구한다(`manifest.py:168`).
    `running_local`은 build/start가 없으므로 **kind별로 필수 집합을 나눈다**
    - `compose_project`: 현행 유지
    - `running_local`: `reset`(= 재시작 방법)만 필수. build/start/stop 선택
  - **loopback 검증기(`manifest.py:154`)는 손대지 않는다** — 안전 불변식 1

- [ ] **R-4. `catalog.py` 이중 출처**
  - `targets/manifests/`(built-in demo 20개) + 사용자 레지스트리를 **함께** 발견
  - ⚠️ **`catalog.py:84`의 `expected_target_ids` 결합을 풀어야 한다** — 지금은 발견된 **모든** manifest가 source-lock 엔트리를 요구한다. built-in에만 요구하도록 분리
  - ⚠️ **`catalog.py:159`의 repo 탈출 검사 교체** — 목적은 docstring대로 *"never an MCP-supplied path"*다. 레지스트리의 `source_path`는 MCP 입력이 아니라 **사용자가 대역 외로 승인한 경로**이므로, "repo 안" 대신 **"승인 기록의 source_path와 일치"**로 바꾼다. 불변식이 약해지는 게 아니라 출처가 바뀌는 것
  - **§3A-3 방어 심층화:** built-in target과 충돌하는 registry entry는 catalog 조회에서도
    built-in이 우선한다. 등록 단계의 충돌 거부(P1)와 함께 조용히 다른 target을 검사하는
    일을 막는다

- [ ] **R-5. `source_lock.py` / `source_bootstrap.py`** — ⚠️ **2026-07-21 03:09 합의로 방향 정정됨**

  경로가 **둘**이다. 초안은 하나만 봤다.

  | 경우 | 처리 |
  |---|---|
  | built-in 20개 | 현행 유지 (`madcamp-official` prefix + 40자 commit) |
  | **외부 벤치마크 repo**(Juice Shop) | **`external_allowlist`로 확장** ← 신규. **P1이 구현**(03:12 승인) |
  | 사용자 로컬 프로젝트 | source-lock 자체를 **건너뛴다**. clone하지 않고 이미 로컬에 있는 원본을 쓴다 |

  - **왜 Juice Shop이 source-lock을 타야 하나**: image-only 동적 target으로 제한하면 static·scope 게이트와 LLM 패치가 전부 bypass된다 — `source_dir`이 실제 파일 트리를 가리켜야 한다. 그래서 pinned source를 `.vibecutter/targets/sources/juice-shop`에 vendor한다(P2 권고, P1 동의)
  - P2 몫: `external_allowlist` + `juice-shop` 엔트리를 `targets/source-lock.yaml`에 추가, source bootstrap, manifest/compose/smoke/reset 등록
  - **P1이 검증 로직을 먼저 올려야 시작 가능** → P1 W-1
  - **삭제하지 말 것**: 기존 20개의 재현성 장치다

- [~] **R-6. target별 active-run lease primitive** (§3A-8; orchestration 연결 대기)
  - 고정 loopback port를 공유하므로 target당 lifecycle mutation run은 하나만 허용한다
  - lease에는 `target_id`, 소유 `run_id`, 취득 시각, timeout을 기록한다
  - 정상 reset/kill 시 해제하고, timeout된 lease는 명시적으로 회수한다
  - 이 잠금은 driver 내부의 순차 candidate 처리와 별개로 여러 MCP 요청·배치를 막는다

---

## P2 — Juice Shop (데모 2의 전제)

- [ ] **J-1. manifest 등록** — OWASP Juice Shop **v17.3.0** (digest `sha256:123acb31ed8bb05ebb06934a29be83d4e11a46cae937b9ed2bf2bda29d98130`)
  - 이미 검증됨: `GET /rest/products/search?q=` 에서 boolean 차등 재현 (apple 200/631B, true 200/18662B, false 200/30B)
- [ ] **J-2. regression 계약 A/B 확정** — P3 회신 대기 중(2026-07-21 02:46부터)
  - A: pinned source에 `npm install` 후 `npm run test:server`
  - B: 공식 이미지 smoke (health + 정상 검색 + SQLi 수정 후 동일 검색)
  - ⚠️ **`test_suites=[]`면 regression 게이트가 False라 FIXED 불가.** 반드시 하나는 있어야 데모 2가 완주한다
  - **synthetic pass test는 만들지 않는다**(P2 원칙 유지)
- [ ] **J-3. build/health/reset 확인** 후 P3에게 넘김

---

## 하지 말 것

- ❌ `core/policy_engine.py` 수정 — P1 것. `registry.py`를 제공하고 P1이 호출
- ❌ loopback 검증기(`manifest.py:154`) 완화
- ❌ `targets/manifests/`·`source-lock.yaml` 삭제 — built-in demo profile로 남는다
- ❌ VM에 target·evidence·MCP 배치 — **VM은 LLM 관문만**
- ❌ 임의 취약점 삽입 — 승인된 교육용 앱(Juice Shop)만

## 보고

계약 규칙 3 형식. 특히 **G-3(엔드포인트 정보)와 R-1(레지스트리 시그니처)은 P4·P1이 대기 중**이라 완료 즉시 공지.
