# Vibe Cutter — P1(이지민) 5일 실행 계획

> 참고 문서: `Vibe_Cutter_MCP_심화_기획_및_구현_보고서.docx`(기획서), `cowork_rule.md`(협업 규약), Notion "4명/5일 분업 계획"(팀 배분표)
> 이 문서는 세 소스 중 상충하는 내용이 있으면 **Notion 5일 계획 > 기획서 DOCX > cowork_rule.md** 순으로 따른다 (cowork_rule.md 1절 판단 우선순위 기준, 팀 리더 최신 지시가 최우선).

## 0. 내 역할 요약

**P1 = Platform/MCP.** 소유 영역: MCP 서버, policy engine, evidence DB, state machine, judge 배선, 리포트 인프라, **공통 contracts**.

다른 역할과의 관계:
- P2(안종화, Target/Infra) — Docker/VM 격리, target manifest, adapter, reset/snapshot, worktree/테스트 러너
- P3(박준서, Security/Agent) — attack surface, IDOR/XSS/Injection verifier, root-cause locator, patch 생성
- P4(유나연, Model/Eval) — inventory, RAG/코드인덱스, Semgrep 통합, baseline/metric, LoRA, 발표 자료

**내가 가장 먼저 해야 할 일**: 공통 스키마(Target/Run/Observation/Candidate/Finding/Patch/Validation/Trajectory)와 MCP tool input/output schema를 **Day1 오전에 먼저 공개**한다. cowork_rule.md 5절 "P1은 공통 schema와 tool input/output을 먼저 공개한다"는 명시적 규칙이고, Notion 리스크 표에서도 "P1 evidence store(D2)"가 늦어지면 P3(D3~D4 병목)가 막힌다고 경고한다. 이 프로젝트의 최대 리스크는 내 파트가 늦게 나가는 것이다.

**절대 건드리지 않을 것**: P2/P3/P4의 소유 영역(adapter 내부 로직, verifier 세부 구현, LoRA 학습 코드 등)은 직접 구현하지 않는다. 필요하면 최소 변경 + handoff에 이유 기록.

**Handoff 규칙**: 매일 작업 종료 시 `docs/handoffs/D{day}-P1.md`를 cowork_rule.md 6절 템플릿(상태/변경 파일/제공 인터페이스/검증/타 역할에 필요한 사항/결정·가정·리스크)으로 남긴다. 특히 "제공 인터페이스"는 그날 내가 노출한 schema/tool/resource를 정확히 적어야 다른 역할이 바로 붙일 수 있다.

---

## Day 1 — 골격 스캐폴딩: 공통 계약 + MCP 서버 + evidence store + state machine + policy engine v1

**Notion 완료 기준**: Host에서 상태·artifact 조회 가능.

### 오전 (최우선, 다른 팀원이 기다림)

- [x] 저장소 구조를 기획서 11.2절 기준으로 확장한다 (현재는 `mcp_server/server.py` 더미만 존재):
   ```
   core/{state_machine.py, policy_engine.py, evidence_store.py, judge.py, planner.py}
   contracts/ (또는 core/schemas.py) — 공통 Pydantic 모델
   mcp_server/{resources.py, tools_inventory.py, tools_analysis.py, tools_repair.py}
   policies/{scope.yaml, commands.yaml, vulnerability_profiles/}
   docs/handoffs/
   ```
- [x] **공통 데이터 모델을 Pydantic으로 정의** (기획서 11.3절 Entity 표 그대로): `Target`, `Run`, `Observation`, `Candidate`, `Finding`, `Patch`, `Validation`, `Trajectory`. 각 필드는 문서 표를 따른다 (예: Finding = verification_state, impact, evidence_ids, reproducibility 등).
- [x] **상태 머신 정의** (`core/state_machine.py`): 기획서 5.2절 고정 상태를 그대로 enum화.
   ```
   REGISTERED → BUILDING → READY → MAPPING → CANDIDATE_SCAN → VERIFYING
   → VERIFIED / REJECTED → LOCALIZING → PATCH_PROPOSED → WAITING_APPROVAL
   → PATCH_APPLIED → VALIDATING → FIXED / RETRY / HUMAN_REVIEW
   ```
   Finding 상태는 별도: `candidate | verified | rejected | fixed | human_review`. **이 이름은 cowork_rule.md에서 "조용히 변경 금지"로 못박은 공통 계약이다** — 바꾸려면 handoff에 영향 범위를 남겨야 한다.
- [x] **Finding/Candidate 상태 전이는 deterministic judge만 판정**하도록 구조를 짠다 (LLM confidence는 우선순위에만 사용, 최종 판정에는 미사용 — 5.3절 원칙). 이건 이후 judge.py 설계의 전제이므로 Day1에 인터페이스로 못박아 둔다.
- [x] 이 스키마와 tool schema 초안을 **`docs/handoffs/D1-P1.md`로 오전 중 먼저 게시**하고, 팀 채널에 "공통 계약 나왔다"고 알린다. (다른 팀원이 기다리는 지점)

### 오후

- [x] MCP stdio 서버 확장 (`mcp_server/server.py` → 모듈 분리). 부록 A 방식으로 tool schema 정의 (`inputSchema`/`outputSchema` 명시).
- [x] MCP Resources 뼈대 구현 (6.4절): `vibecutter://targets`, `vibecutter://targets/{target_id}/manifest`, `vibecutter://runs/{run_id}/state`, `vibecutter://runs/{run_id}/evidence`, `vibecutter://findings/{finding_id}`, `vibecutter://policies/scope`, `vibecutter://reports/{run_id}`. 이 시점엔 target/run이 없으므로 mock/dummy 데이터로 응답하되 schema 형태는 최종 형태로 맞춘다.
- [x] `evidence_store.py` 구현: observation, tool call, artifact를 저장. **모든 artifact는 SHA-256 hash + 생성 tool/version과 함께 저장** (5.3절, 재현성 요구사항). SQLite로 시작 (SQLModel/SQLAlchemy).
- [x] `policy_engine.py` v1: target allowlist 검증 골격 (`target_id → 고정 IP/port/container ID`), `command_id + typed args`만 허용하는 커맨드 검증 골격. 아직 실제 target이 없어도 인터페이스와 거부 로직(임의 URL/IP 거부)은 지금 만든다 — Definition of Done 항목("등록되지 않은 target_id, IP, URL, command_id가 모두 거부된다")이 여기 걸려 있다.
- [x] audit log 골격: tool call, args hash, actor, target, time, result, changed files를 남기는 최소 로거. 오늘부터 모든 tool 호출에 걸어둔다.
- [x] **다른 역할의 tool은 P1이 스텁으로 노출**한다: `vc_verify_access_control` 등 P3 소유 도구는 오늘 스키마만 등록하고 구현은 "not implemented" 응답. P2/P4도 동일. 이렇게 해야 오늘 저녁 시점에 전체 tool 목록이 Host에서 보인다. (6번 항목에서 24개 tool 전부 스키마+스텁으로 이미 등록 완료)
- [x] 검증: MCP Host(Claude Code 등)에서 stdio로 서버를 붙여 resource 조회, dummy tool 호출이 되는지 확인. **stdout에 JSON-RPC 외 출력이 없는지 반드시 확인** (Definition of Done 1번 항목, print debug 하나만 있어도 프로토콜이 깨짐).

### 오늘 커뮤니케이션
- [x] **P2, P3, P4에게 오전 중**: 공통 스키마 + tool schema 확정본 공유 (docs/handoffs/D1-P1.md).
- [ ] **P3에게**: evidence_store의 쓰기 API(observation 기록 방법)를 명확히 전달 — Notion 리스크 표에 "P1 evidence store(D2)"가 P3 착수 조건으로 명시되어 있어, 실제로는 오늘 저녁까지 나와야 P3가 Day2 오전에 막히지 않는다.
- [ ] **P2에게**: target manifest 스키마(9.3절)를 내 `Target` Pydantic 모델과 필드명을 맞춰야 하므로, P2가 만드는 manifest 필드(`id`, `stack`, `build.command_id`, `network.allowed_hosts` 등)를 오늘 중 서로 확인.
- [ ] **P4에게**: inventory 결과가 들어갈 `Target` 스키마 필드 확인.

---

## Day 2 — verify tool 배선 + 승인 게이트 + judge 게이트 skeleton + findings resource

**Notion 완료 기준**: 승인 → verifier 호출 경로 완성.

**어제 handoff 요약 (D1-P1/P2/P3/P4, D2-P3 기준)**:
- Day1 전원 완료. 그런데 **P3가 이미 밤사이 WebGoat로 IDOR verified 1건을 증명**했다(D2-P3.md) — 단, MCP tool 경로를 안 거치고 `verifiers.access_control.verify()`를 직접 호출한 개념 증명이다. 오늘 내 tool 배선이 끝나야 "MCP를 통한" 완주가 된다.
- P3가 P1 Day1 산출물을 실제로 실행해 **구멍 3개를 재현**했다: ①`update_finding_status()`가 evidence_id 존재 여부를 확인하지 않아 허구 id로도 verified 승격됨(코드 레벨 하드 가드라던 주장이 실제로는 뚫림) ②`write_artifact()`에 secret redaction이 전혀 없어 JWT가 artifact에 평문으로 남음(재현 확인됨) ③`max_requests`에 부록 A의 `ge=1,le=20` 제약이 스키마에 없음.
- `policies/scope.yaml`/`policies/commands.yaml`이 **여전히 완전히 비어 있다**(`targets: {}`, `commands: {}`). P2가 D1에 실제로 build/health까지 통과시킨 target이 19개나 있는데(D1-P2.md 포트 목록) 하나도 policy_engine을 못 통과한다 — 오늘 verify tool을 실 target에 못 붙이는 직접적 원인.

### 0. 어제 구멍 메우기 (다른 모든 작업보다 먼저)

- [x] **구멍① 허구 evidence_id 승격 차단**: `core/evidence_store.py:update_finding_status()`에서 각 `evidence_id`를 `get(Observation, eid)`로 실존 확인 + `Observation.run_id == finding.run_id` 일치 검사 추가. 존재하지 않거나 다른 run 소속이면 신규 `InvalidEvidenceError`. `transition_finding()`은 순수 함수로 그대로 두고 store 계층에서만 막았다(P3 제안대로).
  - [x] 회귀 테스트(`tests/test_evidence_store.py`): 존재하지 않는 id로 승격 시도 → 실패. 다른 run의 진짜 id로 승격 시도 → 실패. 같은 run의 진짜 id → 정상 승격.
- [x] **구멍② secret redaction 소유권 확정 + 구현**: P1이 저장 계층 소유로 확정하고 `core/redaction.py`(신규)를 만들어 `write_artifact()` 저장 직전에 적용. P3의 `verifiers/access_control.py:redact()` 패턴(JSESSIONID/Bearer/password)을 승격했고, Bearer 접두사 없이 body에 그냥 박힌 JWT도 잡는 패턴을 추가했다. hash는 저장되는(redaction 후) bytes 기준으로 계산되도록 수정. UTF-8로 디코딩 안 되는 바이너리는 원본 그대로 저장(현재 텍스트 기반 규칙의 한계, 문서화함).
  - [x] 회귀 테스트(`tests/test_redaction.py`, `tests/test_evidence_store.py`): JWT/Bearer/JSESSIONID/password 평문 미노출, hash-저장 bytes 일치, 바이너리 무변형, redact 멱등성 확인.
  - [ ] **P3에게 알려 verifier 쪽 임시 `redact()` 호출 제거 요청** — 아직 안 함(오늘 커뮤니케이션 항목에서 처리). 이중 적용은 idempotent라 지금 당장 깨지진 않는다.
- [x] **구멍③ max_requests 상한 강제**: `mcp_server/tools_analysis.py`의 `vc_verify_*` 세 함수 시그니처를 `Annotated[int, Field(ge=1, le=20)]`(FastMCP가 실제로 스키마 제약을 뽑아내는 패턴 확인 후 적용)로 변경. 생성된 tool inputSchema에 `minimum: 1, maximum: 20, default: 10`이 실제로 박히는 것과, `max_requests=999` 호출이 tool 본문 도달 전 스키마 검증 단계에서 거부되는 것을 `mcp.call_tool()`로 직접 확인.
- [x] **`VerifyResult`/`VerifierOutput` 중복 제거**: `contracts/schemas.py`에 `VerificationResult`를 신설해 통합. `verifiers/types.py`는 `VerifierOutput = VerificationResult` 별칭으로 바꿔 `verifiers/access_control.py`(P3 소유, 미수정) 등 기존 코드가 변경 없이 그대로 동작한다. `mcp_server/tools_analysis.py`도 이 타입을 사용하도록 변경.

**검증**: 전체 회귀 테스트(P1 신규 10 + P2 31 + 기존) `python -m unittest discover -s tests` 47 passed. P4의 독립 스위트(`scanners.test_batch_scan`/`eval.test_baseline`/`model.test_code_index`/`datasets.inventory`)도 재실행해 스키마 변경 영향 없음 확인.

### 1. 정책 등록 — target allowlist/command 채우기 (verify tool을 실 target에 붙이기 위한 전제)

- [x] `policies/scope.yaml`에 D1-P2.md가 제시한 실제 통과 target 19개(`26s-w1-c1-02`~`26s-w1-c3-08` 중 build/health 통과분, `26s-w1-c1-01`/`26s-w1-c2-03`/`26s-w1-c3-07`은 의도적으로 제외 — 이유를 파일에 주석으로 남김)의 `allowed_hosts`/`port`를 등록. port는 각 `targets/manifests/<id>.yaml`의 `base_url`에서 직접 추출해 manifest와 어긋나지 않게 함.
- [x] `policies/commands.yaml`에 `build_target`/`start_target`/`reset_target` command_id를 `{target_id: str}` typed args로 등록. (`reset_target`의 명시적 승인은 typed-args가 아니라 `TargetRuntimeService.reset()`의 `approved` 파라미터로 별도 강제되는 구조라 commands.yaml에는 `approved`를 넣지 않음 — 코드 확인 후 원래 계획 수정.)
- [x] `core.policy_engine.require_target_allowed`/`require_host_allowed`/`require_valid_command`를 실제 target_id(`26s-w1-c1-03`, `26s-w1-c2-07`)로 직접 호출해 더 이상 `PolicyViolation`이 나지 않는 것, 미등록 target은 여전히 거부되는 것을 확인.
- [x] ~~`TargetRuntimeService`로 register→build→start→check_readiness 전체 round-trip~~ **21개 전체로는 블로커, 1개 subset으로는 register+readiness까지 실증 완료**:
  - 🔴 **블로커 원인**: `TargetCatalog.load()`가 `targets/manifests/`의 21개 매니페스트를 전부 즉시 검증하는데, 그중 3개(`26s-w1-c2-05`, `26s-w1-c2-08`, `26s-w1-c3-04`)가 `role_fixtures[].secret_env_names`에 `VIBECUTTER_*` 접두사가 아닌 원본 provider 이름(`GOOGLE_API_KEY`, `GEMINI_API_KEY`, `KIS_APP_KEY` 등)을 그대로 적어 `runtime/manifest.py`의 `environment_names_only` validator에서 `ValidationError`가 난다. 하나라도 깨지면 catalog 전체 로드가 죽어 **어떤 target에 대해서도** `TargetRuntimeService`가 동작하지 않는다.
  - **우회 검증**: 정상 manifest 1개(`26s-w1-c1-03`)만 담은 임시 manifest 디렉터리로 `TargetCatalog`를 별도 구성해(P2 파일은 전혀 안 건드림) 실제 프로덕션 코드 경로(`TargetRuntimeService.register()`/`.check_readiness()`)를 끝까지 통과시켰다. `register()`는 정상적으로 `Target`을 반환했고, `check_readiness()`는 `ready=False`(사유: 이 머신에 P2의 로컬 source clone과 role fixture 환경변수가 없음 — 코드 문제 아님)까지 정확히 보고했다. **정책 등록 자체는 문제 없다는 것을 이 subset 테스트로 확정.**
  - 🟡 **새로 발견한 버그(P2 소유, 수정 안 함)**: 같은 subset으로 `build()`까지 시도하니 `runtime/target_service.py`의 실패 경로가 `target.id`(`RegisteredRuntimeTarget`엔 없는 속성 — `target.manifest.id`여야 함)를 참조해 `TargetOperationError` 대신 `AttributeError`가 터진다. build가 실패할 때마다(지금처럼 소스 없음이든 실제 빌드 에러든) 원인 메시지가 가려지는 버그. **P2에게 알리기만 하고 직접 고치지 않기로 결정**(runtime/은 P2 소유 — 사용자 확인).
- [x] **P2에게 커뮤니케이션 항목 확정** (오늘 커뮤니케이션 섹션에 반영): ① 3개 manifest의 `secret_env_names`를 `VIBECUTTER_` 접두사로 바꾸거나 validator를 완화해달라 — 지금 상태로는 Day2 전체가 실 target에 못 붙는다. ② `runtime/target_service.py` build 실패 경로의 `target.id` → `target.manifest.id` 버그 수정 요청. ③ IDOR 검증 가능한 target(사용자 2명 + 각자 소유 seed 자원) 하나 지정 요청(D2-P3.md가 이미 요청했는데 아직 응답 없음).

### 2. verify tool 실배선 (원래 Day2 핵심 목표)

- [ ] **run 승인 게이트**: verification 카테고리(공격성 도구, 6.6절) 호출 전 run-level 승인 여부를 확인하는 공통 게이트를 `vc_verify_*` 진입점에 추가. 미승인 run은 거부.
- [ ] **`vc_verify_access_control` 본문 실제 구현** (`mcp_server/tools_analysis.py`):
  1. policy 검사(`require_target_allowed`/`require_host_allowed`) + candidate/run 존재 확인
  2. `Run.status`를 `transition(..., RunState.VERIFYING)`으로 전이
  3. `candidate_id`로 `Candidate` 조회 → `verifiers.access_control.verify(run_id, candidate, max_requests=max_requests)` 호출
  4. 결과의 `evidence_ids`로 `update_finding_status(finding_id, VERIFIED 또는 REJECTED, evidence_ids=...)` 호출(구멍① 수정판이 실제로 막는지 여기서 다시 확인)
  5. `VerificationResult` 반환
- [ ] `vc_verify_injection`/`vc_verify_xss`는 P3가 아직 verifier를 구현하지 않았으므로 policy/승인 게이트/상태 전이 배선까지만 만들고, verifier 호출부만 `NotImplementedError`로 남긴다(완성되면 바로 붙게 인터페이스는 맞춰둔다).
- [ ] **WebGoat가 아닌 실제 몰입캠프 target**(1의 P2 지정 target)에 MCP tool 경로로 `vc_verify_access_control`을 실제 호출해 candidate → verified가 되는지 확인 — "WebGoat이라서 된 것"이 아님을 오늘 증명한다(D2-P3.md가 남긴 리스크 항목 해소).

### 3. judge.py skeleton + Attack gate 실동작

- [ ] 7.6절 6개 게이트 함수 시그니처 정의: `check_build`, `check_attack`, `check_positive_functionality`, `check_regression`, `check_static`, `check_scope`(각각 `Validation`의 필드 하나씩을 채우는 형태).
- [ ] **Attack gate만 실제 동작**: patch 적용 후 동일 attack이 더 이상 성공하지 않는지 재확인하는 로직. 오늘은 실제 patch가 없으므로 `verifiers.access_control.verify()`를 재호출해 `verified=False`가 나오는 경로를 단위 테스트로 통과시켜 둔다(Day3에 실제 patch loop와 연결).
- [ ] 나머지 5개 게이트는 스텁(`NotImplementedError`)으로 남긴다.
- [ ] **judge가 LLM 주장을 그대로 승격 못 하도록 하드 가드 재확인**: `update_finding_status`(구멍① 수정판)를 거치지 않고 `FindingRow`를 직접 쓰는 경로가 코드베이스에 없는지 grep으로 확인.

### 4. findings resource 완성

- [ ] `vibecutter://findings/{finding_id}`가 더미 대신 `evidence_store.get(Finding, finding_id)`를 실제로 조회해 부록 B 스키마 형태로 반환하도록 `mcp_server/resources.py` 수정(아직 없는 필드는 null 유지).
- [ ] `mcp_server/resources.py`의 stale docstring("evidence_store가 아직 없으므로 더미 응답") 갱신 — P3가 이미 지적함.

### 5. 공통 계약 이견 정리 (P3가 "오늘이 사실상 마지막 무료 변경 창구"라고 지목)

- [ ] `Observation.type`을 자유 문자열 대신 고정 값 집합으로: `http_exchange | db_diff | browser_trace | log | route_map | role_map`(P4 trajectory 조인과 직결 — P4에도 확인).
- [ ] `Candidate`에 `vuln_class` + 최소한의 typed 공격 파라미터(예: `attack_params: dict[str, str]`) 추가 — P3가 IDOR 공격 정보를 `signals`에 key=value 문자열로 욱여넣는 우회를 없앤다.
- [ ] `Finding.affected_role`(단수) → `affected_roles: list[str]`로 변경(IDOR는 victim/attacker 2역할이 본질).
- [ ] 위 3건 변경 후 `contracts/schemas.py` 전체 인스턴스화 스모크 테스트 재실행, P3/P4에 변경 내용 공지.
- [ ] `RootCause` 필드 확장(reachability/ownership/최소 수정 범위/유사 과거 패치, 수정 위치 계층)은 Day3 착수 전 준비로 남기고 오늘은 optional 필드 자리만 예약(로직은 Day3).

### 오늘 커뮤니케이션

- [ ] **P3와 아침 첫 동기화(최우선)**: 구멍①②③ 수정 계획 공유, `VerifyResult`/`VerifierOutput` 통합 방향 확인, verify tool 본문 소유권이 P1이라는 전제(D1-P3.md 제안대로) 최종 확인, `verifiers/access_control.py`의 임시 `redact()` 제거 시점 조율.
- [ ] **P2에게**: (a) 🔴 `targets/manifests/{26s-w1-c2-05,26s-w1-c2-08,26s-w1-c3-04}.yaml`의 `role_fixtures[].secret_env_names`가 `VIBECUTTER_*` 규칙을 어겨 `TargetCatalog.load()`가 전체 실패하는 것 최우선 수정 요청(지금은 어떤 target도 `vc_register_target`/`build`/`start`/`check_readiness`가 안 됨). (b) 🟡 `runtime/target_service.py` build 실패 경로의 `target.id`(존재 안 함) → `target.manifest.id` 오타 수정 요청. (c) `policies/scope.yaml`/`commands.yaml` 등록 내용(host/port) 최종 확인. (d) IDOR 검증 가능한 target(2 사용자 + 각자 소유 자원) 1개 지정 요청, role fixture(로그인 endpoint + 자격증명 + seed 자원 id) 요청.
- [ ] **P4에게**: `Observation.type` 값 집합에 `http_exchange` 포함 확정 요청, batch scan JSONL(`candidates/<app>.candidates.jsonl` + `summary.json`) 산출물을 evidence/candidate store가 흡수할 포맷 확정, inventory(41개) vs `targets/`(21개 manifest) 단일 진실 소스 합의(P2/P4 상충 지점 중재).
- [ ] **저녁 handoff**: `docs/handoffs/D2-P1.md`에 "구멍①②③ 수정 완료, scope/commands 등록 완료, verify 경로 실배선 완료(access_control만, injection/xss는 배선만), judge는 attack gate만 실동작·나머지 5게이트는 인터페이스만, 계약 변경 3건(Observation.type/Candidate.vuln_class/Finding.affected_roles)" 명시. P3/P2/P4에 필요한 다음 정보 요청 남기기.

---

## Day 3 — judge 게이트 전체 완성 + generate/apply 분리 + 승인

**Notion 완료 기준**: 게이트 통과 시 verdict 산출.

- [ ] **6개 judge 게이트 전체 구현**:
   - [ ] Build gate: P2 adapter의 build 결과 확인
   - [ ] Attack gate: 기존 재현 시퀀스가 더 이상 보안 영향 없음
   - [ ] Positive functionality gate: 정상 권한 사용자 기능 성공
   - [ ] Regression gate: 기존 test suite 통과 (P2 test runner 호출)
   - [ ] Static gate: 새 high severity finding/secret 없음 (P4의 Semgrep 결과 재확인)
   - [ ] Scope gate: **패치가 target worktree 밖 파일을 변경하지 않음** — 이건 절대 원칙(10.1절)과 직결되므로 가장 엄격하게 구현.
- [ ] **`vc_generate_patch`와 `vc_apply_patch`를 별도 도구로 명확히 분리**. generate는 원본 미변경, apply는 **explicit user confirmation 필수** + **git worktree에만 적용** (원본 branch 직접 변경 금지 — 절대 원칙). 이 분리 자체가 Definition of Done 핵심 항목이다.
- [ ] 모든 게이트 통과 시 Finding 상태를 `fixed`로, 하나라도 실패 시 `RETRY`/`HUMAN_REVIEW`로 전이하는 로직 완성.
- [ ] Report 인프라 착수: `vc_generate_report`용 데이터 조합 로직 (P4가 Day3에 HTML/SARIF export를 만들 예정이므로, 그 전에 report가 참조할 데이터 소스(finding+evidence+patch+validation 조인)를 오늘 준비).

### 오늘 커뮤니케이션
- [ ] **P3에게**: 첫 IDOR closed-loop 완주 시점에 맞춰 judge가 실제로 verdict를 내는지 함께 확인 (P3 완료 기준 "IDOR closed-loop 완주"와 내 게이트 완성이 같은 날 맞물림 — 반드시 오후에 한 번 실제 target으로 end-to-end 리허설).
- [ ] **P2에게**: regression suite 배선(P2 오늘 작업)과 내 Regression gate 연동 확인. snapshot rollback이 patch apply 실패 시 정상 복구되는지 함께 테스트.
- [ ] **P4에게**: report가 참조할 evidence/finding 스키마가 안정화됐음을 알리고, P4의 report 생성 코드가 이 스키마를 그대로 소비하도록 조정.
- [ ] 교차 리뷰 원칙(Notion 리스크 표): Infra(P2)와 Judge(P1이 배선하지만 실질 판정 로직은 P3와 공동)는 서로 다른 사람이 리뷰 — 내 judge 게이트 구현을 P3 또는 P2에게 리뷰 요청해 self-confirmation 오류를 줄인다.

---

## Day 4 — E2E 통합 + kill switch/rollback + MCP Skill 번들

**Notion 완료 기준**: 명령 한 줄 → 전체 파이프라인.

- [ ] `audit_local_target` MCP Prompt 완성 (6.5절) — 한 번의 요청으로 `register → build → map → scan → verify → localize → patch → validate → report` 전체가 상태 머신을 타고 흐르도록 오케스트레이션(`core/planner.py`).
- [ ] **Kill switch**: global pause file + supervisor timeout 구현 (10.2절). 아무 때나 실행 중단 가능해야 함.
- [ ] **Rollback 경로**: git worktree 삭제 + (P2 제공) VM snapshot/volume reset을 P1의 상태 머신에서 호출할 수 있도록 통합.
- [ ] **SKILL.md 작성** (6.8절 예시 기반): 언제 도구를 호출할지, 승인 시점, 절대 금지 범위, 보고서 형식을 규정. 핵심 규칙 예시:
   - [ ] `vc_list_authorized_targets`가 반환한 target에만 동작
   - [ ] 임의 네트워크 목적지 구성 금지
   - [ ] patch 적용은 explicit user confirmation 없이 금지
   - [ ] `verified=true`는 오직 judge 결과로만 인정
   - [ ] 패치 후 반드시 replay_attack + regression_suite 실행
   - [ ] 3회 연속 수정 실패 시 human review 요청
- [ ] Host 설정 예시(claude_desktop_config류) 작성.
- [ ] P4가 밤에 돌리는 LoRA 학습/OWASP Benchmark 배치가 evidence_store의 trajectory 데이터를 읽어갈 수 있도록 **오늘 낮 동안 trajectory export 인터페이스**(4.5절 학습 샘플 구조에 맞는 JSONL export)를 완성해 P4에 넘긴다 — 이게 늦으면 밤샘 학습 배치 자체가 시작을 못 한다.

### 오늘 커뮤니케이션
- [ ] **P4에게 낮 동안 최우선**: trajectory export 포맷/위치를 확정해 전달 — Day4 밤 P4의 7B QLoRA 학습 배치가 이 데이터를 쓴다. 오후 안에 끝내지 못하면 밤샘 배치가 밀린다.
- [ ] **P2에게**: holdout 앱 clean-room snapshot 및 demo target 준비 상태를 확인하고, 내 kill switch/rollback이 P2의 snapshot 메커니즘과 실제로 맞물리는지 함께 리허설.
- [ ] **P3에게**: 3개 취약점군(IDOR/XSS/Injection) 전체가 오늘 안에 하드닝되므로, 파이프라인 전체를 한 번 같이 돌려보고 게이트에서 걸리는 케이스 확인.
- [ ] 저녁 handoff에 "명령 한 줄 파이프라인 완성, kill switch 동작 확인, trajectory export 완료" 상태 기록.

---

## Day 5 — 통합 freeze + RUNBOOK + Skill/host 문서

**Notion 완료 기준**: 클린 환경에서 재현 가능.

- [ ] **공통 계약/인터페이스 freeze** — 오늘부터는 스키마/도구 시그니처를 바꾸지 않는다. 문제가 생기면 최소 패치만.
- [ ] `RUNBOOK.md` 작성: GPU/VM 설치, model serving 기동, target reset, demo 실행 순서. P2(VM/target reset)·P4(model serving) 섹션은 각자에게 내용을 받아 통합.
- [ ] `SECURITY_POLICY.md`, `MCP_SPEC.md` 등 필수 산출물(15.1절) 중 내 소유 영역 문서 정리·최종화.
- [ ] 클린 환경에서 처음부터 전체 파이프라인이 재현되는지 리허설 (register→report까지).
- [ ] **Definition of Done 체크리스트 최종 점검** (부록 C):
   - [ ] MCP 서버가 stdio로 실행, stdout은 JSON-RPC만
   - [ ] 미등록 target_id/IP/URL/command_id 전부 거부
   - [ ] 1개 이상 앱에서 외부 evidence로 verified 확인
   - [ ] patch가 원본이 아닌 git worktree에만 적용
   - [ ] patch 후 동일 공격 실패 + 정상 기능 성공 자동 확인
   - [ ] 모든 tool call과 변경 파일이 audit log에 기록
   - [ ] holdout 결과와 실패 사례가 최종 보고서 포함 (P4와 공동 확인)
   - [ ] SKILL 문서가 승인·중단·금지 범위를 명확히 규정
- [ ] 데모 리허설 지원: audit log를 통해 스코프 위반 0건, 원본 branch 미변경을 실시간으로 P3와 함께 재확인.

### 오늘 커뮤니케이션
- [ ] **전원**: 통합 freeze 공지 — 오늘부터 계약 변경 금지, 문제 생기면 즉시 공유.
- [ ] **P2·P4**: RUNBOOK 해당 섹션 요청 및 취합.
- [ ] **P3**: 최종 안전 재확인(스코프 위반/secret 로그 0건)을 함께 audit log로 검증.
- [ ] **P4**: 최종 리포트에 들어갈 안전 지표(범위 밖 접속, 금지 명령, 원본 branch 변경, secret 로그 — 목표 0건, 12.3절)를 내 audit log에서 뽑아 전달.

---

## 밤 배치와 P1의 관계

P1은 밤샘 배치 작업(Dockerize, Semgrep, build/health, audit, LoRA)을 직접 돌리지 않지만, **각 밤 배치가 의존하는 인프라를 그 전날 낮까지 반드시 완성해야 한다**:

| 밤 | 배치 작업 (담당) | P1이 그 전에 준비해둬야 할 것 |
| --- | --- | --- |
| D1 밤 | 나머지 앱 Dockerize + 전 앱 Semgrep (P2/P4) | evidence_store가 candidate/observation을 받을 수 있어야 함 (Day1 오후 완성분) |
| D2 밤 | 전 앱 build/health 배치 (P2) | policy_engine의 target allowlist 검증이 다수 target을 다룰 수 있어야 함 |
| D3 밤 | 첫 audit 배치 8~10개 앱 (P2) | judge 6게이트 전체 완성 (Day3 완료 기준과 정확히 일치) |
| D4 밤 | 7B QLoRA + OWASP Benchmark + base vs full 비교 (P4) | trajectory export 인터페이스 완성 (Day4 낮 최우선 작업) |

---

## 핵심 리스크 (P1 관점)

| 리스크 | 신호 | 대응 |
| --- | --- | --- |
| 공통 계약이 늦게 나옴 | P2/P3/P4가 Day1 오후에도 스키마를 못 받음 | Day1 오전 공개를 다른 모든 작업보다 우선. mock이라도 형태를 먼저 고정 |
| evidence_store API 불일치 | P3의 verifier가 evidence를 못 씀 | Day1 저녁~Day2 아침 P3와 직접 동기화, 실제 쓰기 예제 코드 함께 확인 |
| judge가 LLM 주장을 그대로 승격 | verified 남발, false positive 과다 | evidence 없이는 상태 전이 자체가 불가능하도록 하드 가드 (코드 레벨에서 우회 불가) |
| patch가 원본 branch를 건드림 | 절대 원칙 위반, 프로젝트 신뢰성 붕괴 | apply 도구는 worktree 경로만 받도록 타입으로 강제, scope gate에서 이중 검증 |
| MCP stdout 오염 | Host와의 JSON-RPC 파싱 깨짐 | 모든 로그는 stderr/file로만, print() 금지 원칙 코드 리뷰 시 항상 확인 |

---

## 매일 리듬 체크리스트

- [ ] 아침: 어제 handoff(`docs/handoffs/D{day-1}-*.md`) 확인, 특히 P2/P3/P4가 내게 요청한 항목
- [ ] 낮: 오늘 소유 작업 진행, 공통 계약 변경 필요 시 즉시 관련자에게 공유(조용히 바꾸지 않기)
- [ ] 저녁: `docs/handoffs/D{day}-P1.md` 작성 (상태/변경 파일/제공 인터페이스/검증/타 역할에 필요한 사항/결정·가정·리스크)
- [ ] 저녁: 밤 배치가 도는 경우, 그 배치가 의존하는 내 인프라가 실제로 동작하는지 마지막으로 한 번 확인
