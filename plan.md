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

- [x] **run 승인 게이트**: `vc_verify_*` 세 tool에 `approved: bool = False` 파라미터 추가(기존 `vc_apply_patch`/`vc_reset_target` 패턴과 동일). `mcp_server/tools_analysis.py`의 `_prepare_verification()` 공통 헬퍼가 제일 먼저 이 게이트를 확인 — 미승인이면 verifier 호출 전에 `PermissionError`.
- [x] **`vc_verify_access_control` 본문 실제 구현** — 계획한 5단계를 `_prepare_verification()`(공통) + tool 본문(verifier별) 두 층으로 배선:
  1. 승인 게이트 → 2. `require_target_allowed(run.target_id)` policy 검사 → 3. `Run.status`를 `VERIFYING`으로 전이(이미 VERIFYING이면 재전이 생략 — 여러 candidate를 같은 run에서 검증 가능) → 4. `candidate_id` 조회 + `find_or_create_finding()`로 Finding 지연 생성(신규 — 지금까지 Candidate→Finding을 만드는 코드가 어디에도 없었다) → 5. `verifiers.access_control.verify()` 호출 → 6. `update_finding_status(finding.id, VERIFIED/REJECTED, evidence_ids=...)`.
  - **알려진 한계 문서화**: policy 검사가 `target_id`까지만 확인하고 verifier가 실제로 때리는 host/port는 검사하지 못한다(Candidate에 typed 공격 파라미터가 없어서 — 섹션 5 계약 이견과 연결됨). 스키마 개선 후 `require_host_allowed`까지 추가할 것.
- [x] `vc_verify_injection`/`vc_verify_xss`는 `_prepare_verification()`까지 동일하게 타지만 verifier 호출부는 `NotImplementedError`로 남김(P3 verifier 미구현).
- [x] **테스트로 배선 검증**(`tests/test_verify_tool_wiring.py`, 10건): 미승인 거부, 미등록 target 거부, 존재하지 않는 run/candidate 거부, VERIFYING 전이(1회만, 재호출해도 안 바뀜), Finding 지연 생성/재사용, `verifiers.access_control.verify`를 mock으로 대체해 실제 `mcp.call_tool()` 경로로 verified→Finding 승격/rejected→미승격/evidence 기록까지 확인, injection stub도 동일하게 정책·상태 전이는 타고 verifier 직전에서 멈추는 것 확인.
- [ ] ~~WebGoat가 아닌 실제 몰입캠프 target에 MCP tool 경로로 실제 호출~~ **P2 블로커로 보류** — `TargetCatalog` 전체 로드가 3개 깨진 manifest 때문에 죽어 있어(섹션 1 참고) 아직 실제 target으로 candidate를 만들 방법 자체가 없다(SAST/mapping도 전부 스텁). 지금 검증은 실제 policy 등록(`26s-w1-c1-03`) + mock verifier 조합으로 배선 로직만 증명한 상태 — verifier 자체가 실 앱에서도 되는지는 P2 블로커 해소 + P3의 role fixture 확보 후에 마저 확인해야 한다.

### 3. judge.py skeleton + Attack gate 실동작

- [x] 7.6절 6개 게이트 함수 시그니처 정의(`core/judge.py`): `check_build`, `check_attack`, `check_positive_functionality`, `check_regression`, `check_static`, `check_scope`(전부 `(run_id, patch_id) -> bool`, `Validation`의 필드 하나씩을 채우는 형태).
- [x] **Attack gate만 실제 동작**: `check_attack(run_id, finding_id, *, verifier=verify_access_control)` — finding의 원본 `candidate_id`로 verifier를 재호출해 `verified=False`(더 이상 공격이 안 통함)면 gate 통과. `verifier`를 주입 가능하게 열어둬서 Day3에 injection/xss verifier가 생기거나 patched worktree 대상으로 바뀌어도 시그니처는 그대로 재사용 가능. 오늘은 실제 patch가 없으므로 "지금 코드베이스를 다시 찌른다"는 의미로 문서화.
- [x] 나머지 5개 게이트는 스텁(`NotImplementedError`, 각자 Day3에 뭘 붙일지 docstring에 명시: build→P2 adapter, positive→role fixture, regression→P2 test runner, static→P4 Semgrep 재실행, scope→worktree 경로 diff 검사).
- [x] **테스트**(`tests/test_judge.py`, 5건): attack gate가 mock verifier로 pass/fail 양쪽 다 정확히 판정하는 것, 존재하지 않는 finding/candidate-less finding 거부, 나머지 5게이트가 전부 `NotImplementedError`인 것 확인.
- [x] **judge가 LLM 주장을 그대로 승격 못 하도록 하드 가드 재확인**: `grep -rn "verification_state\s*="`으로 전체 검색 — `core/evidence_store.py`의 `update_finding_status()` 내부 1곳과 `mcp_server/resources.py`의 더미 데이터 생성자 1곳(영속화 안 되는 예시 응답) 외엔 없음을 확인. 우회 경로 없음.

**검증**: 전체 회귀 62개(P1 신규 15 추가) 통과.

**추가(P3 Notion "Plan B" handoff 반영)**: P3가 `repair/validators.py`를 오늘 직접 구현하기로 하면서(judge 완성을 안 기다리고 attack·positive gate 실행기를 단독 동작하게 만드는 설계 — `verifiers.access_control.verify()`를 judge가 소비하는 것과 같은 패턴) `check_positive_functionality()`가 `validators.validate_patch()`를 호출하도록 미리 배선해달라고 요청. 위 6개 게이트 표에 반영 완료(Positive functionality gate 항목 참고). `verifiers/access_control.py`에 `IdorProbe.owner_marker` 필드를 추가하는 것(정상기능 게이트가 "주인이 자기 자원을 여전히 본다"를 판정하는 데 필요)은 P3 소유 파일 소폭 수정이라 P1은 손대지 않음.

### 4. findings resource 완성

- [x] `vibecutter://findings/{finding_id}`가 더미 대신 `evidence_store.get(Finding, finding_id)`를 실제로 조회하도록 `mcp_server/resources.py` 수정. 없는 finding_id는 `ValueError`. 더 이상 안 쓰는 `_dummy_finding()`/`FindingStatus` import 제거.
- [x] `mcp_server/resources.py`의 stale docstring("evidence_store가 아직 없으므로 더미 응답") 갱신 — findings/policies 두 resource는 실제 데이터, 나머지(targets/manifest/run/evidence)는 아직 더미라고 명확히 구분해 적었다.
- [x] **테스트**(`tests/test_resources.py`): 실제 `mcp.read_resource()` 프로토콜 경로로 저장된 Finding(verified 상태 + evidence_ids 포함)이 그대로 반환되는 것, 없는 finding_id는 에러 나는 것 확인.

**검증**: 전체 회귀 64개 통과.

### 5. 공통 계약 이견 정리 (P3가 "오늘이 사실상 마지막 무료 변경 창구"라고 지목)

- [x] `Observation.type`을 자유 문자열 대신 고정 값 집합으로: 신규 `ObservationType` StrEnum(`http_exchange | db_diff | browser_trace | log | route_map | role_map`). `verifiers/access_control.py`가 이미 쓰는 `"http_exchange"` 문자열 리터럴은 pydantic이 enum 값으로 그대로 coerce하므로 **P3 파일은 한 글자도 안 바뀌어도 계속 동작**함을 확인.
- [x] `Candidate`에 `vuln_class: Optional[str]` + `attack_params: dict[str, str]` 추가 — **기존 `signals` 필드는 그대로 유지**(additive만). P3의 `verifiers/access_control.py:probe_from_candidate()`가 여전히 `signals`를 파싱하고, P4의 SAST/SCA candidate도 `signals`의 `focus:`/`severity:` 태그를 그대로 쓴다(grep으로 두 역할의 `.signals` 사용처를 전부 확인 후 결정) — `signals` 우회를 실제로 걷어내는 건 verifier 재작성이 필요해 P3와 조율 후 별도 진행.
- [x] `Finding.affected_role`(단수) → `affected_roles: list[str]`로 변경. grep으로 이 필드가 스키마 정의 외에는 **아무 데서도 참조되지 않음**을 먼저 확인했고(사용처 0건), 그래서 마이그레이션 걱정 없이 바로 리네임.
- [x] `core/evidence_store.py`의 SQLModel Row 클래스(`CandidateRow`/`FindingRow`)를 동일하게 동기화, `write_artifact()`의 `observation_type` 타입도 `ObservationType`로.
- [x] 전체 회귀 테스트 재실행 → **`.vibecutter/evidence.db`가 예전 컬럼 스키마로 이미 존재해 `no such column: candidate.vuln_class`로 19개 실패**. `SQLModel.create_all()`은 기존 테이블에 컬럼을 추가하지 않는다(마이그레이션 도구 없음, D1-P1.md에서 이미 인지한 한계) — `.vibecutter/`는 gitignored 로컬 스크래치라 안전하게 삭제 후 재생성, 64개 전체 + P4 독립 스위트(SAST/SCA/batch/baseline) 재확인 통과.
- [x] 신규 `tests/test_schema_contract_changes.py`(7건) 추가: `ObservationType`이 알려진 6개 값은 받고 미지 값은 `ValidationError`로 거부하는 것, `write_artifact(observation_type="http_exchange")`처럼 P3가 이미 쓰는 평문 문자열 호출이 여전히 동작하는 것, `Candidate`가 `signals`만 채운 기존 생성 패턴 그대로 동작하는 것 + 새 typed 필드 round-trip, `Finding.affected_roles`(list) round-trip과 예전 `affected_role`(단수) 키워드가 에러 없이 조용히 무시되는 것(extra="forbid" 미설정이 알려진 한계) 확인. 전체 회귀 71개 통과.
  - 🟡 **팀 전체에 알릴 것**: 지금처럼 스키마를 자유롭게 바꿀 수 있는 건 로컬 DB가 비어 있기 때문이다. **실제 target으로 run이 쌓이기 시작하면(P2 블로커 해소 후) 이후의 스키마 변경은 전원이 각자 로컬 `.vibecutter/evidence.db`를 지워야 하거나 마이그레이션이 필요**해진다 — 이번이 사실상 마지막 무료 변경 창구라는 P3의 지적이 코드로도 확인됨.
- [ ] `RootCause` 필드 확장(reachability/ownership/최소 수정 범위/유사 과거 패치, 수정 위치 계층)은 Day3 착수 전 준비로 남기고 오늘은 손대지 않음(로직은 Day3).

### 오늘 커뮤니케이션

- [ ] **P3에게**: (a) 구멍①②③ 수정 완료 + `VerifyResult`/`VerifierOutput`을 `contracts.schemas.VerificationResult`로 통합 완료(별칭으로 `verifiers/types.py`도 갱신했지만 `verifiers/access_control.py`는 무수정) 공유. (b) `verifiers/access_control.py`의 임시 `redact()`는 저장 계층(`core/redaction.py`)에서도 동일 규칙으로 다시 걸리니 지금 당장 지우지 않아도 안전(idempotent) — 다만 중복 유지보수 피하려면 제거 시점 확인 요청. (c) `Candidate.vuln_class`/`attack_params` 필드를 추가했다(기존 `signals` 파싱은 그대로 둠) — 새 필드로 옮겨 갈지, 언제 옮길지는 P3 판단에 맡기고 강제하지 않았다는 것 공유. (d) verify tool 본문(P1 소유) 실배선 완료, `vc_verify_access_control`이 `verifiers.access_control.verify()`를 그대로 호출한다는 것 확인 요청. (e) Plan B handoff 요청대로 `check_positive_functionality()` → `repair.validators.validate_patch(run_id, patch_id) -> bool` 위임 배선 완료 — **`validate_patch()`는 positive functionality 결과만 bool로 반환해야 한다**는 계약을 확인 요청(attack 결과까지 합쳐서 반환하는 형태면 judge 쪽에서 못 받는다).
- [ ] **P2에게**: (a) 🔴 `targets/manifests/{26s-w1-c2-05,26s-w1-c2-08,26s-w1-c3-04}.yaml`의 `role_fixtures[].secret_env_names`가 `VIBECUTTER_*` 규칙을 어겨 `TargetCatalog.load()`가 전체 실패하는 것 최우선 수정 요청(지금은 어떤 target도 `vc_register_target`/`build`/`start`/`check_readiness`가 안 됨). (b) 🟡 `runtime/target_service.py` build 실패 경로의 `target.id`(존재 안 함) → `target.manifest.id` 오타 수정 요청. (c) `policies/scope.yaml`/`commands.yaml` 등록 내용(host/port) 최종 확인. (d) IDOR 검증 가능한 target(2 사용자 + 각자 소유 자원) 1개 지정 요청, role fixture(로그인 endpoint + 자격증명 + seed 자원 id) 요청.
- [ ] **P4에게**: `Observation.type`을 `ObservationType` enum으로 고정 완료(`http_exchange` 포함이라 기존 코드 영향 없음) 공유, batch scan JSONL(`candidates/<app>.candidates.jsonl` + `summary.json`) 산출물을 evidence/candidate store가 흡수할 포맷 확정, inventory(41개) vs `targets/`(21개 manifest) 단일 진실 소스 합의(P2/P4 상충 지점 중재).
- [ ] **전원에게**: 스키마 변경 시 로컬 `.vibecutter/evidence.db`를 지워야 한다는 것 공유(오늘 섹션 5에서 실제로 겪음 — `SQLModel.create_all()`은 기존 테이블에 컬럼을 추가하지 않아 컬럼 추가/리네임 후엔 `no such column` 에러가 남). 마이그레이션 도구 도입 여부는 Day3 이후 논의.
- [x] **저녁 handoff**: `docs/handoffs/D2-P1.md`에 "구멍①②③ 수정 완료, scope/commands 등록 완료(P2 manifest 블로커로 실제 round-trip은 subset 검증까지), verify 경로 실배선 완료(access_control만, injection/xss는 배선만), judge는 attack gate만 실동작·나머지 5게이트는 인터페이스만, 계약 변경 3건(Observation.type/Candidate.vuln_class·attack_params/Finding.affected_roles) 전부 additive/무해 확인, findings resource 실데이터 연동" 명시. P3/P2/P4에 필요한 다음 정보 요청 남기기. (Day3 완료 시점에 뒤늦게 작성 — 원래 이 문서가 빠져 있던 것을 확인 후 채움)

---

## Day 3 — judge 게이트 전체 완성 + generate/apply 분리 + 승인

**Notion 완료 기준**: 게이트 통과 시 verdict 산출.

- [x] **6개 judge 게이트 전체 구현**:
   - [x] Build gate: `manifest.model_copy(update={"source_dir": "."})`로 worktree를 빌드 대상으로 삼는 패턴(P2 `RunScopedTestRunner`와 동일) 구현. **알려진 한계**: Compose `working_dir` overlay target은 아직 patched worktree가 아니라 원본을 빌드(P2 run-scoped overlay 대기, D3-P1.md 기록).
   - [x] ~~Attack gate: 기존 재현 시퀀스가 더 이상 보안 영향 없음~~ **Day2 섹션 3에서 이미 실동작 완료** — `check_attack()`이 `verifiers.access_control.verify()`를 재호출해 `verified=False`를 확인. 그대로 유효.
   - [x] ~~Positive functionality gate: 정상 권한 사용자 기능 성공~~ **완료(D3)** — Day2엔 지연 import로 배선만 해뒀는데, 오늘 P3가 D3-P3.md에서 `repair/validators.py:validate_patch(run_id, patch_id) -> bool`을 계약대로 실제 구현·재확인했다고 알려와 `core/judge.py`를 top-level import로 정리했다(`check_attack`과 같은 패턴). `tests/test_judge.py`도 mock 대상을 `core.judge.validate_patch`로, 미구현 케이스를 "존재하지 않는 patch_id → ValueError"(실제 구현이 내는 에러)로 갱신.
   - [x] Regression gate: `catalog.test_runner_for(target_id).run(run_id)` 그대로 호출 — 이미 worktree 전용이라 블로커 없이 바로 완성.
   - [x] Static gate: 원본 source와 patched worktree 양쪽에 `scanners.sast.run_semgrep` 재실행 후 `scanners.aggregate.aggregate`로 high/critical 후보 수 비교.
   - [x] Scope gate: **패치가 target worktree 밖 파일을 변경하지 않음** — `diff_touched_files()`/`assert_diff_within_worktree()`로 구현, `vc_apply_patch`의 사전 강제와 동일 규칙 공유(단일 지점 실패 비의존).
- [x] **`vc_generate_patch`와 `vc_apply_patch`를 별도 도구로 명확히 분리**. generate는 원본 미변경, apply는 **explicit user confirmation 필수** + **git worktree에만 적용**(실제 임시 Git repo에서 `git worktree add`+`git apply` end-to-end 검증, 원본 branch 미변경 확인 포함).
- [x] 모든 게이트 통과 시 Finding 상태를 `fixed`로, 하나라도 실패 시 `RETRY`로 전이하는 로직 완성(`compute_verdict()` + `_finalize_validation()`). **HUMAN_REVIEW**는 재시도 횟수 상한 로직(Day4 `core/planner.py` 소관)이 아직 없어 오늘은 안 씀 — 기존 설계(`state_machine.py` 주석)대로.
- [x] Report 인프라 착수: `core/report.py:build_run_report(run_id)`로 finding+evidence+patch+validation 조인 완성. 실제 HTML/SARIF 렌더링은 P4 소유, 아직 미배선.
- [x] **`vc_localize_root_cause` 배선 완료** (D3-P3.md 요청, 원래 계획엔 없던 항목인데 P3가 `repair/locator.py`를 오늘 실제 구현하면서 요청): `mcp_server/tools_repair.py`가 `finding_id → Finding → Run → target(catalog) → source_root(manifest.source_dir)`를 조회해 `repair.locator.localize(finding, source_root=...)`를 호출. ~~**Day2 섹션 1의 P2 manifest 블로커가 여기도 그대로 전파**된다~~ **[갱신 — D1-P2.md 12:14본에서 해소 확인]**: P2가 8개 manifest의 `secret_env_names`를 `VIBECUTTER_*` 규칙으로 고치고 `generic` adapter alias도 `generic-docker`로 정정해, checked-in manifest 22개 전부 `TargetCatalog.load()`를 통과한다. `TargetRuntimeService.build()`의 `target.id` AttributeError 버그도 함께 수정됨. **즉 이 tool은 이제 실제 target으로 호출 가능한 상태** — 남은 건 아래 "D1-P2 반영" 섹션의 후속 정리(코드가 아직 `manifest.source_dir`를 직접 조합 중이라 P2가 새로 노출한 `catalog.source_root_for()`로 교체 필요). 테스트(`tests/test_localize_root_cause.py`, 3건)는 `_service()`를 mock으로 대체해 배선 로직만 검증.
- [x] **P3 제안(설계 판단) — 최종 결정: 이번엔 통합 안 함**: judge가 6게이트를 다 돌리면 `check_attack`(verify 1회) + `check_positive_functionality`(validators 내부 재현 1회) = 사실상 같은 IDOR 시퀀스를 2번 재현한다. P3는 `repair.validators.run_security_validation()` 하나로 attack+positive를 한 번에 뽑을 수 있다고 제안(D3-P3.md). worktree 전제는 확정됐지만, `check_attack`이 이미 Day2에 실 target(WebGoat)으로 검증된 코드라 지금 리팩터링하면 회귀 리스크가 있고 이득은 효율(HTTP 재현 1회 절약)뿐이라 보류 — Day4/5 하드닝 때 재검토.

### D1-P2.md(12:14 갱신본) + D2-P4.md 반영 — 오늘 실행 순서

D1-P2.md를 다시 읽고 확인한 결과, Day2 때 걸었던 P2 manifest 블로커 2건(catalog 전체 로드 실패, build 실패 경로 AttributeError)이 모두 해소됐고 P2가 다음 API를 새로 노출했다: `catalog.source_root_for(target_id)`(경로 탈출 검사 포함, MCP가 임의 경로를 못 주도록 강제), `catalog.source_repository_for(target_id)`, `catalog.worktree_manager_for(target_id).create(run_id)`, `catalog.test_runner_for(target_id).run(run_id)`.

D2-P4.md도 확인: P4가 GPU 불필요 항목을 전부 끝냈다 — `scanners.sast.run_semgrep`/`scanners.sca.run_osv`(candidate 생성), `scanners.aggregate.aggregate(...).kept`(중복제거+FP reject+우선순위, P3는 이걸 verify해야 함), `scanners.vocab.candidate_severity/candidate_owasp`(Finding.severity/owasp_category 채울 매핑 함수, 이미 스키마엔 필드가 있지만 `find_or_create_finding()`이 아직 안 채움), `model.trajectory.TrajectoryRecorder`(학습 샘플용 상태 전이 기록기). 그리고 P1에게 구체적으로 4가지를 물었다: (a) trajectory 기록을 P1이 상태 전이 시 직접 호출할지 vs P4가 evidence_store에서 사후 조립할지, (b) `aggregate.kept`를 CANDIDATE_SCAN→VERIFYING 사이 어디서 부를지, (c) Day3 리포트 조인 데이터 형태, (d) severity/owasp 값 집합 채택 여부, (e) `vc_run_sast`/`vc_run_sca` 배선(현재 `mcp_server/tools_analysis.py`에 아직 "P4 통합 대기" stub로 남아 있음 — 이미 다 나왔으니 stale).

아래는 이 두 handoff를 합쳐서 다시 짠 실행 순서다(의존성 기준, 위쪽일수록 선행):

1. [x] **(병행 착수) P2에게 선통보**: patch worktree를 build context로 쓰는 run-scoped Compose overlay가 필요하다는 것 — `docs/handoffs/D3-P1.md`에 기록해 전달.
2. [x] **`policies/scope.yaml`에 `26s-w1-c3-09` 등록** — 완료, `require_target_allowed()` 직접 호출로 통과 확인.
3. [x] **설계 판단 4건을 몰아서 결정** (오늘 배선할 모든 tool의 형태를 좌우하므로 구현 전에 정리):
   - trajectory 기록 주체 — P1이 상태 전이 지점(`core/state_machine.py:transition`, verify/build/apply 등 각 tool)에서 직접 `TrajectoryRecorder.record_step()`을 호출하는 쪽으로 결정(사후 조립은 evidence_store 스키마 변경 없이도 되지만 label 시점 판단이 P4 쪽에 다시 필요해져 이원화됨). → `core/trajectory.py`로 구현 완료.
   - severity/owasp vocab 채택 — `scanners.vocab.SEVERITY`/`OWASP_2021` 값 집합을 그대로 채택하고 `find_or_create_finding()`에서 `candidate_severity(candidate)`/`candidate_owasp(candidate)`로 `Finding.severity`/`Finding.owasp_category`를 채우기로 결정(스키마 필드는 이미 있고 지금까지 비어 있었을 뿐이라 additive). → 구현 완료.
   - `aggregate.kept` 위치 — `vc_run_sast`/`vc_run_sca` tool 본문에서 각 스캐너 호출 직후 결과를 모아 `aggregate()`를 호출하고 `.kept`만 저장하는 것으로 결정(스캔 두 개를 각각 부르는 기존 tool 분리 구조를 유지하되, 후처리 단계에서 병합). → 구현 완료, cross-scanner dedup은 알려진 한계로 문서화.
   - `check_attack`/`check_positive_functionality` 통합 여부 — **보류로 최종 결정**(위 6개 게이트 섹션 참고).
4. [x] **`find_or_create_finding()`에 severity/owasp 반영** (`core/evidence_store.py`) — 3번 결정 적용, 회귀 테스트 2건.
5. [x] **`vc_run_sast`/`vc_run_sca` 배선**: `scanners.sast.run_semgrep`/`scanners.sca.run_osv` 호출 → `scanners.aggregate.aggregate(...).kept`로 정리 → `Candidate` 저장(+trajectory 기록 훅). `_prepare_scan()` 공통 헬퍼로 CANDIDATE_SCAN 전이(멱등) 처리, 테스트 8건.
6. [x] **`vc_localize_root_cause` 정리**: `_REPO_ROOT / target.manifest.source_dir` 수작업 조합을 `_service().catalog.source_root_for(run.target_id)` 호출로 교체하고, 이제 사실이 아닌 "3개 manifest 블로커" docstring 문구 제거.
7. [x] **`vc_generate_patch` 배선**: `finding_id → Finding`, `repair.locator.localize()`로 `root_cause`, `catalog.source_root_for(run.target_id)`로 `source_root`를 넘겨 `repair.patcher.generate_patch(run_id, finding, root_cause, source_root=...)` 호출 → `Patch(approval=PENDING)` 반환(+trajectory 기록). 실패 시(합성 후보 0개) run 상태 불변 처리, 테스트 4건.
8. [x] **`vc_apply_patch` 구현**: `confirmed=True` 게이트 통과 후 `catalog.worktree_manager_for(target_id).create(run_id)`로 대상 소스 worktree 생성(재시도 시 재사용) → patch diff 적용(+trajectory 기록). **scope gate**를 여기서 사전 강제. 실제 임시 Git repo에서 `git worktree add`+`git apply` end-to-end 검증(원본 branch 미변경 확인 포함) 5건.
9. [x] **judge `check_scope` 게이트 구현** — 8번의 사전 강제와 짝을 이루는 사후 검증. `diff_touched_files()`/`assert_diff_within_worktree()`/`ScopeViolationError`로 구현, 테스트 6건.
10. [x] **judge `check_build`/`check_regression`/`check_static` 게이트 구현 + `vc_build_and_test`/`vc_replay_attack`/`vc_validate_regression` 배선**: `check_build`/`check_static`은 P2 `RunScopedTestRunner`와 같은 `source_dir="."` 치환 패턴으로 worktree를 대상 삼음(Compose `working_dir` target은 알려진 한계로 문서화). `check_regression`은 `catalog.test_runner_for(target_id).run(run_id)` 그대로 호출 — 블로커 없이 완성. 세 tool이 patch당 공유 Validation row를 채운다. 테스트 14건(judge 10 + tool 4).
11. [x] **Finding `fixed`/`RETRY` 전이 로직 완성** (`compute_verdict()` + `_finalize_validation()`). `HUMAN_REVIEW`(재시도 횟수 상한)는 기존 설계대로 Day4 planner 소관, 오늘은 손대지 않음.
12. [x] **`vc_generate_report`용 데이터 조인 준비**(finding+evidence+patch+validation) — `core/report.py:build_run_report(run_id)`로 완성, P4의 HTML/SARIF export가 이 형태를 그대로 소비(D2-P4 요청 c 응답). 테스트 3건.
13. [x] **`26s-w1-c2-04`로 첫 실제 closed-loop 리허설 — 부분 완료**: `catalog.get()`/`check_readiness()`까지 실 target으로 확인(readiness는 `ready=False`, 사유: 이 세션 환경에 P2 로컬 source clone 없음 + manifest가 Windows `py` launcher 참조 — 코드 문제 아님). register→build→start→...→replay_attack 전체 라이브 완주는 **사용자 지시로 P3가 자신의 환경에서 이어가기로 함**(실제 source clone 보유).
14. [x] **커뮤니케이션 정리 + 저녁 `D3-P1.md` handoff 작성** — 완료, 아래 "오늘 커뮤니케이션" 갱신 및 `docs/handoffs/D3-P1.md` 참고.

### 오늘 커뮤니케이션
- [x] **P3에게**: (a) `check_positive_functionality`가 top-level import로 정리됐고 계약(bool, positive만) 그대로 잘 붙는 것 확인 요청. (b) `vc_localize_root_cause` 배선 완료 알림 — 단, P2 manifest 블로커가 풀려야 실제 target으로 호출 가능하다는 것 공유. (c) 2회 재현 최적화(`run_security_validation()` 통합)는 이번엔 보류로 최종 결정했다고 회신(회귀 리스크 대비 이득이 효율뿐이라 Day4/5로 미룸). (d) 그 외 헤드업 3건(RootCause 얇음/`redact()` 제거 시점 Day5/`attack_params` 마이그레이션은 patcher 이후) 전부 확인, 지금은 대응 불필요.
- [x] **P3에게 (D3-P1.md로 전달)**: Repair/Mutation/Judge 전 구간(`vc_localize_root_cause`→`vc_generate_patch`→`vc_apply_patch`→`vc_build_and_test`/`vc_replay_attack`/`vc_validate_regression`) 배선 완료 알림. **`26s-w1-c2-04` 실제 closed-loop 라이브 리허설은 P3가 자신의 환경(실제 source clone 보유)에서 이어가기로 사용자와 합의** — 이 tool들을 그대로 실 target에 호출하면 된다.
- [x] **P2에게 (D3-P1.md로 전달)**: `26s-w1-c3-09`를 `policies/scope.yaml`에 등록 완료 알림. manifest 블로커 2건(catalog 로드 실패, build AttributeError) 수정 확인. patch worktree용 run-scoped Compose overlay 필요성 재확인(1번 항목). **[신규]** `26s-w1-c2-04` `check_readiness()`가 `unavailable_executables=['py']`를 보고함 — manifest 커맨드가 Windows `py` launcher 참조, 크로스플랫폼 이식성 격차로 D5 클린 환경 재현 전에 정리 필요할 수 있음.
- [x] **P4에게 (D3-P1.md로 전달)**: report 데이터 조인(`core.report.build_run_report`) 준비 완료 알림(D2-P4 요청 c 응답) — HTML/SARIF export에서 그대로 소비 가능. `check_static`이 `run_semgrep`/`aggregate` API를 그대로 재사용하니 유지 요청.
- [ ] 교차 리뷰 원칙(Notion 리스크 표): Infra(P2)와 Judge(P1이 배선하지만 실질 판정 로직은 P3와 공동)는 서로 다른 사람이 리뷰 — 내 judge 게이트 구현을 P3 또는 P2에게 리뷰 요청해 self-confirmation 오류를 줄인다. (아직 실행 안 함 — 리뷰 요청은 사람 간 커뮤니케이션이라 사용자가 팀 채널에서 직접 전달해야 함)

---

## Day 4 — E2E 통합 + kill switch/rollback + MCP Skill 번들

**Notion 완료 기준**: 명령 한 줄 → 전체 파이프라인.

**어제 handoff 요약 (D3-P1/P2/P2-status-update/P2-clean-room-prep/P3 기준, D3-P4는 아직 없음)**:
- **P2가 D3에서 run-scoped worktree + Compose overlay + rollback을 전부 완성**했다: `catalog.run_overlay_for(target_id, run_id).prepare()` → `overlay.execute("build"|"start")`, `catalog.test_runner_for(target_id).run(run_id)`(worktree 전용 regression), `TargetRuntimeService.reset_run(target_id, run_id, approved=True)`(Compose reset 성공 후에만 worktree 정리, 실패 시 worktree 보존). `26s-w1-c2-04`가 live로 떠 있고(`:14017`/`:14018`), `26s-w1-c3-09`는 clean-room/holdout 후보로 준비됨.
- **P2가 D3-P2-status-update.md에서 P1에게 직접 요청한 두 가지가 아직 반영 안 됨**: ①"Compose 기반 `check_build()`/start 경로에서 static manifest 실행 대신 P2 overlay를 호출해 patched worktree를 build/start하도록 배선할 것", ②"P1의 kill switch에는 `reset_run()`을 연결할 것". 지금 `check_build`/`vc_build_and_test`는 D3-P1.md가 이미 "알려진 한계"로 기록한 대로 `source_dir="."` 치환 패턴만 쓰고 있어 `working_dir` overlay를 쓰는 target에서는 여전히 원본을 빌드한다 — **patched 코드를 실제로 검증하지 못하는 상태**. 이게 Day4에서 P2 몫이 아니라 P1이 오늘 가장 먼저 갚아야 할 빚이다.
- **P3가 D3에서 c1-05(Spring, JWT)에서 closed-loop 한 바퀴(발견→verified→localize→patch v1/v2→재공격 실패+정상기능 통과)를 실증**했다 — 단, apply→재빌드→재기동은 P2 자동화가 없어 **수동으로 대행**했다. 위 P2 overlay 배선이 끝나야 이걸 `vc_apply_patch`→`vc_build_and_test`→`vc_replay_attack` MCP 경로로 자동 재현할 수 있다. 또한 P3의 `surface/graph.py`(IDOR 프리필터)가 `c2-04`/`c1-05`/`c2-05`/`c3-08` 4개 앱에서 recall·precision 실증까지 끝나 있어, candidate 자동 발견 경로도 이미 쓸 수 있다.
- 🔴 **팀 공통 블로커, P2와 P3 둘 다 제기**: `semgrep`이 Python 3.14 환경에서 실행 자체가 안 된다(`opentelemetry` import 실패). `check_static` 게이트와 P4의 SAST 배치가 이 위에서 돈다 — 지금 상태로는 Day4 E2E 리허설에서 static gate가 무조건 죽는다. 팀이 실행 Python을 3.11/3.12로 통일하거나 semgrep을 시스템 바이너리(brew)로 분리해야 한다(D1-P3에서 이미 제기됐던 버전 불일치가 실제로 터진 것).
- **P4의 D3 handoff가 없다.** D2-P4 이후 상태가 갱신됐는지 모른다 — trajectory export 요구사항, severity/owasp vocab 최종 확인, semgrep 블로커 인지 여부를 오늘 아침 직접 확인해야 한다.

### 0. 오전 최우선 — 어제 넘어온 채무 정리 (다른 모든 작업보다 먼저)

- [x] **P2 overlay를 build 경로에 실제 연결** — 확인해보니 이미 완료돼 있었다. `git log`로 확인한 결과 `81c06be feat: judge 게이트 수정` 커밋(main/planner에 이미 병합됨)이 정확히 이 작업을 했다: `check_build`가 `target.manifest.docker_isolation is not None`이면 `catalog.run_overlay_for(target_id, run_id)` → `overlay.prepare()` → `overlay.execute("build")`를 쓰고, source-native target만 기존 `source_dir="."` 패턴을 유지한다. 이 plan을 짤 때 참고한 D3-P1.md(14:17 작성)가 이 수정(16:39 커밋) 이전 시점이라 낡은 정보였다 — **handoff 문서보다 실제 코드/git log를 항상 먼저 확인할 것**. `check_regression`은 원래부터 `catalog.test_runner_for(target_id).run(run_id)`라 손댈 것 없음. baseline container와 run overlay의 포트 충돌 문제는 아직 미해결로 남아 있어 아래 항목으로 이월.
- [ ] baseline container와 patched run overlay가 같은 loopback port를 쓸 수 있다는 P2 경고(D3-P2-status-update.md) — 포트 할당은 `runtime/compose_isolation.py`/overlay 생성 로직(P2 소유)의 영역이라 P1이 직접 고치지 않는다. 오늘 커뮤니케이션에서 P2에게 실행 순서(예: baseline 먼저 내리고 overlay 실행) 확인만 받는다.
- [ ] 🔴 **semgrep 블로커 팀 확인**: 오전 중 P2/P3/P4에게 상태 공유하고 팀 결정(버전 통일 vs brew 분리)을 받아온다 — 이 결정이 안 나면 오늘 `check_static` 게이트와 P4 SAST 밤 배치가 못 돈다. 결정이 나면 `scanners.sast.run_semgrep` 호출 경로(P4 소유)에 맞춰 내 `check_static` 게이트 실행 환경도 동일하게 맞춘다.
- [ ] **P4 상태 직접 확인**: D3-P4.md가 없으므로 오늘 아침 P4에게 직접 물어 (a) severity/owasp vocab·`aggregate.kept` 배선이 기대대로 동작하는지, (b) semgrep 블로커를 이미 인지하고 있는지, (c) trajectory export에 필요한 정확한 필드/포맷(4.5절 학습 샘플 구조)을 확인한다 — 이 답을 받아야 아래 6번(trajectory export)을 P4가 실제로 쓸 수 있는 형태로 만들 수 있다.

### 1. Kill switch 구현 (10.2절)

- [x] global pause file(`.vibecutter/PAUSE`) 존재 여부를 확인하는 공통 가드(`core/kill_switch.py` 신규, `check_not_paused()` → `KillSwitchEngaged`)를 만들고, `_prepare_verification()`/`_prepare_scan()`(`tools_analysis.py`)과 `tools_repair.py`의 `vc_localize_root_cause`/`vc_generate_patch`/`vc_apply_patch`/`vc_build_and_test`/`vc_replay_attack`/`vc_validate_regression` 6곳 진입부에서 공통으로 호출한다. `vc_pause`/`vc_resume`(`mcp_server/tools_control.py` 신규)은 승인 없이 언제든 호출 가능하고 이 가드 자체를 타지 않는다(pause 중에도 resume은 돼야 하므로). `vc_kill_run`도 같은 이유로 가드를 안 탄다(정리는 pause 중에도 가능해야 함).
- [ ] supervisor timeout: run이 일정 시간 이상 걸리면 강제로 pause 상태로 전이 — **Day4 나머지 작업(planner/SKILL.md/trajectory export)을 먼저 끝내기로 하고 보류**. stdio 단일 프로세스 MCP 서버라 진짜 백그라운드 supervisor는 별도 스레드/프로세스가 필요해 pause file보다 설계 폭이 크다 — Day5 하드닝 때 재검토.
- [x] 테스트(`tests/test_kill_switch.py`, 7건): pause file 존재 시 `_prepare_verification`/`_prepare_scan`이 `KillSwitchEngaged`로 거부되는 것, `clear_pause()` 후 정상 재개되는 것, `vc_pause`→`vc_resume` MCP round-trip.

**검증**: 전체 회귀 146개(kill switch 7건 포함) 통과.

### 2. Rollback 경로 연결

- [x] P2가 제공한 `TargetRuntimeService.reset_run(target_id, run_id, approved=True)`를 신규 `vc_kill_run(run_id: str, approved: bool) -> RunResetResult` tool(`mcp_server/tools_repair.py`)로 노출. reset 실패 시 worktree를 보존한다는 P2 계약은 그대로 존중(삭제 재시도하지 않음, `ok=False`만 반환).
- [x] **[결정] kill 이후 Run 상태는 바꾸지 않는다** — `state_machine.py`에 kill 전용 상태가 없고, kill/rollback은 인프라 정리이지 verified/fixed 같은 보안 판정이 아니라서 공통 계약(RunState 그래프)을 오늘 새로 확장하지 않기로 했다. 강제 중단 사실은 `@audited`(자동 audit log)와 `record_trajectory_step()`으로 남긴다. 확장이 필요해지면 P2/P3와 먼저 공유.
- [x] **[결정] `vc_kill_run`은 kill switch(pause)와 무관하게 항상 호출 가능** — `vc_pause`/`vc_resume`과 같은 이유: pause 중에도 이미 시작된 run은 정리할 수 있어야 한다.
- [x] 테스트(`tests/test_kill_run.py`, 6건): approval 없는 거부, 존재하지 않는 run 거부, `reset_run`이 정확한 `(target_id, run_id, approved=True)`로 호출되는 것 + Run 상태 불변, reset 실패 시 예외 없이 `ok=False`, trajectory 기록, **pause 중에도 호출되는 것** 확인.

**검증**: 전체 회귀 146개(kill switch 7 + kill_run 6 신규) 통과.

### 3. `core/planner.py` — `audit_local_target` 오케스트레이션 + 재시도 상한

**[설계 변경]** 기획서 6.5절 원문(docx 추출 확인)을 다시 읽어보니 MCP Prompt는 "Host가 어떤 순서로 tool을 부를지" 안내하는 메시지 템플릿이지, 상태 머신을 대신 실행하는 Python 오케스트레이터가 아니었다(6.7절 "한 도구는 한 가지 명확한 상태 전이만 수행", 6.8절 SKILL 예시도 Host가 tool을 순차 호출하는 걸 전제). 그래서 계획을 조정했다: 프롬프트는 안내 텍스트만 반환하고(`mcp_server/prompts.py`), **실제 안전 강제(재시도 상한)는 프롬프트가 아니라 `vc_generate_patch` tool 자체가 코드 레벨로 한다** — Host가 규칙을 잊거나 무시해도 4번째 patch 시도는 tool이 거부한다. 이게 이 프로젝트 전체의 원칙(judge도 LLM 판단이 아니라 evidence로 강제)과 일관된다.

- [x] 6.5절 MCP Prompt로 `audit_local_target`을 `mcp_server/prompts.py`(신규)에 등록(`@mcp.prompt()`). register→build→map→scan→verify→localize→patch(승인)→validate→report 순서와 승인 시점, 재시도 상한, kill switch(`vc_pause`)를 안내하는 텍스트를 반환한다. 실제 tool/resource 이름(예: `vibecutter://policies/scope`)만 참조하고, docx 예시에 있지만 실제로 구현되지 않은 `vc_list_authorized_targets`/`vc_judge_evidence` 같은 이름은 쓰지 않았다(존재하지 않는 tool을 안내하면 Host가 혼란스러워진다).
- [x] **3회 연속 patch 실패 → `HUMAN_REVIEW` 강제 전이** (`core/planner.py` 신규): `patch_attempt_count(run_id, finding_id)`로 이 finding에 이미 생성된 Patch 수를 세고, `enforce_retry_budget(run, finding, next_attempt_no=...)`가 `MAX_PATCH_ATTEMPTS=3`을 넘으면 evidence artifact를 남기고 Finding을 `HUMAN_REVIEW`로 승격 + `RetryBudgetExhausted` 예외.
- [x] **`vc_generate_patch`에 배선** (`mcp_server/tools_repair.py`): attempt_no를 항상 1로 고정하던 기존 버그를 고쳐 `patch_attempt_count()+1`로 계산해 `repair.patcher.generate_patch()`에 실제로 전달 — 예전엔 RETRY로 재시도해도 `attempt_no`가 올라가지 않았다(patcher.py 자체 docstring이 이미 "planner가 다음 attempt_no로 재시도"를 전제하고 있었는데 실제 연결이 없었음).
- [x] **[공통 계약 변경, additive]** `core/state_machine.py`의 `RUN_TRANSITIONS[RunState.RETRY]`에 `RunState.HUMAN_REVIEW`를 추가(기존 `PATCH_PROPOSED` 경로는 유지) — 재시도 소진은 patch/verifier 판정이 아니라 프로세스 종료 사유라 RETRY의 기존 목적지만으로는 표현이 안 됐다. P2/P3에 공유 필요(오늘 커뮤니케이션 항목).
- [x] 테스트: `tests/test_planner.py`(7건, retry budget 상한 이내/초과, evidence 확인, RETRY→HUMAN_REVIEW 전이 legality), `tests/test_generate_patch_retry.py`(3건, attempt_no 계산·4번째 시도 거부), `tests/test_prompts.py`(2건, prompt 등록·내용 확인).
- [ ] (원래 계획했던) 전체 register→report mock 기반 happy-path 오케스트레이션 테스트는 하지 않기로 했다 — mapping tool(`vc_map_routes` 등)이 아직 P3 stub(`NotImplementedError`)이라 end-to-end는 애초에 못 돈다. Host가 각 tool을 부르는 구조로 바뀌어서 "P1이 대신 오케스트레이션 함수를 통째로 테스트"할 필요도 없어졌다(테스트 대상은 각 tool의 안전장치).

**검증**: 전체 회귀 158개(planner 7 + generate_patch_retry 3 + prompts 2) 통과.

### 4. build/regression 자동 경로로 c1-05(또는 c2-04) closed-loop 리허설 재현

- [ ] 0번(overlay 배선)과 3번(planner)이 끝난 뒤, P3가 D3에 c1-05에서 수동으로 완주했던 closed loop를 `vc_apply_patch → vc_build_and_test → vc_replay_attack → vc_validate_regression` MCP 경로로 다시 실행해 자동화된 한 바퀴를 증명한다. 이게 Notion Day4 완료 기준("명령 한 줄 → 전체 파이프라인")의 실질적 증거.
- [ ] `check_static`은 semgrep 블로커가 그날 안에 풀리면 포함, 안 풀리면 알려진 한계로 문서화하고 나머지 5게이트만으로 verdict 확인.

### 5. SKILL.md 작성 (6.8절 예시 기반)

- [x] 저장소 루트 `SKILL.md` 작성. docx 6.8절 원문 예시(`vc_list_authorized_targets`,
  `vc_judge_evidence` 등)를 그대로 베끼지 않고 **실제 구현된 tool/resource 이름으로
  다시 썼다** — 그 두 tool은 실제로 존재하지 않는다(문서 초안에만 있었음), 대신
  `vibecutter://policies/scope` resource와 `vc_verify_*`/`update_finding_status`가 같은
  역할을 한다. 각 규칙에 **[코드 강제]**(우회 불가)/**[Host 책임]**(서버가 안 막아줌)를
  라벨링해 Host가 뭘 스스로 지켜야 하는지 명확히 했다:
   - [x] `policies/scope.yaml`에 등록된 target에만 동작 (코드 강제, `PolicyViolation`)
   - [x] 임의 네트워크 목적지 구성 금지 (코드 강제, tool 입력이 식별자만 받음)
   - [x] patch 적용은 explicit user confirmation 없이 금지 (코드 강제 + Host 책임 혼합 — `confirmed=True` 자체는 강제되지만 "진짜 사용자에게 물어봤는지"는 Host 책임)
   - [x] `verified=true`는 오직 judge 결과(evidence 기반)로만 인정 (코드 강제, `update_finding_status`의 evidence 실존 검사)
   - [x] 패치 후 반드시 `vc_build_and_test`+`vc_replay_attack`+`vc_validate_regression` 전부 실행 (Host 책임 — 하나라도 빠지면 verdict가 영원히 미확정)
   - [x] 3회 연속 수정 실패 시 human review 요청 — planner 구현(섹션 3)과 문구 일치, 코드 강제로 격상(`vc_generate_patch`가 4번째 시도 자체를 거부)
   - [x] pause 시 즉시 중단 — `vc_pause` 호출은 Host 책임, 이후 모든 tool 거부는 코드 강제
- [x] Host 설정 예시(claude_desktop_config류, `.venv` 인터프리터 경로 지정) 작성.
- [x] **[신규 발견]** SKILL.md를 실제 tool 배선과 대조하며 쓰다가 발견한 진짜 gap: `vc_map_routes`/`vc_map_roles`/`vc_index_code`가 전부 스텁이고 Run을 `READY`→`MAPPING`으로 옮기는 다른 tool도 없어서, **지금은 Host가 tool 호출만으로 MAPPING 단계를 통과할 방법이 없다**(`vc_run_sast`/`vc_run_sca`는 `MAPPING`/`CANDIDATE_SCAN` 상태를 요구). `surface.graph.find_idor_suspects`(P3, D3 완료)는 이미 있는데 tool로 배선이 안 됐다 — SKILL.md에 알려진 격차로 남겨두고, 아래 커뮤니케이션 항목에서 P3에게 공유.

### 6. Trajectory export 인터페이스 완성 (P4 밤 배치 전제, 오후 최우선)

**[계획 조정]** 0번에서 P4에게 직접 물어 정확한 포맷을 확인하기로 했었는데, D3-P4.md가 여전히 없어 실제로 물어볼 방법이 없었다(팀원 상태 확인은 사람 간 커뮤니케이션이라 대행 불가). 대신 `model/trajectory.py`(P4가 이미 D2에 구현해 둔 것)를 직접 읽어보니 학습 샘플 포맷(`to_sft_sample()`)과 필터링 규칙(`training_samples()`, evidence/validation 연결된 것만)이 이미 코드로 정의돼 있었다 — 그래서 새 포맷을 지어내지 않고 **P4가 이미 정한 포맷을 그대로 재사용**했다. 이게 "물어봐서 확정"보다 더 안전하다(코드가 곧 계약).

- [x] `core/trajectory.py`에 `export_training_dataset(output_path=None, *, run_ids=None)` 추가. `.vibecutter/trajectories/*.jsonl`(모든 run, 또는 지정한 run만)을 순회해 `model.trajectory.training_samples()`로 label 없는(evidence/validation 미연결) 스텝을 제외하고, `model.trajectory.to_sft_sample()`로 그 run의 Observation을 evidence로 조인해 `.vibecutter/trajectories/export/training_samples.jsonl` 하나로 합친다. 새 필터링/변환 로직은 만들지 않았다 — P4 함수를 그대로 호출하는 접착 코드만 추가.
- [x] 테스트(`tests/test_trajectory_export.py`, 5건): label 없는 스텝 제외, run의 evidence 조인 확인, 여러 run이 한 파일로 합쳐지는 것, 존재하지 않는 run_id는 에러 없이 건너뛰는 것, 기본 출력 경로가 `TRAJECTORY_DIR` 하위인 것.
- [ ] **P4에게 전달은 아직 못 함** — D3-P4.md 부재로 P4의 현재 작업 상태(이 함수 시그니처가 실제로 필요한 형태와 일치하는지)를 확인 못 했다. 아래 커뮤니케이션 항목에서 전달.

**검증**: 전체 회귀 169개(trajectory export 5건 포함) 통과.

### 7. P3 candidate bridge 배선 (계획에 없던 항목 — P3가 실시간으로 요청)

P3가 `surface/candidates.py:candidates_for_target(run_id, provisioning, source_root)`를
완성하고 단일 진입점으로 넘겨줬다(`docs/VERIFIER_BATCH_INTERFACE.md` §2/§3 계약, IDOR
suspect 프리필터 + P2 provisioning을 합쳐 typed Candidate 또는 blocked를 낸다). P1이
map/scan 도구 중 하나에 이 한 줄만 배선하면 감사 루프가 실제로 돈다는 요청이었다.

- [x] **신규 tool `vc_scan_access_control(run_id) -> ScanResult`** (`mcp_server/tools_analysis.py`) — `vc_run_sast`/`vc_run_sca`와 같은 패턴(`_prepare_scan`/`_store_scan_candidates` 재사용): `catalog.source_root_for()` + `vc_get_verifier_provisioning()`(P2가 이미 노출한 tool의 내부 함수 `service.verifier_provisioning()`)을 조회해 `candidates_for_target()`에 넘기고, 결과 candidate를 기존 aggregate 파이프라인으로 저장한다. `BridgeResult.blocked`(provisioning 미비로 candidate를 못 만든 경우)는 trajectory에 사유를 남긴다 — "endpoint만 보고 공격하지 않는다"는 P3 계약을 여기서 우회하지 않았다.
- [x] **[추가로 닫은 실제 블로커] `_prepare_scan()`의 READY→MAPPING gap 해소**: SKILL.md 작성 중 발견한 문제(Host가 tool 호출만으로는 MAPPING 단계를 통과할 수 없었음, 섹션 5 참고)를 이번에 실제로 고쳤다 — `_prepare_scan()`이 `READY`로 들어오면 `MAPPING`→`CANDIDATE_SCAN`까지 한 번에 전이시킨다(mapping tool 구현을 더는 기다리지 않음). `vc_run_sast`/`vc_run_sca`도 같은 함수를 쓰므로 이제 셋 다 `READY`에서 바로 호출 가능 — 곁다리 수혜지만 부작용은 없다(additive, 기존 MAPPING/CANDIDATE_SCAN 진입 경로 그대로 유지).
- [x] 테스트: `tests/test_scan_access_control.py`(4건 — candidate 저장+상태 전이, blocked 사유 기록, source_root/provisioning 전달 확인, 미등록 target 거부), `tests/test_scan_tool_wiring.py` 갱신(READY 케이스를 "거부"에서 "cascade 성공"으로 수정 + 무관한 상태는 여전히 거부 확인 케이스 추가).
- [x] **[뒤늦게 발견한 빠뜨린 연결] `audit_local_target` 프롬프트 텍스트 자체가 여전히 `vc_map_routes`(스텁)를 가리키고 있었다** — tool/state_machine은 고쳤는데 Host에게 주는 안내문(`mcp_server/prompts.py`)을 안 고쳐서, 프롬프트 그대로 따르면 여전히 3번에서 멈추는 상태였다. P2가 "audit_local_target prompt가 step 3에서 멈춘다"고 정확히 지적해서 알았다 — `_STEPS`의 3번을 `vc_scan_access_control`/`vc_run_sast`/`vc_run_sca`로 교체하고 이후 번호를 다시 맞췄다. `SKILL.md`의 "표준 절차"도 동일하게 갱신(더 이상 "알려진 격차"가 아님). `tests/test_prompts.py`에 `vc_scan_access_control` 언급 확인 추가.
- [x] **P2 확인 사항 교차 확인**: (a) `res.blocked`를 "P2 fixture 준비/계약 요청으로 기록"하라는 요청 — 기존 구현이 이미 `BlockedTarget.reason`/`needed`(예: "P1 승인으로 vc_prepare_verifier_fixture 실행", "P2가 fixture 구현")를 trajectory에 그대로 남기고 있어 추가 변경 불필요, 그대로 충족. (b) P2가 준비 중이라는 `26s-w1-c2-01`은 `policies/scope.yaml`에 이미 등록돼 있음(포트 14011) — 정책 등록은 안 막힘.

**검증**: 전체 회귀 174개(vc_scan_access_control 4 + 관련 수정 포함) 통과.

### 오늘 커뮤니케이션
- [ ] **P4에게 아침 최우선**: D3 상태가 없어 직접 확인 필요(0번) — severity/owasp vocab·semgrep 블로커 인지 여부 확인.
- [ ] **P4에게 낮 동안 최우선**: `core.trajectory.export_training_dataset()` 완성 알림 — `.vibecutter/trajectories/export/training_samples.jsonl`에 모든 run의 학습 샘플이 P4 자신의 `model.trajectory.to_sft_sample()` 포맷 그대로 모여 있다. **P4의 실제 요구사항과 다르면(예: run 전체 evidence를 통째로 조인하는 지금 방식이 너무 거칠다면) 오늘 안에 알려달라** — `to_sft_sample()`/`training_samples()` 자체는 손대지 않았으니 P4가 그 두 함수만 바꾸면 이 export도 자동으로 따라간다.
- [ ] **P2에게**: (a) overlay를 build/regression 경로에 연결 완료 알림, 포트 충돌 처리 방식 확인 요청. (b) kill switch가 `reset_run()`을 호출하도록 연결했다는 것과 kill 이후 Run 상태 표시 방식(2번 설계 판단) 공유. (c) semgrep 블로커에 대한 팀 결정 참여 요청. (d) `c3-09`(holdout 후보) 준비 상태 확인, Day5 clean-room 리허설에 그대로 쓸 수 있는지 확인.
- [ ] **P3에게**: (a) overlay 배선 완료로 c1-05 closed-loop를 이제 MCP 경로로 자동 재현할 수 있다는 것 알림, 함께 리허설 요청. (b) semgrep 블로커 팀 결정 공유. (c) `RootCause` 확장/`redact()` 제거는 예정대로 Day5로 유지 확인. (d) `vc_generate_patch`가 이제 `attempt_no`를 실제로 계산해 `repair.patcher.generate_patch()`에 넘긴다는 것 확인 요청 — patcher.py 자체 docstring이 전제하던 연결이라 P3 쪽 코드 변경은 없어야 정상. (e) ✅ **해소 완료**: `vc_map_routes` 등 mapping 스텁 문제 — `vc_scan_access_control` 신규 tool로 `candidates_for_target()`을 배선하고 `_prepare_scan()`의 READY→MAPPING gap도 같이 닫았다(섹션 7). c2-04/c1-05로 `vc_scan_access_control` → `vc_verify_access_control` 실제 호출 체인을 P3 환경에서 테스트해달라고 요청.
- [ ] **P2·P3 공통**: `core/state_machine.py`의 `RUN_TRANSITIONS[RunState.RETRY]`에 `HUMAN_REVIEW`를 추가한 것(additive, 기존 `PATCH_PROPOSED` 경로 유지) 공유 — 공통 계약 변경이라 "조용히 변경 금지" 규칙에 따라 알림.
- [ ] 저녁 handoff에 "overlay 배선 완료, kill switch/rollback 동작 확인, planner 오케스트레이션 완성, 3회 실패 HUMAN_REVIEW 전이 확인, trajectory export 완료, semgrep 블로커 상태" 기록.

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

## Extra Day — 기획서 원문 재대조 후 미구현/미충족 항목 클로징

**배경**: `Vibe_Cutter_MCP_심화_기획_및_구현_보고서.docx` 전문(부록 A/B/C, 6.4~6.6절, 10.2~10.3절, 11.3절, 15.1절)과 현재 코드를 기계적으로 재대조한 결과, Day1~5에 "배선 완료"로 적었지만 실제로는 규격을 못 채운 항목과, P3/P4가 이미 산출물을 냈는데 P1 tool이 아직 스텁인 항목이 남아 있음을 확인했다. 아래는 그 격차를 닫는 상세 계획이다.

**우선순위 원칙**: Phase 0(3개 취약점군 closed-loop) → Phase 1(Definition of Done 미충족) → Phase 2(기획서 명시 기능 누락) → Phase 3(안전장치 잔여 + 문서). Phase 0이 발표 핵심 수치("3개 취약점군 end-to-end", 12.4절 목표 성공)를 세우고, Phase 1이 부록 C 미충족 3건을 닫는다.

### 0. 팀과 먼저 합의 (착수 전 아침에 확정 — 이게 안 나오면 Phase 0-3/2-4가 막힘)

- [ ] **P3에게 — XSS/Injection의 positive functionality gate 처리 방침**: `repair/validators.py`가 `_replay_idor`/`idor_oracle`만 써서 IDOR 전용이다(7.6절 6게이트 중 positive functionality). 두 가지 중 택1을 오늘 아침 확정:
  - (a) `validators.py`를 `vuln_class`별로 확장해 XSS/Injection도 정상 기능 재현 — P3 소유 파일 대규모 수정, Day5엔 리스크 큼.
  - (b) **(권장)** XSS/Injection은 positive gate를 regression gate로 대체하고 "IDOR만 6게이트, XSS/Injection은 5게이트"를 알려진 한계로 문서화 — `compute_verdict()`가 vuln_class를 보고 positive_test를 skip(None이 아닌 True로 자동 채움)하도록 판정. 이 판단이 Phase 0-3 구현 형태를 좌우한다.
- [ ] **P2·P3에게 — Run↔candidate 카디널리티 계약**: 어제 넣은 `VERIFYING→VERIFIED` 전이(cb03925) 때문에 run 하나가 candidate 하나만 검증 가능해졌는데(VERIFIED의 유일한 목적지는 LOCALIZING뿐), `audit_local_target` 프롬프트 step 4는 "각 candidate를 검증"하라고 지시해 두 번째 candidate에서 `InvalidTransitionError`가 난다. candidate마다 run을 새로 파는 쪽(권장)으로 갈지, Run을 candidate 루프 컨테이너로 되돌릴지 확정. → Phase 2-6과 연결.
- [ ] **P4에게 — 리포트 소유권 분담**: `vc_generate_report`(HTML)/`vc_export_sarif`(SARIF) 둘 다 아직 `NotImplementedError`인데 D4-P4.md에 배선 기록이 없다. HTML은 P1이 `core.report.build_run_report()` 위에 직접 렌더러를 쓰고, SARIF만 P4가 얹는 분담을 제안·확정(Day5에 P4 응답을 기다리면 부록 C-7이 날아감).

### Phase 0 — 3개 취약점군 closed-loop 완성 (최우선, ~2-3h)

**핵심 발견**: P3가 `verifiers/xss.py:246`·`verifiers/injection.py:226`에 IDOR과 **동일 시그니처**(`verify(run_id, candidate, *, max_requests)`)로 verifier를 이미 구현·실앱 검증까지 끝냈고(`verifiers/dispatch.py`의 `_NOT_READY = frozenset()`가 세 군 전부 준비 완료를 선언), 그런데 P1의 tool은 아직 "P3 구현 대기" `NotImplementedError`다. 이것 하나가 2주차 Exit Criteria와 12.4절 목표 성공("3개 취약점군")을 막고 있다.

- [ ] **0-1. `vc_verify_injection`/`vc_verify_xss` 본문 실배선** (`mcp_server/tools_analysis.py:306-336`):
  - [ ] 상단 import에 `from verifiers.injection import verify as verify_injection`, `from verifiers.xss import verify as verify_xss` 추가.
  - [ ] `vc_verify_injection` 본문을 `vc_verify_access_control`(:256-273)과 동일 패턴으로 교체: `run, candidate, finding = _prepare_verification(...)` → `result = verify_injection(run_id, candidate, max_requests=max_requests)` → `update_finding_status(finding.id, VERIFIED/REJECTED, evidence_ids=result.evidence_ids)` → `_finalize_verification_run(run, verified=result.verified)` → `return result`.
  - [ ] `vc_verify_xss`도 동일하게 `verify_xss` 호출로 교체.
  - [ ] 두 tool의 docstring에서 "P3 verifier 미구현" 문구 제거하고 "P3가 실앱 4개(c2-04/c2-05/c3-08/c1-05)로 검증 완료" 반영(D4-P3-verifier-validation.md 근거).
- [ ] **0-2. judge `check_attack`을 vuln_class 라우팅으로 교체** (`core/judge.py:139-142`): 지금은 `_is_mutation_candidate`로 read/write IDOR 사이에서만 고른다 — XSS/Injection finding의 attack gate를 돌리면 `verify_access_control`이 IDOR 파라미터를 찾다 터진다. `verifier is None`일 때 `verifiers.dispatch.verify_candidate`(vuln_class로 idor/xss/injection 자동 선택)를 쓰도록 교체하고, 중복이 된 `_is_mutation_candidate`(:92-100)와 `verify_mutation_access_control` import를 제거. 명시적 `verifier` 주입 경로는 그대로 유지(테스트용).
- [ ] **0-3. positive functionality gate의 non-IDOR 처리** (`core/judge.py:201-215`, 0번 합의 결과 반영):
  - [ ] 합의 (b)인 경우: `check_positive_functionality`가 finding의 vuln_class를 조회해 IDOR가 아니면 regression gate 결과로 대체(또는 `compute_verdict`가 vuln_class별로 positive_test를 6번째가 아닌 5게이트로 처리). 판정 로직을 명확히 문서화.
  - [ ] 합의 (a)인 경우: P3의 `validators.validate_patch` 확장 완료를 기다린 뒤 top-level import 유지.
- [ ] **0-4. 회귀 테스트** (`tests/test_verify_tool_wiring.py` 확장): xss/injection verifier를 mock으로 대체해 (a) 미승인 거부, (b) verified→Finding 승격 + Run VERIFIED 전이, (c) rejected→미승격 + Run VERIFYING 유지를 `mcp.call_tool()` 실경로로 확인. `test_write_oracle_wiring.py`의 `CheckAttackAutoDispatchTests`에 xss/injection candidate 라우팅 케이스 추가.
- [ ] **0-5. 전체 회귀 재실행** — `.vibecutter/evidence.db` 삭제 후 `python -m unittest discover -s tests` 전건 통과 확인.

### Phase 1 — Definition of Done 미충족 3건 (~2-3h)

- [ ] **1-1. verify 경로에 host 정책 검증 추가** (부록 C-2 "미등록 IP/URL 거부", `mcp_server/tools_analysis.py:83`): `_prepare_verification`이 지금 `require_target_allowed(run.target_id)`만 호출해, verifier가 실제로 때리는 `candidate.attack_params["base_url"]`은 정책 검증 없이 통과한다(`require_host_allowed`의 유일한 호출처가 P2 target_service뿐).
  - [ ] `base_url`이 attack_params에 있으면 `require_host_allowed(run.target_id, candidate.attack_params["base_url"])`를 candidate 조회 직후 호출. 없는 candidate(hand-built 등)는 기존대로 target 검증만.
  - [ ] docstring의 "스키마가 개선되면 require_host_allowed를 추가한다"(:71-74) 문구를 "추가 완료"로 갱신.
  - [ ] 테스트: allowed_hosts 밖 base_url을 가진 candidate → `PolicyViolation`으로 verifier 호출 전 거부.
- [ ] **1-2. audit log의 `changed_files` 실채움 + error redaction** (부록 C-6, 10.2절):
  - [ ] `core/audit_log.py`의 `audited` wrapper가 tool 반환값에서 변경 파일을 뽑을 수 있도록 확장 — 반환이 `Patch`면 `.files`, `Validation`이면 없음 등. 가장 단순한 형태: `record(...)`에 `changed_files` 인자를 넘기는 별도 경로를 열고, `vc_apply_patch`가 성공 후 `patch.files`를 명시 기록(wrapper 자동 추출이 어려우면 tool 본문에서 `audit_log.record` 직접 호출).
  - [ ] `audit_log.py:120`의 `error=str(exc)`를 `error=redact(str(exc))`로 감싸 git stderr/토큰 섞인 URL이 audit_log 테이블에 평문으로 남지 않게 한다(`core.redaction.redact` import).
  - [ ] 테스트: `vc_apply_patch` 성공 후 audit entry의 `changed_files`가 patch.files와 일치, secret 섞인 예외 메시지가 redact되는지.
- [ ] **1-3. `vc_generate_report` HTML 렌더러 구현** (부록 C-7, 15.1 REPORT.html, `mcp_server/tools_repair.py:460-467`):
  - [ ] `core/report.py`에 `render_html(report: RunReport) -> str` 추가 — 부록 B Finding Report Schema(title/CWE/severity/status/evidence/root_cause/patch diff/validation)를 최소 HTML 테이블로 렌더. 외부 의존 없이 f-string/템플릿.
  - [ ] `vc_generate_report`가 `build_run_report(run_id)` → `render_html()` → `.vibecutter/runs/{run_id}/report.html` 저장 → `ReportResult(artifact_uri=..., format="html")` 반환. `NotImplementedError` 제거.
  - [ ] `vibecutter://reports/{run_id}` resource(현재 더미)도 실제 저장 경로를 반환하도록 갱신.
  - [ ] 테스트: 저장된 Finding+evidence+patch+validation이 있는 run으로 호출 → HTML 파일 생성 + 필드 포함 확인.

### Phase 2 — 기획서 명시 기능 누락 (~3-4h, 위에서부터 자름)

- [ ] **2-1. Resources 4개 더미 → 실데이터** (6.4절, 11.5 P0 "Host에서 run 상태·artifact 조회", `mcp_server/resources.py`): `runs/{run_id}/state`는 `get(Run, run_id)`, `runs/{run_id}/evidence`는 `list_by_run(Observation, run_id)`, `targets`는 `list` 기반, `targets/{id}/manifest`는 catalog 조회로 교체. 없는 id는 `ValueError`. `_dummy_*` 함수 제거. **틀린 상태(항상 REGISTERED)를 자신 있게 보고하는 게 미구현 에러보다 위험**하므로 우선순위 높음.
  - [ ] 테스트: 저장된 run/observation이 resource 프로토콜 경로로 그대로 반환되는지.
- [ ] **2-2. Prompts 4개 추가** (6.5절 표, `mcp_server/prompts.py`): `verify_candidate`(특정 후보 최소 재현), `repair_verified_finding`(root cause→patch), `retest_patch`(공격+정상 기능 회귀), `triage_report`(영향/재현성/난이도 우선순위). 각각 실제 구현된 tool 이름만 참조(`audit_local_target`과 같은 규칙 — 존재하지 않는 tool 안내 금지). 테스트: 4개 prompt 등록 + 내용 확인.
- [ ] **2-3. `Finding` 필드 저장 배선** (부록 B, 11.3절, `mcp_server/tools_repair.py`): `vc_localize_root_cause`/`vc_generate_patch`가 `localize()`로 계산한 `RootCause`를 버리지 말고 `finding.root_cause`에 저장(+ `vc_generate_patch`가 매번 재계산하는 낭비도 제거 — 저장된 걸 재사용). `vc_apply_patch` 후 `finding.patch_ids`에 patch.id append, `_finalize_validation`에서 `finding.selected_patch_id`/`validation_id` 채움. 테스트: 리포트에 root_cause/patch가 null이 아니게 나오는지.
- [ ] **2-4. trajectory에 label 전달** (4.6절, `core/trajectory.py` 호출처 8곳): 지금 `record_trajectory_step`이 label을 안 넘겨 `training_samples()`가 전량 탈락 → `export_training_dataset()`이 빈 JSONL을 만든다(P4 D4 밤 QLoRA 입력 0건). verify 성공 시 `label="verified"`, `_finalize_validation`의 FIXED 시 `label="fixed"`, rejected/human_review도 각 지점에서 전달. 테스트: 완주 run의 export가 최소 1건 샘플을 내는지.
- [ ] **2-5. redaction 규칙 확장** (10.2 Secret handling, `core/redaction.py`): 현재 JSESSIONID(Java)/Bearer/password/JWT만 커버. Express `connect.sid`, Django `sessionid`, JSON `{"accessToken":...}`/`{"token":...}`(eyJ로 시작 안 하는 opaque 토큰) 패턴 추가 — c3-08(express)/c2-08(Django)/c2-02·c1-06(self-signup token) evidence가 지금 평문 저장 위험. 테스트: 각 신규 패턴 미노출 + 기존 idempotent 유지.
- [ ] **2-6. Run↔candidate 카디널리티 반영** (0번 합의 결과): candidate마다 run을 새로 파는 쪽으로 확정되면 `audit_local_target` 프롬프트 step 4/5를 "candidate마다 run 생성"으로 갱신하고, 배치 드라이버가 그렇게 돌도록 문서화. 계약 변경이면 P2/P3에 "조용히 변경 금지" 규칙대로 알림.

### Phase 3 — 안전장치 잔여 + 필수 문서 (여유 시, 위에서부터)

- [ ] **3-1. `Run.ended_at` 기록** (11.3절 `start/end`): run이 FIXED/REJECTED/HUMAN_REVIEW 종료 상태로 전이할 때 `ended_at`을 채운다(현재 build 실패 경로에서만 세팅됨).
- [ ] **3-2. `core/db.py` WAL + busy_timeout** (배치 동시 실행 "database is locked" 방지): `create_engine`에 `connect_args={"timeout": 30}` + 최초 1회 `PRAGMA journal_mode=WAL`. `get_engine()`이 매 호출 `create_all`을 다시 도는 것도 최초 1회로 축소. 모듈 docstring이 "잠금 위험을 줄인다"고 주장하지만 실제 PRAGMA가 없던 격차.
- [ ] **3-3. kill switch supervisor timeout** (10.2절): Day4에 보류한 항목. run이 상한 시간 초과 시 자동 pause. stdio 단일 프로세스라 별도 watchdog 스레드 필요 — Day5 여유 없으면 알려진 한계로 문서화만.
- [ ] **3-4. 정책 파일 hash 검증** (10.3절 "시작 시 policy file/target registry 서명/hash 검증"): `Target.manifest_hash` 필드는 이미 있으나 검증 로직이 없다. 서버 시작 시 `policies/scope.yaml`/`commands.yaml`의 hash를 로깅/고정. 최소 구현으로 착수.
- [ ] **3-5. `Observation` untrusted 태깅** (10.3절 prompt injection 방어): target 웹 콘텐츠에서 읽은 observation을 별도 data channel로 구분하는 필드/표기. 스키마 additive 변경이라 Day5 freeze 원칙과 충돌 — 문서화 우선, 구현은 합의 후.
- [ ] **3-6. `policies/vulnerability_profiles/` 채우기** (11.2절): 지금 `.gitkeep`만 있는 빈 디렉터리. 취약점군별 프로파일(안전 템플릿/oracle 규칙 참조)을 최소 3개(idor/xss/injection) 문서로.
- [ ] **3-7. P1 소유 필수 산출물 문서** (15.1절, 현재 SKILL.md만 존재): `MCP_SPEC.md`(tools/resources/prompts schema+권한), `SECURITY_POLICY.md`(allowlist/command policy/sandbox/audit/금지 범위), `ARCHITECTURE.md`(MCP/model/VM/evidence flow), `RUNBOOK.md`(P2 target reset·P4 model serving 섹션은 각자에게 받아 통합). Day5 원래 항목과 중복되므로 함께 처리.

### Extra Day 커뮤니케이션
- [ ] **P3에게**: (a) XSS/Injection verify tool 배선 완료 + `check_attack` vuln_class 라우팅 전환 알림 — verifier 쪽 코드 변경 불필요 확인 요청. (b) positive gate 방침(0번) 최종 결정 회신. (c) closed-loop을 c2-04(XSS)/injection 대상 앱으로 P3 환경에서 실측 요청.
- [ ] **P2에게**: Run↔candidate 카디널리티 결정 공유(계약 변경 시), `sweep_stale_run_overlays` 병합 여부 재확인(어제 보류).
- [ ] **P4에게**: (a) trajectory label 배선 완료 → `export_training_dataset()`이 이제 실샘플을 낸다는 것 알림. (b) HTML은 P1이 렌더, SARIF export만 P4 소유로 분담 확정. (c) report 데이터 소스(`core.report.build_run_report`)는 그대로 유지.
- [ ] **저녁 handoff**: `docs/handoffs/D-extra-P1.md`에 Phase 0~3 완료/보류 항목, 기획서 대비 남은 격차(supervisor timeout/untrusted 태깅 등 문서화만 한 것), Definition of Done 최종 상태를 명시.

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
| semgrep이 Python 3.14에서 실행 불가 (D3 발견, P2/P3 공동 제기) | `check_static` 게이트와 P4 SAST 배치가 죽음 | Day4 오전 팀 결정(3.11/3.12 통일 vs brew 시스템 바이너리) 없이는 static gate를 E2E 리허설에서 제외하고 알려진 한계로 문서화 |

---

## 매일 리듬 체크리스트

- [ ] 아침: 어제 handoff(`docs/handoffs/D{day-1}-*.md`) 확인, 특히 P2/P3/P4가 내게 요청한 항목
- [ ] 낮: 오늘 소유 작업 진행, 공통 계약 변경 필요 시 즉시 관련자에게 공유(조용히 바꾸지 않기)
- [ ] 저녁: `docs/handoffs/D{day}-P1.md` 작성 (상태/변경 파일/제공 인터페이스/검증/타 역할에 필요한 사항/결정·가정·리스크)
- [ ] 저녁: 밤 배치가 도는 경우, 그 배치가 의존하는 내 인프라가 실제로 동작하는지 마지막으로 한 번 확인
