# P1 (이지민) — 2일 스프린트 계획

> 상위 문서: **[TEAM_CONTRACT.md](TEAM_CONTRACT.md)** — 충돌 시 그쪽이 이긴다.

## 내 역할 한 줄

**MCP 표면과 통합의 소유자.** tool/prompt/진입점, 정책 조회, 브랜치 병합, 최종 리허설.

## 내 파일 (배타적)

`mcp_server/**`, `core/policy_engine.py`, `core/report.py`, `core/orchestrator.py`, `core/state_machine.py`, `tests/**`

**남의 파일은 안 고친다.** `runtime/`(P2), `repair/`·`verifiers/`(P3), `model/`·`scanners/`(P4).

---

## P0 — D1 09:00~10:00 · 브랜치 병합 (다른 모든 것보다 먼저)

이번 스프린트가 어긋난 근본 원인이다. 세 갈래가 서로를 못 봐서 P2는 `main`을 보고 "RAG 미구현", P3는 자기 브랜치 기준으로 판단했다.

- [ ] **M-1. `origin/rag` → main** (c8e48f8 + 277b956 + 307c078). RAG 배선 + 코드 컨텍스트 경로. main 460 → 463 tests 예상
- [ ] **M-2. `origin/security/agent` → main** (a189c17 `llm_synth`, 015f23c locator CWE 분기). 충돌 예상 지점: `repair/` 없음(P3 전용), `plan.md`는 무시하고 P3 것 채택
- [ ] **M-3. 병합 후 전체 테스트** → Discord에 **규칙 3 형식**으로 공지. main 커밋 해시 명시
- [ ] **M-4. 전원에게 "main 리베이스하라" 공지.** 이후 모든 주장은 main 기준

⚠️ **병합은 사람이 한다**(팀 규칙). 나는 충돌 해소와 검증까지 하고 최종 push는 사용자 확인 후.

---

## P1 — 정책을 로컬 레지스트리로 (P2와 짝)

**의존**: P2의 `runtime/registry.py`(계약 3.1). D1 오전에 시그니처만 확정되면 **P2 구현 완료 전에도** 내 쪽을 목으로 짤 수 있다.

- [ ] **R1-1. `core/policy_engine.py` 이중 출처 전환**
  - `require_target_allowed(target_id, *, registry=None)`가 ① `policies/scope.yaml`(built-in demo 20개) ② `LocalRegistry`(사용자 승인) 순으로 조회
  - **기존 20개 경로를 깨지 않는다** — c1-05 gold가 fallback이라 필수
  - `require_host_allowed`도 같은 이중 출처. loopback 검증은 manifest 계층에 있으므로 여기선 host 일치만
  - 테스트: built-in만 / registry만 / 둘 다 없으면 거부 / registry의 non-loopback은 P2가 이미 막으므로 여기선 신뢰

- [ ] **R1-2. `vc_register_local_target` tool 신규** (`mcp_server/tools_inventory.py`)
  ```python
  def vc_register_local_target(
      manifest: dict, source_path: str, confirmed: bool = False
  ) -> RegistrationPreview | Target
  ```
  - `confirmed=False`: **저장하지 않고 preview 반환** — base_url, source_path, git 상태, **argv 전문(요약·생략 금지)**
  - `confirmed=True`: `LocalRegistry.approve()` 호출 → audit log
  - **argv 전문 표시가 git PR 리뷰를 대체하는 지점이다**(안전 불변식 2). 줄이지 않는다
  - `vc_apply_patch(confirmed=True)`와 완전히 같은 패턴이라 새 개념이 아니다

- [ ] **R1-3. 기존 `vc_register_target` 정리** — 이름과 달리 "체크인 manifest와 byte 비교"만 한다. docstring을 사실대로 고치고 built-in demo 전용임을 명시. **삭제하지 않는다**(기존 테스트·데모가 씀)

- [ ] **R1-4. `tools_analysis.py` host 검사** — `require_host_allowed`가 이중 출처를 타므로 자동으로 따라온다. **테스트만 추가**(사용자 target의 verify가 통과하는지)

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
