# P3 — 2일 스프린트 계획

> 상위 문서: **[TEAM_CONTRACT.md](TEAM_CONTRACT.md)** — 충돌 시 그쪽이 이긴다.

## 내 역할 한 줄

**판정과 수리의 소유자.** verifier·6게이트·패치 합성. **LLM은 합성에만, 판정에는 절대 안 들어온다.**

## 내 파일 (배타적)

`verifiers/**`, `repair/**`, `core/judge.py`

**남의 파일은 안 고친다.** `mcp_server/tools_repair.py` 배선은 **P1**이 한다(이미 합의됨, 2026-07-21 02:19).

---

## P0 — 브랜치 정리 (D1 오전, P1과 함께)

`origin/security/agent`에만 있는 두 커밋이 main에 들어가야 나머지가 시작된다.

- [ ] **M-1. `a189c17`(`repair/llm_synth.py`) main 병합** — P1이 집행, 나는 충돌 해소 지원
- [ ] **M-2. `015f23c`(locator rationale CWE 분기) main 병합**
  - XSS/SQLi finding에도 IDOR "소유권 검사 누락" 문구가 나가던 것을 고친 것. **안 들어가면 모델이 소유권 가드를 만들어 attack 게이트가 계속 reject한다** — 데모 2의 숨은 블로커
- [ ] **M-3. 병합 후 `test_llm_synth`(7건) + `test_locator`(37건) main에서 재확인**

---

## P1 — `running_local`의 6게이트 정의 (신규, 나만 결정 가능)

**이번 스프린트에서 가장 설계가 필요한 항목이다.** 사용자가 "이미 떠 있는 서비스"를 등록하면 build 명령이 없다.
그런데 6게이트 중 **build·regression이 명령 실행을 전제**한다.

- [ ] **K-1. kind별 게이트 의미 확정** (`core/judge.py`)

  | 게이트 | `compose_project` | `running_local` |
  |---|---|---|
  | build | 현행 | 명령 없으면 **N/A**(통과로 세지 않고 별도 표기) |
  | attack | 현행 | 현행 (재공격 — 변경 없음) |
  | positive | 현행 | 현행 |
  | regression | test_suite 실행 | test_suite 없으면 **FIXED 불가**로 명시 |
  | static | Semgrep 재실행 | 현행 (소스만 있으면 됨) |
  | scope | diff 경로 검사 | 현행 |

- [ ] **K-2. "N/A 게이트"를 통과로 위조하지 않는다.** `Validation`에 그대로 `None`을 남기고 `compute_verdict()`가 **FIXED로 올리지 않게** 한다. 게이트를 못 돌린 것과 통과한 것은 다르다
- [ ] **K-3. 사용자에게 뭐가 부족한지 알려준다** — "test_suite가 없어 regression 게이트를 못 돌립니다. FIXED 대신 PATCH_PROPOSED까지만 갑니다" 같은 명시적 사유
- [ ] **K-4. c1-05 gold가 안 깨지는지 확인** — `compose_project` 경로는 현행 유지가 원칙

⚠️ 이 설계 없이 `running_local`을 열면 **"게이트를 안 돌리고 FIXED"**가 나온다. 그건 제품 주장 자체를 무너뜨린다.

---

## P2 — LLM 패치 합성 완성 (데모 2)

`repair/llm_synth.py`는 이미 만들었다(`a189c17`, 테스트 7/7). 남은 건 정렬과 실검증이다.

- [ ] **S-1. P4의 공유 컨텍스트 빌더와 정렬** — 계약 3.4
  - `scanners.rag_enrich.code_context()`가 `{candidate_id: 줄번호 붙은 스니펫}`을 준다
  - 지금 `build_prompt`는 root_cause 파일 소스를 자체 redaction해 싣는다. **급히 걷어낼 필요 없다** — `core.redaction`은 idempotent라 중복 적용이 무해하다
  - 다만 **줄번호가 붙은 스니펫이 모델에게 훨씬 유용하다**(모델이 "6번 줄이 sink"라고 짚을 수 있음). 여유가 있으면 전환
- [ ] **S-2. `PatchModelClient` 실물로 검증** — P4가 `build_patch_model_client()`를 주면 목이 아닌 실제 235B로 1회 합성. 지금까지는 목으로만 검증됨
- [ ] **S-3. diff 파싱 견고성** — 모델이 fenced block·설명문·경로 오타를 섞어 낼 때 후보를 버리되 예외로 터지지 않는지. `expected-file 필터`가 이미 있으니 실응답으로 재확인
- [ ] **S-4. `assert_diff_within_worktree` 통과 확인** — worktree 밖 경로를 건드리는 후보는 `core.judge`가 막지만, 합성 단계에서 미리 버리는 게 낫다

---

## P3 — Juice Shop verify 계약 (데모 2의 전제, P2 대기 중)

**P2가 2026-07-21 02:46부터 내 회신을 기다리고 있다. 이게 D1 최우선 회신이다.**

- [ ] **J-1. regression 계약 A/B 회신**
  - A: `npm install` 후 `npm run test:server`
  - B: 공식 이미지 smoke(health + 정상 검색 + SQLi 수정 후 동일 검색)
  - ⚠️ **판단 기준**: `test_suites=[]`면 regression 게이트가 False라 **FIXED가 안 나온다.** 데모 2가 "LLM 패치로 FIXED까지"를 보여주는 거라면 반드시 하나를 골라야 한다
  - 내 권고: **B가 결정적이고 빠르다.** A는 `package-lock` 부재로 `npm ci` 불가 상태라 재현성이 흔들린다
- [ ] **J-2. verify 계약 확정** — `vuln_class=injection`, safe payload/observe/positive-liveness/rollback
  - 검색 endpoint `GET /rest/products/search?q=`는 **read**라 우리 injection verifier의 안전 계약(SELECT-only·불리언 tautology·파괴적 write 금지)에 부합
  - 로그인 SQLi(`' OR 1=1--`)는 auth-bypass tautology라 **blind 차등 오라클과 결이 다르다** — 2순위
- [ ] **J-3. verified → LLM 패치 → 6게이트 완주 1회** (P4의 client 확보 후)

---

## P4 — 데모 리허설 (D2)

- [ ] **F-1. 데모 2 완주** (Juice Shop SQLi → LLM 패치 → FIXED)
- [ ] **F-2. fallback 확인** — c1-05 gold(`run-897ad65c686f`)가 여전히 도는지. **깨지면 최우선 복구**
- [ ] **F-3. 한계 문서화** — injection positive=liveness까지 / xss positive=benign 반영 확인 / `running_local`의 N/A 게이트

---

## 하지 말 것

- ❌ **`core/judge.py`에 LLM 주입** — 안전 불변식 3. 판정은 evidence와 게이트 결과로만
- ❌ **못 돌린 게이트를 통과로 표기** — K-2
- ❌ `mcp_server/**` 직접 수정 — P1 것. 배선 요청은 Discord로
- ❌ 임의 취약점 삽입 — 승인된 교육용 앱만
- ❌ c1-05 gold 경로를 깨는 변경

## 보고

계약 규칙 3 형식. **J-1(regression A/B)은 P2가 대기 중이라 D1 오전 최우선.**
