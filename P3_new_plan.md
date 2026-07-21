# P3 — 2일 스프린트 계획

> 상위 문서: **[TEAM_CONTRACT.md](TEAM_CONTRACT.md)** — 충돌 시 그쪽이 이긴다.
>
> **상태(2026-07-21 갱신)**: 엔진(판정·오라클·패치 어댑터·배선·테스트)·계약 P3 몫 **완료**. 남은 건
> **J-3 완주**뿐. candidate gap은 **코드상 해결**(`b512141`): surface는 이미 Node.js를 파싱했고 진짜
> 문제는 `inject_param`이 SQL 변수(criteria)를 잡던 것 → HTTP 파라미터(q) 역추적으로 수정. J-3 남은
> 전제는 **실 Juice Shop Docker 실측 + 235B endpoint(현재 UP)** — J-3 아래 참고.

## 내 역할 한 줄

**판정과 수리의 소유자.** verifier·6게이트·패치 합성. **LLM은 합성에만, 판정에는 절대 안 들어온다.**

## 내 파일 (배타적)

`verifiers/**`, `repair/**`, `core/judge.py`

**남의 파일은 안 고친다.** `mcp_server/tools_repair.py` 배선은 **P1**이 한다(이미 합의됨, 2026-07-21 02:19).

---

## P0 — 브랜치 정리 (D1 오전, P1과 함께)

`origin/security/agent`에만 있는 두 커밋이 main에 들어가야 나머지가 시작된다.

- [x] **M-1. `a189c17`(`repair/llm_synth.py`) main 병합** — 완료
- [x] **M-2. `015f23c`(locator rationale CWE 분기) main 병합** — 완료
- [x] **M-3. 병합 후 `test_llm_synth` + `test_locator` main에서 재확인** — 완료 (현재 llm_synth 17 / locator 40)

---

## P1 — `running_local`의 6게이트 정의 (신규, 나만 결정 가능)

**이번 스프린트에서 가장 설계가 필요한 항목이다.** 사용자가 "이미 떠 있는 서비스"를 등록하면 build 명령이 없다.
그런데 6게이트 중 **build·regression이 명령 실행을 전제**한다.

- [x] **K-1. kind별 게이트 의미 확정** (`core/judge.py`) — `_target_kind` + running_local이면 `check_build`→None

  | 게이트 | `compose_project` | `running_local` |
  |---|---|---|
  | build | 현행 | 명령 없으면 **N/A**(통과로 세지 않고 별도 표기) |
  | attack | 현행 | 현행 (재공격 — 변경 없음) |
  | positive | 현행 | 현행 |
  | regression | test_suite 실행 | test_suite 없으면 **FIXED 불가**로 명시 |
  | static | Semgrep 재실행 | 현행 (소스만 있으면 됨) |
  | scope | diff 경로 검사 | 현행 |

- [x] **K-2. "N/A 게이트"를 통과로 위조하지 않는다.** `compute_verdict()`가 게이트 None이면 verdict 안 냄 + `check_regression` 빈 test_suites=False — 기존 구현으로 자동 강제 (P1 3A-11#3 인정). 테스트: `test_judge.test_running_local_returns_none_without_attempting_build`
- [ ] **K-3. 사용자에게 뭐가 부족한지 알려준다** — "test_suite 없어 regression 못 돌림, PATCH_PROPOSED까지만" 같은 명시적 사유. ⚠️ **부분**: judge는 None 반환(✅)하나 **user-facing 사유 표시는 미구현** — report/tool 레이어(P1)로 보임
- [x] **K-4. c1-05 gold가 안 깨지는지 확인** — `_target_kind` 기본 compose_project라 inert. `run-897ad65c686f` 6게이트 全1·FIXED 유지 확인(2026-07-21)

⚠️ 이 설계 없이 `running_local`을 열면 **"게이트를 안 돌리고 FIXED"**가 나온다. 그건 제품 주장 자체를 무너뜨린다.

---

## P2 — LLM 패치 합성 완성 (데모 2)

`repair/llm_synth.py`는 이미 만들었다(`a189c17`). 남은 건 정렬과 실검증이다.

- [x] **S-1. P4의 공유 컨텍스트 빌더와 정렬** (계약 3.4) — `make_llm_synthesizer(context_provider=...)` 주입점 + `_number_lines`로 폴백 소스 줄번호화(code_context와 동일 형식). P1이 `_code_context_for`로 배선함
- [x] **S-2. `PatchModelClient` 검증** — 현재 어댑터 ↔ 실 `_ChatPatchClient` 결합 오프라인 스모크 통과(degrade/wrap/integration). **실 235B 1회 합성은 J-3에서** (endpoint 종속)
- [x] **S-3. diff 파싱 견고성** — 펜스 언어 무관·설명문·탭 타임스탬프 내성 + 어떤 입력에도 예외 미발생. 테스트 추가
- [x] **S-4. `assert_diff_within_worktree` 사전거부** — `_is_scope_safe_path`로 절대경로·`..` 후보 합성 단계에서 drop. 테스트 추가

---

## P3 — Juice Shop verify 계약 (데모 2의 전제)

- [x] **J-1. regression 계약 A/B 회신** — **B(image smoke)** 채택·전송. `test_suites: juice-shop-search-smoke`로 매니페스트 반영됨
- [x] **J-2. verify 계약 확정** — `vuln_class=injection`, `GET /rest/products/search?q=`, blind 차등 오라클, liveness positive, reset rollback. 전송 완료. 오라클은 J-2 실측 패턴(631/18662/30B)으로 회귀 테스트 잠금(`test_juice_shop_sqli_demo_pattern`)
- [ ] **J-3. verified → LLM 패치 → 6게이트 완주 1회** — ❌ 미실행. **패치 경로는 코드상 완결·오프라인 검증 완료**, 남은 건 순수 환경 블로커 2개:
  - **(1) 실 Juice Shop Docker 실측** — fixture는 구조 모사일 뿐 실 서버 응답이 아니다. 실 컨테이너에서 verify가 blind 차등(J-2 오라클)을 실제로 내는지 1회 확인 필요(P2 단계 0 Docker 종속).
  - **(2) 235B endpoint** — **현재 DOWN**(재확인 시 key:no, 아까 UP이었으나 P2 터널/env 내려감). 실 235B로 Sequelize 템플릿 리터럴 SQLi 파라미터화 패치를 실증하려면 복귀 필요(P2).
  - ✅ **candidate 공급 해결(`b512141`)** — surface는 이미 Node(.js/.ts)를 파싱한다(이전 "미지원" 서술은 stale). 실제 gap이던 `inject_param`(SQL 변수 criteria)을 `_http_param_for`로 HTTP 파라미터(q) 역추적. `test_node_sqli_traces_http_param_not_sql_variable` 잠금.
  - ✅ **패치 대상 파일 해결(`faf01ab`)** — Express는 route 등록(server.ts)과 handler 정의(routes/search.ts)가 분리돼 root_cause.file이 SQL 없는 파일을 짚던 문제를, `extract_routes`가 handler 심볼을 정의 파일로 되짚게 + candidate source_symbols를 sink 파일:라인으로 수정. `RootCause.file=routes/search.ts` 확인.
  - ✅ **패치 프롬프트 오프라인 검증** — 실배선(`make_llm_synthesizer` + `_code_context_for`)으로: SQL sink 노출·SQLi 파라미터화 유도(IDOR 오유도 없음)·PatchCandidate가 routes/search.ts 대상 diff 생성 확인. **endpoint만 돌아오면 J-3 완주 가능.**

---

## P4 — 데모 리허설 (D2)  *(P4 소유 — P3 참고용)*

- [ ] **F-1. 데모 2 완주** (Juice Shop SQLi → LLM 패치 → FIXED) — J-3 종속
- [ ] **F-2. fallback 확인** — c1-05 gold(`run-897ad65c686f`). P3 확인: 로컬 evidence.db에서 6게이트 全1·FIXED 유지(2026-07-21) ✅
- [x] **F-3. 한계 문서화** — [`docs/P3_VERIFY_JUDGE_LIMITS.md`](docs/P3_VERIFY_JUDGE_LIMITS.md). injection positive=liveness / xss positive=benign·실행관찰 / injection payload 비파괴 / running_local N/A 게이트 / static semgrep 의존 — 코드 검증 완료. P1이 SECURITY_POLICY.md로 취합 예정

---

## 하지 말 것

- ❌ **`core/judge.py`에 LLM 주입** — 안전 불변식 3. 판정은 evidence와 게이트 결과로만
- ❌ **못 돌린 게이트를 통과로 표기** — K-2
- ❌ `mcp_server/**` 직접 수정 — P1 것. 배선 요청은 Discord로
- ❌ 임의 취약점 삽입 — 승인된 교육용 앱만
- ❌ c1-05 gold 경로를 깨는 변경

## 보고

계약 규칙 3 형식.
