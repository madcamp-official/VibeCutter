# 남은 일 통합 계획 (REMAINING_PLAN)

> **갱신 2026-07-22.** 이 문서 **하나만 읽어도** "지금 어디까지 됐고 · 무엇이 왜 남았고 ·
> 어느 파일을 고치면 되는지 · 다 됐는지 어떻게 확인하는지"를 알 수 있게 쓴다. 처음 보는
> 사람 기준으로 용어·이유·근거 파일을 모두 적었다.
> 계약·인터페이스의 **최종 근거는 여전히 `TEAM_CONTRACT.md`**. 여기는 "무엇을·누가·어떤
> 순서로·어떻게 확인하는지"를 담는다.

---

## 0. 이 제품이 사용자에게 하는 약속 (방향 확정 · 2026-07-21)

모든 남은 작업은 아래 목적을 향한다. 판단이 애매하면 이 절로 돌아온다.

- **타깃 사용자 = 보안 지식이 거의 없는 개발자/일반 사용자.** 전문 용어를 모른다고 가정한다.
- **사용자 경험 = "사용자는 요청만, agent가 알아서."** 사용자가 "내 프로젝트 검사해줘"라고
  하면, agent(Claude 등 MCP 호스트)가 등록·스캔·검증·수정계획·(승인 후)수정·재검증을 **대신**
  수행한다. 사용자는 노동이 아니라 **결정(승인)만** 한다.
- **agent가 사용자에게 보고하는 것은 딱 3가지, 전부 쉬운 말로:**
  1. **발견한 위험** — "로그인한 사람이면 누구나 남의 주문을 볼 수 있어요"처럼 *앱·데이터의
     말*로. CWE/OWASP/엔드포인트 같은 내부 용어는 채팅에 올리지 않는다.
  2. **수정 계획** — "주문을 보여주기 전에 본인 것인지 서버가 확인하도록 바꿀게요"처럼. diff가
     아니라 계획을 보여주고 승인받는다.
  3. **(승인 시) 수정한 내용** — "고쳤어요. 예전 공격이 이제 안 통하고 앱이 정상 동작하는 것까지
     다시 확인했어요."
- **agent가 사용자에게 하는 질문은 쉬운 예/아니오(또는 보기 선택)만.** 앱·데이터 언어로 묻고,
  agent가 레포를 보고 스스로 알아낼 수 있는 건 묻지 않는다.
- **안전 원칙은 그대로(절대 안 깎는다):** 판정(`verified`/`fixed`)은 evidence와 결정론적 judge만
  내린다. 패치는 원본이 아니라 run별 격리 Git worktree에만 적용한다. `FIXED`는 6게이트(Build·
  Attack replay·Positive·Regression·Static·Scope) 전부 통과해야 한다. **사용자 승인 없이는 어떤
  명령 실행·패치 적용·외부 전송도 하지 않는다.**
- **모델 전략: 주 = Qwen3-235B(외부 API), fallback = 72B.** ⚠️ 72B는 **아직 코드·설정에 미반영**
  이다(현재 fallback 기본값이 옛 7B). → 3절.

---

## 1. 지금 위치 (사실)

- ✅ **엔진 전부 완성** — verifier(idor/xss/injection 3종)·judge(6게이트)·llm_synth·patch_client·
  RAG·MCP 배선(W-1~10)·승인 흐름(`vc_export_patch`/`vc_resume_audit`)·lease·runtime metadata. **약 568 tests 그린.**
- ✅ **235B endpoint UP + 실 235B 패치 합성 증명** — Python SQLi를 파라미터 바인딩으로 정확히
  수정(`LIKE '%'+q+'%'` → `LIKE ?, ['%'+q+'%']`). "template 밖 코드를 235B가 패치한다"는 데모 2
  핵심 주장이 실모델로 성립.
- ✅ **c1-05 gold**(IDOR verified→FIXED, 6게이트 全 통과) + **c2-04 reject**(오탐 3건 정확히 거절)
  — IDOR은 실앱 closed-loop 실증 완료.
- ✅ **Juice Shop 등록·pinned source bootstrap** + **P2가 CAMP-1에서 default-bridge로 런타임 경로
  확보**(`/rest/products/search?q=apple` HTTP 200 실측, 2026-07-21 18:48).

**→ "새로 만드는" 단계는 거의 끝.** 남은 건 ①**IDOR 외 2종의 실증·정확도·성능**(4절), ②**임의
사용자 온보딩 완성**(5절), ③**비전문 사용자 UX**(6절), ④**모델 fallback 배선**(3절), ⑤**발표
완주·측정·문서**(7절).

### 1.1 취약점 3종 실증 현황 (한눈)

| | IDOR | Injection(SQLi) | XSS |
|---|---|---|---|
| 검증 오라클 | ✅ 완성(read+write) | ✅ 완성(불리언 차등) | ✅ 완성(격리 브라우저 실행) |
| 후보 자동생성 | ✅ 성숙 | ✅ **(2026-07-22) I1/I2/I3 완료 — Node 인라인 핸들러 gap 해소** | ⚠️ 서버 반사 4패턴(Python 계열만) |
| 실 235B 패치 | (template) | ✅ 스모크 성공 | ❌ 미검증 |
| **실앱 E2E(verified→FIXED)** | ✅ **완료** | ❌ **0회**(J-3 실주행만 남음, 착수 가능) | ❌ **0회**(데모 타깃 없음) |

세 종의 **판정 엔진·안전경계는 동등하게 완성**돼 있고, 차이는 "실증 진척"뿐이다. Injection은 코드
한 곳 + 데모 1회면 IDOR급, XSS는 데모 타깃 확보와 후보 커버리지 확장이 더 필요하다.

---

## 2. 크리티컬 패스 (한 줄)

**단계 0(병렬: Node 후보 gap·ablation·SARIF·72B) → 데모 2 완주(Injection FIXED) → 데모 1 완주(임의
사용자 E2E) + 측정 → 비전문 UX·안전·문서 → E2E·리허설.**
~~가장 큰 단일 리스크는 데모 2의 Injection 후보 gap 하나(4.1 I1).~~ **(2026-07-22 갱신, P1
감사) I1은 이미 해결됐다**(커밋 `ac292a0`, 4.1 I1 참고) — 이제 남은 유일한 병목은 **7.1의
J-3 실주행(P3)**뿐이다. 그것만 끝나면 실 235B FIXED 증거가 나오고 나머지는 병렬로 수렴한다.

---

## 3. 모델 tier — 235B 주 / 72B fallback (72B는 보류)

**현재 운영 결정**: primary=235B. 72B fallback은 준비 전까지 보류한다.
**현실(2026-07-21 코드 기준)**:
- 현재 `.env`에는 **primary(235B)만** 있고 `VIBECUTTER_LLM_FALLBACK_ENDPOINT`가 **미설정** →
  235B 터널이 죽으면 fallback 없이 곧바로 **휴리스틱**으로 떨어진다.
- 코드 기본값 `model/endpoints.py:43` `DEFAULT_FALLBACK_MODEL = "Qwen/Qwen2.5-Coder-7B-Instruct"`
  — **아직 7B**. `.env.example`·`endpoints.py` docstring·`docs/P4_MODEL_SERVING_RUNBOOK.md`도 전부 7B로 서술.
- 즉 **"72B fallback"은 아직 코드·설정·문서 어디에도 없다.** (7B→72B 전환이 최근이라 문서 곳곳에 7B 잔재)

**해야 할 일**
- [ ] **[보류]** 72B endpoint 기동(GPU 서버) + 도달 URL/모델ID/키를 P4에 전달. 72B 서버와
  계약이 준비될 때 재개한다. 현재 발표·E2E의 필수 조건이 아니다.
  (`resolve_tiers`, chained fallback)은 tier-agnostic이라 그대로 재사용된다.
- [ ] **[보류]** `.env`에 `VIBECUTTER_LLM_FALLBACK_ENDPOINT` + `VIBECUTTER_LLM_FALLBACK_MODEL=<72B id>` 추가.
- [ ] **[보류]** `model/endpoints.py`의 `DEFAULT_FALLBACK_MODEL`을 72B로 교체 + `.env.example`·docstring·
  `docs/P4_MODEL_SERVING_RUNBOOK.md`의 7B 표기를 72B로 일괄 정정.
- **완료 판정**: `python -m model.endpoints`가 primary 235B `[UP]` + fallback 72B `[UP]` 둘 다
  보이고, 235B를 죽였을 때 호출이 72B로 넘어가며 `llm_used=True/tier=fallback`이 metadata에 남는다.

---

## 4. ★ IDOR 외 2종(Injection·XSS) 정확도·성능 향상 로드맵 (핵심 · 주담당 P3)

> 이 절이 이번 갱신의 핵심이다. 목표는 두 가지로 나뉜다.
> **정확도** = 진짜 취약점을 놓치지 않고(recall) 안전한 코드를 오탐하지 않는다(precision).
> **성능** = 더 많은 스택/패턴을 커버하고(coverage), 빠르게 돌고(speed), 패치 성공률(6게이트
> 통과율)을 올린다.
> 파이프라인은 **① 후보 생성(surface) → ② 검증 오라클(verifiers) → ③ 패치(repair) → ④ 측정(eval)**
> 4단계다. 각 작업에 **무엇/왜/어디(파일)/완료 판정**을 적었다.

### 4.1 Injection (CWE-89) — 엔진·235B 패치 완성, "후보 생성"이 병목

검증 오라클(`verifiers/injection.py`)은 이미 매우 견고하다(불리언 차등 blind, baseline 노이즈
바닥으로 오탐 억제, GET 기본 + 비-GET은 `read_query` 계약 없으면 거부해 파괴적 write 방지, self-check
6/6). **약점은 오라클이 아니라 "취약한 코드를 찾아 verify 가능한 후보로 만드는" surface 단계다.**

**① 후보 생성 정확도·커버리지**

- [x] **I1. (최우선·데모2 유일 블로커) Node 인라인 핸들러 본문 추출** — `surface/graph.py:186 _node_handlers`
  **(완료 확인 2026-07-22, P1 감사)** — 커밋 `ac292a0`(fix(sqli): injection 후보 생성 경로를
  프리필터와 sync — 줄 넘는 sink + 인라인 핸들러 + 주석 제외)에서 완료. `surface/graph.py`에
  `_NODE_INLINE_FN`이 추가돼 인라인 arrow function 본문을 잡고, `_node_symbol_index`의
  텍스트 기반 `_brace_body` 캡처가 클로저 반환 패턴도 자연스럽게 포함한다.
  `tests/test_inject_xss_bridge.py::test_node_sqli_traces_http_param_not_sql_variable`가
  Juice Shop의 정확한 클로저 팩토리 패턴(라우트는 한 파일, `search()` 팩토리는 다른 파일)을
  재현해 `inject_path=/rest/products/search`, `inject_param=q`를 검증하고 통과함. **데모2
  블로커 해소 — 7.1의 J-3 완주를 지금 시작할 수 있다.**
  - **무엇**: 지금 `_node_handlers`는 라우트가 **이름 붙은 심볼**(예: `router.get('/x', searchProducts)`
    처럼 별도 선언된 컨트롤러 함수)을 참조할 때만 그 본문을 잡는다. **인라인 arrow function**
    (`app.get('/x', (req,res)=>{ ...SQL... })`)과 **클로저 반환 패턴**(Juice Shop의
    `module.exports = () => (req,res)=>{...}`)은 본문을 못 잡아, 그 안의 SQL sink를 못 본다.
  - **왜**: Juice Shop SQLi(`/rest/products/search`)가 정확히 이 클로저 패턴이라 **injection
    candidate가 아예 생성되지 않는다** → 데모 2가 여기서 막혀 있다. (앞서 "Node.js 미지원"이라
    표현했으나 정확히는 `.js/.ts` 파싱은 되고 **인라인/클로저 본문만 미추출**이다.)
  - **어디**: `surface/graph.py`의 `_node_handlers`/`_node_symbol_index`. 라우트 등록 호출
    (`_NODE_CALL`)의 인자에서 인라인 arrow function 본문과, "함수를 반환하는 팩토리"의 반환 본문을
    추가로 추출하는 분기를 넣는다.
  - **완료 판정**: `python -m surface.graph <juice-shop-source>` 실행 시 `/rest/products/search`
    핸들러가 잡히고, `surface.candidates.injection_xss_candidates(...)`가 그 경로로 injection
    candidate를 1건 이상 낸다.

- [x] **I2. SQL sink 탐지 범위 확장(다중 라인·템플릿 리터럴·ORM raw)** — `surface/candidates.py:342 _sql_sink_in_body`
  **(완료 확인 2026-07-22, P1 감사)** — 커밋 `c3b6b26`(줄 넘는 SQL sink 탐지 — 동적 SQL
  대입 후 실행)에서 완료. `_sql_sink_in_body`가 `pending` dict로 동적 SQL 대입을 추적해
  `_EXEC_WINDOW` 줄 안의 실행 호출과 매칭한다. `test_cross_line_python_sqli_becomes_candidate`
  통과, write SQL은 여전히 `blocked`(`test_write_sql_is_blocked_not_candidate` 통과)로
  안전 원칙 유지 확인. ORM raw 호출(`sequelize.query`/`knex.raw`)은 `_EXEC` 정규식에
  포함돼 있으나 전용 단위 테스트는 없음(경미).
  - **무엇**: 지금은 `_DYN`(동적 결합)과 `_EXEC`(실행)이 **한 줄에 같이** 있어야 sink로 본다.
    쿼리를 여러 줄에 걸쳐 만들거나(변수에 SQL을 조립한 뒤 다음 줄에서 실행), JS 백틱 템플릿
    리터럴(`` `...${q}...` ``), ORM raw 호출(`sequelize.query(...)`, `knex.raw(...)`,
    `db.execute(f"...")`)은 놓친다.
  - **왜**: 실제 앱은 대부분 여러 줄에 걸쳐 쿼리를 만든다 → 놓치면 **recall(놓침)** 손해.
  - **어디**: `_sql_sink_in_body`를 "핸들러 본문 내에서 동적 문자열이 실행 호출로 흘러가는지"를
    라인 단위가 아니라 **본문 단위**로 보게 확장. 안전 원칙 유지: **SELECT 계열만** injection
    candidate로 만든다(write SQL은 지금처럼 blocked). 
  - **완료 판정**: 다중 라인 SELECT 조립 + 백틱 리터럴 + `sequelize.query` 각각에 대한 단위
    테스트(`tests/test_inject_xss_bridge.py`)가 injection candidate를 만들고, write SQL은 여전히 blocked.

- [x] **I3. 주입 파라미터 이름 추론 정확도** — `surface/candidates.py:405`
  **(완료 확인 2026-07-22, P1 감사)** — `_http_param_for`(`candidates.py:399`)가
  `req.query.q`/`req.body.X`/`req.params.X`를 sink 줄 → 대입 → body로 역추적한다.
  query/body/path 각 케이스와 "SQL 변수명 ≠ HTTP 파라미터명"(Juice Shop 케이스)까지
  단위 테스트로 확인됨.
  - **무엇**: 지금 `param = _interp_var(line) or "q"` — 못 뽑으면 `"q"`로 가정한다. 파라미터를
    틀리게 잡으면 verifier가 **엉뚱한 필드를 찔러 false negative**가 난다.
  - **왜**: 오라클이 아무리 정확해도, 틀린 파라미터로 재현하면 취약점을 못 재현한다 → recall 손해.
  - **어디**: 동적 값이 온 출처(`req.query.q` → `q`, `req.body.username` → `username`, `req.params.id`
    → path param)를 역추적해 `inject_param`·`inject_location`·`inject_method`를 채운다.
  - **완료 판정**: query/body/path 각 케이스에서 verifier probe의 `inject_param`이 실제 요청
    필드명과 일치(단위 테스트로 고정).

**② 검증 오라클 정확도(정밀 튜닝, 선택)**

- [ ] **I4. (선택) 콘텐츠 유사도 기반 차등 보강** — `verifiers/injection.py:injection_oracle`
  - **무엇**: 현재 판정은 응답 **길이 차이(delta)** + 상태코드 갈림 2신호다. 응답 길이가 입력마다
    자연스럽게 크게 흔들리는 앱에서는 길이만으로 부족할 수 있다.
  - **왜**: 정밀도(precision)를 더 올리려면 "참 응답이 거짓 응답의 상위집합인가(행이 추가로
    열렸나)" 같은 구조 신호가 있으면 좋다. **단 안전 원칙은 유지**(time-based·스택쿼리·UNION·
    파괴적 payload 절대 금지).
  - **완료 판정**: 기존 self-check 6/6 유지 + 길이 노이즈가 큰 합성 케이스에서 오탐이 줄어드는
    회귀 테스트 추가. **급하지 않음 — I1~I3 먼저.**

**③ 패치 성공률**

- [ ] **I5. injection 패치 6게이트 통과율 측정·개선** — `repair/locator.py`(sink 힌트)
  - **무엇**: 235B가 파라미터 바인딩 패치를 만드는 건 스모크로 증명됐다. 이제 **여러 injection
    케이스에서 6게이트를 실제로 통과하는 비율**을 재고, 실패 원인(잘못된 sink 위치, cross-file
    쿼리 등)을 locator 힌트로 보완한다.
  - **어디**: `repair/locator.py`는 이미 CWE-89를 "sink형"으로 분류해 파라미터화 힌트를 준다
    (`_SINK_TYPE_CWES`). 쿼리 조립과 실행이 **다른 파일**에 있을 때 sink 위치를 정확히 짚도록 보강.
  - **완료 판정**: Juice Shop 포함 injection 케이스에서 `PATCH_APPLIED → FIXED` 성공률을 기록
    (4.4 측정과 연결).

### 4.2 XSS (CWE-79) — 오라클은 최상, 실증까지 가장 멀다

검증 오라클(`verifiers/xss.py`)은 세 종 중 설계 품질이 가장 높다("반사됐나"가 아니라 **격리
Playwright에서 실제로 실행됐나**로 판정, reflected/stored 지원, egress 차단, benign marker만).
**약점은 ① 후보 자동생성이 얇고 ② 로컬 데모 타깃이 없다는 것.**

**① 후보 생성 커버리지(가장 큰 약점)**

- [x] **X1. 서버측 반사 XSS 패턴 확장** — **완료(`ea1ac35`)**. `_SERVER_XSS`(HTMLResponse·mark_safe·render_template_string·Markup) + Express `res.send/write/end`(템플릿 리터럴·직접·중간변수 concat, 살균/res.json/정적 제외). 템플릿엔진(EJS `<%- %>`·Handlebars `{{{ }}}`·jinja `|safe`)은 템플릿 **파일** sink이라 X2(라우트 매핑)로. — `surface/candidates.py _SERVER_XSS/_EXPRESS_XSS`
  **(부분 진행 확인 2026-07-22, P1 감사)** — 커밋 `31df59a`/`96600bc`로 프리필터
  (`surface/inject_xss.py`)는 13개 sink 패턴(`jinja.safe`/`thymeleaf.utext` 포함)까지
  늘었지만, **실제 candidate를 만드는** `_SERVER_XSS` 정규식(`candidates.py:355`)은 여전히
  `HTMLResponse|mark_safe|render_template_string|Markup`(전부 Python 호출형) 4개뿐이다.
  프리필터가 찾아도 candidate 생성 단계에서 걸러지는 gap이 남아있음 — Express `res.send`,
  EJS `<%- %>`, Handlebars `{{{ }}}`는 아직 candidate로 안 이어짐.
  - **무엇**: 지금 자동 candidate는 FastAPI `HTMLResponse(f"...{var}...")` **한 패턴만** 잡는다.
  - **왜**: 실제 앱의 대다수 반사 XSS는 다른 형태다 → 못 잡으면 recall 0.
  - **어디**: Express `res.send(userInput)`/`res.write`, 템플릿 엔진의 비이스케이프 출력(Jinja2
    `|safe`, EJS `<%- %>`, Handlebars `{{{ }}}`, Thymeleaf `th:utext`) 등으로 sink 패턴을 늘린다.
  - **완료 판정**: 각 패턴에 대한 단위 테스트가 xss candidate(라우트+파라미터 포함)를 생성.

- [ ] **X2. 프론트/템플릿 XSS를 검증 가능한 후보로** — `surface/candidates.py:426`
  - **무엇**: 지금 프론트엔드 XSS sink(`.innerHTML=`, React `dangerouslySetInnerHTML`, DOM sink)는
    **전부 `blocked`**(라우트·파라미터를 정적으로 못 붙임)로 남는다 → 검증까지 못 간다.
  - **왜**: SPA/프론트 렌더 XSS가 현대 앱에서 큰 비중이라, blocked만 쌓이면 XSS 실증이 불가능.
  - **어디(둘 중 택1 또는 병행)**: (a) **fixture 계약** — inject_path·inject_param·render_path를
    받아 stored/reflected candidate를 만든다(비전문 사용자는 이 값을 모르니 **6절 스캐폴딩/질문**과
    연결). (b) **가벼운 동적 라우트 발견** — 어느 URL이 어느 sink를 렌더하는지 crawl로 매핑
    (`vc_browser_crawl` 확장).
  - **완료 판정**: 최소 한 프론트 XSS sink가 blocked가 아니라 verify 가능한 candidate로 전환되어
    오라클까지 도달.

- [ ] **X3. stored XSS 후보 생성** — `surface/candidates.py`
  - **무엇**: 오라클은 stored를 지원하지만(`_replay_stored`), 후보 생성이 stored candidate
    (inject_path→render_path 매핑)를 **만들지 않는다**. 현재 자동 생성은 reflected만.
  - **완료 판정**: 저장 후 다른 경로에서 렌더되는 케이스에 대해 `context="stored"` candidate 생성.

**② 검증 오라클 성능(속도)**

- [ ] **X4. Playwright 브라우저 재사용으로 속도 개선** — `verifiers/xss.py:_replay_reflected/_replay_stored`
  - **무엇**: 지금 verify마다 브라우저를 새로 띄우고 payload마다 600ms 대기 + 새 페이지를 연다.
    후보가 많으면 느리다.
  - **어디**: 브라우저/context를 verify 범위에서 재사용하고, 첫 실행 확인 후 남은 payload를 조기
    종료(이미 `if executed: break`는 있음 — context 재사용으로 launch 비용 절감).
  - **완료 판정**: 동일 결과를 유지하면서 다수 후보 verify 시간이 눈에 띄게 감소.

- [ ] **X5. Playwright 런타임 사전점검·degrade 보고** — `verifiers/xss.py` + 배선(P1)
  - **무엇**: chromium이 없으면 XSS verify가 실패한다. 실행 전 설치 여부를 점검하고, 없으면
    "브라우저 미설치로 XSS 검증 불가"를 **사용자에게 쉬운 말로** 보고(억지로 verified 처리 금지).
  - **완료 판정**: chromium 부재 환경에서 명확한 사유 반환 + 파이프라인이 죽지 않음.

**③ 패치·데모**

- [x] **X6. XSS 패치 locator 힌트(프레임워크별 출력 인코딩)** — **완료(`517c0f8`)**. `_xss_fix_hint`가 sink 파일 확장자로 프레임워크 추정해 rationale에 올바른 수정 방향(React→DOMPurify/JSX, Vue→v-html 제거, Python→autoescape/markupsafe.escape, JS/Express→textContent/escape-html, 템플릿→비이스케이프 출력 교체)을 실어 235B가 접근제어 가드 대신 이스케이프/정화 패치를 하게 함. — `repair/locator.py`
  - **무엇**: CWE-79는 이미 "sink형"으로 분류돼 출력 인코딩 힌트를 준다. 프레임워크별 정확한
    수정(autoescape on, `escape()`, `textContent` 대신 `innerHTML`, `DOMPurify`)을 힌트에 반영해
    235B가 소유권 가드 같은 엉뚱한 패치를 만들지 않게 한다.
  - **완료 판정**: XSS 패치가 attack 게이트(재실행 시 미실행)와 positive 게이트를 통과.

- [~] **X7. (P2/P3) XSS 검증 target 확보** — OWASP Juice Shop으로 결정(2026-07-22).
  - 소스에는 DOM XSS 교육 경로가 존재한다(`frontend/src/hacking-instructor/challenges/domXss.ts`,
    `/search`, query `q`, `#searchValue` 렌더링). 다만 현재 `targets/manifests/juice-shop.yaml`은
    SQLi 검색 smoke만 선언한다.
  - **남은 계약**: P3가 실제 verifier용 safe payload, observe/positive 조건, reflected/stored
    context, rollback/reset, deterministic regression command를 확정해야 한다. 계약 전에는
    XSS candidate를 verified로 주장하지 않는다.
  - **완료 판정**: 승인된 Juice Shop XSS candidate가 Playwright oracle에 도달해 evidence를 만들고,
    최소 1건의 실제 XSS 검증 결과가 재현된다.

### 4.3 측정 (두 종 공통 · 담당 P4, 소스는 P2)

- [ ] **M1. Injection·XSS를 ablation/eval 표본에 포함** — `eval/priority_ablation.py`, `eval/compare.py`
  **(2026-07-22 P1 감사)** — 부분 진행: `.vibecutter/targets/sources/`가 0개→7개(목표 16개)로
  P2가 일부 채웠고, P4가 `eval/reflect_runs.py`(커밋 `2ee9b93`)로 "이 run이 235B로 돌았는지
  휴리스틱 degrade였는지" 판정 전처리를 추가했다 — 이건 M1의 **전제조건**이지 M1 자체는 아니다.
  `priority_ablation.py`/`compare.py`는 아직 클래스별(injection/xss/idor) precision·순위
  집계 breakdown을 안 내고, 생성된 결과 아티팩트도 아직 없다.
  - **무엇**: 우선순위 ablation 하네스(MRR/first_true_rank)와 verified-precision을 **클래스별로**
    낸다. 현재 벤치 앱 16종 소스가 로컬에 없어(`.vibecutter/targets/sources/` 비어있음) 전체
    주행이 막혀 있다 → **P2가 소스 확보 후** 실주행.
  - **완료 판정**: heuristic vs rag-llm 팔에서 injection·xss 각각의 순위 개선과 verified precision이
    수치로 나온다(RQ3 근거에 클래스별로 편입).
- [ ] **M2. 클래스별 패치 성공률(6게이트 통과율) 집계** — 별도 하네스
  - **완료 판정**: idor/injection/xss 각각 `verified→FIXED` 성공률 표가 발표 자료에 들어간다.

### 4.4 (참고) SAST 규칙 커버리지 — 담당 P4

- [ ] **주의**: 위 surface(정적 프리필터) 확장과 별개로, `scanners/sast`의 semgrep 규칙도
  injection/xss sink를 충분히 커버하는지 점검한다. surface와 SAST는 **다른 경로로 후보를 낸다**
  (`aggregate`에서 합쳐짐). 둘 중 하나만 커버하면 놓친다.

---

## 5. 임의 사용자 온보딩 = 우리 목적(데모 1) 완성 (담당 P1+P2)

"임의 사용자가 자기 프로젝트를 검사·자동패치"는 데모 1이자 제품의 존재 이유다. 배관은 있으나
**아직 실제 사용자 프로젝트로 끝까지 돌린 적이 없고**, 몇 조각이 비어 있다.

- [x] **U1. (가장 큰 빈 조각) manifest 자동 스캐폴딩 도구 신설** — 신규 `vc_scaffold_manifest`
  **(완료 2026-07-22)** — `mcp_server/scaffold.py`(탐지 로직) + `mcp_server/tools_inventory.py`
  (`vc_scaffold_manifest` 등록) + `tests/test_scaffold_manifest.py`(11 tests, 전체 스위트
  579 그린). docker-compose 우선 경로(주 서비스 선택→포트/adapter/test 탐지)와 compose 없는
  단일 서비스 fallback(node/fastapi/spring-boot, `kind=running_local`) 둘 다 구현. 확신 없는
  값은 `evidence`/`warnings`로 근거를 남기고 조용히 틀리게 채우지 않음. 통합 테스트로 "draft가
  `vc_register_local_target`의 `_build_preview`에 블로커 없이 도달"까지 확인해 완료 판정을
  문자 그대로 검증함. **도구 자체는 파일만 읽고 아무것도 등록·실행하지 않으며, `confirmed=True`
  승인 게이트는 그대로.**
  - **무엇**: 지금 `vc_register_local_target(manifest: dict, ...)`은 **manifest를 이미 만들어서**
    받는다. 즉 지금은 agent가 manifest(build/start/stop/reset argv·healthcheck·test_suites)를
    **손으로 조립**해야 하고, 비전문 사용자는 이 값을 모른다.
  - **왜**: "사용자는 요청만" 경험을 실현하는 **핵심 한 수**. 레포(`docker-compose.yml`·
    `package.json`·`pom.xml`·`requirements.txt` 등)를 읽어 stack·포트·명령·health·test를 **탐지해
    manifest 초안 + "이 값을 어느 파일에서 뽑았는지 근거"**를 함께 낸다. 그러면 "사용자가 manifest를
    쓴다(나쁨)"가 "사용자가 초안을 쉬운 말로 승인한다(좋음)"로 바뀐다. **안전 게이트는 그대로**
    (여전히 `confirmed=True` 승인 필요).
  - **완료 판정**: docker-compose 프로젝트에 대해 도구가 유효한 manifest 초안 + 근거를 내고, 그
    초안이 `vc_register_local_target`의 미리보기로 그대로 넘어간다.

- [x] **U2. adapter 거부 메시지 개선(R1-X)** — `mcp_server/tools_inventory.py`, `runtime/manifest.py:23`
  **(완료 2026-07-22)** — `_friendly_adapter_error`/`_validate_manifest`(`mcp_server/tools_inventory.py`)
  가 `vc_register_local_target`의 스키마 검증을 감싸, adapter 필드의 enum 거부만 골라
  "generic-docker를 쓰세요 + 4종 모두 동일 동작" 안내로 바꾼다. adapter 외 다른 검증 실패는
  손대지 않고 그대로 raw `ValidationError`를 낸다(범위를 U2가 지목한 케이스로만 한정).
  `tests/test_local_registry_policy.py`의 `AdapterRejectionMessageTests`(3 tests)로 확인,
  전체 스위트 582 그린.
  - **무엇**: `AdapterKind`는 4종(spring-boot/fastapi/node/generic-docker) enum이고, 실제로는 네
    종류가 **동일 동작**을 한다(`adapters/registry.py:16` — 전부 `ManifestCommandAdapter`). 즉
    **기능 제한이 아니라 라벨**이고, `generic-docker`가 사실상 만능 탈출구다. 그런데 사용자가 자기
    스택명(django 등)을 넣으면 raw pydantic enum 에러만 나와 **탈출구가 있는데도 벽으로 느낀다**.
  - **해야 할 일**: 등록 거부 시 "매칭 안 되면 `generic-docker`를 쓰세요"라는 **쉬운 안내**를 준다.
  - **완료 판정**: 미지원 스택명으로 등록 시도 시 명확한 대안 안내가 나온다.

- [x] **U3. egress 동의(코드가 외부 LLM으로 나가는 것)** — `mcp_server/**`(P1)
  **(완료 2026-07-22)** — `core/egress_consent.py`(kill switch와 같은 durable marker-file
  패턴) + `vc_consent_llm_egress(granted: bool)` tool(`mcp_server/tools_control.py`) +
  `vibecutter://consent/llm_egress` 조회 resource(`mcp_server/resources.py`, Host가 매번
  다시 묻지 않게). 동의 범위는 TEAM_CONTRACT §3A-10대로 **패치 합성 + rerank 스니펫 둘 다**
  — `mcp_server/tools_repair.py::_get_llm_client`와 `mcp_server/tools_analysis.py::
  _rerank_hook_from_env` 두 호출 지점 모두에서 동의 없으면 endpoint를 아예 probe하지 않고
  기존 "endpoint 없음" 폴백(template-only 패치 / 휴리스틱 정렬)으로 조용히 degrade한다 —
  새 예외를 만들지 않고 안전 불변식 3(판정에 LLM 없음)과 같은 정신을 따름. `prompts.py`의
  `audit_local_target`/`repair_verified_finding`에 동의 확인 안내 추가(강제는 아님 — 실제
  게이트는 코드가 함). `tests/test_egress_consent.py`(11 tests, 신규) + 기존
  `test_tools_repair_llm_wiring.py`/`test_scan_tool_wiring.py`에 동의 전제 추가. 전체
  스위트 594 그린.
  - **무엇**: 첫 LLM 호출/등록 시 "코드 일부(secret 제거)가 AI 모델로 전송돼 수정안을 만든다"를
    **쉬운 예/아니오로 1회 동의**받고 기록한다(현재 미구현).
  - **완료 판정**: 동의 표시·기록이 남고, 동의 없이는 LLM 합성 경로로 넘어가지 않는다.

- [ ] **U4. 데모 1 E2E 완주** — 전원
  - **무엇**: 실제 사용자 프로젝트를 `vc_register_local_target(confirmed=True)`로 등록 → snapshot →
    policy 통과 → 스캔 → verified → 수정계획 승인 → `vc_resume_audit`(6게이트) → **FIXED** → patch
    export → reset까지 **한 번 끝까지** 돈다.
  - **완료 판정**: 위 전 과정이 로그로 재현되고, IDOR c1-05와 별개의 "사용자 프로젝트" 사례가 생긴다.

- [ ] **U5. (참고) 정직한 범위 제약 명시** — base_url loopback-only(로컬 앱만), closed-loop엔 clean
  git 필요. 이건 UX 버그가 아니라 안전 경계다 → "이 범위 안에서 다 자동으로 해준다"고 문서·안내에
  명확히 적는다.

---

## 6. 비전문 사용자 경험 — 쉬운 질문·3항목 보고 (담당 P1)

> **중요**: 이건 안전 장치를 안 건드리는 **표현 계층** 변경이다. `confirmed=True` 승인 게이트·
> redaction·정책 거부는 프롬프트를 신뢰하지 않고 **코드가 강제**한다(`mcp_server/prompts.py` 도입부).
> 따라서 말투/보고만 바꾼다.

**현재 상태(반대로 되어 있음)**: `SKILL.md`의 "출력 형식"은 finding마다 `cwe`·`owasp_category`·
`evidence_ids`·diff·6게이트 결과를 보고하라고 하고, `mcp_server/prompts.py`는 "patch diff를 그대로
보여주고 승인받아라"라고 한다 — 보안 전문가를 독자로 가정. 비전문 사용자에겐 정반대.

- [x] **C1. `SKILL.md` "출력 형식"을 3항목 쉬운 보고 계약으로 재작성** — `SKILL.md`
  **(완료 2026-07-22)** — "출력 형식" 절 전체를 ①발견한 위험 ②수정 계획 ③(승인 시)수정한
  내용 3항목 계약으로 재작성(각 항목에 REMAINING_PLAN §0 예시 문장 재사용 + Finding 필드를
  "번역"하는 것이지 나열이 아니라는 점을 명시). 기본적으로 숨기는 6항목(candidate/worker-run
  내부, 재시도 예산, SAST/SCA 내부, evidence ID, 게이트별 개별 판정, CWE/OWASP 코드)을
  각각 "요청 시 어느 resource로 보여줄지"까지 명시. `vc_generate_report`/`vc_export_sarif`가
  이미 구현됐는데 옛 문서가 "미구현"으로 서술하던 stale 서술도 이 절 안에서 함께 바로잡고,
  상세 리포트를 채팅 요약과 별도 층으로 명문화(C4 SKILL.md 쪽 요구사항 일부 선반영). 승인
  게이트·evidence 기반 판정·재시도 상한은 코드가 그대로 강제한다는 점을 "바뀌지 않는 것"으로
  명시해 표현 계층 변경임을 분명히 함. 문서 변경이라 자동 테스트 대상 없음(grep 확인:
  `tests/`에 `SKILL.md`를 참조하는 테스트 없음).
  - 채팅 보고 = ①발견한 위험 ②수정 계획 ③(승인 시)수정한 내용, 전부 앱·데이터 언어의 쉬운 말.
  - **기본적으로 숨길 것**: candidate/worker-run 내부 기계, 재시도 예산, SAST/SCA 내부, evidence
    ID, 게이트별 개별 판정, CWE/OWASP 코드. (원하면 "자세히 보기"로만.)
- [x] **C2. `mcp_server/prompts.py`에 "번역-not-dump 승인" 지침** — `mcp_server/prompts.py`
  **(완료 2026-07-22)** — 등록 argv 승인이 실제로는 **어느 프롬프트에도 안내가 없던 빈
  구멍**이었음을 발견(기존 5종 프롬프트 중 신규 로컬 프로젝트 등록을 다루는 게 하나도 없었음
  — `audit_local_target`은 이미 등록된 target_id를 전제로 함). 그래서 신규
  `register_local_project(source_path)` 프롬프트를 추가해 U1 `vc_scaffold_manifest` →
  쉬운 말 승인(raw argv는 "자세히 보기" 요청 시에만) → `vc_register_local_target
  (confirmed=True)` 흐름을 안내. 기존 두 패치-diff 승인 지점(`_STEPS` 7번,
  `_REPAIR_VERIFIED_FINDING` 3~4번)도 "diff를 그대로 보여주고"에서 "위 계획대로 고쳐도
  될까요? [네/아니오] (바뀌는 코드 보기)"식 번역 패턴으로 재작성. 모듈 docstring에
  "번역-not-dump" 원칙 절 추가(raw 값을 안 보여줘도 `@audited`가 감사기록은 항상 남긴다는
  점 명시). `tests/test_prompts.py`에 신규 프롬프트 테스트 3개 + 패치 승인 번역 패턴
  테스트 2개 추가, 두 tool-참조 일관성 테스트에도 신규 프롬프트 반영. 전체 스위트는
  623 테스트 중 623(제 변경분 기준)이지만, **제 변경과 무관하게 이미 커밋된 상태
  (`fb2dae3`)에서부터 `tests/test_vulnerability_profiles.py` 2건이 실패 중**이었음을
  확인(git stash로 격리 검증) — XSS/injection payload가 verifier 소스와 안 맞음, P3 소유
  `verifiers/xss.py`/`verifiers/injection.py` 쪽 최근 변경(`security/agent` 브랜치 merge
  추정) 때문으로 보이며 C2 범위 밖이라 손대지 않음. P3에게 별도 보고 필요.
  **[해결됨 2026-07-22]** P3가 커밋 `2b482dc`(fix(profiles): vulnerability_profiles YAML을
  verifier payload 소스와 sync)로 수정 완료 확인 — 23/23 통과, 전체 스위트 630/630 통과.
  - **딜레마**: 안전상 승인 2번(등록 argv·패치 diff)이 필요한데, 비전문가는 raw argv/diff를 의미
    있게 승인 못 한다. 숨기면 blind 승인(가짜 동의), raw로 보이면 이해 못 함.
  - **해법**: 승인 대상을 산출물이 아니라 **쉬운 말 설명**으로. 예: 등록="앱을 검사하려면 앱을
    켜야 해요 — 평소 시작 명령을 실행해도 될까요? [네/아니오] (자세히 보기)", 패치="위 계획대로
    고쳐도 될까요? [네/아니오] (바뀌는 코드 보기)". **raw argv/diff는 '보기'로 접어두되 항상
    감사기록으로 남긴다.**
- [x] **C3. 쉬운 질문 원칙 명문화** — `SKILL.md` + `prompts.py`
  **(완료 2026-07-22)** — `SKILL.md`에 "출력 형식"과 짝을 이루는 신규 "질문 원칙" 절 추가
  (예/아니오·보기 선택만 / 앱·데이터 언어 / agent가 스스로 알아낼 수 있는 건 안 물음 —
  확신 있는 값은 계획에 포함해 보고, 확신 낮은 값만 "~로 봤는데 맞나요?"로 확인). `prompts.py`
  모듈 docstring에 동일 원칙을 C2 "번역-not-dump" 문단 옆에 병기하고, `register_local_project`
  프롬프트(C2에서 신설)의 1~2단계를 이 원칙에 맞게 구체화 — `vc_scaffold_manifest`의
  `evidence`(확신 있음)/`warnings`(확신 낮음) 구분을 그대로 "보고 vs 확인" 구분으로 매핑,
  정말 감지 못한 값도 자유 서술보다 보기 선택("포트가 3000/8000/8080 중 하나인가요?")을
  우선하도록 명시. `tests/test_prompts.py`에 검증 테스트 1개 추가. 전체 스위트 624(제
  변경분 기준 전부 그린 — C2 완료 시 보고한 `test_vulnerability_profiles.py` 사전 실패
  2건은 그대로, 제 변경과 무관함을 재확인).
  - 예/아니오 또는 보기 선택만. 앱·데이터 언어로(전문용어 금지). **agent가 레포에서 스스로 알아낼
    수 있는 건 묻지 않는다**(포트·시작 명령은 감지 후 "이거 맞죠?" 확인만).
- [x] **C4. 2단 리포트 분리** — 채팅=3항목 쉬운 요약 / 상세 HTML·SARIF(`core/report.py`·
  `eval/report_export.py`)=감사·전문가용. 상세본은 그대로 두되 "기본 채팅엔 안 올림"을 계약에 명시.
  **(완료 2026-07-22)** — 계약의 핵심(채팅=3항목 요약, 상세 HTML/SARIF는 별도 층)은 이미
  C1(`SKILL.md` "출력 형식"의 "상세 리포트(전문가용, 별도 층)" 문단)이 명시해뒀음을 확인.
  그 문서-계약을 렌더러 코드 쪽에도 거울처럼 남기려고 `core/report.py`(P1 소유, HTML)와
  `eval/report_export.py`(P4 소유, SARIF — **렌더링 로직은 건드리지 않고 docstring만
  추가**) 양쪽 모듈 docstring에 "이 산출물은 상세·감사용이며 내용을 줄이지 않는다 / 기본
  채팅 노출 여부는 Host 쪽 문제(SKILL.md 출력 형식 참고)"라는 동일 문장을 추가. "패치 승인
  때 코드 보기 접어두기" 절반은 C2(`prompts.py`의 두 patch-diff 승인 지점 재작성)에서 이미
  완료됨을 재확인 — 별도 코드 변경 불필요("코드 보기"를 요청할 때만 diff 노출은 Host
  프롬프트 계층의 문제이지 `Patch` 스키마가 diff를 안 담아야 하는 문제가 아님, patch diff는
  git apply 바이트 정확성 때문에 redaction도 하지 않는 기존 결정과 같은 이유로 스키마는
  그대로 둠). 검증: 전체 스위트 624(기존 사전 실패 2건 그대로) + `eval/test_report_export.py`
  4/4(pytest-스타일 스크립트라 `python -m eval.test_report_export`로 별도 실행) 모두 그린 —
  docstring만 바꿔 동작 변화 없음을 재확인.
- 패치 승인 때 기본으로 "바뀌는 코드 보기"를 **접어두기** — C2에서 완료(위 참고)

---

## 7. 발표 필수 — 데모 완주 · 측정 · 문서 · 리허설

### 7.1 데모 2 완주(Injection FIXED) — 발표 핵심 증거
- [ ] **[P3]** 4.1 **I1 해결 후 J-3 1회 완주**: Juice Shop SQLi → verify(불리언 차등) → localize →
  **235B 패치** → 6게이트 → **FIXED**. run_id 공유. (Docker/런타임 경로는 P2가 default-bridge로 확보 완료.)
  **(2026-07-22 P1 감사)** I1은 이미 해결됨(4.1 참고) — **지금 바로 J-3 실주행에 착수 가능.**
  다만 Juice Shop default-bridge는 P2가 "smoke baseline"으로만 채택했고 발표 경로로 아직
  승격하지 않았다는 점(Windows Docker Desktop internal-network 헬스체크 타임아웃, Linux
  npm install 지연)을 감안해 실주행 전 P2와 런타임 상태를 먼저 맞추는 게 안전하다.
- [ ] **[P1]** 이 완주가 승인 흐름(`PATCH_PROPOSED` 정지 → 승인 → `vc_resume_audit` → 6게이트)으로 도는지 확인.
- [ ] **[P4]** 그 run metadata(llm_used/tier/health)를 ablation 표본에 반영.

### 7.2 측정 집계
- [ ] **[P4]** 4.3 **M1/M2** — heuristic vs rag-llm 클래스별 verified precision·순위 개선·패치 성공률.
  **RQ3 근거**("RAG 코드 컨텍스트 + LLM 재랭킹이 휴리스틱보다 우선순위·패치 성공률을 개선하는가").

### 7.3 안전 완성 + 필수 문서
- [ ] **[P4]** SARIF redaction — `eval/report_export.py`의 `render_sarif`/`_finding_to_sarif_result`에
  `redact()` 적용(현재 0건).
- [ ] **[P1]** patch diff / container log redaction(patch diff는 `git apply` 바이트 정확성 때문에 별도 접근).
- [x] **[P1]** `SECURITY_POLICY.md` — 승인모델·loopback 불변식·argv 승인·LLM 전송 범위·"제3자 LLM API 안 씀".
  **(완료 2026-07-22)** — 저장소 루트에 신설. 승인 모델(6개 승인 지점 표), loopback 불변식
  (스키마+allowlist 이중 계층), argv 승인(shell=False + 구문 거부 이중 방어), LLM 전송 범위
  (TEAM_CONTRACT의 확정 문구 "제3자 LLM API를 쓰지 않는다" 그대로 인용 + 자체 서빙/vLLM/
  OpenAI-호환-프로토콜이지 OpenAI Inc.가 아님을 명확히 구분 + Cloudflare 엣지 TLS 종단이라는
  잔여 위험까지 정직하게 명시 + U3 동의 게이트 반영), redaction 범위(정확한 패턴 목록 +
  patch diff/container log/SARIF 세 가지 미해결 gap을 숨기지 않고 명시), kill switch, 패치
  worktree 범위 제한, secret 취급(manifest엔 이름만) 순으로 구성. 마지막 "알려진 한계"
  절에서 fallback 아직 7B인 점 등 진행 중 상태도 정직하게 적음. 문서 작성 전 서브에이전트로
  모든 인용 사실(엔드포인트가 실제로 팀 자체 GPU인지, redaction 패턴 정확한 목록, 각
  승인 게이트의 정확한 강제 코드 위치)을 코드에서 재확인해 틀린 보안 주장을 담지 않도록 함.
- [~] **[P2/P4]** `RUNBOOK.md` — P2 runtime(build/start/reset/lease·default-bridge)과 235B
  degrade 정책은 문서화 완료. 72B fallback serving 절은 endpoint 준비 전까지 보류한다.
- [ ] **[P3]** F-3 한계 문서 — injection positive=liveness / xss positive=benign / running_local N/A 게이트.

### 7.4 E2E 검증 + 리허설
- [ ] **[전원]** 전체 시나리오 통과 — 등록 → snapshot → scan/verify → `PATCH_PROPOSED` 승인 →
  6게이트 → `FIXED` → patch export → reset.
- [ ] **[전원]** 리허설 — 데모 1(사용자 프로젝트 등록·검사·수정) + 데모 2(Juice Shop SQLi→235B→FIXED)
  + fallback(c1-05) + reject(c2-04) 시연.
- [ ] **[전원]** 발표 슬라이드 / MCP_SPEC 취합.

---

## 8. 팀원별 한눈 요약

**(2026-07-22 P1 전수 감사 — 실제 코드/테스트 상태 기준. 아래 각 절의 상세 항목이 최신.)**

- **[P1] 거의 완료.** 6절 UX(C1~C4) ✅ · U1~U3 ✅ · `SECURITY_POLICY.md` ✅. 남은 건 patch
  diff/container log redaction(7.3, 미착수), 데모 2 승인흐름 확인(7.1, **지금 착수
  가능** — I1 해결됨), `.env` 72B fallback 값 추가(3절, P2 URL 전달 대기로 블로킹), U4(전원).
- **[P2] 진척 적음, 대부분 의도적 보류.** 72B endpoint 미착수(문서화된 결정으로 보류) · X7
  XSS 데모 타깃 미착수(Juice Shop을 "발표 target 아님"으로 명시 제외) · M1 벤치 소스
  0→7/16(부분) · Juice Shop default-bridge는 "smoke baseline"으로만 채택, 발표 경로 미승격 ·
  루트 `RUNBOOK.md` 미착수(P2 전용 문서만 존재).
- **[P3] ★ 가장 진척 큼.** I1·I2·I3 ✅ **완료 확인**(데모2 블로커 해소!) — 이어서 I4(선택)·I5·
  X2~X6 미착수, X1은 부분(Python 계열 4패턴만 candidate 생성). `test_vulnerability_profiles.py`
  선제 수정 완료. **다음 최우선: 7.1 J-3 실주행.**
- **[P4]** M1/M2는 전제조건(`reflect_runs.py`, run 분류)만 착수, 클래스별 실제 집계는 아직.
  SARIF redaction 여전히 0건(미착수). 72B로 `DEFAULT_FALLBACK_MODEL` 교체 미착수(문서도 7B
  그대로). SAST 규칙 CWE 매핑은 존재하나 sink 완전성 공식 점검은 안 됨(4.4).

---

## 9. 크리티컬 패스 (다시 · endpoint UP 이후)

~~I1(Node 인라인 핸들러) →~~ **(2026-07-22 갱신) I1 해결됨** → **데모 2 완주(7.1 J-3, P3
착수 가능)** → 데모 1 E2E(+U1 스캐폴딩, ✅ 완료) → 4절 나머지 정확도·성능 + 6절 UX(✅ 완료) +
3절 72B → 측정·문서·리허설.
가장 큰 단일 리스크는 이제 **7.1 J-3 실주행 하나**(P3). 그 다음 큰 레버는 **X7(XSS
데모 타깃, P2 — 아직 미착수)**과 **3절 72B endpoint(P2/P4 — 아직 미착수)**.
