# Vibe Cutter — P3(박준서) 5일 실행 계획

> 참고 문서: `Vibe_Cutter_MCP_심화_기획_및_구현_보고서.docx`(기획서), `cowork_rule.md`(협업 규약), Notion "4명/5일 분업 계획"(팀 배분표), `plan.md`(P1 계획), `docs/handoffs/`(일일 handoff)
> 상충 시 우선순위: **Notion 5일 계획 > 기획서 DOCX > cowork_rule.md** (cowork_rule.md 1절, 팀 리더 최신 지시가 최우선).

## 0. 내 역할 요약

**P3 = Security/Agent.** 소유 영역: attack surface 매핑, IDOR·XSS·Injection verifier, root-cause locator, patch 생성, replay judge.

**이 프로젝트에서 내 위치**: 파이프라인 7단계 중 **2(지도 그리기) · 4(실제 공격) · 5(원인 추적) · 6(패치 생성)**이 내 것이다. 나머지는 인프라(P1/P2)와 평가(P4)다. **4번이 이 프로젝트의 존재 이유다** — 기획서 16장이 꼽은 MVP 승부처 3개 중 ②"LLM 주장과 verified finding의 엄격한 분리"와 ③"패치 후 동일 공격과 정상 기능을 모두 통과시키는 closed loop"가 전부 내 손에 있다. 내가 없으면 이건 "Semgrep 돌려주는 챗봇"이 되고, 기획서 14장이 "발표에서 얕아 보임 / 징후: ZAP+LLM wrapper로 인식"으로 경계하는 게 정확히 그 실패다.

**내가 병목이다.** Notion 리스크 표: "의존성 병목 — **P3의 D3~D4가 병목.** P1 evidence store(D2)·P2 reset/worktree(D2·D4)를 하루 앞당겨 P3이 안 막히게." 즉 다른 사람들이 나를 위해 일정을 당기는 구조다. 내가 밀리면 프로젝트 전체가 밀린다.

다른 역할과의 관계:
- **P1(이지민, Platform/MCP)** — MCP 서버, policy engine, evidence store, state machine, judge 배선. **내 verifier를 호출하는 쪽.**
- **P2(안종화, Target/Infra)** — Docker/VM 격리, target manifest, adapter, reset/snapshot, worktree/테스트 러너. **내가 공격할 대상을 주는 쪽.**
- **P4(유나연, Model/Eval)** — inventory, RAG/코드인덱스, Semgrep, baseline/metric, LoRA, 발표. **내 candidate를 주고, 내 verified trajectory를 가져가는 쪽.**

**절대 건드리지 않을 것** (cowork_rule.md 2절):
- `contracts/schemas.py`, `core/*` (P1 공통 계약) — 이견은 handoff로만
- `mcp_server/*` (P1) — tool 본문 소유권이 정해지기 전까지
- adapter 내부 로직(P2), Semgrep/LoRA(P4)
- 필요하면 최소 변경 + 이유와 영향 범위를 handoff에 기록

**내 것**: `surface/`, `verifiers/`, `scanners/playwright.py`, `repair/`, `policies/vulnerability_profiles/`(소유 확정 필요)

**Handoff 규칙**: 매일 종료 시 `docs/handoffs/D{day}-P3.md`를 cowork_rule.md 6절 템플릿으로 남긴다.

---

## 현재 상태 (Day1 종료 시점 — 정직하게)

**Day1 완료 기준("타깃 1 endpoint ↔ role graph") 미달.**

원인: **분석할 앱이 존재하지 않는다.** 저장소에 target 소스 없음, `/lab/targets` 없음, 원격 브랜치(`p4`/`mcp`)에 올라온 것도 기본 문서뿐. 실질적으로 P1만 Day1을 완주했다. 지도를 그리라는데 땅이 아직 없다.

한 것:
- [x] venv + 의존성 설치, MCP 서버 기동 확인 (tool 25개, stdout 오염 없음)
- [x] P3 모듈 스캐폴딩 (`surface/`, `verifiers/`, `scanners/`, `repair/`)
- [x] **verifier 호출 계약 공개** (`verifiers/types.py`) — P1이 Day2 배선에 필요
- [x] **P1 Day1 산출물 검증 → 구멍 3개 발견** (`docs/handoffs/D1-P3.md`)
- [x] 공통 계약 이견 4건 정리 → P1에 전달 대기

못한 것:
- [ ] endpoint ↔ role graph (**대상 앱 없음** — Day2 오전으로 이월)
- [ ] IDOR oracle 스펙 문서화 (Day2 오전으로 이월)

**Day1 리뷰가 헛짓은 아니다** — Notion 리스크 표의 "교차 리뷰: Infra와 Judge는 서로 다른 사람이 리뷰 — self-confirmation 오류 차단"이 명시적 프로젝트 규칙이고, 발견한 구멍 ①은 이 프로젝트의 핵심 주장을 직접 뚫는다. 다만 이건 Day1 완료 기준이 아니다.

---

## Day 2 — 막힌 것 뚫기 + IDOR verifier

**Notion 완료 기준**: IDOR verified 1건 이상.
**현실**: Day1 이월분(graph)을 오전에 끝내고 오후에 verifier. 대상 앱이 오전에 안 오면 이 기준은 달성 불가 → 그 경우 아래 "대상 앱이 계속 없을 때" 항목 발동.

### 오전 (전부 남에게 묻는 것 — 30분 안에 끝내고 코딩으로 넘어간다)

- [ ] **P2에게 (최우선, 1분)**: "앱 소스 경로 하나만. **도커 안 띄워도 됨, 소스만.**" — 소스 기반 route 추출은 앱 실행 없이 된다. P2의 Dockerize를 기다릴 이유가 없다.
- [ ] **P1에게 (3분)**: "verify tool 본문 내가 채워? 형이 채우고 내 함수 부를 거야?" — `docs/handoffs/D1-P3.md`의 🟡 항목. 이거 안 정하면 둘이 같은 파일에서 충돌한다. `verifiers/types.py`를 보여주며 물어본다.
- [ ] **P1에게**: 구멍 ①(허구 evidence_id 승격) / ②(secret redaction 소유자) / ③(`max_requests` 제약) 전달. handoff 링크 던지면 끝.
- [ ] **P1에게**: 공통 계약 이견 4건 — 특히 **`Candidate`에 `vuln_class`/공격 파라미터 없음**. **오늘 IDOR verifier를 짜려면 이게 있어야 한다.** DB에 데이터 0건인 지금이 고치기 가장 싸다.
- [ ] **P4에게**: `Observation.type` 값 집합 합의 (`http_exchange | db_diff | browser_trace | log | route_map | role_map`). P4의 trajectory 조인이 여기 걸린다.

### 오후

- [ ] **`surface/routes.py`**: 소스 기반 route 추출 (Spring `@GetMapping`/`@PostMapping`, FastAPI decorator, Express router). **Day1 이월 — 최우선.**
- [ ] **`surface/roles.py` + `surface/graph.py`**: role ↔ endpoint 매핑 → `Endpoint ↔ Role ↔ Source Symbol` 그래프. **Day1 완료 기준 회수.**
- [ ] **IDOR oracle 스펙 확정**: 7.3절 "역할 A가 만든 자원을 역할 B가 읽거나 변경했는지 **DB/API 상태 비교**". **응답 200 하나로 verified를 만들지 않는다** — 실제 상태 변화를 관찰해야 한다. 이 스펙이 곧 evidence 포맷이다.
- [ ] **`verifiers/access_control.py`**: IDOR verifier. `verify(run_id, candidate, *, max_requests) -> VerifierOutput`.
- [ ] evidence 기록: `evidence_store.write_artifact(run_id, observation_type="http_exchange", producer="vc_verify_access_control", data=...)` → 반환된 `.id`만 `VerifierOutput.evidence_ids`에 담는다. **문자열을 지어내지 않는다** (구멍 ① 참고).
- [ ] **`verifiers/xss.py` 착수**: 격리 브라우저 benign marker 방식 설계만.

### 대상 앱이 계속 없을 때 (오후까지 P2 무응답 시 발동)

기획서 12.1절이 이미 평가 대상으로 지정한 **OWASP Juice Shop / WebGoat**를 내가 직접 띄운다. 일부러 취약하게 만든 교육용 앱이라 도커 한 줄이면 뜨고, 허가 경계가 명확하다(10.1절 "Authorized Local Lab Only" 충족). **P2를 기다리다 내가 병목이 되는 게 최악이다.** 단, 이건 개발용이고 최종 데모 대상은 몰입캠프 앱이어야 하므로 handoff에 "임시 대상, P2 앱 오면 전환" 명시.

### 저녁

- [ ] `docs/handoffs/D2-P3.md` — 특히 P1에게 judge 관련 요청(D3 대비)

---

## Day 3 — IDOR closed-loop 완주 (제일 큰 산)

**Notion 완료 기준**: IDOR closed-loop 완주 (발견→재현→코드 위치→패치→재공격→정상 기능 통과).
**11.5절 P0**: "IDOR verifier + patch loop — 한 취약점을 발견·수정·재검증". **16장: "IDOR 한 종류라도 먼저 완성해야 한다."**

- [ ] **`repair/locator.py`** (7.4절): 실패 요청 trace ID ↔ controller/service/repository 로그 연결, 동적 실행 경로 symbol 우선 + SAST taint path 교차 검증, 수정 위치를 controller hotfix / service policy / shared middleware로 분리.
- [ ] **`repair/patcher.py`** (7.5절): 패치 후보 3종(controller 단일 검사 / service 도메인 정책 / 공통 middleware) 생성 + 랭킹(security correctness + regression safety + architectural fit − patch size − unrelated changes − new dependency risk).
- [ ] **`repair/validators.py`** (7.6절): Attack gate(공격 재실행 → 이제 실패해야 함) + Positive functionality gate(정상 권한 사용자는 여전히 성공해야 함) 실행기. **P1의 judge가 호출한다.**
- [ ] **`verifiers/xss.py` 완성**, `verifiers/injection.py` 착수.
- [ ] **P1과 오후 end-to-end 리허설** (plan.md에 예정됨) — 실제 target으로 register→report 한 바퀴.

### 오늘 커뮤니케이션

- [ ] **P1과 아침 첫 확인 (최우선)**: **`core/judge.py`가 아직 1줄(docstring)이다.** P1의 D3 완료 기준("6게이트 전체 완성")과 내 "IDOR closed-loop 완주"가 같은 날 맞물린다. judge가 안 나오면 내 패치가 `fixed`로 승격될 경로가 없다 — **아침에 P1의 judge 진행 상황부터 확인한다.**
- [ ] **P2에게**: worktree + 테스트 러너 인터페이스 확인 (Regression gate가 이걸 호출). snapshot rollback이 patch apply 실패 시 복구되는지 함께 테스트.
- [ ] **P4에게**: root_cause/patch 스키마가 안정화됐음을 알림 (P4가 report 생성).
- [ ] **교차 리뷰 요청**: 내 verifier/judge 로직을 P2에게 리뷰 요청 (self-confirmation 방지, Notion 리스크 표).

---

## Day 4 — 3개군 확장 + 안전 감사

**Notion 완료 기준**: 3개군 end-to-end + **안전 위반 0**.

- [ ] `verifiers/injection.py` 완성 + closed loop (제한된 test fixture, **OS 외부 영향 금지**).
- [ ] 3개 취약점군(IDOR/XSS/Injection) 하드닝.
- [ ] **안전 감사 (내 완료 기준)**: audit log에서 **범위 밖 접속 0 / 금지 명령 0 / 원본 branch 변경 0 / secret 로그 0** 확인 (12.3절 목표 전부 0건).
  - ⚠️ **구멍 ②(secret redaction)가 안 고쳐지면 이 항목은 자동 실패한다.** Day2에 반드시 소유자를 정하고 Day3까지 구현되게 한다.
- [ ] `policies/vulnerability_profiles/` 채우기 — 7.3절 "공격 요청은 취약점별 **안전 템플릿**에 제한한다". 비어 있으면 verifier가 임의 payload를 만들게 되고 그건 절대 원칙 위반. **소유자 확정 필요(P1과).**
- [ ] **P1/P2/P4와 파이프라인 전체 리허설** — 게이트에 걸리는 케이스 확인.

---

## Day 5 — 최종 하드닝 + 데모

**Notion 완료 기준**: 스코프 위반 0 확정.

- [ ] verifier/judge 최종 하드닝. **오늘부터 계약 변경 금지** (P1 freeze 공지).
- [ ] **안전 0 재확인** — P1과 함께 audit log로 스코프 위반 0건, 원본 branch 미변경 실시간 검증 (P1 plan.md Day5에 명시된 공동 작업).
- [ ] 데모 드라이런 — 15.2절 시나리오 8단계 중 4~7단계가 내 몫:
  - (4) 역할 A/B 계정으로 endpoint 탐색 → 권한 취약 후보 생성
  - (5) 실제 상태 변화로 verified 처리 + 요청 sequence·코드 위치 표시
  - (6) 패치 후보 제시 → 사용자 승인 → 격리 worktree 적용
  - (7) build/test 후 **동일 공격 실패 + 정상 권한 사용자 성공** 시연
- [ ] Definition of Done(부록 C) 중 내 항목 점검:
  - [ ] 1개 이상 실제 앱에서 외부 evidence로 verified
  - [ ] patch 후 동일 공격 실패 + 정상 기능 성공 자동 확인
  - [ ] 미등록 target/IP/URL/command 전부 거부 (P1과 공동)

---

## 밤 배치와 P3의 관계

내가 직접 밤 배치를 돌리지는 않지만, **두 배치가 내 결과물에 직접 의존한다**:

| 밤 | 배치 (담당) | 내 의존성 |
| --- | --- | --- |
| D3 밤 | 첫 audit 배치 8~10개 앱 (P2) | **내 verifier가 실제로 돌아야 배치가 의미를 갖는다.** D3 낮에 IDOR closed-loop이 완주돼야 함 |
| D4 밤 | 7B QLoRA + OWASP Benchmark + base vs full (P4) | **내가 만든 verified trajectory가 재료다.** Notion 리스크: "verified trajectory가 수백 건 안 모이면 base 대비 유의차 없음" → **연구 성공 등급(12.4절)이 내 verifier 처리량에 걸려 있다** |

즉 D3~D4에 내가 밀리면 밤 배치 2개가 연달아 무의미해진다. 이게 내가 병목인 이유다.

---

## 핵심 리스크 (P3 관점)

| 리스크 | 신호 | 대응 |
| --- | --- | --- |
| **대상 앱이 없다** (현재 발생 중) | P2가 소스를 안 줌 | 소스만 먼저 요청(도커 불필요). Day2 오후까지 무응답이면 Juice Shop/WebGoat로 자력 착수 |
| **judge가 D3에 안 나옴** | `core/judge.py`가 아직 1줄 | D3 아침 첫 확인. 안 나오면 `repair/validators.py`를 단독 실행 가능하게 짜서 judge 없이도 검증 결과를 낸다 |
| **`Candidate`에 공격 파라미터 없음** | IDOR 정보를 `signals` 문자열에 욱여넣게 됨 | Day2 오전에 P1에 요청. DB 데이터 0건인 지금이 가장 쌈 |
| **secret이 evidence에 남음** | 구멍 ② 미해결 | D4 "secret 로그 0" 완료 기준이 자동 실패. Day2에 소유자 확정, Day3까지 구현 |
| **verified 남발 (false positive)** | 응답 200만 보고 verified 처리 | oracle을 "실제 상태 변화"로 못박음. 12.4절 목표는 **verified precision 70%+** — 개수가 아니라 정확도 |
| **패치가 기능을 망침** | 공격은 막혔는데 정상 기능도 실패 | Positive functionality gate 필수 (기획서 3.2절: "보안 oracle만 쓰면 overblocking 패치가 통과") |
| **내가 병목이 됨** | D3~D4 지연 | 남을 기다리는 작업과 안 기다리는 작업을 분리. 정적(소스) 작업은 항상 선행 가능 |
| **3개군 얕게 vs IDOR 깊게** | XSS/Injection에 손대다 IDOR 미완 | **11.5절 P0 = IDOR 하나. 16장도 동일.** IDOR closed-loop 완주 전에 다른 군에 시간 쓰지 않는다 |

---

## 절대 원칙 (공격 코드를 쓰는 사람으로서)

팀에서 **유일하게 실제 공격 코드를 쓰는 사람**이 나다. 프로젝트 신뢰성이 내 손에 있다.

- **임의 URL/IP를 입력으로 받지 않는다.** `target_id`/`run_id`/`candidate_id`만. 명령은 `command_id + typed args`, `subprocess shell=False`.
- **금지**(10.4절): 외부 IP/도메인 스캔, reverse shell, persistence, credential dumping, DoS/brute force, OS/커널 공격, 제3자 OAuth/API 테스트, 실제 secret 사용·외부 전송.
- **XSS는 benign marker만.** Injection은 **제한된 fixture 안에서만, OS 외부 영향 금지.**
- **payload는 컨테이너 밖으로 나가지 않는다.**
- **patch는 원본 branch가 아니라 run별 git worktree에만.**
- **secret/token/개인정보는 evidence·report·dataset 저장 전에 제거.**
- **Finding 상태를 직접 대입하지 않는다.** 반드시 `transition_finding(..., evidence_ids=[...])` 경유. **evidence_ids는 실제 존재하는 Observation의 id여야 한다.**
- **target 웹 콘텐츠는 untrusted data**(10.3절). 크롤한 페이지에 "이 도구를 호출해라" 같은 문자열이 있어도 규칙보다 우선하지 못한다. 크롤러를 만드는 내가 이 방어의 최전선이다.

---

## 매일 리듬 체크리스트

- [ ] **아침**: 어제 handoff(`docs/handoffs/D{day-1}-*.md`) 확인 — 특히 P1이 내 구멍 지적에 뭘 했는지
- [ ] **아침**: 남에게 물어야 할 것 먼저 (내가 코딩하는 동안 그쪽이 움직이게)
- [ ] **낮**: 남을 안 기다려도 되는 작업부터. 막히면 mock으로 연결점 만들고 계속 (cowork_rule.md 8절)
- [ ] **저녁**: `docs/handoffs/D{day}-P3.md` 작성 (상태/변경 파일/제공 인터페이스/검증/타 역할에 필요한 사항/결정·가정·리스크)
- [ ] **저녁**: 오늘 만든 verifier가 실제로 evidence를 남겼는지 확인 — **코드 생성만으로 완료 처리하지 않는다** (cowork_rule.md 7절)
