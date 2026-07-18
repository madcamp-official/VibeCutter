# D4 / P3 Handoff (세션 마무리 — 오늘 작업 요약 + P1·P2·P4 인계)

> 오늘 P3 세션 전체를 한 곳에 요약하고, P1·P2·P4가 아침에 이어받을 action item을 통합한다.
> 세부는 아래 "참조 문서"의 개별 handoff에 있다. (handoff 번호는 팀 관례상 D5를 비워 둬 D4 접미사 유지.)

## 상태

완료. 오늘 세션에서 아래를 마쳤다(전부 origin/main 머지, 프리필터만 커밋 대기):

1. **Python 3.13 통일** — semgrep(opentelemetry) 3.14 블로커 해소. `setuptools<81` 필수(pkg_resources).
2. **IDOR closed-loop 자동 FIXED 첫 완주** — c1-05, 6게이트 전부 True. bearer 재프로비저닝 409 수정.
3. **Injection verifier 구현** — 불리언 차등 blind SQLi oracle + **자연 변동 노이즈 바닥 하드닝**(오탐 방지).
4. **XSS·Injection verifier를 실제 앱 4개로 검증** — 오탐 0(precision 실증).
5. **XSS/Injection suspect 프리필터** — 세 군 모두 자동 발견 완비. 실앱 오탐 0, 취약 샘플 TP(커밋 대기).

## 오늘 한 것 (커밋)

| 주제 | 커밋 | 세부 문서 |
| --- | --- | --- |
| Python 3.13 문서 | `5e450a6` | D4-P3-closed-loop.md |
| IDOR closed-loop fix(bearer) | `4eadf65` | D4-P3-closed-loop.md |
| closed-loop 완주 문서 | `caf816b` | D4-P3-closed-loop.md |
| Injection verifier | `1ad6d78` | D4-P3-verifier-validation.md |
| XSS·Injection 실앱 검증 문서 | `201d245` | D4-P3-verifier-validation.md |
| Injection oracle 하드닝 | `e6562ab` | (이 문서 아래) |
| **XSS/Injection 프리필터** | (커밋 대기) `surface/inject_xss.py`, `tests/test_inject_xss_prefilter.py` | (이 문서 아래) |

전체 테스트 **234 PASS**. 세 verifier(IDOR/XSS/Injection) 전부 구현·실앱 오탐검증 완료, 발견(프리필터)도 완비.

## 다른 역할에 필요한 사항 (통합 — 아침 우선순위)

### P1
- **(배선) `vc_verify_xss`·`vc_verify_injection`** — 아직 `NotImplementedError`. verifier 본문
  (`verifiers/xss.py`·`verifiers/injection.py`)은 구현·검증 완료. `verifiers.{xss,injection}.verify(run_id,
  candidate, max_requests=...)` 호출 + `update_finding_status` 배선만(=`vc_verify_access_control` 복붙,
  policy/승인/상태전이는 이미 배선).
- **(배선) `VERIFYING → VERIFIED` Run 전이** — verify tool이 Finding만 승격하고 Run은 안 옮겨,
  `vc_generate_patch`가 막힌다(closed-loop에서 드라이버가 수동 우회함). 스캔 tool의 멱등 전이 패턴으로 배선.
- 세부: D4-P3-closed-loop.md, D4-P3-verifier-validation.md.

### P2
- **(런타임 위생 2건 — 배치 안정성 직결)**
  1. MySQL healthcheck(`mysqladmin ping`)가 grants 완료 전에 healthy 보고 → fresh volume에서 앱 접속
     실패(간헐적). healthcheck를 앱 유저 인증까지 확인/앱 접속 재시도/start 버퍼 중 하나.
  2. 완료된 run의 run-scoped 오버레이(`vc-<hash>`)가 teardown 안 되고 포트 점유 → 다음 run 앱 기동 실패.
     run 종료 시 `reset_run(target_id, run_id, approved=True)` + stale sweep.
- **(auth 계약 대기)** c2-02/c1-06은 P3가 선언형 bearer 계약 지정 필요하나 **소스가 로컬에 없다** → P2가
  소스/런타임 제공하면 P3가 `_SELF_SIGNUP_HINTS`에 추가. c2-01은 이미 등록됨.
- 세부: D4-P3-closed-loop.md.

### P4
- **(신규 학습 데이터) verified→fixed trajectory** — c1-05 closed-loop(`run-e32346b2a4b0`)이 evidence 기반
  verified + 6게이트 fixed까지 완주. base vs full 학습의 실물 재료(CWE-639/Spring/bearer).
- **(신규 evidence 축)** XSS=`browser_trace`, Injection=`http_exchange`(boolean_diff). trajectory/dataset에
  XSS(CWE-79)·Injection(CWE-89) 라벨 추가 가능.
- **(배치 타깃팅)** 이제 `surface.inject_xss.find_{injection,xss}_suspects`로 XSS/Injection 후보를 앱에서
  자동 발견 가능(IDOR `find_idor_suspects`와 동형) → "어느 앱·어느 지점을 verify할지"를 데이터로 선정.
- 세부: D4-P3-verifier-validation.md.

### 전원
- **`requirements.txt`에 `playwright` 추가 필요** — XSS verifier 실행 의존성. 현재 P3 로컬에만 설치돼,
  없으면 다른 작업자/CI에서 XSS verify가 import부터 실패(공유 파일이라 flag).

## 이번에 추가된 것 (위 문서에 아직 없는 2건)

### Injection oracle 하드닝 (`e6562ab`)
- 참/거짓을 각 1회 비교하던 oracle에 **노이즈 바닥** 도입: benign baseline을 2회 재서 자연 변동 V를 측정,
  판정 임계를 `48 + 2×V`로 올려 타임스탬프·nonce·페이지네이션 있는 엔드포인트의 오탐을 막는다. 조용한
  엔드포인트(V=0)는 동작 불변(랩 TP 유지). 통제 랩으로 "같은 응답, 옛 로직 FP / 새 로직 정확"을 실증.

### XSS/Injection suspect 프리필터 (커밋 대기)
- `surface/inject_xss.py`: `find_injection_suspects()`(원시 SQL 동적 결합+실행) / `find_xss_suspects()`
  (위험 sink+동적 값). 파라미터화·ORM·리터럴·살균·로그는 제외(precision 지향).
- **실앱 4개(c2-04/c2-05/c3-08/c1-05) 오탐 0**, 취약 샘플(Python/Node SQLi, React/Vue XSS) TP. 단위 12건.
- 만들며 실측 오탐 2패턴 수정: 영어 "from"이 든 로그 문장(→강한 SQL 형태+실행 지점 필수+로그 제외),
  살균/벤더 디자인툴 파일(→살균 함수 값 제외+`_ds`/vendor 디렉토리 제외).
- **P3 후속(내일)**: 프리필터 suspect → verify 가능한 `Candidate`로 잇는 **브리지 배선**(IDOR
  `surface/candidates.py`와 동형). injection은 sink↔라우트, XSS는 라우트/파라미터 연결 필요.

## 결정·가정·리스크

- **세 verifier 코어는 완성** — 남은 마찰은 P3 밖(P1 배선)과 P3 후속(브리지). 프리필터로 발견까지 자동화돼,
  P1 배선 + P2 런타임 위생이 만나면 XSS/Injection도 배치-ready가 된다.
- **프리필터는 precision 우선** — 정밀 taint 분석이 아니라 패턴 매칭이라, 다줄 build-then-execute SQL이나
  서버 템플릿 엔진(Jinja `|safe`)은 후속. recall은 verifier가 백스톱.
- 오늘 도커·스크래치패드 정리 완료. 커밋 대기: `surface/inject_xss.py`, `tests/test_inject_xss_prefilter.py`.

## 참조 문서
- `docs/handoffs/D4-P3-closed-loop.md` — 3.13 전환 + IDOR 자동 FIXED + P1/P2 gap
- `docs/handoffs/D4-P3-verifier-validation.md` — XSS·Injection 실앱 4개 검증 + 보완할 점
- `docs/handoffs/D4-P3.md`, `docs/handoffs/D4-P3-xss-locator.md` — write-IDOR / XSS·locator
