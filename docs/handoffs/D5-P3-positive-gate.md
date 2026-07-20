# D5 / P3 Handoff (XSS/Injection positive functionality 게이트 — P1 0-3 합의 대응)

> P1의 "0-3 (XSS/Injection positive functionality gate) 합의 요청"에 대한 P3 결정과 구현.
> driver 단일 경로에 injection/xss scan이 배선되면서 3군(IDOR/XSS/Injection)이 verify→localize→
> patch→apply까지 자동으로 흐르는데, **validate 단계의 positive functionality 게이트만 IDOR
> 전용**이라 XSS/Injection worker가 자동 FIXED에 도달하지 못하던 문제를 해소한다.

## 상태

완료(구현 + 회귀). P1이 제시한 3안 중 **refined-(a)** 를 채택·구현했다. `core/judge.py`(P1)는
변경하지 않았고, 변경은 P3 소유 파일에만 있다. 전체 **416 tests green**.

## 결정 — 왜 (b)가 아니라 refined-(a)인가

P1 제안: (a) full 6-gate 신규 구현 / (b) 5-gate로 positive 생략(추천) / (c) 보류(human_review).

P3 채택: **refined-(a)** — positive 게이트를 vuln_class로 분기해 클래스별로 구현하되, 결과
정확성 재구성 같은 무거운 부분은 하지 않고 기존 verifier machinery를 재사용해 가볍게.

근거:
1. **MVP 승부처 유지** — plan-p3.md / 기획서 3.2절: "보안 oracle만 쓰면 overblocking 패치가
   통과"라서 positive 게이트는 필수. (b)는 3군 중 2군에서 이걸 통째로 버린다.
2. **가장 흔한 나쁜 패치(정상 기능을 깨는 overblocking = 500/빈응답)를 XSS·Injection에서도
   실제로 잡는다.** (b)면 그런 패치가 FIXED로 승격된다.
3. **전부 P3 소유, P1 코드 변경 0** — `check_positive_functionality`는 이미 `validate_patch(
   run_id, patch_id) -> bool`에 위임만 하므로, 분기를 `validate_patch` 내부에 두면 judge/
   compute_verdict/6게이트 배선은 그대로다.
4. **작업량이 작다** — Injection verifier는 이미 benign baseline 요청(`_send`)을, XSS verifier는
   `_reflected_url`+httpx를 갖고 있어 positive replay가 그걸 재사용한다(P1이 우려한 "큰 작업량"
   회피).

## 변경 파일

- `repair/validators.py`:
  - `validate_patch()`를 `verifiers.dispatch.class_of` 기준으로 분기(`check_attack`이
    `verify_candidate`로 3군을 재현하는 것과 같은 기준 — 드리프트 방지).
  - 신규 순수 oracle: `xss_positive_gate_oracle(status, benign_value, body)`,
    `injection_positive_gate_oracle(status, body)`.
  - 신규 실행기: `_xss_positive_gate()`, `_injection_positive_gate()`, 요청 헬퍼
    `_send_xss_benign()`, evidence 헬퍼 `_store_positive_evidence()`.
  - `__main__` self-check에 두 신규 oracle 케이스 추가.
- `tests/test_validators_positive.py`(신규, 14 tests): 두 oracle + `validate_patch` dispatch
  라우팅(idor/xss/injection) + 게이트 실행기(요청·evidence monkeypatch로 헤르메틱).

## 제공 인터페이스 (계약)

- `validate_patch(run_id, patch_id) -> bool` — **시그니처·반환 불변**. P1 `check_positive_functionality`
  가 그대로 호출한다. 내부에서만 vuln_class로 분기한다.
  - `idor`: 기존 `run_security_validation`(재현 1회로 attack+positive, positive만 노출).
  - `xss`: benign 평문값 주입 → 2xx + 반영 확인. reflected/stored 대응. XSS는 과이스케이프가
    안전하므로 escape 여부를 실패로 보지 않는다(평문 marker는 escape에 불변).
  - `injection`: benign 값(`probe.baseline_value`)으로 2xx + 비지 않음(**liveness**) 확인.
- 두 게이트 모두 evidence 저장(`observation_type="http_exchange"`, producer
  `vc_validate_patch:positive_{xss,injection}`, **응답 원문 미기록** — status/len/판정만).

## 검증

- `python -m repair.validators` self-check: attack/positive/xss/injection oracle 전부 OK.
- `tests/test_validators_positive.py`: 14/14.
- 전체 스위트: **416 passed** (직전 402 + 14). `core/judge.py` 무변경으로 기존 judge/validation
  테스트 회귀 0.

## 다른 역할에 필요한 사항

### P1
- **변경 0 확인** — `check_positive_functionality → validate_patch(bool)` 계약 그대로,
  `compute_verdict`/6게이트/트라젝터리 배선 손댈 것 없음. scan tool 배선 덕에 이제 3군 모두
  scan→verify→...→validate→FIXED가 코드상 열렸다.
- (별개, 선택) audit_log `run_id`/`event_type` 컬럼은 D5-P3-safety-audit.md 건으로 따로.

### P2 — 실제 3군 자동 FIXED 시연의 남은 전제
- **XSS/Injection이 실제로 있는 target**: 현 로컬 앱은 clean이라 프리필터 후보 0
  (D5-P3-verify-batch.md). 취약 교육용 target(Juice Shop/WebGoat류) 또는 승인된 취약 fixture가
  있어야 positive/attack 게이트가 데이터를 낸다.
- **regression 게이트용 test_suite**: `docker_isolation` target인데 `test_suites=[]`이면
  `check_regression`이 False라 FIXED 불가(`core/judge.py:220`). 시연 target엔 test suite 필요.
- **(선택) injection positive 강화용 fixture**: known-good 입력값 → 기대 결과(marker) 매핑이
  있으면 liveness를 "결과 정확성"으로 승격 가능. 없으면 현행 liveness 유지.

### P4
- 취약 target이 확보되면 **XSS(CWE-79)·Injection(CWE-89)도 verified→fixed 라벨 궤적**이
  생성 가능해진다(지금까지 IDOR c1-05만 fixed였음) → base-vs-full 학습 다양성 확대.

## 결정·가정·리스크

- **[결정] injection positive = liveness only** — 엔드포인트가 살아있고(2xx) 빈 응답이 아닌지
  까지만. 정상 쿼리가 *정확한 행*을 반환하는지(결과 정확성)는 미검증. known-good→기대결과
  fixture(P2)가 오면 강화. 그래도 overblocking 핵심(패치가 500/빈응답 유발)은 잡는다.
- **[결정] xss positive = benign 평문 반영 확인** — 정상 렌더가 유지되는지. 과이스케이프는
  안전하므로 실패로 보지 않는다.
- **[한계] 능력은 열렸으나 시연은 취약 target(P2)에 의존** — 이 배선 자체로 데모 데이터가
  생기지는 않는다. 위 P2 항목이 전제.
- **[안전] 불변** — positive replay는 attack이 아니라 benign 요청(payload/격리 브라우저/egress
  가드 불필요), evidence에 응답 원문 미기록, 허용 base_url만(candidate.attack_params).

## 참조
- P3 결정 근거: `repair/validators.py`(docstring), `core/judge.py`(6게이트/compute_verdict, 무변경).
- 연결 handoff: `docs/handoffs/D5-P3-verify-batch.md`(코퍼스 clean → 취약 target 필요),
  `docs/handoffs/D5-P3-safety-audit.md`(audit_log 컬럼 별건).
