# P3 → P2 · Juice Shop XSS verify 계약 (X7 확정본)

> P2 `docs/JUICE_SHOP_XSS_CANDIDATES.md`의 후보에 대한 **P3 verifier 계약 확정본**.
> P3가 소유·고정하는 것: `vuln_class`·`context`·**positive/observe 조건(benign marker 실행)**·payload(안전 경계)·
> **deterministic regression command**·rollback 의미. P2가 runtime에서 확정하는 것: health/reset, manifest 배선.
> verified 판정은 승인된 runtime의 격리 Playwright oracle + evidence로만 한다(정적 근거로 verified 안 함).

## ✅ X7 확정 상태 (2026-07-22)
| 항목 | 상태 |
|---|---|
| inject_path (Angular hash route) | **확정** — P2 runtime 계약(2026-07-22): 검색 `/#/search?q=`, track `/#/track-result?id=` |
| safe payload | **확정(P3)** — `verifiers/xss._benign_payloads` benign marker only |
| positive/observe 조건 | **확정(P3)** — 격리 Playwright에서 marker **실행**(`!!window[flag]`) |
| reflected 계약 (#1 검색 / #2 track) | **확정 — read-only, seed-ready** |
| stored 계약 (#3 feedback) | context/seed는 확정, **DB 변경이라 P2 fixture/reset 계약 후 진행** |
| deterministic regression command | **확정** — manifest test_suite `xss_search_smoke` (= `tools/juice_shop_xss_smoke.py`), liveness는 `search_smoke` |
| shape-lock | `tests/test_xss_verifier.py::{test_juice_shop_reflected_xss_contract, test_juice_shop_stored_xss_contract_seed}` |

---

## 오라클 불변식 (세 후보 공통)
- **실행됐을 때만 verified** — 반사만으로는 아니다. 격리 headless 브라우저에서 주입한 benign marker가
  실제로 실행(window 플래그 set)돼야 한다(`verifiers/xss.xss_oracle`, `executed=True` 필수).
- **benign marker payload만** — `window['<flag>']=1` 하나만 세팅. 네트워크·쿠키·alert·지속성 없음.
  egress는 대상 origin 밖으로 차단(`verifiers/xss._benign_payloads`, `_egress_guard`). 우회 컨텍스트 포함
  (`<img src=x onerror=>`·`<svg/onload=>`·`<details ontoggle=>`·대소문자 혼합 `ScRiPt`).
- Juice Shop 검색/track-order는 `bypassSecurityTrustHtml`(`[innerHtml]`)로 렌더하므로 innerHTML로 실행되는
  `<img src=x onerror=...>`·`<svg onload=...>` payload가 트리거한다(우리 payload 세트가 이미 포함).

## Deterministic regression command (6게이트 regression 용, 공통)
- **정상 기능 회귀**는 manifest `test_suites`의 결정적 명령으로 돈다(J-3의 `search_smoke`와 동형):
  - `search_smoke` — `["{vibecutter_python}", "tools/juice_shop_smoke.py"]` (검색 liveness: `/rest/products/search?q=apple`→200)
  - `xss_search_smoke` — `["{vibecutter_python}", "tools/juice_shop_xss_smoke.py"]` (XSS 경로 렌더 liveness)
- 이 명령들은 **비-Compose 순수 Python**이라 `run_overlay`가 argv 그대로 실행한다(`fd50c76` 이후). regression
  게이트는 이 스모크가 **패치 후에도 통과**해야 pass — overblocking(입력을 통째로 지워 검색/렌더가 깨지는) 패치를 잡는다.
- **positive functionality**(P3 `xss_positive_gate_oracle`)는 별도로 benign 평문 마커가 패치 후에도 응답에 반영되는지 확인(과이스케이프는 안전이라 실패 아님).

---

## 후보 1 (권장·우선) — reflected/DOM XSS · 검색
| 키 | 값 |
|---|---|
| vuln_class / context | `xss` / `reflected` |
| inject_method | `GET` |
| inject_param | `q` |
| inject_path | **`/#/search?q=`** (P2 확정 Angular hash route) |
| observe | 같은 페이지. 검색어가 `#searchValue` / `app-search-result`에 `bypassSecurityTrustHtml`로 렌더 |
| positive | benign marker 실행(window 플래그). Playwright가 payload 삽입 후 `!!window[flag]` |
| auth / role | 없음(비로그인 검색) |
| rollback / reset | **없음(읽기 전용)** — DB 변경 없음, target reset 불필요 |
| regression | `xss_search_smoke` + `search_smoke` (패치 후에도 200/렌더). positive = benign 검색어가 페이지를 안 깨고 렌더 |

## 후보 2 — reflected XSS · track-order
| 키 | 값 |
|---|---|
| vuln_class / context | `xss` / `reflected` |
| inject_method | `GET` |
| inject_param | `id` |
| inject_path | **`/#/track-result?id=`** (P2 확정 Angular hash route) |
| observe | 같은 페이지. `results.orderNo`가 `[innerHtml]`로 렌더(`track-result.component.ts` `bypassSecurityTrustHtml`) |
| positive | benign marker 실행(window 플래그) |
| auth / role | 없음(주문 id로 조회) — P2가 runtime에서 비인증 접근 확인 |
| rollback / reset | **없음(읽기 전용)** |
| regression | `xss_search_smoke`(track 경로 렌더 liveness). benign id로 track-result가 200/렌더되는지 |

> **라이브 노트(2026-07-22, P1 X7 실주행)**: #1 검색은 **verified=true**(evidence obs-1bf69d9ac722, 격리
> 브라우저에서 onerror marker 실행). #2 track-order는 `inject_path`에 이미 `?id=`가 있어 verifier의
> `_reflected_url`이 `?id=?id=<payload>`로 겹쳐 실패했었음 → **verifier를 기존 쿼리 병합하도록 수정**(겹침
> 제거, 검색/track 둘 다 `?id=<payload>` 한 벌). 이후에도 track이 안 뜨면, track-result는 **유효한 order
> 백엔드 조회 후 렌더**되는 구조일 수 있어 seed된 order id fixture가 필요할 수 있음(P2와 확정 — X7 follow-up).

## 후보 3 (후속) — stored XSS · feedback
- context=`stored`. `_replay_stored`가 inject→render_path 분리를 이미 지원한다. **계약-seed로 바로
  검증 가능**(아래 attack_params). 단 **DB 변경**이라 승인된 target reset + fixture 계약이 전제 →
  P2 fixture/reset 준비 후 진행. positive는 동일(격리 브라우저 marker 실행).

  P2가 seed할 candidate.attack_params:
  ```
  base_url:      http://127.0.0.1:14020
  context:       stored
  inject_method: POST
  inject_path:   /api/Feedbacks
  inject_param:  comment
  render_path:   /#/about        # feedback gallery (또는 관리자 feedback 표)
  ```
  rollback: **DB 변경 → 승인된 target reset 필수**(읽기 전용인 #1/#2와 다름).
  regression: stored는 fixture 재준비 + reset이 결정적 command에 포함돼야 한다(P2 fixture 계약과 함께 확정).
  shape 잠금: `tests/test_xss_verifier.py::test_juice_shop_stored_xss_contract_seed`.

> **참고(X3 범위)**: 후보 빌더의 **소스 기반 stored 자동생성**(write 핸들러 → 저장 → 다른 경로 render
> 상관분석)은 정밀도가 낮아 follow-up으로 둔다. 데모/일반 사용자 stored는 위처럼 **계약-seed**로 만든다.

## 후보 4 (후순위)
- header(`true-client-ip`) + auth + shared DB mutation → 인증·rollback 계약 확정 후. 지금은 보류.

---

## P2 진행 순서(권장)
1. 후보 1 계약(`/#/search?q=`, read-only)으로 manifest에 XSS test_suite(`xss_search_smoke`) 배선 확인 → 격리
   Playwright verify 1회. 읽기 전용이라 reset 위험 최소.
2. 후보 2(`/#/track-result?id=`)를 별도 reflected로 확인.
3. 후보 3(stored)은 fixture/reset 계약 준비 후.

계약 shape는 `tests/test_xss_verifier.py::test_juice_shop_reflected_xss_contract`로 회귀 잠금.
