# P3 → P2 · Juice Shop XSS verify 계약

> P2 `docs/JUICE_SHOP_XSS_CANDIDATES.md`의 후보에 대한 **P3 verifier 계약 확정본**.
> P3가 소유·고정하는 것: `vuln_class`·`context`·**positive 조건(benign marker 실행)**·payload(안전 경계)·
> rollback 의미. P2가 runtime에서 확정하는 것: 실제 `inject_path`(Angular hash 라우팅), health/reset, manifest.
> verified 판정은 승인된 runtime의 격리 Playwright oracle + evidence로만 한다(정적 근거로 verified 안 함).

## 오라클 불변식 (세 후보 공통)
- **실행됐을 때만 verified** — 반사만으로는 아니다. 격리 headless 브라우저에서 주입한 benign marker가
  실제로 실행(window 플래그 set)돼야 한다(`verifiers/xss.xss_oracle`).
- **benign marker payload만** — `window['<flag>']=1` 하나만 세팅. 네트워크·쿠키·alert·지속성 없음.
  egress는 대상 origin 밖으로 차단. (`verifiers/xss._benign_payloads`, `_egress_guard`)
- Juice Shop 검색/track-order는 `bypassSecurityTrustHtml`(`[innerHtml]`)로 렌더하므로 innerHTML로 실행되는
  `<img src=x onerror=...>`·`<svg onload=...>` payload가 트리거한다(우리 payload 세트가 이미 포함).

---

## 후보 1 (권장·우선) — reflected/DOM XSS · 검색
| 키 | 값 |
|---|---|
| vuln_class / context | `xss` / `reflected` |
| inject_method | `GET` |
| inject_param | `q` |
| inject_path | 검색 렌더 페이지의 `q` 쿼리 — **P2가 runtime에서 확정**(Angular 해시 라우팅이면 `/#/search`) |
| observe | 같은 페이지. 검색어가 `#searchValue` / `app-search-result`에 `bypassSecurityTrustHtml`로 렌더 |
| positive | benign marker 실행(window 플래그). Playwright가 payload 삽입 후 `!!window[flag]` |
| auth / role | 없음(비로그인 검색) |
| rollback / reset | **없음(읽기 전용)** — DB 변경 없음, target reset 불필요 |
| regression/smoke | 기존 `GET /rest/products/search?q=apple` → 200 (liveness). XSS positive = benign 검색어가 페이지를 깨지 않고 렌더 |

## 후보 2 — reflected XSS · track-order
| 키 | 값 |
|---|---|
| vuln_class / context | `xss` / `reflected` |
| inject_method | `GET` |
| inject_param | `id` |
| inject_path | track-result UI 페이지의 `id` 쿼리 — **P2 확정**(`/#/track-result?id=` 형태) |
| observe | 같은 페이지. `results.orderNo`가 `[innerHtml]`로 렌더(`track-result.component.ts` `bypassSecurityTrustHtml`) |
| positive | benign marker 실행(window 플래그) |
| auth / role | 없음(주문 id로 조회) — P2가 runtime에서 비인증 접근 확인 |
| rollback / reset | **없음(읽기 전용)** |
| regression/smoke | benign id로 track-result가 200/렌더되는지 |

## 후보 3 (후속) — stored XSS · feedback
- context=`stored`. `_replay_stored`는 이미 지원(inject → render_path 분리). 단 **DB 변경**이라 승인된
  target reset + fixture 계약 필요 → P2 fixture/reset 준비 후 진행. inject: `POST /api/Feedbacks` `comment`,
  render_path: `/#/about`(feedback gallery). positive는 동일(marker 실행).

## 후보 4 (후순위)
- header(`true-client-ip`) + auth + shared DB mutation → 인증·rollback 계약 확정 후. 지금은 보류.

---

## P2 진행 순서(권장)
1. 후보 1 계약으로 manifest에 XSS test_suite(read-only) 추가 → runtime에서 inject_path 확정 → 격리
   Playwright verify 1회. 읽기 전용이라 reset 위험 최소.
2. 후보 2를 별도 reflected로 확인.
3. 후보 3은 fixture/reset 준비 후.

계약 shape는 `tests/test_xss_verifier.py::test_juice_shop_reflected_xss_contract`로 회귀 잠금.
