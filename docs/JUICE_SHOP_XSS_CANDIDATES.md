# Juice Shop XSS 후보군

2026-07-22 기준 정적 소스 점검 결과다. 이 문서는 공격 실행 결과가 아니라 P3가
verifier 계약을 확정하기 위한 후보 목록이다. 실제 `verified` 판정은 승인된 runtime에서
Playwright oracle과 evidence를 통해서만 한다.

## 후보 우선순위

| 우선순위 | 유형 | 입력 경로 | 관찰 경로 | 변경성 | 상태 |
|---|---|---|---|---|---|
| 1 | reflected/DOM XSS | `GET /search?q=<marker>` | UI `/search`, `#searchValue` 또는 `app-search-result` | 읽기 전용 | 계약 필요 |
| 2 | reflected XSS | `GET /rest/track-order/{id}` + UI `/track-result?id=` | 주문번호 `results.orderNo`가 `[innerHtml]`로 렌더됨 | 읽기 전용 | 계약 필요 |
| 3 | stored XSS | `POST /api/Feedbacks`의 `comment` | `/about` feedback gallery 또는 관리자 feedback 표 | DB 변경 | fixture/reset 필요 |
| 4 | header/reflected XSS | 인증 후 `true-client-ip` header | 계정/로그인 IP 표시 영역 | DB 변경 | auth·rollback 계약 필요 |

## 정적 근거

- DOM XSS 교육 흐름: `frontend/src/hacking-instructor/challenges/domXss.ts`
  - 입력 fixture `#searchQuery input`
  - 렌더 fixture `#searchValue`, `app-search-result`
- reflected track-order 흐름:
  - `routes/trackOrder.ts`의 `:id`
  - `frontend/src/app/track-result/track-result.component.ts`의
    `bypassSecurityTrustHtml` 및 `[innerHtml]`
- stored feedback 흐름:
  - `POST /api/Feedbacks`는 로그인 없이 허용된다고 `server.ts`에 명시
  - `frontend/src/app/about/about.component.ts`와
    `frontend/src/app/administration/administration.component.ts`에서 feedback comment를
    trusted HTML로 렌더
- header 흐름:
  - `routes/saveLoginIp.ts`가 `true-client-ip`를 사용자 레코드에 저장하는 경로를 가짐

## P3가 확정해야 하는 계약

각 후보에 대해 다음을 제공해야 한다.

- `vuln_class=xss`, `context=reflected|stored`
- safe method/path/query/body 또는 header 입력
- observe path와 DOM selector
- benign marker 및 Playwright positive 조건
- 인증/role fixture 필요 여부
- rollback: 읽기 전용이면 없음, DB 변경이면 승인된 target reset
- deterministic regression/smoke command

## 권장 진행 순서

1. 후보 1(검색 DOM XSS)을 먼저 계약한다. 읽기 전용이라 reset 위험이 가장 낮다.
2. 후보 2(track-order)을 별도 reflected 후보로 확인한다.
3. 후보 3(stored feedback)은 fixture·reset 계약이 준비된 뒤 진행한다.
4. 후보 4(header XSS)는 인증과 shared DB mutation 때문에 후순위로 둔다.

현재 `targets/manifests/juice-shop.yaml`에는 SQLi search smoke만 선언되어 있다. 위 후보 중
하나가 P3 계약으로 확정되기 전에는 manifest/test-suite를 임의로 추가하지 않는다.
