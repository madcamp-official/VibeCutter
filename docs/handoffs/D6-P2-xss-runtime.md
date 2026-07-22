# D6 / P2 Handoff

## 상태
진행 중 — Juice Shop XSS runtime 계약의 정적 확인 완료, live Playwright 실행은 P3가 수행

## 변경 파일
- `docs/handoffs/D6-P2-xss-runtime.md`: Juice Shop reflected XSS 실행 조건과 현재 runtime 상태 기록

## 제공 인터페이스
- target: `juice-shop`
- base URL: `http://127.0.0.1:14020`
- health: `GET /rest/products/search?q=apple` → expected `200`
- reflected search route: `/#/search?q=<benign-marker>`
- reflected track-order route: `/#/track-result?id=<value>`
- search DOM sink: `#searchValue` / `app-search-result`
- track-order DOM sink: `track-result`의 `results.orderNo` `[innerHtml]`
- reset: 두 후보 모두 read-only라 별도 데이터 rollback 없음. 일반 runtime 종료 시 manifest의 `reset` 사용
- smoke suites: `juice-shop-search-smoke`, `juice-shop-xss-search-route-smoke`

## 검증
- 소스에서 Angular route `search`, `track-result` 및 `bypassSecurityTrustHtml` sink 확인
- manifest/Compose가 `14020` loopback publish와 위 smoke suite를 선언하는 것 확인
- 현재 Windows Docker daemon에 실행 중인 컨테이너가 없어 live health/Playwright는 아직 실행하지 못함

## 다른 역할에 필요한 사항
- P3: 위 경로와 marker 조건으로 fresh XSS verify를 실행하고 run ID/evidence를 공유
- P1: XSS run에서 patch 승인 후 `vc_resume_audit`를 기존 SQLi와 같은 흐름으로 연결

## 결정·가정·리스크
- Juice Shop은 발표 target이 아닌 엔지니어링 검증 target으로 유지
- 후보 1(search)을 우선하고, stored feedback/header XSS는 fixture/reset 계약 전까지 보류
- Docker daemon이 실행되면 `reset → build/start → health → XSS smoke → reset` 순서로 재현
