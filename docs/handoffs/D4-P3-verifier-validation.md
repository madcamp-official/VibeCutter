# D4 / P3 Handoff (보충: XSS·Injection verifier를 실제 앱 4개로 검증)

> D4-P3-closed-loop.md(IDOR 자동 FIXED) 이후, IDOR만큼 검증이 안 됐던 **XSS·Injection verifier를
> 실제 앱 4개(c2-04·c2-05·c3-08·c1-05)에 직접 돌려** 오탐(false positive) 저항을 실측한 결과다.
> 협업자가 "세 verifier가 각각 어디까지 검증됐는지"를 알 수 있게 남긴다. 팀 관례상 D5 번호는 최종
> 통합 전까지 비워 두므로 접미사 보충으로 남긴다.

## 상태

완료(실앱 실측). **결론: XSS·Injection verifier 모두 실제 clean 앱에서 오탐 0** — 이 프로젝트 핵심
지표인 verified precision(안전한 코드를 flag 안 하기, 12.4절)을 세 군 전부 실앱에서 실증했다.
다만 **실앱 true-positive와 프리필터 자동화는 아직 gap**(아래 "보완할 점").

배경: IDOR은 실앱(c1-05/c2-04)·clean앱(c2-05/c3-08)·자동 closed-loop까지 검증됐지만, XSS·Injection은
그동안 **내가 만든 통제 랩서버로만** 검증돼 신뢰를 덜 벌었다. 그 gap을 실앱으로 메운 작업이다.

## 검증 내용 (무엇을·어떻게)

- **대상 4개 앱을 전부 Docker로 실제 기동**(격리 로컬 컨테이너)한 뒤, verifier를 실제 엔드포인트에 실행.
- **XSS**: `playwright`(격리 headless 브라우저) 설치 후, reflected 컨텍스트로 프론트/API 엔드포인트에
  benign marker 주입 → 실행 여부 관찰.
- **Injection**: 불리언 차등 oracle로 **로그인 엔드포인트(SELECT 기반, `read_query=true`)의 인증 필드**와
  GET 쿼리 지점에 참(`OR '1'='1`)/거짓(`OR '1'='2`) 주입 → 응답 차등 관찰.
- 정찰: 4개 앱 모두 **ORM 파라미터화 쿼리**(SQLAlchemy `.filter()`, JPA Criteria, Prisma) + **자동
  이스케이프 SPA**(React/Next/Vue) + JSON API. 설계상 두 취약점에 강함.

## 결과

### XSS — 실앱 4개 × 14개 엔드포인트, 오탐 0

| 타깃 | 스택 | 테스트 엔드포인트 | 결과 |
| --- | --- | --- | --- |
| c2-04 | FastAPI + React | 프론트 루트·search / API `/shared-vocabs`·`/api/data` (4) | **전부 verified=False** |
| c2-05 | FastAPI + React | 프론트 루트·search / API 루트 (3) | **전부 verified=False** |
| c3-08 | Next.js SSR + Nest | Next 루트 / `/write?next` / `/phone-verification?next` / API (4) | **전부 verified=False** |
| c1-05 | Spring + React | 프론트 루트·search / API 루트 (3) | **전부 verified=False** |

판정 사유: 전부 "payload가 응답에 반사되지 않음". 위험 sink(`dangerouslySetInnerHTML`/`v-html`/
`innerHTML`) 0건, 서버측 HTML 반사 0건.

### Injection — 실앱 4개(로그인/GET), 오탐 0

| 타깃 | 주입 지점 | 결과 | 사유 |
| --- | --- | --- | --- |
| c2-04 | 로그인 `POST /login/` `username` | **verified=False** | 참/거짓 응답 **0바이트 차이** → 리터럴 처리(파라미터화) |
| c2-05 | 로그인 `POST /auth/login` `id` | **verified=False** | 0바이트 차이 → 파라미터화 |
| c1-05 | 로그인 `POST /api/auth/login` `email` | **verified=False** | 0바이트 차이 → 파라미터화 |
| c3-08 | `GET /api/health` `q` (로컬 로그인 없음, Kakao OAuth 전용) | **verified=False** | 0바이트 차이 |

**중요**: injection은 XSS의 "반사 안 됨"보다 강한 결과다 — 주입이 **실제 로그인 쿼리까지 도달**했는데도
참/거짓 응답이 **정확히 같아**(0바이트) oracle이 "살균됨"으로 판정했다. 즉 verifier가 진짜 injection
지점을 만나도 안전한 앱을 오탐하지 않음을 실증.

## 신뢰 수준 (세 verifier 현황)

| verifier | 실앱 오탐 저항 | 실앱 true-positive | 파이프라인/closed-loop |
| --- | --- | --- | --- |
| IDOR | ✅ (c2-05/c3-08 clean=0) | ✅ (c1-05/c2-04 verified) | ✅ 자동 FIXED |
| XSS | ✅ (실앱 4개 오탐 0) | ⚠️ 랩서버만 | ⬜ |
| Injection | ✅ (실앱 4개 오탐 0) | ⚠️ 랩서버만 | ⬜ |

## 보완할 점 (다음 작업으로 시사)

1. **실앱 true-positive 미검증 (XSS·Injection 공통)** — 로컬 4개가 다 clean이라 "실제 취약 앱을
   verified=True로 잡는다"는 아직 **통제 랩서버로만** 증명됨. 의도적 취약 fixture(또는 취약 타깃)에서
   실앱 TP를 확인해야 신뢰가 IDOR 수준에 도달한다.
2. **XSS "반사되지만 이스케이프됨" 실앱 미검증** — 이번 14개는 전부 *입력을 반사 안 하는* 엔드포인트라,
   oracle의 핵심 판별(반사O + 실행X → verified=False)은 **단위 테스트로만** 커버됨. 입력을 실제 렌더하는
   지점(인증 후 저장 자원 렌더 등)에서 실앱 확인 권장.
3. **Injection 자연 응답 변동 오탐 — 이번 4앱에선 안 났으나(0바이트) 이론적 리스크 잔존** — 응답이
   요청마다 변하는 엔드포인트(타임스탬프·nonce·페이지네이션)에선 참/거짓이 우연히 달라 오탐 가능.
   **하드닝 제안**: baseline을 2회 재서 자연 변동을 측정하고, 참-거짓 차이가 그 변동을 넘을 때만 flag.
4. **XSS/Injection suspect 프리필터 부재** — IDOR은 `surface.graph.find_idor_suspects`로 candidate를
   자동 발견하지만, XSS/Injection은 아직 없어 **엔드포인트를 수동 지정**했다. 배치 자동화하려면 반사
   지점/쿼리 파라미터 프리필터가 필요(P3 후속).

## 다른 역할에 필요한 사항

- **P1 — MCP 배선**: `mcp_server/tools_analysis.py`의 `vc_verify_xss`·`vc_verify_injection`이 아직
  `NotImplementedError`다. verifier 본문(`verifiers/xss.py`·`verifiers/injection.py`)은 준비·검증
  완료이므로, `verifiers.{xss,injection}.verify(run_id, candidate, max_requests=...)` 호출 +
  `update_finding_status` 배선만 하면 된다(`vc_verify_access_control` 복붙 수준, policy/승인/상태전이는
  이미 배선됨).
- **전원 — `requirements.txt`에 `playwright` 추가 필요**: XSS verifier 실행 의존성. 현재 P3 로컬에만
  설치돼 있어, 이게 없으면 다른 작업자/CI에서 XSS verify가 import부터 실패한다(공유 파일이라 flag만 남김).

## 결정·가정·리스크

- **verified precision을 세 군 전부 실앱에서 실증** = 배치를 돌려도 clean 앱에서 false positive가 안
  섞인다는 근거. 특히 injection은 실제 로그인 쿼리에서 오탐 0을 확인.
- **검증은 오탐(precision) 위주** — 로컬 4앱이 잘 만든(ORM/이스케이프) 앱이라 TP를 낼 취약점이 없다.
  이건 앱들이 안전하다는 방증이기도 하다(정직히 clean으로 기록).
- **가정(안전 경계 유지)**: XSS는 benign marker(window 플래그)만 + egress 차단, Injection은 불리언
  tautology payload만(write DML·스택쿼리·UNION·OS 없음) + 비-GET은 `read_query=true` 보증 필요.
  격리 로컬 컨테이너에만 실행, 파괴적 요청 없음. 실행 후 컨테이너·볼륨 정리 완료.
- **재현 스크립트는 scratchpad**(미커밋): XSS·Injection을 임의 타깃에 돌리는 드라이버. 프리필터(보완
  4번)가 생기면 정식 배치로 승격.
