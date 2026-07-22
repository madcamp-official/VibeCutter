# P3 → P2 · Juice Shop SQL Injection verify 계약 (데모2 / J-3)

> 데모2 = Juice Shop 검색 SQLi의 **closed-loop 완주**(scan→verify→localize→patch→judge→FIXED).
> verify 자체는 J-2 실측으로 증명됨(아래 수치). 이 문서는 P2가 **candidate를 결정적으로 seed**해
> J-3 실주행을 시작하도록 P3 verifier 계약을 확정한다.
> P3가 소유·고정: `vuln_class`·oracle(불리언 차등)·**positive 조건**·payload(안전 경계)·evidence redaction·
> rollback 의미. P2가 runtime에서 확정: `base_url`(포트), health/reset, manifest 배선.
> verified 판정은 승인 runtime의 실 target 재현 + evidence로만 한다(정적 근거로 verified 안 함).

## 오라클 불변식 — 왜 안전하고 확실한가
- **불리언 차등(boolean-based blind)**: 참(`OR '1'='1`)은 WHERE를 항상 참으로 만들어 결과셋을 열고,
  거짓(`OR '1'='2`)은 항상 거짓으로 만들어 닫는다. 두 payload는 **딱 한 글자(1 vs 2)만** 다르므로
  응답 차이는 SQL 해석의 증거다(에코로 설명 불가). 응답 200 하나로 verified 하지 않는다.
- **판정 신호(둘 중 하나)**: ① 참/거짓 응답 **길이 차이**가 노이즈 바닥을 넘음, 또는 ② 길이는 비슷해도
  **본문 구조가 크게 갈림**(I4 콘텐츠 발산 신호, `7ee48b0`) — 결과셋 열/닫힘. 상태코드 5xx 경계 갈림도.
- **benign baseline 2회**로 엔드포인트 자연 변동(길이·상태·구조 유사도)을 재 노이즈 바닥을 깔고,
  그 위로만 판정한다(타임스탬프/nonce/페이지네이션 오탐 방지).

## J-3 라이브 실측 (2026-07-22, P1 최초 라이브 run — Docker+235B) ⚠️ LIKE 컨텍스트 주의
> **초기 계약의 18662/30은 오프라인 합성값이었다.** 실제 Juice Shop 검색은 `name LIKE '%<q>%'`라
> 표준 OR tautology로는 참/거짓이 **안 갈린다** — 문자열을 `'`로 탈출하는 순간 앞의 `%`가 `LIKE '%'`
> (전체 매치)가 돼 참·거짓 둘 다 전체 행을 연다. **LIKE-aware AND payload**로만 결과셋이 갈린다.

| 요청 | 응답 크기 | 상태 |
|---|---|---|
| baseline `q=apple` | 631 B | 200 |
| 참 `%' AND '1'='1' AND '1' LIKE '` | ~13,644 B (전체 행) | 200 |
| 거짓 `%' AND '1'='2' AND '1' LIKE '` | ~30 B (0 행) | 200 |
| (참고) 표준 `' OR '1'='1` / `'2` | 13,644 B / 13,644 B (**동일 — 미탐**) | 200 |
| (참고) 주석형 `' OR '1'='1' -- ` | 942 B (닫는 괄호 훼손 → syntax error) | — |

→ LIKE-aware 쌍의 참−거짓 델타(≈13,600 B) ≫ 임계 → **verified**. 이 쌍은 `verifiers/injection.py
_PAYLOAD_PAIRS`에 상위 4쌍(기본 예산)으로 편입돼(SQLite로 Juice Shop 쿼리 재현 검증) J-3가 이제 통과한다.
패치(파라미터화) 후 참≈거짓 → attack 게이트 **verified=False**로 뒤집혀 FIXED를 확증. 잠금:
`tests/test_injection_verifier.py::{test_juice_shop_sqli_demo_pattern, test_like_wildcard_context_payload_present}`.

## P2가 seed할 candidate.attack_params
```
base_url:        http://127.0.0.1:14020     # P2 runtime 포트로 확정
vuln_class:      injection                   # (또는 cwe: CWE-89 → dispatch가 injection으로 교정)
inject_method:   GET                         # 읽기 — 파괴적 아님(아래 안전 경계)
inject_location: query
inject_path:     /rest/products/search
inject_param:    q
baseline_value:  apple                       # 정상 결과가 나오는 benign 값(자연 변동 측정용)
```
- **read_query 불필요**: GET(읽기 의미)이라 자동 허용. 비-GET일 때만 `read_query=true`(SELECT 기반
  보증)가 필요하다 — 이 데모는 해당 없음.
- extra_params 없음(검색은 `q` 단일).

## 안전 경계 (P3 소유·불변)
- **불리언 tautology payload만** 보낸다(`verifiers/injection._PAYLOAD_PAIRS`, 7쌍). INSERT/UPDATE/DELETE/
  DROP·스택쿼리(`;`)·UNION·time-based·OS 커맨드 **전부 없음** — WHERE 평가만 토글하는 읽기.
- `OR '1'='1`은 SELECT의 WHERE만 넓혀 '읽기'가 된다. **GET(읽기)만 자동 허용**, 비-GET은 계약 보증
  없이는 재현 거부(파괴적 쿼리 WHERE 확장 방지).
- **evidence에 데이터 원문 미기록**: 참 조건이 DB 행을 다 반환할 수 있어(개인정보/토큰) 응답 body를
  저장하지 않는다 — 상태코드·길이·델타·redaction된 짧은 스니펫만(`observation_type="http_exchange"`).
- payload는 `base_url` origin 밖으로 나가지 않는다(허용 base_url만, 임의 URL 금지).

## rollback / reset
- **없음(읽기 전용)**. 검색 SQLi는 DB 상태를 바꾸지 않으므로 target reset 불필요 —
  XSS 후보 #3(stored)나 write sink과 달리 read-only라 재실행이 안전하다.

## regression / smoke
- liveness: `GET /rest/products/search?q=apple` → 200.
- injection positive: 참(`OR '1'='1`) 결과셋이 benign보다 크게 열리고 거짓(`OR '1'='2`)은 닫힘.
- 패치 확증: 파라미터화 후 참≈거짓 → verify=False(FIXED gate 통과).

## P2 진행 순서(권장)
1. 위 attack_params로 manifest에 injection test_suite(read-only) 추가 → J-2 재현(verify 1회).
2. localize→patch(235B 파라미터 바인딩)→judge 6게이트→FIXED까지 closed-loop 완주(J-3).
3. FIXED 후 verify 재실행이 verified=False로 뒤집히는지 확인(패치 유효성 확증).

> 계약 shape/oracle는 `tests/test_injection_verifier.py`(`test_juice_shop_sqli_demo_pattern`,
> `InjectionProbeTests`)로 회귀 잠금. 프레임워크별 파라미터화 수정 방향은 locator가 rationale로 제공
> (`repair/locator._sqli_fix_hint`, Node→Sequelize/knex/pg, Python→execute(sql,params)/SQLAlchemy).
