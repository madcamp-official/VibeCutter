# D5 / P3 Handoff (verify 배치 실행 — 라벨된 trajectory 생성 + 볼륨 천장 규명)

> P3 남은 일 #1("여러 target에 verify 배치를 돌려 라벨된 verified/rejected trajectory 생성 —
> P4 GPU 학습 임계경로")을 실행한 결과다. 배선(MCP verify+label, batch driver, P2 runtime)은
> 전부 완료돼 있어 로컬 4개 앱을 Docker로 띄워 배치를 돌렸다. **파이프라인은 실컨테이너로
> end-to-end 동작을 실증했고, 동시에 현재 로컬 코퍼스의 구조적 볼륨 천장을 규명했다.**

## 상태

완료(실행 + 정리). 새 라벨 궤적을 실앱에서 생성했고, XSS/Injection 클래스가 왜 현재 0건인지
결정적으로 확인했다. 커밋한 코드 변경 없음(추적 파일 무변경 — 전부 sanctioned tool/driver 소비 +
Docker 실행). 러너는 scratchpad(미커밋).

## 실행한 것

### 1. IDOR 배치 (`mcp_server.driver.run_target_audit`, sanctioned 경로)
- **c1-05** (self_signup/bearer, Spring/JWT/MySQL): candidates=1, **verified=1, verdict=FIXED**.
  - worker `run-897ad65c686f` — `verified`(vc_verify_access_control) + `fixed`(judge_verdict) 2스텝 라벨.
  - closed-loop 6게이트 전부 통과(패치 전 공격자→피해자 프로필 200 유출 → 패치 후 500 차단 →
    자기자원 유지 → 회귀/static/scope True). overlay reset 완료(P2 reset_run True).
  - **P4 base-vs-full 학습의 gold 재료**(IDOR/CWE-639/Spring/bearer, verified+fixed 완주).
- **c2-04** (fixture_file/none, FastAPI/SQLite): candidates=3, verified=0.
  - workers `run-c100386ab19f`·`run-d441a526d3b1`(read-IDOR) + `run-1327a6097641`(write/mutation-IDOR)
    → 전부 `rejected` 라벨.
  - **정당한 true-negative**: c2-04는 `auth.mode: none`(인증 자체가 없는 앱)이라 "남의 vocab 읽기"가
    권한경계를 넘지 않는다. GET /vocabs/4/words/ 가 200이었지만 verifier가 **200만으로 verified
    처리하지 않고**(P3 핵심 원칙) 마커 유출/상태변화가 없어 거절. precision 실증(오탐 0).

### 2. XSS/Injection 배치 (P3 브리지 `surface.candidates.injection_xss_candidates` + 기존 verify tool)
- driver에 XSS/Injection scan tool이 없어, P3 소유 브리지로 후보를 만들고 candidate-per-worker-Run
  계약대로 worker Run을 만든 뒤 `vc_verify_xss`/`vc_verify_injection`을 tool 계층으로 호출하도록 우회.
- **c2-05 / c2-04 / c1-05 / c3-08 4개 앱 전부: injection=0, xss=0, blocked=0.**
- 즉 **현재 로컬 4개 앱은 정적 injection/XSS 취약 패턴이 실제로 없다**(파라미터화 쿼리·JPA/Prisma
  ORM·서버측 raw HTML 반사 없음). D4-P3-verifier-validation.md의 "실앱 4개 오탐 0"과 정확히 일치 —
  앱이 clean이라 프리필터가 후보를 안 낸다. **verifier/프리필터 문제가 아니라 먹일 취약 대상이 없다.**

## 이번 세션 산출 (P4용 — 실앱 run_id)

| target | vuln | worker run_id | 라벨 |
| --- | --- | --- | --- |
| c1-05 | IDOR (CWE-639) | `run-897ad65c686f` | verified + **fixed** (gold closed-loop) |
| c2-04 | IDOR (read) | `run-c100386ab19f`, `run-d441a526d3b1` | rejected (true-negative) |
| c2-04 | IDOR (write) | `run-1327a6097641` | rejected (true-negative) |

라벨 분포 델타: `verified +1`, `fixed +1`, `rejected +3` (baseline ver28/fix4/rej24 → ver29/fix5/rej27).

## 검증

- 실컨테이너 4개 build/start/scan/verify(+c1-05 patch/replay/validate) 실행. Playwright chromium 기동 확인.
- 배치 종료 후 **잔여 target/overlay 컨테이너 0** (c1-05는 driver reset_run, c2-04/XSS·Inj batch는
  down --volumes teardown). **추적 파일 무변경**(git clean).

## 다른 역할에 필요한 사항

### P4 — 재료 확보 + 데이터 위생
- **gold 궤적** `run-897ad65c686f`(verified→fixed) = base-vs-full 학습의 실물 IDOR 샘플.
  rejected×3(c2-04)은 precision(음성) 쪽 샘플.
- **[중요] 데이터 위생**: 유닛 테스트(`python -m unittest`)가 **같은 `.vibecutter/trajectories/`
  디렉토리에 test-생성 궤적을 섞어 남긴다**(이번에도 테스트 1회로 ~35개 증가). 학습/평가 시
  **실앱 audit run_id로 필터**해야 한다(위 표의 run_id가 이번 세션 실앱분). run_id ↔ 실앱 매핑
  메커니즘(예: trajectory에 target_id/source 태그, 또는 실앱 run allowlist)이 있으면 좋겠다.

### P2 — 볼륨의 실제 병목 (둘 다 필요)
1. **provisioning 등록된 로컬 소스 추가**: IDOR verify가 실제로 되는 로컬 target이 **c1-05·c2-04뿐**이다.
   verifier_provisioning.yaml에 c2-01/c2-02/c1-06이 있지만 **로컬 소스(.vibecutter/targets/sources/)가
   없어 build 불가**. 이 소스들을 주면 self-signup IDOR 배치를 바로 더 돌릴 수 있다.
2. **injection/XSS가 실제로 있는 target**: 현 로컬 4개 앱은 clean이라 두 클래스 라벨이 0건. 취약
   샘플이 있는 앱(또는 plan-p3.md가 fallback으로 지정한 Juice Shop/WebGoat류 교육용 앱)을 격리
   등록하면 XSS/Injection verifier가 그때 데이터를 낸다.

### P1 — (선택) XSS/Injection scan tool 배선
- 지금은 driver 기본 `scan_tool="vc_scan_access_control"`(IDOR 전용)뿐이라 XSS/Injection은 P3 브리지로
  우회했다. `injection_xss_candidates`를 `READY→MAPPING→CANDIDATE_SCAN` 전이와 함께 감싸는 scan tool
  (예: `vc_scan_injection_xss`)이 배선되면, 향후 취약 target이 생겼을 때 `run_target_audit(scan_tool=...)`
  단일 경로로 세 클래스를 다 배치할 수 있다(P3 브리지는 준비됨). 지금 당장은 후보가 0이라 급하진 않다.

## 결정·가정·리스크

- **[결정] 파이프라인 검증 ✅ / 볼륨은 코퍼스 제약**: 배치·verify·label·closed-loop·정리 전부 실컨테이너로
  동작 확인. "수백 건"은 현재 로컬 코퍼스로는 불가 — IDOR는 provisioning 2개 target·앱당 후보 소수,
  XSS/Injection은 앱이 clean(후보 0). **더 많은/취약한 target이 임계경로**(P2).
- **[가정] c2-04 rejected는 신뢰 가능한 음성**: auth 없는 앱이라 IDOR 경계 부재 → oracle이 200을
  verified로 과잉판정하지 않고 거절. P3 "실제 상태 변화만 verified" 원칙이 실앱에서 작동함을 실증.
- **[리스크] P4 학습 데이터 얇음**: 실앱 verified+fixed가 1건(c1-05). Notion 리스크 그대로 —
  얇으면 base 대비 유의차 확보 어려움. P4 대응책(RAG+prompt ablation)과 P2 target 확충 병행 필요.
- **안전**: 로컬 격리 4개 앱만, c1-05는 일회성 DB/JWT secret(env var, 파일 미저장, down --volumes로 폐기),
  XSS는 격리 브라우저 benign marker, Injection은 SELECT 불리언만. 패치는 run-scoped worktree(원본 branch
  불변). secret은 evidence/log 미기록. 스코프 밖 host 접근 0.

## 참조
- sanctioned driver: `mcp_server/driver.py` `run_target_audit`. XSS/Injection 브리지: `surface/candidates.py`
  `injection_xss_candidates`, `surface/inject_xss.py`.
- 이전 P3 세션: `docs/handoffs/D4-P3-session-wrap.md`(3 verifier 완성), `D4-P3-closed-loop.md`(c1-05 자동 FIXED).
