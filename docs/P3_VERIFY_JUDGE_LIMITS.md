# P3 — Verify·Judge 한계 문서 (F-3)

> 상위 문서: **[TEAM_CONTRACT.md](../TEAM_CONTRACT.md)**. 이 문서는 P3 소유 서브시스템(`verifiers/**`,
> `repair/**`, `core/judge.py`)이 **무엇을 판정하고 무엇을 판정하지 않는지**를 코드 기준으로 명시한다.
> P1이 `SECURITY_POLICY.md`로 취합할 P3 섹션(REMAINING_PLAN 단계 3, P3_new_plan F-3).
>
> **원칙**: 못 돌리거나 확인 못 한 것을 통과로 위조하지 않는다. 아래 한계는 "버그"가 아니라
> **의도된 보수적 판정 경계**다 — 오탐(FP)을 줄이고, 판정 주장을 증거가 뒷받침하는 범위로 제한한다.

---

## 1. Positive-functionality 게이트의 판정 깊이 (클래스별)

패치가 취약점을 막았는지(attack 게이트)와 별개로, **정상 기능을 깨뜨렸는지**(overblocking)를 본다.
클래스마다 확인 깊이가 다르다 — 각각 무엇까지 보는지 명시한다.

### 1.1 Injection positive = **liveness까지만** (`repair/validators.py:injection_positive_gate_oracle`)
- **확인**: 정상(benign) 입력에 엔드포인트가 **2xx**로 응답하고 **응답 본문이 비어있지 않다**.
- **미확인**: 정상 쿼리가 *정확한 행*을 돌려주는지(결과 정확성)는 검증하지 않는다.
- **왜**: 결과 정확성은 `known-good 입력 → 기대 결과` 매핑을 담은 **P2 fixture**가 있어야 가능하다.
  그 fixture가 오면 이 게이트를 강화한다(현재는 없음).
- **잡는 것**: 패치가 엔드포인트를 500 내거나 결과를 통째로 날리는 overblocking.
- **함의**: injection 패치가 6게이트 FIXED여도, 그건 "취약점 차단 + 엔드포인트가 정상 입력에 살아있음"
  까지의 주장이지 "검색 결과가 이전과 동일하게 정확하다"는 아니다.

### 1.2 XSS positive = **benign 마커 반영** (`repair/validators.py:xss_positive_gate_oracle`)
- **확인**: 정상 입력(특수문자 없는 평문 마커)이 패치 후에도 응답에 반영된다(raw substring).
- **과이스케이프는 실패가 아니다**: XSS에서 escape는 안전한 방향이므로, 마커가 escape돼 반영돼도 통과.
- **잡는 것**: 입력을 통째로 삭제/거부하거나 페이지를 깨는 overblocking.

### 1.3 IDOR positive = **소유자 재조회** (`repair/validators.py:positive_gate_oracle`)
- **확인**: 패치 후에도 **정당한 소유자는 자기 자원을 여전히 볼 수 있다**(공격만 막고 정상 접근은 유지).
- `idor_oracle`을 그대로 뒤집어 써서 verifier와 판정 근거를 일치시킨다.

---

## 2. Attack 재현의 안전·판정 경계 (`verifiers/**`)

### 2.1 Injection: blind 불리언 차등, **비파괴 payload만** (`verifiers/injection.py`)
- payload는 **불리언 쌍**(참 `OR 1=1` / 거짓 `AND 1=2`)으로 한 글자만 토글 — 응답 차이가 SQL 해석의 증거.
- **금지 토큰 부재**(테스트로 잠금): 스택 쿼리(`;`)·write DML(insert/update/delete)·UNION·time-based
  (sleep/benchmark/waitfor)·OS(exec/xp_/load_file/outfile). 컨테이너 밖으로 새거나 데이터를 바꾸지 않는다.
- **noise-floor 하드닝**: baseline(benign)을 2회 재서 엔드포인트 자연 변동을 측정, `_MIN_DELTA + 2×변동`을
  임계로 삼아 타임스탬프/nonce/페이지네이션에 의한 오탐을 억제. baseline 상태코드가 불안정하면 상태 갈림
  신호를 신뢰하지 않는다.
- **콘텐츠 발산 신호(I4)**: 참(모든 행)과 거짓(빈 결과)의 응답 **길이가 우연히 비슷해** length-delta가
  놓치는 경우도, 두 본문의 **구조 유사도**가 낮으면 결과셋 열/닫힘으로 판정한다(길이 신호 보완, recall↑).
  precision 불변식 유지 — 한 글자 payload 에코·살균 앱(두 무효값이 같은 '없음' 페이지)·노이즈 엔드포인트·
  짧은 본문은 발화하지 않는다(benign 2-sample 유사도를 바닥으로 깔아 억제). recall만 넓히고 오탐은 안 늘린다.
- **비-GET 가드**: `read_query` 보증 없는 비-GET은 재현 거부(`NotImplementedError`) — 파괴적 쿼리에 불리언
  payload가 안 들어가게. endpoint만 보고 공격하지 않는다.

### 2.2 XSS: **실행** 관찰, 반사는 필요조건일 뿐 (`verifiers/xss.py`)
- 판정 근거는 "payload가 HTML에 반사됐나"가 **아니라** 브라우저에서 **benign 마커가 실제로 실행됐나**
  (`window.<flag>` set). 서버가 `&lt;script&gt;`로 escape하면 반사돼도 실행 안 됨 → 취약 아님.
- payload는 `window.<flag>=1` 하나만 세팅 — 네트워크 호출·쿠키 접근 없음(유출 불가, 컨테이너 안전).
- **격리 브라우저 부재 시 degrade(X5)**: Playwright/chromium이 없으면 verify가 크래시하거나 통과로
  위조하지 않고 **`verified=False` + 명확한 사유**로 내려간다(evidence 미기록). 즉 "브라우저 없이는 XSS를
  verified로 만들지 않는다"가 판정 경계 — 실행 관찰이 불가능하면 미확인으로 남긴다(F-negative는 안전 방향).

---

## 3. `running_local` target의 N/A 게이트 (`core/judge.py`, K 작업)

사용자가 "이미 떠 있는 로컬 서비스"(`kind="running_local"`)를 등록하면 build/restart 명령이 없다.
6게이트 중 명령 실행을 전제하는 게이트는 **N/A**로 처리하되, **통과로 위조하지 않는다**.

| 게이트 | `running_local` 동작 | 근거 |
|---|---|---|
| build | **N/A(None)** — patched worktree를 build/restart 못 함 | `check_build` → `_target_kind=="running_local"`이면 `None` |
| regression | test_suite 없으면 **False**(통과 아님) | `check_regression` `not_configured → passed=False` |
| attack / positive / static / scope | 현행대로 동작(소스만 있으면 됨) | — |

- **결과**: `compute_verdict`는 게이트가 하나라도 `None`이면 verdict를 내지 않는다 → `running_local` target은
  **최대 `PATCH_PROPOSED`**에 머물고 **절대 자동 `FIXED`가 되지 않는다**. (K-2: 못 돌린 게이트를 통과로
  세지 않는다.)
- **c1-05 gold 무영향**: `_target_kind` 기본값은 `compose_project`라 기존 compose 경로는 그대로 6게이트 全판정.
- ⚠️ **미구현(K-3, P1 레이어)**: "test_suite가 없어 regression을 못 돌려 PATCH_PROPOSED까지만"이라는
  **사용자向 사유 표시**는 report/tool 레이어(P1) 몫으로 남아있다. judge는 `None`/`False`를 정확히
  반환하지만, 그 이유를 사용자에게 설명하는 것은 아직 P1이 배선해야 한다.

---

## 4. Static 게이트의 환경 의존 (`core/judge.py:check_static`)

- 원본 source와 patched worktree 양쪽에 Semgrep을 재실행해 high/critical 후보 수가 늘지 않았는지 본다.
- **알려진 한계**: `semgrep` 바이너리가 PATH에 없으면 `SemgrepUnavailableError`가 전파된다(`vc_run_sast`와
  동일 제약). 로컬 미설치 환경이 많으므로 데모 환경에서 semgrep 설치를 전제한다.

---

## 5. 판정 불변식 (바뀌지 않는다)

- **LLM은 판정 경로에 절대 안 들어온다**(안전 불변식 3). verdict는 evidence와 게이트 결과(결정적 오라클)로만.
  LLM은 패치 *합성*과 후보 *재랭킹*에만 쓴다.
- **6게이트 全True일 때만 FIXED**. 하나라도 False면 RETRY, 하나라도 None이면 verdict 없음(PATCH_PROPOSED 유지).
- 승인된 교육용 앱에만 재현한다. 임의 취약점 삽입 금지.
