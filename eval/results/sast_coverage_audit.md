# SAST 규칙 커버리지 점검 (REMAINING_PLAN §4.4, 담당 P4)

`scanners/sast/semgrep_runner.py`의 semgrep 룰셋이 injection/xss sink를 충분히 커버하는지 점검.
surface(정적 프리필터)와 SAST는 **다른 경로로 후보를 내고 `aggregate`에서 합쳐진다** — 둘 중
하나만 커버하면 놓치므로, SAST 쪽 단독 커버리지를 여기서 본다.

## 현재 매핑 (`semgrep_runner.py`)

| focus | 룰셋(`FOCUS_RULESETS`) | 정규화되는 CWE(`_CWE_TO_FOCUS`) |
|---|---|---|
| injection | `p/sql-injection`, `p/command-injection` | CWE-89(SQL), 78/77(command), **90(LDAP)**, **943(NoSQL)** |
| xss | `p/xss` | CWE-79, 80, 83 |
| idor | **`()` — SAST 룰셋 없음** (구조적, 아래 갭②) | CWE-639, 862, 863, 284, 285, 566 (broad 스캔 분류용 매핑은 유지) |

**(2026-07-22 수정)** idor 룰셋이 예전엔 `p/insecure-access-control` 였으나 **semgrep registry 에서 HTTP 404**
(존재하지 않는 이름 — `p/broken-access-control` 도 404)라 매 스캔이 실패했다. 공개 registry 에 targeted
access-control 룰셋이 없고 IDOR 는 dataflow sink 로 안 잡히는 구조적 취약점이라, `FOCUS_RULESETS["idor"]`
를 **빈 튜플**로 바꿔 SAST 는 idor 룰셋을 돌리지 않는다. IDOR 후보는 `scanners.surface_idor`(구조적
프리필터)가 낸다(`eval/run_m1.py` 에 배선). `_CWE_TO_FOCUS` 의 idor 매핑은 유지 — broad 스캔의
access-control finding 을 idor 로 분류하기 위함.

## 판정

- **CWE-89(SQLi) / CWE-79(XSS) — 데모 두 종의 핵심 sink는 커버됨.** `p/sql-injection`·`p/xss`
  공식 룰셋이 매핑을 갖고 실주행에서 후보를 낸다(B1 baseline: injection P0.93/R0.87로 강세).
- **갭 ①: NoSQL(CWE-943)·LDAP(CWE-90) injection은 CWE 매핑은 있으나 전용 룰셋이 없다.**
  `p/sql-injection`/`p/command-injection`이 그 sink를 잡지 못하면 SAST 단독으로는 미탐. 현재
  벤치에서 NoSQL은 nodegoat/dvna 등에 있으나 데모 대상(c1-05 IDOR, c2-04 injection)엔 무관.
- **갭 ②: IDOR는 SAST 구조적 약점** — B1 실측에서 IDOR 0/13(미탐). 이건 룰셋 문제가 아니라
  "접근제어 부재"가 데이터플로우 sink로 안 잡히는 근본 한계다. `scanners/surface_idor.py`
  (surface 프리필터 브릿지)와 **동적 verify**가 이 갭을 메운다(aggregate에서 병합).

## 결론

발표 두 종(SQLi·XSS)의 sink는 SAST 룰셋으로 커버된다 → **데모 경로엔 커버리지 갭 없음.**
주변 injection 변종(NoSQL/LDAP)과 IDOR는 SAST 단독으론 부족하나, **surface 프리필터 + 동적
verify가 다른 경로로 보완**하고 `aggregate`가 합치므로 파이프라인 전체로는 커버된다.

향후(비발표): NoSQL/LDAP를 SAST에서도 잡으려면 `FOCUS_RULESETS["injection"]`에 해당 룰셋을
추가한다(예: `p/nosql-injection` 계열) — 다만 이는 dynamic verify가 이미 회수하므로 우선순위 낮음.

_점검일 2026-07-22. 기준: `scanners/sast/semgrep_runner.py` `FOCUS_RULESETS`/`_CWE_TO_FOCUS`._
