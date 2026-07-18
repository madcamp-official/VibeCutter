# D4 / P3 Handoff (보충: XSS verifier + 비-Spring locator)

> D4-P3.md(write-IDOR candidate 경로) 이후 같은 Day4 범위("3개군 확장 + repair 하드닝")의 후속
> 작업을 기록한다. 팀 관례상 D5 번호는 최종 통합 전까지 비워 두므로(D3-P2 명시) 접미사 보충으로 남긴다.

## 상태

두 가지 완료(커밋+테스트).

1. **XSS verifier 완성** — IDOR에 이은 **2번째 oracle 축("실행됐나")**. 격리 Playwright 브라우저에서
   benign marker가 실제 실행됐는지로 판정한다(반사만으로 verified 하지 않음). `verify_candidate`가
   `vuln_class=xss`를 자동 라우팅. 통제 랩서버로 취약(verified)/안전(미verified) 구분 실증.
2. **비-Spring locator 갭 해소**(P1 D4 요청) — `extract_routes`가 Spring 전용이라 FastAPI/Node/Django
   타깃에서 route 매핑이 실패→저신뢰 code_index→프론트엔드 파일 오탐이 나던 문제. route 추출을
   4스택으로 확장 + code_index 폴백에 프론트엔드 가드. c2-04(FastAPI)에서 verified IDOR→실제 백엔드
   handler(main.py)로 locate 확인, c1-05(Spring) 회귀 유지.

추가로 머지 시 write-oracle 계약을 P1 정본(`d6e58de`)에 맞추고 `D4-P3.md` 문서 정정(P2 지적 대응).

## 변경 파일

- `verifiers/xss.py`: **스텁 → 완전 verifier.** 3덩어리(access_control과 동형): `xss_oracle`(실행 신호로
  판정, 대상 독립) + `_replay_reflected`/`_replay_stored`(Playwright 격리 브라우저, **egress 차단**:
  대상 origin 밖 요청 abort) + `verify`(조립 + `browser_trace` evidence). payload는 **benign marker만**
  (`window.<flag>=1`), 네트워크/쿠키/지속성 없음.
- `verifiers/dispatch.py`: `xss` → `xss.verify` 배선(`_NOT_READY`에서 제거). (+ 머지 반영: write-IDOR은
  P1 정본 `verify_mutation_access_control`로 라우팅.)
- `tests/test_xss_verifier.py`: **신규.** 9 유닛(oracle 4 / probe 2 / dispatch 라우팅 2 / **payload 안전성**
  1) — 브라우저 없이 CI에서 돎.
- `surface/routes.py`: **다중 스택 route 추출.** Spring(무변경) + **FastAPI**(`@app|router.<method>` +
  `APIRouter(prefix=)` + 같은 파일 `def` handler) + **Express**(`Router()/express()` 선언 변수만 인정 →
  프론트 `axios.get` 오탐 배제, `app.use("/api", router)` 마운트 prefix) + **Django**(urls.py `path()`,
  best-effort). `node_modules/dist/build/.next` 등 제외. `Route`에 `stack` 필드 추가(additive).
- `repair/locator.py`: **code_index 폴백 프론트엔드 가드.** `_is_frontend_file`(`.tsx/.jsx/.vue`·`frontend/`·
  `dist/` 등)로 프론트엔드 후보를 걸러, `k=5` 검색 중 **백엔드 후보만** 채택. 없으면 `None`(추측 안 함).
- `docs/handoffs/D4-P3.md`: write-oracle 계약을 **P1 정본으로 정정**(candidate에 `mutation_marker` 담고
  `extra_body_json` 키 사용) — 초안의 "미포함/fresh" 서술은 갱신 박스가 우선.
- **(미반영, 요청)** `requirements.txt`에 `playwright` 추가 필요 — verifier 실행 의존성.

## 제공 인터페이스

### `verifiers.xss` — P1의 vc_verify_xss tool이 호출

```python
def verify(run_id: str, candidate: Candidate, *, max_requests: int = 10) -> VerifierOutput
```

- read `verify`와 **동일 시그니처**. `attack_params` 키: `base_url`, `context`("reflected"|"stored"),
  `inject_path`, `inject_param`, `inject_method`(기본 GET), `render_path`(stored용), `extra_params_json`.
- 판정: 격리 브라우저에서 marker 실행 시 verified. evidence는 `observation_type="browser_trace"`.
- `verify_candidate(run_id, candidate)`가 `vuln_class=xss`(또는 CWE-79)를 여기로 라우팅.

### `surface.routes.extract_routes(source_root) -> list[Route]`

- 이제 Spring/FastAPI/Express/Django 4스택. `Route.stack`으로 출처 구분. 시그니처/반환형 불변(additive).

### `repair.locator.localize` (변경 없음, 동작 개선)

- 비-Spring 타깃에서도 route 신호로 실제 handler를 짚는다(프론트엔드 파일 배제). API 불변.

## 검증

| 항목 | 결과 |
| --- | --- |
| XSS E2E (취약 서버=미살균 반사 / 안전 서버=이스케이프) | **PASS** — 취약 verified=True(브라우저 실행), 안전 verified=False(inert), evidence 저장 |
| XSS oracle 단위(실행/반사만/이스케이프/미반사) + payload 안전성 | PASS (9 유닛) |
| route 추출 (오탐 제거 후) | c2-04 **17 fastapi** / c2-05 **18 fastapi** / c3-08 **77 express** / c1-05 **73 spring**, 프론트 오탐 0 |
| **c2-04(FastAPI) verified IDOR → locate** | **PASS** — `backend/src/main.py:main.read_words`(read)·`main.update_vocab_description`(write), 프론트 아님 |
| c1-05(Spring) locate 회귀 | PASS — `UserProfileController.getProfile` |
| 프론트엔드 가드 | PASS — `.tsx`/`apps/web`/`dist/` 제외, `main.py`/`app/api/*.py` 통과 |
| 전체 스위트 | **207 tests, 새 실패 0** (기존 4개 apply/judge pre-existing만) |

**미검증**: Django(로컬 clone 없음 — 구현만, 실측 못 함); XSS는 통제 랩서버로만 검증(실제 타깃 XSS
표면 미정찰); Express handler는 route 파일까지만(컨트롤러 파일 미추적).

## 다른 역할에 필요한 사항

### P1
- **(XSS tool 배선)** `mcp_server/tools_analysis.py`의 `vc_verify_xss` 본문: `NotImplementedError` →
  `verifiers.xss.verify(run_id, candidate, max_requests=...)` 호출 + `update_finding_status`. `vc_verify_access_control`과
  동일 패턴(복붙 수준). policy/승인/상태전이는 이미 배선돼 있음.
- **(비-Spring closed-loop 열림)** c2-04(FastAPI)·Node 타깃에서 `vc_localize_root_cause`/`vc_generate_patch`가
  이제 실제 백엔드 handler를 짚는다 → closed-loop 시도 가능. 단 **apply 경로 fix(`da50a4e`)가 아직
  테스트 빨감**(`repo`에 적용/`repo/backend` 아님) — 그게 먼저 닫혀야 실 apply가 된다.

### P2
- **(요청) `requirements.txt`에 `playwright` 추가** — 공통 파일이라 조용히 안 바꿈(D2 httpx 규약). 브라우저
  바이너리(chromium)는 이미 로컬 캐시에 있어 `pip install playwright`면 됨.
- **(XSS candidate/표면)** XSS를 실제 검증하려면 `inject_path`/`inject_param`이 담긴 candidate가 필요 —
  XSS suspect 프리필터(P3 후속) 또는 P2 fixture. 반영형 XSS는 쿼리 반사 지점이면 됨.
- **(Django 검증)** c2-08 등 Django 소스가 로컬에 오면 locator Django 경로를 실측하겠다.

### P4
- **(신규 evidence 축) `browser_trace`** — XSS 실행 증거. trajectory/dataset에 XSS(CWE-79) 라벨 추가 가능.
- **(비-Spring patch 데이터)** locate가 비-Spring에서 되니, 그동안 Spring뿐이던 patch trajectory를
  FastAPI/Node로 넓힐 수 있다(스택 다양성).

### 전원
- `requirements.txt` playwright. **semgrep Python 3.14 블로커 여전** — static gate·SAST 폴백에 영향.

## 결정·가정·리스크

- **XSS oracle = 실행 판정**(반사만으로 verified 하지 않음). IDOR의 "상태 변화"에 대응하는 XSS의 진짜
  oracle. benign marker(window 플래그)만 쓰고 egress를 차단해 payload가 컨테이너 밖으로 못 나간다(10.4절).
- **write-oracle 계약 = 머지에서 P1 정본 채택**(`mutation_marker`를 candidate에 담음). 내 원안(fresh per
  replay)은 P1 repoint fix와 함께면 불필요 — read-bearer 쪽엔 여전히 유효(별도 수정).
- **routes.py는 정규식 파서**라 근사치: 동적 라우팅·멀티 데코레이터·인라인 arrow handler는 부정확할 수
  있다. **Express handler는 route 파일(`*.routes.ts`)까지**만 짚고 컨트롤러 파일은 미추적(백엔드 위치로는
  충분, 정밀 patch엔 컨트롤러 해석 후속). **Django는 미검증**.
- **프론트엔드 가드는 경로/확장자 휴리스틱** — 백엔드가 `web`류 이름을 쓰는 극단 케이스는 오분류 가능
  (현재 22개 타깃엔 문제 없음). tree-sitter로 교체하면 근본 해소.
- **가정**: XSS candidate의 `attack_params`는 read-IDOR처럼 typed 필드로 온다. SAST(P4)가 CWE-79 후보를
  낼 때 inject 파라미터를 못 채우면 fixture/프리필터로 합쳐야 한다(IDOR `candidate_from_fixture`와 동형).
