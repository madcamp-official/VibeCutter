# D7 / P2 Handoff — LLM patch runtime pivot

## 상태

진행 중. 팀 결정에 따라 모델 학습/LoRA를 중단하고, 외부 72B API를 사용하는 LLM patch
생성 closed-loop를 지원한다. 7B는 72B 설치·작동 확인 전까지 백업으로 유지한다.
P2 소유 범위는 target runtime, patched worktree build, static/test/regression gate용
manifest와 reset이며, LLM 합성·locator·judge는 P1/P3/P4 소유다.

## 확정된 P2 원칙

- 모델 weight 설치·학습은 P2가 수행하지 않는다. 외부 작업자가 72B를 설치하고 endpoint,
  model ID, health/timeout 계약을 제공한 뒤 P1이 agent/planner에 배선한다.
- LLM 출력은 untrusted diff로 취급한다. patch는 승인된 run-scoped worktree에만 적용하고,
  scope → build → attack → positive → regression → static 게이트를 통과해야 `FIXED`다.
- target별 고정 host port 때문에 baseline과 patched overlay를 동시에 띄우지 않는다.
  patched run 종료 후 `reset_run`, shared write 뒤에는 `restore_baseline_after_write`를 호출한다.
- test suite가 없는 target을 regression 통과로 간주하지 않는다. 실제 저장소의 결정적 suite가
  확인된 target만 demo 후보로 승격한다.

## 현재 manifest test-suite inventory

regression/smoke 명령이 선언된 target은 `c1-02`, `c1-03`, `c1-04`, `c1-05`, `c1-06`,
`c1-07`, `c2-01`, `c2-02`, `c2-03`, `c3-03`, `c3-04`, `c3-05`, `c3-06`, `c3-08`,
`c3-09`다. `c2-04`, `c2-05`, `c2-06`, `c2-07`, `c2-08` 등은 현재 suite가 비어 있다.
이 목록은 취약점 존재를 의미하지 않으며, P3가 XSS/SQLi candidate와 endpoint를 지정해야
P2가 해당 target의 build/test contract를 추가할 수 있다.

## 다음 P2 작업

1. P3가 지정한 XSS/Injection target의 source revision·safe endpoint·정상 입력·rollback을
   받아 manifest에 실제 build/test suite가 있는지 확인한다.
2. suite가 없으면 저장소가 제공하는 deterministic test 명령을 검증한 뒤에만 typed
   `test_suites`로 추가하고, 임의의 성공용 테스트는 만들지 않는다.
3. 선택 target에서 clean baseline → LLM patch worktree build → regression/static smoke →
   reset을 실행하고 `run_id` 기준 runtime metadata를 P4에 제공한다.
4. 외부 72B endpoint가 확정되면 P1에 endpoint/model/health/timeout을 전달하고, P2는 target
   runtime과 모델 서버를 섞지 않는다.

## 다른 역할에 필요한 사항

- P1: 72B API endpoint/model ID/health/timeout과 patch generator가 넘기는 diff 계약을 확정해 달라.
- P3: XSS/SQLi demo target_id, vuln_class, safe method/path/body, observe/positive 조건, rollback,
  기대하는 regression command를 알려 달라.
- P4: runtime JSONL의 `run_id` 조인 필드와 LLM endpoint fallback 표기 규칙을 확인해 달라.

## 검증·리스크

- P2 기존 target runtime/overlay/reset 회귀와 c1-05/c2-04/c3-09 clean-room 결과는 유지한다.
- 현재 XSS/SQLi demo target과 실제 test suite는 아직 확정되지 않았다. target 지정 전에는
  manifest나 source를 추정해 변경하지 않는다.

## D7 후속 점검 — template 밖 target 요청

P3 요청에 따라 현재 코퍼스의 suite 보유 target을 소스 기준으로 재점검했다. `c1-02`는
`innerHTML` 사용 지점이 있으나 채팅/닉네임 등 외부 값은 `escape()`를 거쳐 렌더링되고,
`c1-04`의 `innerHTML`은 정적 게임 화면/로컬 방 데이터 렌더링이다. 둘 다 실제 XSS
재현 endpoint로 확정할 근거가 없어 데모 취약 target으로 승격하지 않았다. 기존 handoff도
로컬 앱이 XSS/Injection clean이라 기록하고 있다.

따라서 P2는 임의로 소스에 취약점을 삽입하거나 성공용 regression test를 만들지 않는다.
P3가 승인된 교육용 fixture 또는 실제 target의 `target_id`, `source revision`, `vuln_class`,
safe method/path/body, observe/positive 조건, rollback, deterministic test command를
제공하면 해당 target만 build → test-suite → reset으로 검증한다. 그 전까지는 c1-05 gold,
c2-04 negative, c3-09 holdout을 유지한다.
