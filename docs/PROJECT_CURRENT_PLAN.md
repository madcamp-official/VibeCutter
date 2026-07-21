# Vibe Cutter 현재 프로젝트 계획과 전체 구조

> 2026-07-21 기준. 이 문서는 기존 5일 계획의 기록을 지우지 않고, 현재 팀이 합의한 **3일 데모 우선 계획**을 명확히 한다.

## 1. 프로젝트가 만드는 것

Vibe Cutter는 승인된 로컬/교육용 애플리케이션을 대상으로, 취약점 후보를 찾은 뒤 **실제 증거로 검증하고**, 격리된 worktree에서 패치를 제안·적용·재검증하여 보고서를 만드는 안전한 보안 분석 파이프라인이다.

발표의 목표는 한 명령으로 다음 흐름이 실제 애플리케이션에서 재현되는 것이다.

```text
target 등록 → build/start/health → scan → candidate
→ deterministic verify/evidence → LLM patch proposal
→ isolated worktree apply → 6-gate validation → report
→ run reset/teardown
```

### 판정과 안전의 원칙

- LLM은 우선순위, 원인 후보, patch diff만 제안한다. `verified`와 `fixed`는 evidence와 결정론적 judge만 결정한다.
- patch는 원본 branch가 아니라 run별 Git worktree에만 적용한다.
- `FIXED`는 Build, Attack replay, Positive functionality, Regression, Static, Scope의 6개 gate가 모두 통과해야 한다.
- 등록된 target/manifest 범위 밖 URL·명령·소스는 사용하지 않는다. secret/token/개인정보는 evidence·report·dataset에 저장하지 않는다.
- 모든 실행은 target, source revision, run ID, readiness, reset 결과를 남겨 재현 가능해야 한다.

## 2. 전략 변경: 학습 중심에서 닫힌 루프 데모 중심으로

기존 LoRA 학습은 이번 발표의 필수 산출물에서 제외한다. verified evidence가 아직 충분하지 않아 성능 주장을 하기 어렵기 때문이다. 다만 trajectory·학습 코드·데이터 export 경로는 보존하며, 향후 증류/저비용 자체 호스팅을 위한 확장 가능성으로 제시한다.

현재 모델 전략은 다음과 같다.

- 대형 내부 API 모델(Qwen3-235B)을 planner/rerank 및 LLM patch synthesis의 주 경로로 사용한다.
- 기존 Qwen2.5-Coder-7B는 API 장애·timeout 시 fallback으로 유지한다.
- RQ3는 “LoRA가 base보다 좋은가” 대신 “RAG 코드 문맥 + LLM rerank가 휴리스틱보다 좋은가”로 재정의한다.
- 모델 endpoint가 죽거나 fallback이 사용된 run은 runtime metadata로 구분해, 평가 표본을 섞지 않는다.

## 3. 현재 구현·검증 상태

| 구분 | 상태 | 근거/의미 |
|---|---|---|
| IDOR gold demo | 완료(로컬) | `c1-05`, `run-897ad65c686f`, candidate 1개 verified → `FIXED`; 6 gate 통과 |
| IDOR true-negative | 완료(로컬) | `c2-04` candidate 3개가 모두 rejected. 무인증 앱의 경계 부재를 오탐 없이 거절 |
| holdout clean-room | 준비 | `c3-09`는 clean-room/holdout 재현용 |
| P2 runtime hygiene | 검증 | c1-05/c2-04/c3-09의 reset → build → start/health/readiness → reset 흐름 확인 |
| CAMP-1 c1-05 | 복구·건강 | fresh volume + 같은 실행의 secret 생성 규칙으로 DB/app/frontend healthy 복구 |
| 대형 API/fallback | 배선 완료 | primary/fallback endpoint tier와 health probe가 main에 통합됨 |
| LLM patch synthesis | 통합 중 | P3 adapter와 P1/P4의 호출·문맥 배선이 진행 중 |
| SQLi 일반화 demo | runtime 부분 검증 | OWASP Juice Shop v17.3.0 pinned source bootstrap·Compose build·start/reset 통과. Windows Docker Desktop `internal: true` published loopback은 host에서 timeout되어 health/smoke 운영 Linux 재검증 대기 |

`c1-05`의 gold 결과와 `c2-04`의 reject 결과는 이미 발표·평가의 핵심 근거가 된다. 단, 그 결과는 P3의 로컬 실행 기록이므로 CAMP-1의 새 run과 혼동하지 않는다.

## 4. 데모 target 집합

| 우선순위 | target | 목적 | 현재 상태 |
|---|---|---|---|
| 1 | `26s-w1-c1-05` | IDOR verified → fixed 대표 사례 | gold 결과 존재, CAMP-1 fresh run 재발급 대기 |
| 2 | `26s-w1-c2-04` | IDOR false-positive를 rejected로 거르는 정확도 사례 | fixture/rollback 계약 확정 |
| 3 | `26s-w1-c3-09` | holdout 및 clean-room 재현성 확인 | runtime 준비 |
| 4 | `juice-shop` (후보) | template 밖 SQLi → LLM 파라미터화 patch 일반화 | external source allowlist 병합 뒤 등록 |

Juice Shop은 임의로 취약점을 삽입한 앱이 아니라, 승인된 교육용 취약 애플리케이션을 고정 revision으로 관리하는 후보이다. 추적하는 것은 Git source identity이고, 실제 checkout은 `.vibecutter/targets/sources/`의 관리형·gitignored 복제본이다. 소스를 Git에 vendoring하지 않는다.

## 5. 역할과 3일 실행 순서

| 역할 | 현재 책임 | 즉시 산출물 |
|---|---|---|
| P1 — 통합 | 대형 API/7B fallback, orchestration, kill-switch/rollback, one-command demo, judge 통합 | source-lock external allowlist, LLM synthesis 호출 배선, E2E runbook |
| P2 — runtime | target health, reset/sweep, clean-room, manifest/adapter, 실행 상태표, 장애 대응 | 데모 target 안정화, Juice Shop runtime 등록, run metadata/reset 제공 |
| P3 — security | scan/verify/evidence, root cause, patch/validation, 안전 감사 | IDOR/XSS/Injection의 실제 closed-loop와 verified/fixed 사례 |
| P4 — evaluation | RAG 코드 문맥, API/7B 이중화 지원, metric/report/slide | verified precision·patch success·safety metric 및 발표 자료 |

의존 관계는 `P1 API·orchestration + P2 healthy target → P3 closed-loop evidence → P4 metric/report` 이다. 각 단계가 끝나지 않아도, 기존 gold/negative 증거는 별도로 보존·활용한다.

## 6. 남은 마일스톤과 순서

1. **P1**: `targets/source-lock.yaml`의 승인된 external repository allowlist와 validator/test를 병합한다. 외부 source를 무제한 허용하지 않는다.
2. **P2**: 병합 직후 Juice Shop pinned source bootstrap, manifest/compose, loopback health, smoke regression, reset 계약을 추가한다.
3. **P3**: CAMP-1에서 c1-05 fresh closed-loop를 실행한다. secret 생성·`down --volumes`·build/start/verify가 같은 실행 안에서 이뤄져야 한다.
4. **P2**: P3의 새 `run_id`에 source commit, base URL, readiness, reset/잔여 container·worktree·port, worker/LLM 상태를 JSONL metadata로 연결한다.
5. **P1/P3/P4**: LLM patch synthesis + 코드 문맥을 한 target에서 6-gate로 완주하고, primary/fallback 사용 여부를 분리해 metric/report를 만든다.
6. **전원**: 고정 target으로 reset 후 반복 리허설, report(HTML/SARIF) 산출, scope/secret 위반 0을 확인하고 freeze한다.

## 7. 운영상 주의와 결정 기준

- DB volume과 runtime secret이 불일치하면 앱이 시작하지 않는다. 기존 volume을 유지한 채 secret만 변경하지 않는다.
- `reset_run()`은 run-scoped patched overlay 정리용이다. shared baseline을 변경한 write verifier 뒤에는 `restore_baseline_after_write(..., approved=True)`를 별도로 호출한다.
- endpoint health 실패·heuristic fallback·잔여 container/worktree/port가 있는 run은 평가에서 명시적으로 flag하거나 제외한다.
- API가 내부망인지, 외부 노출인지 확정되지 않은 endpoint에는 source나 secret을 보내지 않는다. 보안 노출 판단은 서비스 소유자가 서버 측 네트워크·인증 설정으로 확인한다.
- historical handoff와 기존 학습 경로는 기록/향후 연구를 위해 유지한다. 이 문서는 현재 데모 실행 우선순위를 정의한다.

## 8. 성공 기준

발표 시점에는 최소 한 target에서 `register → runtime up → scan → evidence-based verify → patch → six-gate validation → report → reset`이 재현되어야 한다. 또한 실제 reject 사례와 fixed 사례를 함께 보여, “LLM 주장”이 아니라 “증거와 judge가 판정하는 닫힌 루프”임을 입증한다.
