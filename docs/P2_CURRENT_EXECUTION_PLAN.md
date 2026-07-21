# P2 실행 범위와 운영 계획

> 2026-07-21 기준. 이 문서는 P2(Target Runtime/Infra)의 소유 범위만 다룬다. 전체 프로젝트의 판단·verifier·patch 구현은 각각 P1/P3의 소유 계약을 따른다.

## 1. P2의 임무

P2는 승인된 target을 재현 가능하고 격리된 상태로 실행 가능하게 만든다. 즉 manifest, adapter, Docker/Compose lifecycle, source checkout, health/readiness, run worktree, reset/sweep, fixture 계약, test runner와 실행 metadata를 책임진다.

P2가 하지 않는 일은 다음과 같다.

- 취약점의 최종 판정, exploit 로직, root cause, patch 내용, `FIXED` 판정(P3/P1 judge)
- LLM prompt/모델 품질, RAG, metric 산출과 발표 자료(P1/P4)
- 승인되지 않은 target·URL·취약 앱을 임의 등록하거나 범위 밖 공격 수행

## 2. 현재 P2가 제공하는 기반

| 항목 | 상태 | 비고 |
|---|---|---|
| 기존 runtime population | 준비 | 약 20개 target의 manifest/adapter/lifecycle 기반을 마련. 이는 “모두 closed-loop 검증됨”이라는 뜻은 아님 |
| clean-room 우선 target | 통과 | c1-05, c2-04, c3-09: reset → build → start/health/readiness → reset 확인 |
| c1-05 CAMP-1 runtime | healthy | DB/app/frontend을 fresh volume 방식으로 복구. P3 fresh run 동안 14006/14007 슬롯 유지 |
| c2-04 fixture 계약 | 준비 | `prepare_idor_fixture`, write contract와 target reset rollback을 P3와 합의 |
| run hygiene | 준비 | run overlay reset, stale overlay sweep, worktree/port/container 잔여 확인 경로 제공 |
| P2 runtime test | 확인 | runtime 관련 단위 테스트를 실행해 lifecycle/reset 경로를 점검 |

### 확정된 데모 target 지원 범위

- **c1-05**: IDOR gold. self-signup/bearer 방식이라 별도 fixture 불필요. P3가 공격마다 ephemeral 계정을 만든다.
- **c2-04**: IDOR true-negative. `PUT /vocabs/{id}/description`, 관측 `/vocabs/?owner_id={owner}`, rollback은 target reset. fixture는 승인된 `prepare_idor_fixture`만 사용한다.
- **c3-09**: holdout/clean-room 재현용이다.
- **Juice Shop SQLi 후보**: `bkimminich/juice-shop:v17.3.0`, source revision `1867b926c5f50e4e692dc9c8f61821413cebe0cd`를 후보로 검증했다. loopback health와 정상/boolean-differential search는 확인했으며, regression은 고정 Docker image의 health + 정상 search smoke를 사용한다.

## 3. 운영 계약

### lifecycle

```text
register → build → start → check_health/readiness
→ (P3 scan/verify/patch/validate) → reset_run → teardown/sweep
```

- write verifier가 shared baseline을 바꾼 경우에는 `reset_run()`만으로 충분하지 않다. P1 orchestrator가 승인된 `restore_baseline_after_write(target_id, approved=True)`를 호출해야 한다.
- run 종료와 다음 batch 시작에는 stale run overlay를 sweep하여 port leak을 방지한다.
- patch는 run-scoped worktree에서만 수행하며 P2 reset은 해당 overlay를 정리한다.

### secret과 volume

- fresh DB volume을 만드는 run은 DB/app의 필요한 secret을 **같은 프로세스·같은 실행**에서 생성하고 build/start/verify까지 이어간다.
- volume을 보존한 채 secret만 바꾸지 않는다. 불일치하면 DB 권한/health가 실패할 수 있다.
- secret 값은 log, handoff, runtime JSONL, report에 기록하지 않는다.

### P4에 제공할 run metadata

P3가 fresh run ID를 전달하면 P2는 JSONL 한 줄에 다음 공개 가능한 metadata를 붙인다.

```text
run_id, target_id, source_commit, base_url, health, readiness,
gpu_worker/llm_endpoint_state, reset_result,
remaining_containers, remaining_worktrees, remaining_ports,
lease_run_id, lease_expires_at
```

구현 위치는 `runtime/metadata.py`이며 기본 산출물은
`.vibecutter/runtime_metadata.jsonl`이다. API key, token, password, 원문 로그는
이 레코드에 저장하지 않는다.

LLM health 실패·fallback·잔여 리소스가 확인된 run은 `FIXED` 통계나 base-vs-model 비교에서 오염 표본으로 표시한다. token, password, 개인 식별 정보는 포함하지 않는다.

## 4. P2의 다음 작업 순서

1. **P3 c1-05 fresh run 보호**: P3가 CAMP-1 closed-loop를 실행하는 동안 14006/14007과 baseline을 건드리지 않는다. P3 요청 시에만 사전 합의된 reset/restore를 수행한다.
2. **P1 source-lock 병합 완료**: external repository는 체크인된 `external_allowlist`에 정확히 일치하는 URL만 허용한다. 무제한 clone은 허용하지 않는다.
3. **Juice Shop runtime 검증**: `juice-shop` pinned managed checkout bootstrap → manifest/Compose → loopback health → normal-search smoke → reset/teardown을 Docker 가능한 환경에서 수행한다. 실제 source checkout은 `.vibecutter/targets/sources/`에 두고 Git에는 source identity만 남긴다.
4. **P4 T-2 배선 확인**: P4의 `observed_chat_fn`/recorder가 rerank trajectory `result`에 들어가도록 P1이 main에 연결한 뒤, LLM 사용 여부가 기록되는지 확인한다.
5. **P3 J-3 실행 지원**: P3가 Juice Shop SQLi verify → LLM patch → 6-gate를 수행할 때 target lease와 fixed port를 보호한다.
6. **runtime metadata attach**: P3가 fresh `run_id`와 evidence 결과를 주면 source revision/readiness/reset/잔여 리소스/LLM 상태를 기록한다.
7. **데모 리허설**: P1의 one-command lifecycle에 맞춰 c1-05, c2-04, c3-09 및 Juice Shop을 reset 포함으로 반복 점검하고 상태표를 갱신한다.
6. **장애 대응**: health failure, port leak, stale overlay, volume/secret mismatch만 P2가 즉시 처리한다. verifier·patch·judge failure는 증거와 함께 P3/P1으로 넘긴다.

## 5. 다른 역할에 필요한 입력

| 대상 | P2가 기다리는 것 | P2가 되돌려 주는 것 |
|---|---|---|
| P1 | external allowlist merge, one-command lifecycle의 reset/restore 호출 위치, 최종 target/run 전달 방식 | target runtime state, reset/sweep 결과, managed source/manifest, runtime metadata |
| P3 | fresh `run_id`, target별 fixture/safe mutation/observe/rollback, runtime을 점유해도 되는 시간 | stable base URL, clean-room baseline, reset, fixture/provisioning 지원 |
| P4 | 평가용 metadata schema와 필터 기준 | run-level JSONL; health/fallback/reset/leak 상태가 포함된 재현성 정보 |

## 6. 완료 판단 기준

P2는 다음을 만족하면 데모 준비 범위의 완료로 본다.

- 선정된 3–5개 target이 동일한 manifest/source revision에서 build, health, readiness를 재현한다.
- 각 run의 reset/sweep 이후 container, worktree, port 잔여가 없거나 명시적으로 보고된다.
- P3가 선택한 fresh run ID에 대해 안전한 runtime metadata가 연결된다.
- approved target의 write fixture는 복구 방법과 함께 문서화되고, secret은 저장되지 않는다.
- Juice Shop은 common source-lock 계약이 병합된 뒤에만 등록하며, build/test/health/reset artifact를 남긴다.

이 문서는 P2의 현재 우선순위다. 대규모 추가 Dockerize, LoRA 학습 환경 운영, 또는 P3의 verifier/patch 구현을 P2가 선행 작업으로 대신 수행하지 않는다.
