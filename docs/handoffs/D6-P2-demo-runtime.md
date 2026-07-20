# D6 / P2 Handoff — demo runtime stabilization

## 상태

진행 중. 새 3일 계획에 맞춰 P2의 초점을 추가 Dockerize가 아닌 데모 타겟의
재현 가능한 기동·reset·복구로 전환한다. P3의 공격/검증 판정과 P1의 큰 API
orchestration은 변경하지 않는다.

## 데모 후보(초안)

| target | 역할 | 현재 근거 | 승격 조건 |
|---|---|---|---|
| `26s-w1-c1-05` | 주력 IDOR closed-loop | 실제 `verified → fixed`, Spring/JWT, fresh reset 실측 | P3가 데모 run ID 확정 |
| `26s-w1-c2-04` | 동적 검증 reject/IDOR evidence | live IDOR read/write evidence, fixture-file | patch demo가 아닌 검증·정확도 사례로 사용 |
| `26s-w1-c3-09` | clean-room/holdout | fresh build/start/health/regression/reset 실측 | P3/P4가 holdout 용도 승인 |
| `26s-w1-c1-06`, `26s-w1-c2-01`, `26s-w1-c2-02` | 추가 IDOR 후보 | self-signup provisioning 계약 | P3가 실제 evidence를 확보한 target만 승격 |

## P2 운영 절차

1. 데모 시작 전 `sweep_stale_run_overlays` → target build/start → health 확인.
2. P3 verify/patch run 동안 target별 고정 port를 공유하므로 worker는 순차 실행.
3. patched overlay를 만든 run 종료 시 `reset_run`; write fixture가 DB 상태를 바꿨으면
   승인된 baseline restore와 fixture 재준비를 별도로 수행.
4. 각 회차에 health, run ID, reset 결과, 잔여 container/worktree/port를 기록하고
   실패하면 후보를 fallback target으로 교체.

## 검증

- P2 runtime 회귀: `py -3.13 -m pytest tests/test_target_service.py tests/test_run_overlay.py tests/test_c1_05_runtime_contract.py tests/test_verifier_provisioning.py -q`
- 결과: **24 passed, 3 subtests passed** (DeprecationWarning 218건은 기존 `utcnow()` 사용).
- 로컬 clean-room lifecycle 실측(각 target별 승인 reset → build → start/health → readiness → 승인 reset):
  - `c1-05`: **PASS**. 첫 시도는 필수 secret env 미설정으로 compose가 거부했으며, 저장하지 않은
    프로세스 범위 일회성 DB/root/JWT 값을 주입한 재시도에서 build `READY`, health `True`, readiness
    `ready=True`, 마지막 reset `True`를 확인했다.
  - `c2-04`: **PASS**. build `READY`, health `True`, readiness `ready=True`, 마지막 reset `True`.
  - `c3-09`: **PASS**. build `READY`, health `True`, readiness `ready=True`, 마지막 reset `True`.
- 세 타겟 실측 직후 Docker container와 `14006/14007`, `14017/14018`, `14036/14037` listening
  port가 남지 않음을 확인했다.
- 세 GPU 20/20 runtime preflight와 c1-05/c2-04/c3-09 lifecycle 실측은 D5-P2에 기록된
  결과를 기준선으로 유지한다. 이번 세션에서는 원격 GPU를 재기동하지 않았다.

## 다른 역할에 필요한 사항

- P1: 큰 API를 연결한 원커맨드의 정확한 lifecycle과 write 후 baseline restore 호출을 확정해 달라.
- P3: 우선 closed-loop target 1~2개와 run ID/fixture 요구사항을 알려 달라. P2가 해당 target을
  데모 우선순위로 고정한다.
- P4: 발표 표에 필요한 runtime 필드(health/reset/replay 횟수 등)를 알려 달라.

## 확정된 통합 계약(2026-07-20)

- P1 원커맨드 순서: `register → build → start/health → scan → verify → (write 시 승인된 baseline restore) → patch overlay → 6-gate validation → reset_run → report export/teardown`.
- `restore_baseline_after_write(target_id, approved=True)`는 write verifier가 shared baseline을 변경한 직후 호출한다. `reset_run`만으로 shared DB fixture를 원복한다고 가정하지 않는다.
- `target_id`는 manifest ID이고, `run_id`는 orchestrator가 run 시작 시 발급하는 값이다. 최종 report/evidence/metric 조인은 `run_id`를 키로 한다.
- P4 runtime metadata JSONL 필드: `run_id`, `target_id`, `source_commit`, `base_url`, `health`, `readiness`, `gpu_worker`, `llm_endpoint_status`, `reset_ok`, `residual_containers`, `residual_worktrees`, `residual_ports`. secret/token/password는 제외한다.
- `health/readiness=false`, LLM endpoint fallback, 또는 residual resource가 있는 run은 fixed/모델 비교 통계에서 별도 플래그하거나 제외한다.

## 결정·가정·리스크

- 20개 전체를 발표 데모에 동시에 올리지 않는다. 고정 host port 때문에 3~5개 후보를 순차 운용한다.
- P2는 취약점의 `verified/fixed` 판정을 하지 않는다. P3 evidence와 P1 judge 결과만 데모 라벨로 사용한다.
- 큰 API/7B fallback은 P1/P4 소유이며 P2는 모델 서버나 Docker를 VM으로 이전하지 않는다.
