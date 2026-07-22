# VibeCutter 운영 Runbook

이 문서는 발표·리허설 때 사용하는 짧은 운영 절차다. 상세한 runtime 계약은
`docs/P2_TARGET_RUNTIME_RUNBOOK.md`, XSS 계약은 `docs/P3_JUICE_SHOP_XSS_CONTRACT.md`를 따른다.

## 1. 기본 원칙

- 사용자가 승인한 target과 manifest 명령만 실행한다.
- 원본 소스/브랜치는 수정하지 않고 run별 worktree/overlay에서 패치한다.
- `FIXED`는 build, attack, positive, regression, static, scope 6개 게이트가 모두 통과한 경우에만 사용한다.
- secret·token·비밀번호는 로그, evidence, report에 기록하지 않는다.
- 72B fallback이 준비되기 전에는 235B primary 단독 운영을 허용하고, 장애 시 heuristic degrade로 표시한다.

## 2. 표준 실행 순서

1. target manifest와 source revision을 확인한다.
2. 이전 run을 승인된 reset으로 정리하고 고정 포트가 비었는지 확인한다.
3. `build → start → health/readiness`를 실행한다.
4. scan/verify를 수행해 evidence가 있는 candidate만 다음 단계로 보낸다.
5. 사용자에게 쉬운 말의 수정 계획을 보여주고 승인받는다.
6. 승인 후에만 patch를 run worktree에 적용한다.
7. `vc_resume_audit(run_id)`로 6개 게이트를 순서대로 실행한다.
8. patch export를 먼저 확인한 뒤 run overlay/worktree를 reset한다.
9. `target_id`, source commit, run ID, health, verdict, reset 결과만 기록한다.

## 3. 현재 권장 데모 target

- `26s-w1-c1-05`: IDOR verified→FIXED gold
- `26s-w1-c2-04`: IDOR false-positive reject 사례
- `juice-shop`: SQLi/XSS 엔지니어링 검증 target(발표 집계 target 아님), loopback `14020`
- `26s-w1-c3-09`: holdout/clean-room

Juice Shop health는 `GET http://127.0.0.1:14020/rest/products/search?q=apple`가 200인지 확인한다.
XSS 검색 smoke는 manifest의 `xss_search_smoke`를 사용한다. reflected 검색/track-order는 읽기 전용이며,
stored feedback은 fixture와 승인된 reset 계약 없이는 실행하지 않는다.

## 4. 실패·복구

- build/start/health 실패 시 같은 run을 무한 재시도하지 말고 원인과 명령 ID를 기록한다.
- regression 실패 시 redacted LOG evidence를 확인한다.
- patch export 실패 시 산출물 회수를 위해 worktree를 삭제하지 않는다.
- run 종료 후 `reset_run(target_id, run_id, approved=True)`로 overlay/worktree/포트를 정리한다.
- shared baseline DB를 변경한 verifier는 별도 승인된 `restore_baseline_after_write`가 필요하다.

## 5. 점검 명령 예시

```bash
python -m model.endpoints
python -m runtime.gpu_preflight --worker-id gpu-1 --expect-port-state available
python -m runtime.gpu_preflight --worker-id gpu-1 --expect-port-state listening
```

원격 GPU 서버의 모델 설치·재시작은 서버 운영자가 확인하며, 이 저장소의 runbook에는 접속 정보나 키를 기록하지 않는다.
