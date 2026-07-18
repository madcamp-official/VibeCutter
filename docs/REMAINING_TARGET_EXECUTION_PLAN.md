# Remaining Target Execution Plan

## Scope gate

**Notion 체크리스트에서 체크된 `target_id`만 실행 대상이다.** `datasets/inventory.yaml`, P2 manifest,
readiness, P3 prefilter는 실행 가능성·우선순위를 알려주는 보조 정보일 뿐, 실행 범위를 결정하지 않는다.

현재 repository에는 Notion 체크 상태가 동기화되어 있지 않다. 따라서 P2 manifest 22개 중 P3가 이미
결과를 남긴 4개를 제외한 18개도 실행 대상이 아니라 **후보 pool**이다. 체크된 목록이 이 문서의 slot에
반영되기 전에는 build, scan, attack, fixture 생성 대상으로 진행하지 않는다.

이미 P3 evidence/정찰 결과가 있는 아래 target은 reference로 유지하며 재발견 queue에 넣지 않는다.

- `26s-w1-c1-05`: JWT IDOR live 검증 및 수동 closed-loop
- `26s-w1-c2-04`: read/write IDOR live verified, verifier/fixture 회귀 기준
- `26s-w1-c2-05`: IDOR 음성(clean), precision 기준
- `26s-w1-c3-08`: 확인한 표면에서 방어됨(OAuth provisioning 제한)

Notion에서 체크되지 않은 W1/W2/기타 repository는 manifest가 있더라도 **excluded**다. 별도 사용자
지시나 체크리스트 갱신 없이는 Dockerize·scan·attack 대상으로 승격하지 않는다.

## 역할별 capacity 계획 (P1 5 / P2 5 / P3 8)

아래는 체크된 target을 받을 때의 처리 용량이다. P3의 직접 보안 검증량을 P1·P2보다 크게 배정한다.
각 slot의 실제 `target_id`는 Notion 체크 목록을 받은 뒤에만 채운다.

| 역할 | slot 수 | 배정 기준 | 산출물 |
| --- | ---: | --- | --- |
| P1 | 5 | 체크된 target 중 readiness가 확보된 항목 | policy-allowed run, typed Candidate 연결, judge/report 입력 |
| P2 | 5 | 체크된 target 중 fixture·runtime blocker가 있는 항목 | readiness/base URL/reset/fixture schema 또는 blocked 근거 |
| P3 | 8 | 체크된 target 중 readiness가 확보된 항목 | prefilter → candidate → verifier/evidence 또는 clean/blocked 근거 |

### P1 slots

| slot | Notion 체크 target_id | 완료 조건 |
| --- | --- | --- |
| P1-1 ~ P1-5 | 체크 목록 반영 전 | surface shortlist → Candidate/run → policy/report 연결 |

P1은 P3의 `find_idor_suspects(source_root)` 결과와 P4 scan 후보를 typed `Candidate`로 연결한다.
`audit_local_target`가 구현되기 전에는 개별 MCP tool 호출 순서와 run ID를 handoff에 기록한다.

### P2 slots

| slot | Notion 체크 target_id | 완료 조건 |
| --- | --- | --- |
| P2-1 ~ P2-5 | 체크 목록 반영 전 | readiness/base URL/reset/fixture schema 또는 blocked 기록 |

P2는 fixed build/start/reset 계약을 유지한다. P3가 제공한 인증·seed 계약이 있을 때만 fixture를 만들며,
자격증명·seed·token을 추측하거나 handoff/evidence에 저장하지 않는다.

### P3 slots

| slot | Notion 체크 target_id | 완료 조건 |
| --- | --- | --- |
| P3-1 ~ P3-8 | 체크 목록 반영 전 | prefilter → candidate → verifier/evidence 또는 clean/blocked 근거 |

P3는 우선순위 높은 endpoint만 typed candidate로 만들고 verifier를 실행한다. target별 결과는 다음 중
하나여야 한다.

1. `candidate → verified/rejected`와 redacted evidence
2. 실현 가능한 patch target이면 root cause와 `Patch(approval=PENDING)`
3. 인증/seed가 없으면 필요한 fixture 계약과 재현 불가 사유
4. candidate가 없으면 검토 범위·prefilter 결과·clean 근거

## 협업 흐름

```text
Notion checked target_id
        │
        ├── P1: target/run/policy/candidate 연결
        ├── P2: readiness/fixture/base URL 제공
        └── P3: prefilter/verifier/evidence
                                      │
                                      ▼
P1: deterministic judge / patch approval
        │
        ▼
P2: patched worktree overlay build/start + regression
        │
        ▼
P3: replay attack + positive-function evidence
        │
        ▼
P1: FIXED / RETRY / HUMAN_REVIEW
        │
        ▼
P4: evidence+validation-linked trajectory/report only
```

## Handoff contract

각 target 작업 뒤에는 다음만 기록한다.

- `target_id`, run ID, source commit
- Notion 체크 근거와 prefilter 후보 수/선택 endpoint
- runtime readiness/base URL/fixture schema(이름만, secret 값 제외)
- candidate/evidence/validation ID 또는 clean·blocked 근거
- patch가 있으면 worktree ID와 reset 여부
- 다음 역할에 필요한 한 가지 입력

## 다음 동기화

Notion의 체크된 `target_id` 목록을 이 문서의 P1/P2/P3 slot에 채운 뒤에만 실제 작업을 시작한다.
그 뒤 manifest/readiness와 P3 prefilter 결과를 사용해 P1 5, P2 5, P3 8의 순서로 배정한다.
