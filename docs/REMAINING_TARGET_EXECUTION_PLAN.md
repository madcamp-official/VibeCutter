# Remaining Target Execution Plan

## 목적과 범위

이 문서는 Notion 체크리스트와 `datasets/inventory.yaml`의 전체 후보 중, **현재 P2 manifest가 있고
로컬 runtime으로 관리되는 W1 target**의 남은 작업을 P1·P2·P3에게 배분한다.

- P2 executable manifest: 22개
- 이미 P3 evidence/정찰 결과가 있는 reference target: 4개
  - `26s-w1-c1-05`: JWT IDOR live 검증 및 수동 closed-loop
  - `26s-w1-c2-04`: read/write IDOR live verified
  - `26s-w1-c2-05`: IDOR 음성(clean)
  - `26s-w1-c3-08`: 확인한 표면에서 방어됨(OAuth provisioning 제한)
- 이 문서의 active queue: **18개**

reference target은 다시 발견 작업에 넣지 않는다. `c1-05`는 자동 closed-loop 통합용, `c2-04`는
verifier/fixture 회귀용, `c2-05`·`c3-08`은 음성/precision 기준으로 유지한다.

`inventory.yaml`에만 있고 P2 manifest·policy·runtime이 아직 없는 19개(W2, W1 `c3-07`,
frontend-only, 기타 프로젝트)는 **backlog**다. 이 iteration에서 Dockerize 또는 공격 대상으로
조용히 승격하지 않는다. active queue의 결과가 나온 뒤 별도 승인으로 다룬다.

## 배분 원칙

repository 숫자만 나누는 것이 아니라 각 역할의 실제 책임을 지킨다.

- **P1**은 후보를 MCP 상태·policy·judge로 연결하는 queue lead다. P1이 보안 판정을 단독으로 내리지 않는다.
- **P2**는 runtime/fixture blocker를 해소하는 queue lead다. 자격증명·seed를 추측하거나 생성하지 않는다.
- **P3**은 직접 attack-surface → verifier → evidence를 수행하는 queue lead다. P3의 직접 검증량을
  8개로 두어 P1/P2보다 많게 배정한다.
- 모든 target의 `verified`/`fixed` 판정은 P1 evidence/judge가 하며, clean은 evidence 또는
  명시된 검토 범위가 있어야만 기록한다.

## Active Queue (5 / 5 / 8)

### P1 — pipeline/triage lead (5개)

모두 현재 P2 readiness가 `true`인 대상이다. P1은 P3의 `find_idor_suspects(source_root)` 결과와
P4 scan 후보를 typed `Candidate`로 연결하고, policy-allowed run·report·judge 입력을 준비한다.

| 우선순위 | target_id | stack | P1 완료 조건 |
| --- | --- | --- | --- |
| 1 | `26s-w1-c3-09` | Spring | holdout clean-room 정책/후보/보고 경로 준비 |
| 1 | `26s-w1-c3-03` | Node | surface shortlist → Candidate/run 생성 |
| 1 | `26s-w1-c3-04` | Node | surface shortlist → Candidate/run 생성 |
| 2 | `26s-w1-c3-05` | Node | surface shortlist → Candidate/run 생성 |
| 2 | `26s-w1-c2-08` | Django/generic | candidate 생성 또는 class-based Django 제한을 명시한 handoff |

P1 공통 산출물은 target별 `run_id`, 후보 목록, policy 통과 결과, evidence store 연결점이다.
`audit_local_target`가 구현되기 전에는 이 순서를 개별 MCP tool 호출로 명시적으로 기록한다.

### P2 — runtime/fixture unblock lead (5개)

아래 대상은 Docker/manifest 자체가 아니라 role-fixture 환경변수 미주입으로 readiness가 `false`다.
P2는 fixed build/start/reset 계약을 유지하면서, P3가 제공한 인증·seed 계약이 있을 때만 fixture를
만든다. 계약이 없으면 `blocked` 사유를 남기고 다음 target으로 이동한다.

| 우선순위 | target_id | stack | 현재 blocker | P2 완료 조건 |
| --- | --- | --- | --- | --- |
| 1 | `26s-w1-c1-03` | Spring | role fixture | P3 fixture 계약 또는 명시적 blocked 기록 |
| 1 | `26s-w1-c1-07` | Node/Prisma | role fixture | seed/login fixture 또는 blocked 기록 |
| 1 | `26s-w1-c2-01` | FastAPI | role fixture | two-role fixture 또는 blocked 기록 |
| 1 | `26s-w1-c2-02` | Node/Prisma | role fixture | seed/login fixture 또는 blocked 기록 |
| 2 | `26s-w1-c1-06` | Node, XSS focus | role fixture | XSS-only runtime 필요성 확인 및 readiness/blocker 기록 |

P2가 target별로 반환할 정보는 `ready` 여부, base URL, reset 방법, fixture field schema,
로그 위치, destructive lifecycle 실행 여부다. token/password/실제 secret은 저장하지 않는다.

### P3 — direct security verification lead (8개)

모두 P2 readiness가 `true`다. P3는 새 IDOR prefilter를 먼저 돌리고, 우선순위 높은 endpoint만
typed candidate로 만든 뒤 verifier를 실행한다. 취약점이 없으면 "검토한 표면에서 clean"과
근거를 남긴다. 이 queue가 P3의 직접 실행 비중을 높이는 배정이다.

| 배치 | target_id | stack | 우선 작업 |
| --- | --- | --- | --- |
| A | `26s-w1-c2-03` | FastAPI | prefilter → 무인증/간단 auth surface 확인 |
| A | `26s-w1-c3-06` | FastAPI | prefilter → candidate/verify |
| A | `26s-w1-c1-02` | Node | route/controller ownership surface 확인 |
| A | `26s-w1-c1-04` | Node | route/controller ownership surface 확인 |
| B | `26s-w1-c1-01` | generic/mixed | manifest adapter 기준으로 surface 확인 |
| B | `26s-w1-c2-06` | Django/generic | decorator route 지원 범위 내 IDOR 확인 |
| B | `26s-w1-c2-07` | Node/Next | API route ownership surface 확인 |
| B | `26s-w1-c3-02` | Django/generic | decorator route 지원 범위 내 IDOR 확인 |

P3 target 완료 조건은 다음 중 하나다.

1. `candidate → verified/rejected`와 redacted evidence
2. 실현 가능한 patch target이면 root cause와 `Patch(approval=PENDING)`
3. 인증/seed가 없으면 필요한 fixture 계약과 재현 불가 사유
4. candidate가 없으면 검토 범위·prefilter 결과·clean 근거

P3가 patch를 생성해도 원본/정식 source clone에 적용하지 않는다. P1 승인 뒤 P2 run worktree에만
적용한다.

## 협업 흐름

```text
P1: target/run/policy 준비
        │
        ├── P3 prefilter + verifier ── evidence/candidate ──┐
        │                                                    │
        └── P2 readiness/fixture/base URL ──────────────────┤
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
P1: six-gate FIXED / RETRY / HUMAN_REVIEW
        │
        ▼
P4: evidence+validation-linked trajectory/report only
```

## 공통 handoff 규칙

target별 작업을 끝낼 때 아래 필드를 기존 `docs/handoffs/D3-P{role}.md`의 후속 갱신 또는
다음 실제 Day handoff에 남긴다.

- `target_id`, run ID, source commit
- prefilter 후보 수와 선택 endpoint
- runtime readiness/base URL/fixture schema(이름만, secret 값 제외)
- candidate/evidence/validation ID 또는 clean·blocked 근거
- patch가 있으면 worktree ID와 reset 여부
- 다른 역할의 다음 입력 한 가지

## 지금 시작하지 않는 backlog

W1 `c3-07`, W2 targets, frontend-only targets, `legendary-super-ultra-red-dragon`,
`26s-w3-c2-01`, `Into-the-Deep`, `spk`는 active queue 결과를 본 뒤 별도로 우선순위를 정한다.
이들은 현재 P2 executable manifest와 policy/runtime contract가 없거나, backend/IDOR 검증 적합성이
확정되지 않았다.
