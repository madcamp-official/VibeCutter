# Remaining Target Execution Plan

## 실행 범위

Notion 체크는 우선순위 신호로 사용하되, **P2가 manifest·loopback runtime·readiness로 실행 가능하다고
판정한 W1 target은 미체크여도 진행 후보에 포함한다.** 이 문서의 active queue는 P2 executable
manifest 22개에서 이미 P3 결과가 있는 4개 reference target을 뺀 18개다.

- reference: `c1-05`(수동 closed-loop), `c2-04`(read/write IDOR), `c2-05`(clean),
  `c3-08`(검토 표면 방어됨)
- active candidate queue: 18개
- W2·기타 inventory는 아직 P2 manifest/runtime contract가 없으므로 backlog다. P2가 viability를
  확인하면 다음 batch에 별도 추가한다.

## 배분 (P1 5 / P2 5 / P3 8)

P3가 직접 security verification을 8개 수행해 P1/P2보다 많은 실행량을 맡는다. 이는 repository의
독점 소유가 아니라 batch lead 배정이며, `verified`/`fixed`는 언제나 P1 evidence/judge가 판정한다.

### P1 — orchestration/candidate-store lead (5개)

| target_id | stack | P1 완료 조건 |
| --- | --- | --- |
| `26s-w1-c3-09` | Spring | holdout clean-room policy/run/report 경로 |
| `26s-w1-c3-03` | Node | suspect/candidate/evidence store 연결 |
| `26s-w1-c3-04` | Node | suspect/candidate/evidence store 연결 |
| `26s-w1-c3-05` | Node | suspect/candidate/evidence store 연결 |
| `26s-w1-c2-08` | Django/generic | candidate 생성 또는 class-view 제한 기록 |

### P2 — provisioning/runtime unblock lead (5개)

| target_id | 현재 상태 | P2 완료 조건 |
| --- | --- | --- |
| `26s-w1-c1-03` | role fixture 필요 | fixture contract 또는 blocked 근거 |
| `26s-w1-c1-07` | role fixture 필요 | seed/login fixture 또는 blocked 근거 |
| `26s-w1-c2-01` | role fixture 필요 | two-role fixture 또는 blocked 근거 |
| `26s-w1-c2-02` | role fixture 필요 | seed/login fixture 또는 blocked 근거 |
| `26s-w1-c1-06` | XSS focus, role fixture 필요 | runtime 필요성/fixture 또는 blocked 근거 |

P2는 `vc_get_verifier_provisioning(target_id)`로 base URL, auth mode, fixture strategy를 먼저 제공한다.
fixture-file 생성은 `vc_prepare_verifier_fixture(target_id, approved=True)`만 사용하며, P3 계약이 없는
인증/seed를 추측하지 않는다.

### P3 — direct security verification lead (8개)

| batch | target_id | stack | 우선 작업 |
| --- | --- | --- |
| A | `26s-w1-c2-03` | FastAPI | prefilter → candidate → verify |
| A | `26s-w1-c3-06` | FastAPI | prefilter → candidate → verify |
| A | `26s-w1-c1-02` | Node | route/controller ownership surface |
| A | `26s-w1-c1-04` | Node | route/controller ownership surface |
| B | `26s-w1-c1-01` | generic/mixed | manifest adapter 기준 surface |
| B | `26s-w1-c2-06` | Django/generic | decorator route 지원 범위 IDOR |
| B | `26s-w1-c2-07` | Node/Next | API route ownership surface |
| B | `26s-w1-c3-02` | Django/generic | decorator route 지원 범위 IDOR |

P3 target 완료 조건은 `verified/rejected` evidence, patch 후보, clean 근거, 또는 provisioning blocker 중
하나다. 원본 source에는 patch를 적용하지 않는다.

## 자동 batch 연결 계약

```text
P2: register/build/start → vc_get_verifier_provisioning
       │                         │
       │                         ├─ fixture_file: 승인된 prepare fixture
       │                         ├─ self_signup: P3 verifier가 ephemeral 계정 생성
       │                         └─ fixture required: P3 계약을 받아 P2가 준비
       ▼
P3: find_idor_suspects(source_root) → verifiable Candidate → verify_candidate
       ▼
P1: Candidate/evidence 저장, 상태 전이, patch 승인과 judge
       ▼
P2: patched worktree overlay build/start + regression
       ▼
P3: replay attack + positive functionality evidence
       ▼
P1: FIXED / RETRY / HUMAN_REVIEW
       ▼
P4: evidence+validation-linked trajectory/report only
```

상세 입력·출력·호출 순서는 [Verifier Batch Interface](VERIFIER_BATCH_INTERFACE.md)를 단일 기준으로
사용한다.

## Handoff 최소 필드

- `target_id`, run ID, source commit
- provisioning strategy/auth mode/base URL/fixture artifact 상태(값·secret 제외)
- prefilter 후보 수와 선택 endpoint
- Candidate/evidence/validation ID 또는 clean·blocked 근거
- patch가 있으면 worktree ID와 reset 여부
- 다음 역할이 수행할 한 가지 입력
