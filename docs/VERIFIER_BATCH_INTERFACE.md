# Verifier Batch Interface

이 문서는 P2 runtime → P3 verifier → P1 judge → P4 trajectory의 실제 연결 계약이다. 임의 URL,
raw shell command, credential/token은 어떤 단계의 입력에도 넣지 않는다.

## 1. P2 provisioning output

P1 또는 P3는 policy-allowed `target_id`로 `vc_get_verifier_provisioning(target_id)`를 호출한다.

```json
{
  "target_id": "26s-w1-c2-04",
  "base_url": "http://127.0.0.1:14017",
  "auth_mode": "none",
  "strategy": "fixture_file",
  "role_fixture_names": ["idor_owner_user_a", "idor_attacker_user_b"],
  "fixture_command_id": "prepare_idor_fixture",
  "fixture_path": ".vibecutter/fixtures/26s-w1-c2-04-idor.json",
  "fixture_available": true
}
```

전략은 다음 네 가지다.

| strategy | 역할 | 다음 호출 |
| --- | --- | --- |
| `fixture_file` | P2가 두 역할·자원을 no-secret fixture metadata로 제공 | stale/reset 뒤에는 P1 승인으로 `vc_prepare_verifier_fixture(..., approved=true)` |
| `self_signup` | P3 verifier가 local ephemeral 계정 두 개와 bearer token을 메모리에서 생성 | P3가 verifier를 직접 호출, token 저장 금지. 가입 응답에 token이 없으면 login-path 계약도 필요 |
| `fixture_contract_required` | 인증/seed 방식이 아직 확정되지 않음 | P3가 필요한 role/resource/endpoint schema를 handoff로 제공, P2가 fixture 구현 |
| `contract_required` | role fixture도 없는 일반 target | P3/P1이 verifier 가능성부터 계약 |

현재 P2 provisioning 전략이 선언된 경로는 `c2-04`(fixture-file/unauthenticated)와
`c1-05`·`c2-01`·`c2-02`(self-signup/bearer)다. `c2-01`은 P2가 source-confirmed
signup/login DTO와 workspace setup을 선언형 bearer probe로 연결했고, 실제 cross-role GET까지
실행했다. bearer probe는 기존 signup-token 4-request 흐름을 유지하면서, 필요할 때만 no-secret
JSON template·login×2·owner resource setup×2를 더해 request budget을 계산한다. token/password는
Candidate/fixture/evidence에 저장하지 않는다.

## 2. P3 suspect → verifiable Candidate bridge

P3는 `find_idor_suspects(catalog.source_root_for(target_id))`의 `IdorSuspect`를 그대로 검증하지
않는다. P2 provisioning output과 합쳐 typed `Candidate`를 만든다.

필수 필드:

- `run_id`, `vuln_class="idor"`, `cwe="CWE-639"`
- `endpoint`: `IdorSuspect.endpoint`
- `source_symbols`: suspect file/handler
- `attack_params.base_url`, `attack_params.auth_mode`
- fixture-file이면 `candidate_from_fixture(run_id, fixture_path)`를 사용해 baseline/attack path와
  marker를 채운다.
- self-signup이면 P3가 확인한 signup path, path template, token key를 `attack_params`에 채운다.

P3는 endpoint만 보고 공격하지 않는다. fixture/self-signup 정보가 없으면 Candidate를 저장하지 않고
`blocked`와 필요한 provisioning contract를 남긴다.

## 3. P1 orchestration loop

P1의 `audit_local_target(target_id)` Host prompt는 target 하나당 아래 호출 순서를 안내하고,
kill switch·retry budget·approval·judge는 tool 계층에서 강제한다. 이 prompt 자체가 상태 머신을
실행하는 함수는 아니다.

1. `vc_register_target` → `vc_build_target` → `vc_start_target`
2. `vc_get_verifier_provisioning`
3. fixture-file이고 artifact가 없거나 reset 뒤면 명시 승인으로 fixture prepare
4. P3 suspect bridge 결과의 Candidate를 evidence store에 저장
5. P3 `verify_candidate(run_id, candidate)` 실행 결과를 P1 verification tool이 evidence store에 기록
6. verified target만 locator → generate patch → explicit apply로 진행
7. P2 run-scoped overlay에서 build/start/regression, P3 replay/positive evidence
8. P1 6-gate judge와 report, P4 trajectory export

P1은 `verified`/`fixed`를 P3 출력만으로 승격하지 않으며, evidence와 deterministic judge를 반드시
거친다.

현재 `vc_map_routes`/`vc_map_roles`/`vc_index_code`는 스텁이다. 따라서 MCP 경로의
`READY → MAPPING → CANDIDATE_SCAN` 전이는 P1 mapping/scan 배선이 들어오기 전까지 막혀 있다.
P3가 제공한 `surface.candidates.candidates_for_target(run_id, provisioning, source_root)`은 이 배선의
단일 후보 진입점이다.
직접 `find_idor_suspects()`를 실행한 결과는 batch 준비에는 사용할 수 있지만, evidence store와
상태 전이를 거치기 전에는 target 완료로 기록하지 않는다.

## 4. P2/P1/P3 호출 순서 합의

| 단계 | 호출자 | 제공자 | 입력 | 출력 |
| --- | --- | --- | --- | --- |
| runtime | P1 | P2 | target ID | base URL, health, readiness |
| provisioning | P1/P3 | P2 | target ID | strategy/auth mode/fixture metadata |
| candidate bridge | P3 | P3 | suspect + provisioning | typed Candidate 또는 blocked |
| verify | P1 batch | P3 | run ID + Candidate | VerificationResult + evidence IDs |
| patch runtime | P1 | P2 | approved target ID + run ID | overlay build/start/regression |
| final verdict | P1 | P1 | validation gates | FIXED/RETRY/HUMAN_REVIEW |

P1/P2/P3는 위 기능 소유권과 별개로 배정된 target의 audit operator가 될 수 있다. operator는
공통 tool을 순서대로 실행하고 결과를 handoff하는 역할이며, 다른 사람 소유 모듈을 복제하거나
별도 verifier/planner를 만들지 않는다.

## 5. Safety boundaries

- P2 fixture preparation, reset, patch apply는 explicit approval이 필요한 mutation 단계다.
- Fixture metadata에는 role ID, path, marker만 남기고 password/token/secret은 저장하지 않는다.
- P3는 allowed `base_url`과 typed attack parameters만 사용한다.
- P4는 evidence와 validation이 연결된 trajectory만 학습/평가에 사용한다.
