# Vibe Cutter 협업 규약

이 문서는 P1~P4가 병렬로 작업한 뒤 안전하게 합치기 위한 최소 규약이다. 각자의 실제 작업 내용과 일정은 기획서 DOCX 및 최신 5일 계획을 따른다.

## 1. 판단 우선순위

1. 팀 리더/사용자의 최신 직접 지시
2. 최신 5일 작업 계획
3. 기획서 DOCX
4. 이 협업 규약

모호한 사항은 합리적으로 결정해 작업을 계속하되, 공통 인터페이스에 영향을 주는 결정은 handoff에 기록한다.

## 2. 역할 경계

| 역할 | 주 소유 영역 |
|---|---|
| P1 | MCP server, core state/policy/evidence/judge, 공통 contracts, report 기반 |
| P2 | target manifest, adapters, lifecycle/runtime, worktree/reset/test runner |
| P3 | attack surface, verifier, root-cause, patch/validation logic |
| P4 | inventory, RAG/model, dataset, baseline/metrics/evaluation |

- 자기 소유 영역은 독립적으로 구현하고 테스트한다.
- 다른 역할의 소유 영역을 수정해야 하면 최소 변경만 하고, 이유와 영향 범위를 handoff에 남긴다.
- 공통 계약(`contracts/`, manifest, 상태 이름, finding/evidence schema, policy)은 조용히 변경하지 않는다.

## 3. 고정 공통 언어

### 상태

```text
REGISTERED → BUILDING → READY → MAPPING → CANDIDATE_SCAN → VERIFYING
→ VERIFIED / REJECTED → LOCALIZING → PATCH_PROPOSED → WAITING_APPROVAL
→ PATCH_APPLIED → VALIDATING → FIXED / RETRY / HUMAN_REVIEW
```

### Finding 상태

```text
candidate | verified | rejected | fixed | human_review
```

### 판정 원칙

- LLM은 가설, 도구 선택, 원인 후보, patch 후보를 만든다.
- `verified`와 `fixed`는 evidence 및 deterministic judge가 판정한다.
- patch는 원본 branch가 아니라 run별 Git worktree에만 적용한다.
- `fixed`는 build, attack replay, 정상 기능, regression, scope 검증이 통과했을 때만 쓴다.

## 4. 공통 안전 규칙

- 등록된 `target_id`와 manifest에서 허용된 범위만 사용한다.
- 임의 URL/IP/shell 문자열을 공통 도구 입력으로 받지 않는다.
- 명령은 `command_id + typed arguments`로 제한한다.
- apply/reset/destructive test는 승인 가능한 별도 단계로 둔다.
- secret, token, 개인정보는 evidence, report, dataset 저장 전에 제거한다.
- tool call, 정책 거부, 파일 변경, validation verdict를 audit trail에 남긴다.

## 5. 상호 의존 시 지킬 것

- P1은 공통 schema와 tool input/output을 먼저 공개한다.
- P2는 target lifecycle 결과, base URL, reset 방법, role fixture, 로그 위치를 제공한다.
- P3는 candidate/evidence/root cause/patch/validation을 공통 schema로 제공한다.
- P4는 raw LLM 주장 대신 evidence와 validation이 연결된 trajectory만 학습·평가에 사용한다.
- 다른 역할의 기능이 아직 없으면 mock/stub을 써도 되지만, handoff에 실제 연동 전제와 제거 조건을 기록한다.

## 6. Handoff 규칙

작업 종료, 통합 전, 또는 다른 역할의 도움이 필요할 때 `docs/handoffs/`에 아래만 남긴다.

```markdown
# D{day} / P{role} Handoff

## 상태
완료 / 진행 중 / 차단됨

## 변경 파일
- `경로`: 변경 이유

## 제공 인터페이스
- 입력:
- 출력:
- 실패/예외:

## 검증
- 실행한 테스트와 결과:
- 아직 실제 환경에서 검증하지 못한 항목:

## 다른 역할에 필요한 사항
- P{N}: 필요한 정보 또는 조치

## 결정·가정·리스크
- ...
```

## 7. 통합 규칙

- 코드 생성만으로 완료 처리하지 않는다. 테스트, dry-run, 또는 실제 artifact가 있어야 한다.
- 충돌이 나면 더 큰 리팩터링보다 공통 계약에 맞춘 최소 수정부터 한다.
- 공통 계약 변경은 호환성 영향과 migration 방법을 handoff에 남긴다.
- 통합 전에는 최소 한 target에서 `register → 실행 → 분석 → evidence → report`가 연결되는지 확인한다.
- 데모 전에는 reset 후 같은 target에서 결과가 재현되는지 확인한다.

## 8. 작업자의 기본 행동

각 작업자는 DOCX, 최신 계획, 이 협업 규약, 자신의 역할을 받은 뒤 다음 원칙으로 자율 작업한다.

- 먼저 기존 변경과 공통 계약을 확인한다.
- 본인 소유 영역에서 막히지 않는 작업부터 진행한다.
- 다른 역할을 기다려야 하면 mock으로 연결점을 만들고, 필요한 계약만 handoff에 명시한다.
- 공통 영역을 바꾸기 전에는 영향 범위를 기록한다.
- 끝날 때는 짧은 handoff를 남긴다.
