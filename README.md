# Vibe Cutter

로컬 MCP 기반 자율 웹 보안 분석·재현·수정·재검증 시스템.

승인된 로컬/격리 웹 애플리케이션을 대상으로 취약점을 실제로 증명하고(재현 가능한 evidence), 근본 원인 패치를 생성한 뒤, 동일 공격 재실행과 정상 기능 회귀 테스트로 수정 여부를 자동 판정하는 MCP 기반 로컬 보안 에이전트입니다.

> **외부 대상 공격 금지.** 등록된 target manifest에 없는 URL/IP/명령은 정책 계층에서 전부 거부됩니다. 자세한 안전 원칙은 [기획서](./Vibe_Cutter_MCP_심화_기획_및_구현_보고서.docx) 10장, [cowork_rule.md](./cowork_rule.md) 4절 참고.

## 문서

| 문서 | 내용 |
| --- | --- |
| [`Vibe_Cutter_MCP_심화_기획_및_구현_보고서.docx`](./Vibe_Cutter_MCP_심화_기획_및_구현_보고서.docx) | 전체 기획서 — 아키텍처, MCP 설계, 공격/검증/수정 엔진, 모델 전략, 평가 설계 |
| [`cowork_rule.md`](./cowork_rule.md) | 4인 협업 규약 — 역할 경계, 공통 계약, handoff 규칙 |
| [`plan.md`](./plan.md) | P1(Platform/MCP) 5일 실행 계획, 체크리스트 |
| `docs/handoffs/` | 일자별 역할별 handoff 기록 (`D{day}-P{role}.md`) |

## 역할 분담

| 역할 | 담당 | 소유 영역 |
| --- | --- | --- |
| P1 | 이지민 | MCP server, core state/policy/evidence/judge, 공통 contracts, report 기반 |
| P2 | 안종화 | target manifest, adapters, lifecycle/runtime, worktree/reset/test runner |
| P3 | 박준서 | attack surface, verifier, root-cause, patch/validation logic |
| P4 | 유나연 | inventory, RAG/model, dataset, baseline/metrics/evaluation |

## 저장소 구조

```
mcp_server/   MCP stdio 서버, resources/tools
core/         state machine, policy engine, evidence store, judge, planner
contracts/    Target/Run/Observation/Candidate/Finding/Patch/Validation/Trajectory 공통 스키마
policies/     scope.yaml, commands.yaml, vulnerability_profiles/ (target allowlist, command 정책)
docs/handoffs/  역할별 일일 handoff 기록
```

`adapters/`, `scanners/`, `repair/`, `model/`, `eval/`은 각 역할(P2~P4)이 자신의 작업 범위에서 추가합니다.

## 설정

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```


## MCP 서버 실행

```bash
source .venv/bin/activate
python mcp_server/server.py
```

stdio 전송 방식으로 동작하며, MCP Host(Claude Code 등)가 subprocess로 실행하는 것을 전제로 합니다. 외부 포트를 열지 않습니다.

## 공통 계약 변경 시 주의

`contracts/`, target manifest, 상태 이름, finding/evidence schema, policy는 프로젝트 전체가 공유하는 계약입니다. 변경이 필요하면 `docs/handoffs/`에 영향 범위와 이유를 남기고, 조용히 바꾸지 않습니다 (cowork_rule.md 2절·6절).
