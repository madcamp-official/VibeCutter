# Claude 검토 요청 — 사용자 시나리오와 현재 구현의 정합성

> 2026-07-21 코드 기준 검토 요청. 이 문서는 설계를 다시 만들자는 제안이 아니라, **현재 구현이 근본적으로 잘못됐는지와 발표 전 반드시 연결해야 하는 지점이 무엇인지** 다른 에이전트가 독립적으로 검토할 수 있게 사실·판단·질문을 분리한 것이다.

## 1. 우리가 지키려는 사용자 시나리오

```text
터미널에서 Agent를 호출
→ “보안 검사해줘”
→ MCP Vibe Cutter가 localhost에서 뜬 승인된 서비스를 검사
→ 취약점을 실제 evidence로 검증
→ 안전한 worktree에서 patch를 제안·적용
→ 동일 공격과 정상 기능을 재검증
→ 결과 report를 반환
```

내부 원칙은 다음과 같다.

- 대상 서비스는 loopback(`localhost`/`127.0.0.1`/`::1`)만 허용한다.
- LLM은 후보 우선순위·원인·patch를 제안할 수 있지만, 취약점과 `FIXED`는 evidence + deterministic judge만 확정한다.
- patch는 run별 Git worktree에만 적용한다.
- build, attack replay, positive functionality, regression, static, scope의 6 gate가 모두 통과해야 `FIXED`다.

## 2. 먼저 내린 잠정 결론

**핵심 구조가 크게 잘못된 것은 아니다.** 특히 다음은 사용자 시나리오와 일치하며 코드로 존재한다.

| 핵심 | 코드상 상태 |
|---|---|
| loopback-only target URL 검증 | 구현됨 (`runtime/manifest.py`) |
| target/host/command allowlist | 구현됨 (`core/policy_engine.py`) |
| Docker target build/start/health/reset, run overlay/worktree | 구현됨 (P2 runtime) |
| IDOR/XSS/Injection verifier와 evidence 기반 finding 승격 | 구현됨 (`mcp_server/tools_analysis.py`, `core/evidence_store.py`) |
| patch의 worktree 격리·scope 검증 | 구현됨 (`mcp_server/tools_repair.py`, `core/judge.py`) |
| 6-gate judge와 HTML report | 구현됨 (`core/judge.py`, `vc_generate_report`) |
| 실제 증거 | c1-05 verified→FIXED gold, c2-04 rejected true-negative, P2 clean-room runtime 기록 |

그러나 현재는 **“안전한 내부 pipeline 부품”은 갖췄지만, 이를 사용자에게 보이는 단일 MCP 경험으로 일관되게 조립하는 작업이 남은 상태**다. 아래 항목은 설계 붕괴가 아니라, 데모/제품 경계에서 반드시 명확히 해야 할 integration gap이다.

## 3. 코드로 확인한 gap

### A. “한 문장으로 자동 실행”은 아직 실제 MCP Tool이 아니다

- `audit_local_target`은 실행기가 아니라 Host에게 Tool 호출 순서를 알려 주는 **MCP Prompt**다. `mcp_server/prompts.py`
- 실제 자동 루프 `run_target_audit(target_id)`는 `mcp_server/driver.py`에 존재하지만 `@mcp.tool()`로 등록되지 않았고, CLI entry point도 없다.
- 실제 등록된 MCP Tool 목록에는 `vc_run_target_audit`이 없다.

따라서 현재 사실은 다음이다.

```text
Agent가 Prompt를 읽고 여러 MCP Tool을 순서대로 호출하면 E2E를 수행할 수 있음
≠ 사용자가 한 문장만 말하면 단일 MCP Tool이 전 과정을 수행함
```

### B. patch 승인 규칙이 interactive 경로와 batch 경로에서 다르다

- interactive Prompt는 patch diff를 보여 주고 `vc_apply_patch(..., confirmed=True)`의 명시 승인을 요구한다.
- 반면 `run_target_audit()`는 내부에서 `confirmed=True`를 직접 넘긴다.

즉 현재 batch는 “batch 실행 자체가 사전 승인”이라는 별도 정책이다. 이것을 인정하고 분리하지 않으면, “명시 승인 없이 patch를 적용하지 않는다”는 설명과 충돌한다.

### C. LLM rerank는 연결됐지만 RAG 코드 문맥은 연결되지 않았다

- `mcp_server/tools_analysis.py`는 `aggregate(..., rerank_fn=...)`에 endpoint tier 기반 LLM rerank 훅을 전달한다.
- 하지만 `scanners/rag_enrich.py:enrich()`는 production scan 경로에서 호출되지 않는다.
- rerank prompt는 CWE, confidence, source location, signal만 보내며 실제 코드 snippet은 보내지 않는다 (`model/serving.py:_candidate_brief`).
- RAG 단위 테스트는 현재 6개 중 3개가 실패한다 (`scanners/test_rag_enrich.py`).

따라서 “RAG 코드 문맥 + 대형 LLM rerank”는 현재 완료 기능이 아니라 구현·배선·회귀 수정이 필요한 다음 단계다.

### D. LLM patch synthesis는 main에 실제 연결되지 않았다

- `repair/patcher.py`는 `synthesize_fn` hook을 받을 수 있다.
- 하지만 `vc_generate_patch()`가 `generate_patch()`를 부를 때 `synthesize_fn`을 전달하지 않는다.
- 현재 main에는 `repair/llm_synth.py`도 없다.

현재 자동 patch는 주로 Spring Java IDOR 소유권 guard template이다. SQLi/XSS/비Java target에 대해 “LLM이 patch를 생성해 FIXED까지 갔다”고 말할 수는 없다.

### E. 신규 사용자의 자기 프로젝트 등록은 아직 제공하지 않는다

`vc_register_target()`은 새 target을 만드는 Tool이 아니다. checked-in manifest와 정확히 같은 입력인지 확인한 뒤, 이미 scope/source-lock/commands에 등록된 target만 활성화한다.

현재 시스템은 정확히 다음 제품이다.

> 팀이 승인하고 localhost에서 기동한 교육용/캠프 target을 감사하는 안전한 MCP 데모.

아직 다음 제품은 아니다.

> 사용자가 임의의 자기 로컬 프로젝트를 MCP에 등록하고 즉시 감사하는 범용 도구.

이 차이는 loopback 보안 원칙을 버려야 한다는 뜻이 아니다. 제품화 시에는 팀 Git allowlist 대신 사용자의 local approval/scope 파일과 명시적 등록 확인으로 승인 주체를 옮기면 된다.

### F. report/cleanup/metadata의 마지막 연결

- `vc_generate_report` HTML은 구현되어 있다.
- `vc_export_sarif`는 아직 `NotImplementedError`다.
- `run_target_audit()`는 HTML report export를 마지막에 호출하지 않는다.
- write verifier 이후 shared baseline 복구(`restore_baseline_after_write`)도 driver에서 일반적으로 연결되지 않았다.
- LLM primary/fallback/heuristic 사용 여부는 run metadata에 기록되지 않는다. 따라서 향후 RAG+LLM 평가 표본이 섞일 수 있다.

## 4. 현재 구현을 정직하게 설명하는 E2E

```text
MCP stdio server
→ 허용된 target_id/manifest/scope/source-lock 확인
→ P2 lifecycle: build → start → health
→ candidate 생성: IDOR surface bridge + Semgrep + OSV
→ 선택적 LLM rerank (endpoint 불가 시 heuristic)
→ candidate 하나당 worker Run 생성
→ deterministic verifier가 실제 HTTP 재현과 evidence를 남김
→ verified만 root-cause localize
→ 현재는 template 중심 patch proposal
→ 승인된 apply는 target Git worktree에만 적용
→ patched runtime에서 6 gate 실행
→ FIXED / RETRY / HUMAN_REVIEW
→ HTML report 가능, run overlay reset 가능
```

이 흐름의 강점은 LLM이 틀려도 `verified`/`fixed` 판정이 evidence와 judge를 통과하지 못한다는 점이다. 약점은 사용자 경험을 끝까지 자동화하는 MCP 진입점과, RAG/LLM patch 일반화가 아직 조립되지 않았다는 점이다.

## 5. 데모 전 최소 수정 제안

아래 순서가 사용자 시나리오를 가장 적은 변경으로 충족한다.

1. **실제 MCP entry tool/CLI 추가**: `vc_audit_target(target_id)` 또는 동등 CLI를 추가한다. 내부에서 driver를 호출하되, 기본 경로는 patch proposal에서 멈춘다.
2. **승인 흐름 단일화**: Agent가 diff를 보여 주고 사용자가 승인한 후에만 apply→6 gate→report를 재개한다. 자동 batch는 별도 명시 모드로 격리하고 audit log에 남긴다.
3. **driver 마지막 단계 보완**: report 생성, write baseline restore, teardown/reset을 target 계약에 따라 연결한다.
4. **LLM telemetry**: run별 `llm_mode`(primary/fallback/heuristic), endpoint health, latency를 secret 없이 기록한다.
5. **RAG/LLM patch는 별도 milestone**: RAG test 복구→production wiring→snippet redaction/context 제한→LLM synthesizer 주입 순으로 진행한다.

위 1~4는 “사용자 시나리오가 실제로 동작한다”는 데모 완성에 필수다. 5는 “대형 API가 코드 문맥을 이해해 일반적인 patch를 만든다”는 확장 서사에 필요하다.

## 6. 다른 Claude에게 확인받고 싶은 질문

아래 문항을 각각 **(a) 내 판단이 맞음 / (b) 데모상 허용 가능한 한계 / (c) 발표 전 반드시 수정 / (d) 제품화 후 과제**로 분류해 달라.

1. `run_target_audit()`를 MCP Tool/CLI로 노출하지 않은 현재 상태에서 “한 문장으로 E2E”라고 발표해도 되는가?
2. interactive Prompt의 사용자 승인과 batch driver의 `confirmed=True` 자동 apply를 어떤 정책으로 통일해야 하는가?
3. RAG module이 production에 미연결이고 관련 테스트가 깨진 상태에서 RAG+LLM 효과를 발표 metric으로 주장하면 안 되는가?
4. LLM patch synthesizer가 main에 없을 때, 데모 범위를 “Spring IDOR template closed-loop”으로 한정하는 것이 정직한가?
5. 현재 checked-in allowlist 방식은 “승인된 localhost target 데모”라는 목적에는 충분한가? 사용자 own-project onboarding은 발표 후 설계로 분리해도 되는가?
6. c1-05 gold / c2-04 true-negative / c3-09 clean-room에 더해 Juice Shop SQLi를 지금 등록·완주하는 것이 일반화 증명에 가장 효율적인가?

## 7. 검토 당시 테스트 근거

- Python 3.13 환경에서 driver, prompts, scan wiring, target runtime, model endpoint 관련 선택 테스트: **63 passed**.
- `scanners/test_rag_enrich.py`: **3 failed, 3 passed**.
- 전체 suite는 clean-green 상태가 아니므로, RAG 관련 metric·문구는 회귀 수정 전까지 완료로 표시하지 않는다.

## 8. 요청하는 최종 판단

이 프로젝트는 **방향을 갈아엎을 단계가 아니라**, 이미 구현한 안전한 pipeline을 사용자 시나리오에 맞게 한 경로로 수렴시켜야 하는 단계인가? 그렇다면 위 “데모 전 최소 수정”의 우선순위가 맞는지, 더 작고 안전한 대안이 있는지 검토를 요청한다.
