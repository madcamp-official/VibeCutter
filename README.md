# Vibe Cutter

**로컬 MCP 기반 자율 웹 보안 분석·재현·수정·재검증 에이전트.**

승인된 로컬/격리 웹 애플리케이션의 취약점을 **재현 가능한 evidence로 실제 증명**하고, 근본
원인 패치를 생성한 뒤, **동일 공격 재실행 + 정상 기능 회귀 + 6게이트 결정론 판정**으로 수정
여부를 자동으로 가려냅니다. 판정(`verified`/`fixed`)에는 LLM이 개입하지 않으며, 패치는 원본이
아니라 run별 격리 Git worktree에만 적용됩니다.

> **외부 대상 공격 금지.** 등록된 target manifest(loopback 전용)에 없는 URL/IP/명령은 정책
> 계층에서 전부 거부됩니다. 안전 원칙 전문은 [`SECURITY_POLICY.md`](./SECURITY_POLICY.md),
> 기획서 10장, [`cowork_rule.md`](./cowork_rule.md) 4절 참고.

## 핵심 기능

- **자율 closed-loop**: 등록 → 스캔 → 검증 → 원인 지목 → 패치 → (승인) → 재검증을 에이전트가 대신 수행. 사용자는 **결정(승인)만** 합니다.
- **결정론적 검증 오라클**: IDOR(권한 우회)·SQL Injection(불리언 차등)·XSS(격리 브라우저 실행) 3종을 실제로 재현해 증명.
- **6게이트 판정**: `build · attack · positive_test · regression · static · scope` 전부 통과해야 `FIXED`. LLM은 후보 재랭킹·패치 합성에만 쓰고 판정엔 관여하지 않음(안전 불변식).
- **LLM 패치 합성**: 외부 Qwen3-235B(OpenAI 호환 API)가 template 밖 스택도 패치 diff 생성. 실패한 패치는 게이트가 걸러 RETRY/HUMAN_REVIEW로.
- **RAG 코드 컨텍스트**: BM25 + 임베딩 코드 인덱스로 후보 위치의 코드를 모델에 제공.
- **표준 리포트**: 사람이 보는 요약(3항목) + 상세 HTML + SARIF 2.1.0(GitHub code scanning 연동), secret은 redaction.
- **평가 하네스**: 벤치마크 기반 precision/recall, heuristic vs 235B 우선순위 ablation(MRR), 클래스별 패치 성공률.

## 기술 스택

| 구분 | 사용 |
| --- | --- |
| 언어/런타임 | **Python 3.13** (팀 공통. semgrep이 3.14에서 실행 불가하던 블로커 회피) |
| MCP | `mcp` 1.28 (FastMCP, **stdio 전송** — 외부 포트 없음) |
| 데이터/스키마 | `pydantic` 2.x, `pydantic-settings`, `sqlmodel`(SQLite evidence store), `PyYAML` |
| 정적 분석 | `semgrep` 1.90 (SAST), 자체 surface 그래프(라우트·핸들러·sink 추출) |
| 동적 검증 | Playwright(격리 브라우저, XSS), stdlib HTTP(IDOR/injection 오라클) |
| 패치 격리 | Git **worktree** (원본 branch 미변경) |
| LLM | 외부 **Qwen3-235B** OpenAI 호환 API(Cloudflare 터널), stdlib `urllib`만으로 호출 |
| 설정 | `python-dotenv` (`.env`) |
| 모델 서빙(선택) | `requirements-gpu.txt` — torch/vLLM (GPU 서버 전용, 팀 공통엔 미설치) |

## 프로젝트 구조

```
mcp_server/     MCP stdio 서버 · vc_* 도구(register/scan/verify/patch/report) · driver(closed-loop 오케스트레이션)
core/           상태머신 · policy engine · evidence store(SQLite) · judge(6게이트) · planner · report · redaction · audit log
contracts/      schemas.py — Target/Run/Observation/Candidate/Finding/RootCause/Patch/Validation/Trajectory 공통 스키마
runtime/        target lifecycle(build/start/reset) · manifest · source-lock/bootstrap · worktree · lease · compose 격리 · test runner
surface/        공격 표면 — 라우트/역할 매핑, 코드 그래프, inject/xss 후보 위치, IDOR 의심 지점
scanners/       후보 통합(aggregate) · SAST(semgrep) · SCA(osv) · surface_idor 브릿지 · RAG enrich · secret scan
verifiers/      검증 오라클 — access_control(IDOR) · injection(SQLi) · xss · dispatch(vuln_class 분기) · profiles
repair/         locator(원인 지목) · patcher(diff 생성) · llm_synth(235B 합성 어댑터) · validators(게이트 실행기)
model/          endpoints(티어체인·235B) · serving(rerank/embed 훅) · patch_client · code_index(RAG) · trajectory
eval/           baseline · compare/priority_ablation(MRR) · patch_success(클래스별 FIXED) · sample_filter · reflect_runs · report_export(SARIF) · run_m1
adapters/       command adapter · registry (typed command 실행 계약)
datasets/       inventory(감사 대상 카탈로그) · inventory_benchmark(정답 라벨) · benchmark_source_lock(벤치 소스 pin)
policies/       scope.yaml · commands.yaml · vulnerability_profiles/ (target allowlist, 명령 정책)
targets/        target manifest · compose · source-lock (등록된 대상 정의)
tests/          통합·계약 테스트 (약 568개)
docs/           handoffs(역할별 일일 기록) · 런북
```

## 핵심 흐름 (closed-loop)

```
register(loopback target) → build/start → map(routes·roles·code index)
  → candidate scan(SAST·SCA·surface) → verify(결정론 오라클: IDOR/SQLi/XSS)
  → localize root cause → generate patch(235B LLM 또는 template)
  → [사용자 승인] → apply to run-scoped worktree
  → 6게이트 검증(build·attack·positive·regression·static·scope)
  → FIXED / RETRY / HUMAN_REVIEW → export patch → reset
```

- **상태**: `REGISTERED → BUILDING → READY → MAPPING → CANDIDATE_SCAN → VERIFYING → VERIFIED/REJECTED → LOCALIZING → PATCH_PROPOSED → WAITING_APPROVAL → PATCH_APPLIED → VALIDATING → FIXED/RETRY/HUMAN_REVIEW`
- **에이전트 보고는 3가지**(쉬운 말): 발견한 위험 / 수정 계획 / (승인 시) 수정 결과. 내부 용어(CWE·엔드포인트)는 상세 리포트에만.
- **약 40개 `vc_*` MCP 도구** 제공: `vc_register_local_target`, `vc_run_sast/sca`, `vc_verify_access_control/injection/xss`, `vc_generate_patch`, `vc_apply_patch`(승인 필수), `vc_build_and_test`, `vc_replay_attack`, `vc_validate_regression`, `vc_generate_report`, `vc_export_sarif`, `vc_export_patch`, `vc_resume_audit` 등.

## 실행 및 설정

**1) 가상환경 + 의존성** (Python 3.13)
```bash
python3.13 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

**2) (선택) LLM endpoint 설정** — 없으면 휴리스틱으로 자동 degrade(오프라인 동작)
```bash
cp .env.example .env
# .env 편집:
#   VIBECUTTER_LLM_ENDPOINTS=https://<235B endpoint>/v1
#   VIBECUTTER_LLM_API_KEY=<key>
#   VIBECUTTER_LLM_MODEL=qwen3-235b
set -a; source .env; set +a
python -m model.endpoints          # [UP] 이면 235B 도달 OK
```

**3) MCP 서버 실행** (stdio — MCP Host가 subprocess로 구동, 외부 포트 없음)
```bash
python mcp_server/server.py
```

**4) 테스트**
```bash
python -m unittest discover -s tests        # 통합·계약 테스트
python -m model.test_endpoints              # 모듈별 스크립트 테스트(예)
```

> semgrep은 Python 3.11~3.13에서 정상, **3.14 미지원**. Windows는 semgrep만 WSL/Docker 권장.

## 역할 분담

| 역할 | 담당 | 소유 영역 |
| --- | --- | --- |
| P1 | 이지민 | MCP server, core state/policy/evidence/judge, 공통 contracts, report |
| P2 | 안종화 | target manifest, adapters, lifecycle/runtime, worktree/reset/test runner |
| P3 | 박준서 | attack surface, verifier, root-cause, patch/validation logic |
| P4 | 유나연 | inventory, RAG/model, dataset, baseline/metrics/evaluation |

## 문서

| 문서 | 내용 |
| --- | --- |
| [`TEAM_CONTRACT.md`](./TEAM_CONTRACT.md) | 공통 계약·인터페이스의 최종 근거 |
| [`SECURITY_POLICY.md`](./SECURITY_POLICY.md) | 승인 모델·loopback 불변식·argv 승인·LLM 전송 범위·redaction |
| [`cowork_rule.md`](./cowork_rule.md) | 4인 협업 규약 — 역할 경계, 공통 계약, handoff |
| [`REMAINING_PLAN.md`](./REMAINING_PLAN.md) | 남은 일 통합 계획 |
| `docs/handoffs/` | 역할별 일일 handoff (`D{day}-P{role}.md`) |
| 기획서 `.docx` | 아키텍처·MCP 설계·검증/수정 엔진·모델·평가 전문 |

## 공통 계약 변경 시 주의

`contracts/`, target manifest, 상태 이름, finding/evidence schema, policy는 프로젝트 전체가
공유하는 계약입니다. 변경이 필요하면 `docs/handoffs/`에 영향 범위와 이유를 남기고 조용히
바꾸지 않습니다 (cowork_rule 2·6절, `contracts/schemas.py`는 freeze).
