# Vibe Cutter — P4(유나연) 5일 실행 계획

> 참고: Notion "4명/5일 분업 계획"(팀 배분표), `plan.md`(P1 계획), `plan-p3.md`(P3 계획),
> `cowork_rule.md`(협업 규약), 기획서 DOCX.
> 상충 시 우선순위: **Notion 5일 계획 > 기획서 DOCX > cowork_rule.md**.
> 이 문서는 P4 자신의 할 일 추적용이다 — 매일 아침 여기서 오늘 할 일을 확정한다.

## 0. 내 역할 요약

**P4 = Model/Eval.** 소유 영역: 앱 inventory·선별, RAG/코드인덱스, Semgrep·SCA 통합,
candidate 통합·우선순위, baseline·metric·평가, trajectory 수집, LoRA 학습, 리포트·발표.

다른 역할과의 관계(내가 주고받는 것):
- **P1(Platform)** — 공통 contracts, evidence store, judge, 리포트 데이터 조인
  (`core.report.build_run_report`), tool 배선(vc_run_sast/sca), trajectory export.
- **P2(Target/Infra)** — target manifest·소스 경로(`.vibecutter/targets/sources/<id>`),
  adapter override, **GPU 서버 접속 정보**.
- **P3(Security)** — verifier(내 candidate의 `vuln_class`로 분기), locator(내 `code_index`·
  SAST `source_symbols` 소비), verified/fixed evidence(내 학습 데이터의 재료).

**내 두 축**: ① **탐지 품질**(candidate 통합·FP reject·우선순위·RAG) → precision.
② **평가·학습**(baseline metric, trajectory, LoRA, 리포트) → 성공 등급 입증.

**절대 원칙**: 남의 소유 영역(verifier 세부, adapter 내부, judge 로직)은 직접 구현하지
않는다. 공유 파일(`scanners/`, `requirements.txt`)은 내 파일만 커밋. GPU 없이 되는 일과
GPU 필요한 일을 분리해서, GPU 없을 때도 항상 선행 가능한 작업을 먼저 한다.

**Handoff**: 매일 종료 시 `docs/handoffs/D{day}-P4.md` (cowork_rule §6 템플릿). 작업은
**그 작업이 속한 D의 handoff**에 적는다(서빙=D2 보류항목, LoRA=D4 등 — D를 확인하고 기록).

---

## 현재 상태 (Day 4 아침 기준 — 정직하게)

**환경**: 팀 Python **3.13 통일**(`.python-version`). semgrep 1.90.0 은 3.11~3.13 정상,
**3.14만 실행 불가**(WSL/Linux 실측). **SAST 실주행은 내가 WSL/3.13 에서 담당.** Windows
팀원은 semgrep 만 WSL/Docker(OS 문제). 프로젝트 `.venv`(3.13) 구성 완료.

| 항목 | D | 상태 |
| --- | --- | --- |
| inventory(41 discovery + 15 benchmark), 로더/검증 | D1 | ✅ 완료 |
| RAG 코드인덱스(`model/code_index.py`, BM25 + embed_fn 훅) | D1 | ✅ 완료 |
| Semgrep/SCA 통합(`run_semgrep`/`run_osv` → Candidate) | D1 | ✅ 완료(실주행 검증) |
| baseline 하니스(`eval/baseline.py`, `run_baseline.py`) | D1 | ✅ 완료 |
| candidate 통합·FP reject·우선순위(`scanners/aggregate.py`) | D2 | ✅ 완료 |
| RAG 우선순위(`scanners/rag_enrich.py`) | D2 | ✅ 완료 |
| trajectory 수집(`model/trajectory.py`) | D2 | ✅ 완료 |
| B1/B2 baseline 배선 + `--benchmark` | D2 | ✅ 완료 |
| severity/OWASP 어휘(`scanners/vocab.py`) — P1 채택됨 | D2 | ✅ 완료 |
| 모델 서빙 endpoint + rerank_fn/embed_fn 훅(`model/serving.py`) | D2 보류 | 🟡 코드/테스트 완료, **GPU 접근 대기** |
| **HTML/SARIF 리포트 export** | **D3** | ✅ 렌더러 완료(`eval/report_export.py`, 6/6). 실 evidence 시 `build_run_report`로 실데이터 스위치 |
| verified trajectory 축적, batch 결과 수집 | D3 | ⏸️ 실 evidence 대기 |
| 7B QLoRA 학습 스크립트(`model/train_lora.py`) | D4 | 🟡 스크립트 완료, **GPU + 실 evidence 대기** |
| OWASP Benchmark base vs full 비교 | D4 밤 | ⏳ 예정 |
| 최종 metric·report.pdf·슬라이드·발표 | D5 | ⏳ 예정 |

**한 줄 요약**: D1·D2 는 사실상 끝. **D3의 리포트 export 가 밀려 있는 게 지금 제일 급한 것.**
GPU 작업(서빙 훅·LoRA)은 준비 완료 상태로 접근/데이터만 기다린다.

---

## Day 1 — inventory · RAG · 스캐너 통합 · baseline (✅ 완료)

| 작업 | 완료 기준 | 상태 |
| --- | --- | --- |
| inventory → discovery/benchmark 카탈로그 | 로더·검증 통과 | ✅ |
| RAG 코드인덱스(BM25 + embed 훅) | search/find_symbol 동작 | ✅ |
| Semgrep/SCA → Candidate 통합 | candidate 산출 | ✅ (실주행 검증) |
| baseline 하니스 | precision/recall/F1/benchmark score | ✅ |
| **모델 서빙 endpoint** | 모델 응답 | 🟡 GPU 대기(serving.py 준비) |

## Day 2 — 탐지 품질: 통합·FP reject·우선순위·trajectory (✅ 완료)

| 작업 | 완료 기준 | 상태 |
| --- | --- | --- |
| candidate 통합 + FP reject | 중복제거·오탐 제거 | ✅ |
| base LLM+RAG 가설 우선순위 | 우선순위 점수 | ✅ (RAG까지; LLM은 rerank_fn 훅) |
| trajectory 수집 시작 | 상태전이 기록 | ✅ |
| B1/B2 baseline | 셀별 metric | ✅ |
| (보류) 서빙 + rerank_fn/embed_fn 훅 연결 | 훅에 모델 주입 | 🟡 GPU 대기(serving.py 준비 완료) |

## Day 3 — 리포트 export + verified trajectory 축적 (🔴 오늘 착수)

| 작업 | 완료 기준 | 의존성 |
| --- | --- | --- |
| ~~HTML/SARIF 리포트 생성~~ ✅ | **report 1건 export** | P1 `build_run_report` 소비 → `eval/report_export.py`(render_html/render_sarif). 목 데이터로 실 export 검증 완료 |
| verified trajectory 축적 | trajectory 저장 | P1 judge 의 verified/fixed evidence 필요 |
| batch 결과 수집 | 배치 산출 집계 | P2 20개 runtime 소스 |

**오늘 최우선 = 리포트 export.** P1 이 `RunReport.findings[i]`(finding/evidence/patch/
validation 묶음)를 이미 준비해 뒀으므로, **데이터는 P1, 렌더링(HTML/SARIF)은 P4.**
- HTML: 사람이 보는 리포트(finding별 증거·패치·검증 표).
- SARIF: 표준 정적분석 포맷(도구 상호운용 — GitHub code scanning 등에 올릴 수 있음).
- 실 evidence 가 아직이면 P1 export 형태에 맞춰 **목 데이터로 렌더러를 먼저 완성**하고,
  evidence 나오면 바로 실데이터로 돌린다(GPU/실주행 없이 선행 가능).

## Day 4 — LoRA 학습 + 벤치마크 (🟡 스크립트 준비됨)

| 작업 | 완료 기준 | 의존성 |
| --- | --- | --- |
| (밤) 7B QLoRA 학습 | 어댑터 저장 | **GPU 접근**(P2) + **실 verified/fixed evidence**(P1/P3) → P1 export |
| (밤) OWASP Benchmark base vs full | 비교표 초안 | 위 학습 완료 + inventory_benchmark 라벨 |
| (아침) metric·failure 분석 | 실패 유형 정리 | 위 결과 |

**GPU-free 선행 완료**:
- **비교 하네스** `eval/compare.py` — 두 산출물 → base→full 델타 표 + 앱별 개선/악화(4/4).
  두 산출물만 나오면 "비교표 초안"이 바로 나온다.
- **벤치마크 음성 샘플** — `inventory_benchmark.yaml` 에 c2-05(IDOR-clean, P3 검증) 추가.
  공개 15개는 전부 양성이라 오탐(precision/FPR)을 못 쟀는데, 이제 clean 앱 오탐을 측정한다.
- `model/train_lora.py`(순수 데이터준비/GPU학습 2층), `model/serving.py`(rerank_fn/embed_fn),
  `requirements-gpu.txt`, `docs/P4_MODEL_SERVING_RUNBOOK.md`.
**블로커 2개**: ① GPU 접속 정보(P2), ② 실 evidence(없으면 학습 데이터 0 — cowork_rule §5).
데이터 얇으면 Notion 리스크 대응: **RAG + prompt ablation 으로 대체.**

## Day 5 — 최종 평가 · 발표

| 작업 | 완료 기준 |
| --- | --- |
| 최종 metric(precision·patch·일반화·안전) | 수치 확정 |
| report.html/pdf | 산출물 |
| 슬라이드/영상 | 발표 자료 |
| 발표 | 완성 |

---

## 밤 배치와 P4 의 관계

| 밤 | 배치 (담당) | 내 의존성 |
| --- | --- | --- |
| D1 밤 | 전 앱 Semgrep 스캔 (P2/P4) | 내 `run_semgrep`/배치가 재료. **WSL/3.13 에서 내가 돌린다**(Windows 불가) |
| D3 밤 | 첫 audit 배치 8~10개 (P2) | 배치 산출 candidate → 내 baseline·리포트 재료 |
| D4 밤 | **7B QLoRA + OWASP Benchmark + base vs full (P4 주관)** | **내가 이 밤의 주인공.** verified trajectory 가 재료 → P3 처리량·P1 export 에 성공 등급이 걸림 |

---

## 핵심 리스크 (P4 관점)

| 리스크 | 신호 | 대응 |
| --- | --- | --- |
| **리포트 export 지연** | D3 항목이 계속 밀림 | 오늘 최우선. 실 evidence 없어도 **P1 RunReport 형태로 목 렌더러 선행**, 나중에 실데이터 스위치 |
| **학습 데이터 부족** | verified trajectory 수백 건 안 모임 | Notion 리스크. base 대비 유의차 없으면 **RAG+prompt ablation 으로 대체**. 20개 runtime 체크를 학습 성공으로 라벨링 금지(P2/P3 지시) |
| **GPU 접근 지연** | P2 접속 정보 무응답 | 서빙/학습은 **준비만 해두고**, GPU 없이 되는 리포트·baseline·목 렌더러를 먼저 한다 |
| **24GB 서빙+학습 OOM** | 동시 실행 시 메모리 초과 | 서빙 4bit(AWQ)로 낮추거나 시간대 분리(런북 명시) |
| **semgrep 환경 혼란** | 팀원이 Windows 에서 안 됨 | 원인=OS(버전 아님). SAST 실주행은 내가 WSL/3.13. 팀원은 WSL/Docker |
| **공유 파일 오염** | `scanners/`·`requirements.txt` 커밋 충돌 | 내 파일만 add. GPU 의존성은 `requirements-gpu.txt` 로 분리(공통 오염 방지) |
| **precision 과 개수 혼동** | verified 개수만 봄 | 목표는 **verified precision 70%+**(12.4절). negative 샘플(c2-05 등)로 오탐도 측정 |

---

## API 안정 약속 (남이 내 걸 소비 중 — 깨지 말 것)

- `model.code_index`: `CodeIndex.build(root).search(q, k=1)` → `hit.chunk.file` (P3 locator + P1 check_static).
- SAST `source_symbols` **"파일:줄"** 포맷 (P3 locator 교차검증).
- `scanners.sast.run_semgrep` / `scanners.sca.run_osv` / `scanners.aggregate.aggregate` (P1 tools + judge).
- `--use-p2-sources` source root + inventory/runtime adapter override 계약 (P2).
- `model.trajectory.to_sft_sample()` 포맷 = P1 export 계약. 바꾸면 P1 export 도 따라 바뀜.

---

## 매일 리듬 체크리스트

1. **아침**: 이 문서 + 밤사이 갱신된 `docs/handoffs/*` 를 읽고 오늘 할 일 확정.
   내가 받아야 할 것(P1 export·P2 GPU·P3 evidence)이 왔는지 먼저 확인.
2. **낮**: GPU 없이 선행 가능한 것(리포트·baseline·목 렌더러·데이터준비)을 먼저.
   블로커는 담당자에게 **한 줄로** 즉시 요청하고 안 기다리는 일로 넘어간다.
3. **저녁**: 그 날 한 일을 **해당 D의 handoff**에 기록(§6 템플릿). 남에게 줄 것/받을 것 명시.
4. **커밋**: 내 파일만. 커밋 메시지는 실제 변경 기준. (git 실행은 내가 직접)
