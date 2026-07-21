# Vibe Cutter — P4(유나연) 5일 실행 계획

> 참고: Notion "4명/5일 분업 계획"(팀 배분표), `plan.md`(P1 계획), `plan-p3.md`(P3 계획),
> `cowork_rule.md`(협업 규약), 기획서 DOCX.
> 상충 시 우선순위: **Notion 5일 계획 > 기획서 DOCX > cowork_rule.md**.
> 이 문서는 P4 자신의 할 일 추적용이다 — 매일 아침 여기서 오늘 할 일을 확정한다.

## ★ 프로젝트 방향 변경 (2026-07-21, 팀 결정) — 이 문서 최우선 반영

세 가지가 바뀌었고, 아래 계획 전체가 이 결정을 따른다.

1. **모델 서빙 = 72B 외주 설치.** GPU 3대(camp1/2/3)에 외부 작업자가 **72B**를 안전하게
   설치 중. **7B는 살려둔 채** 72B를 올리고, **작동 확인되면 7B를 내린다.** → P4는 서빙을
   직접 설치하지 않는다. 내가 할 일은 **72B endpoint를 파이프라인 훅(rerank/embed/patch)에
   배선**하고, **7B를 fallback으로 두는 chained ChatFn**을 구성하는 것뿐.
   (`model/serving.py`의 `make_chained_chat_fn`이 이미 이 구성을 지원 — 72B primary, 7B fallback.)
2. **학습(LoRA/QLoRA) 포기.** `model/train_lora.py`, "7B QLoRA 학습", "base(7B) vs
   fine-tuned 비교"는 **전부 취소.** trajectory는 **학습셋이 아니라 few-shot 예시·평가
   trace**로만 쓴다. `eval/compare.py`는 폐기하지 않고 **"base=SAST/7B vs full=72B+RAG+prompt"
   ablation 비교**로 용도만 바꾼다(코드 재사용).
3. **패치 = LLM 생성 방식으로 전환.** 기존 결정론적 `repair/patcher.py`(Java IDOR 템플릿 diff)
   대신, **72B가 patch diff를 생성**한다. **다행히 `generate_patch(..., synthesize_fn=)` 자리가
   이미 비어 있다** — LLM 경로는 새 코드가 아니라 이 훅에 72B를 물리는 것. LLM 출력은
   **untrusted diff** → run-scoped worktree에만 적용 → `scope→build→attack→positive→regression
   →static` 6게이트를 통과해야 `FIXED`. **게이트 판정 오라클 `core.judge.compute_verdict`는
   패치 출처와 무관하게 동일** — 즉 게이트/판정 코드는 바뀌지 않는다.
   **소유 경계**: `vc_generate_patch`(synthesize_fn 배선)는 **P3/P1 소유** — P4는 patcher를
   고쳐 쓰지 않는다. **P4의 몫 = ① 72B 백엔드 model 훅 제공(chat_fn/synthesize helper),
   ② 이 closed-loop의 성공률·게이트별 통과율 측정.**

**한 줄로 바뀐 P4의 일**: (학습 삭제) + (72B 배선) + (LLM patch **평가** 추가).
소유 축이 "탐지 품질 + 학습"에서 **"탐지 품질 + (72B 파이프라인·LLM patch) 평가·리포트"**로 이동.

## 0. 내 역할 요약

**P4 = Model/Eval.** 소유 영역: 앱 inventory·선별, RAG/코드인덱스, Semgrep·SCA 통합,
candidate 통합·우선순위, baseline·metric·평가, trajectory 수집, **72B 파이프라인 배선·
LLM patch 평가**, 리포트·발표. (~~LoRA 학습~~ — 2026-07-21 취소.)

다른 역할과의 관계(내가 주고받는 것):
- **P1(Platform)** — 공통 contracts, evidence store, judge, 리포트 데이터 조인
  (`core.report.build_run_report`), tool 배선(vc_run_sast/sca), trajectory export.
- **P2(Target/Infra)** — target manifest·소스 경로(`.vibecutter/targets/sources/<id>`),
  adapter override, **GPU 서버 접속 정보**.
- **P3(Security)** — verifier(내 candidate의 `vuln_class`로 분기), locator(내 `code_index`·
  SAST `source_symbols` 소비), verified/fixed evidence(내 **평가·patch 성공률·few-shot**의 재료).

**내 두 축**: ① **탐지 품질**(candidate 통합·FP reject·우선순위·RAG+72B rerank) → precision.
② **평가·리포트**(baseline metric, **base vs full ablation**, **LLM patch 성공률**, 리포트)
→ 성공 등급 입증. (~~LoRA 학습~~은 축에서 제거 — 대신 72B+RAG+prompt ablation이 "full" 팔.)

**절대 원칙**: 남의 소유 영역(verifier 세부, adapter 내부, judge 로직)은 직접 구현하지
않는다. 공유 파일(`scanners/`, `requirements.txt`)은 내 파일만 커밋. GPU 없이 되는 일과
GPU 필요한 일을 분리해서, GPU 없을 때도 항상 선행 가능한 작업을 먼저 한다.

**Handoff**: 매일 종료 시 `docs/handoffs/D{day}-P4.md` (cowork_rule §6 템플릿). 작업은
**그 작업이 속한 D의 handoff**에 적는다(서빙=D2 보류항목, LoRA=D4 등 — D를 확인하고 기록).

---

## 현재 상태 (2026-07-21 아침 기준 — 방향 변경 반영, 정직하게)

**환경**: 팀 Python **3.13 통일**(`.python-version`). semgrep 1.90.0 은 3.11~3.13 정상,
**3.14만 실행 불가**(WSL/Linux 실측). **SAST 실주행은 내가 WSL/3.13 에서 담당.** Windows
팀원은 semgrep 만 WSL/Docker(OS 문제). 프로젝트 `.venv`(3.13) 구성 완료.

| 항목 | 상태 |
| --- | --- |
| inventory(41 discovery + 16 benchmark), 로더/검증 | ✅ 완료 |
| RAG 코드인덱스(`model/code_index.py`, BM25 + embed_fn 훅) | ✅ 완료 |
| Semgrep/SCA 통합(`run_semgrep`/`run_osv` → Candidate) | ✅ 완료(실주행 검증) |
| baseline 하니스(`eval/baseline.py`, `run_baseline.py`) | ✅ 완료 |
| candidate 통합·FP reject·우선순위(`scanners/aggregate.py`) | ✅ 완료 |
| RAG 우선순위(`scanners/rag_enrich.py`) | ✅ 완료 |
| trajectory 수집(`model/trajectory.py`) — 이제 **few-shot/평가 trace 용**(학습X) | ✅ 완료 |
| B1/B2 baseline 배선 + `--benchmark` | ✅ 완료 |
| severity/OWASP 어휘(`scanners/vocab.py`) — P1 채택됨 | ✅ 완료 |
| surface_idor 브릿지 + B1 실측(IDOR F1 0→0.60) | ✅ 완료(`eval/results/`) |
| HTML/SARIF 리포트 export(`eval/report_export.py`) | ✅ 렌더러 완료(6/6). 실 evidence 시 `build_run_report`로 실데이터 스위치 |
| 모델 서빙 훅(`model/serving.py`, chained 72B→7B) | 🟡 코드/테스트 완료. **72B endpoint 확정 대기(외주 설치 중)** |
| ~~7B QLoRA 학습(`model/train_lora.py`)~~ | ❌ **취소(학습 포기)** — 코드는 남기되 계획에서 제거 |
| ~~OWASP Benchmark base(7B) vs fine-tuned 비교~~ | ❌ **취소** → **base(SAST/7B) vs full(72B+RAG+prompt) ablation**으로 대체 |
| **LLM patch closed-loop 평가**(FIXED 성공률·게이트별 통과율) | 🔴 **신규 — 이번 2일 핵심.** P3 verify + P2 worktree gate 산출물 소비 |
| 최종 metric·report·슬라이드·발표 | ⏳ 이번 2일 마무리 |

**한 줄 요약**: 탐지·리포트 하부구조는 사실상 완성. 이제 남은 건 **① 72B 배선(외주 endpoint
나오면 훅에 연결), ② 학습 대신 base vs full ablation 실측, ③ LLM patch 성공률 측정, ④ 리포트·
발표.** 학습 블로커가 사라진 대신, 평가의 무게중심이 **72B 파이프라인·LLM patch 성공률**로 옮겨감.

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

## ★ 이번 2일 계획 (2026-07-21 ~ 07-22) — 방향 변경 후 P4가 실제로 할 일

원칙 그대로: **72B endpoint(외주)가 아직이면 그걸 기다리지 말고, endpoint 없이 되는
일(하네스 재정의·목 patch로 gate 로직·리포트·발표 뼈대)을 먼저 끝낸다.** endpoint가
살아나면 훅만 갈아끼워 실측으로 스위치.

### Day 1 (07-21) — 배선 재정의 + LLM patch 평가 하네스

| # | 작업 | 완료 기준 | 의존성 / endpoint 없이 선행? |
| --- | --- | --- | --- |
| 1 | **학습 잔재 정리** — `train_lora.py`·`requirements-gpu.txt`의 학습 부분을 계획/런북에서 "취소"로 명시(코드는 삭제 말고 보존). 서빙 런북에서 QLoRA/base-vs-fine-tuned 절 제거·대체 | 런북·plan에 학습 취소 반영 | ✅ 선행 가능(문서만) |
| 2 | **72B 배선 훅** — `make_chained_chat_fn([72B, 7B])`로 rerank_fn/embed_fn 구성 + **patch용 synthesize helper(chat_fn 기반)** 을 P3에 넘길 형태로 제공(patcher는 안 고침). base_url/model을 72B로 스위치할 config 1곳으로 모음. 72B down→7B fallback, 둘 다 down→BM25/항등 폴백 유지 확인 | `model/test_serving.py` 통과 + 목 endpoint로 fallback 경로 검증 | ✅ 선행(목 endpoint). 실 endpoint 나오면 스위치 |
| 3 | **LLM patch 평가 하네스(신규 — 이번 2일 유일한 실질 신규 코드)** — `Validation` 레코드의 6게이트 필드(`build/attack/positive_test/regression/static/scope`, `core.judge` 계약)를 읽어 **게이트별 통과율 + 최종 FIXED 성공률**을 집계. `compute_verdict`와 같은 필드를 소비하므로 판정과 어긋나지 않음 | 목 `Validation` 로 성공률 표 산출 + 유닛테스트 | ✅ 선행(목 verdict). 실 산출물 나오면 스위치 |
| 4 | **base vs full ablation 재정의** — `eval/compare.py`를 "base(SAST단독/7B) vs full(72B+RAG+prompt)"로 라벨만 바꿔 재사용. 학습 팔 제거 | ablation 비교표가 두 라벨로 렌더 | ✅ 선행(하네스 완성됨) |

### Day 2 (07-22) — 실측 + 리포트 + 발표

| # | 작업 | 완료 기준 | 의존성 |
| --- | --- | --- | --- |
| 5 | **full 파이프라인 실측** — 72B endpoint 확정되면 벤치마크 16개에 full(72B+RAG) 돌려 precision/recall/FPR/F1 산출, base와 ablation 비교표 확정 | 비교표 실데이터 1장 | **72B endpoint(외주)** |
| 6 | **LLM patch 성공률 실측** — P3가 verify한 데모 target(예: Juice Shop SQLi 후보 등) 1~2개에서 72B patch → 게이트 통과율/FIXED 집계 | patch closed-loop 표 1장 | P2 worktree gate + P3 verify + 72B |
| 7 | **리포트 실데이터 스위치** — `report_export`를 `build_run_report` 실 evidence로 HTML/SARIF 1건 출력(목 → 실) | 실 리포트 1건 | P1 실 evidence |
| 8 | **슬라이드·발표** — 논지: "SAST 단독 한계(IDOR=0) → 동적 verify → **72B LLM patch closed-loop**". 학습 대신 **72B+RAG ablation과 patch 성공률**로 성공 등급 입증 | 발표 자료 완성 | 위 표들 |

**블로커·대응**: ① 72B endpoint 미확정 → #5·#6 실측만 대기, #1~#4·#7 뼈대는 선행. endpoint
도달성은 외주/`P2`에 확인 요청(`/health` 비인증 프로브). ② 실 evidence 얇음 → 데모 target
1~2개라도 closed-loop 1회 완주를 확보(개수보다 **한 바퀴 실증**이 발표 논지의 핵심).

---

## 밤 배치와 P4 의 관계

| 밤 | 배치 (담당) | 내 의존성 |
| --- | --- | --- |
| D1 밤 | 전 앱 Semgrep 스캔 (P2/P4) | 내 `run_semgrep`/배치가 재료. **WSL/3.13 에서 내가 돌린다**(Windows 불가) |
| D3 밤 | 첫 audit 배치 8~10개 (P2) | 배치 산출 candidate → 내 baseline·리포트 재료 |
| ~~D4 밤~~ | ~~7B QLoRA + base vs full~~ → **취소(학습 포기)**. 대신 **72B+RAG ablation + LLM patch 성공률 실측** | verify 산출물·worktree gate 결과가 재료 → 성공 등급이 걸림 |

---

## 핵심 리스크 (P4 관점)

| 리스크 | 신호 | 대응 |
| --- | --- | --- |
| **리포트 export 지연** | D3 항목이 계속 밀림 | 오늘 최우선. 실 evidence 없어도 **P1 RunReport 형태로 목 렌더러 선행**, 나중에 실데이터 스위치 |
| ~~학습 데이터 부족~~ → **학습 포기로 해소** | — | 학습 리스크 소멸. 대신 **base vs full ablation + patch 성공률**이 성공 등급 근거 |
| **72B endpoint 미확정/도달불가** | 외주 설치 지연, `/health` timeout | 실측(#5·#6)만 대기하고 배선·하네스·리포트 뼈대(#1~#4,#7)를 선행. endpoint는 chained fn으로 72B→7B fallback |
| **LLM patch = untrusted diff** | 모델이 잘못된/광범위 diff 생성 | run-scoped worktree에만 적용, scope→build→attack→positive→regression→static 게이트 전부 통과해야 FIXED. 게이트 통과율 자체를 지표로 |
| **patch 실증 0바퀴** | 데모까지 closed-loop 1회도 못 돎 | 개수 대신 **1~2개 target 완주**를 최우선. P2 worktree gate·P3 verify와 조기 조율 |
| **semgrep 환경 혼란** | 팀원이 Windows 에서 안 됨 | 원인=OS(버전 아님). SAST 실주행은 내가 WSL/3.13. 팀원은 WSL/Docker |
| **공유 파일 오염** | `scanners/`·`requirements.txt` 커밋 충돌 | 내 파일만 add. GPU 의존성은 `requirements-gpu.txt` 로 분리(공통 오염 방지) |
| **precision 과 개수 혼동** | verified 개수만 봄 | 목표는 **verified precision 70%+**(12.4절). negative 샘플(c2-05 등)로 오탐도 측정 |

---

## API 안정 약속 (남이 내 걸 소비 중 — 깨지 말 것)

- `model.code_index`: `CodeIndex.build(root).search(q, k=1)` → `hit.chunk.file` (P3 locator + P1 check_static).
- SAST `source_symbols` **"파일:줄"** 포맷 (P3 locator 교차검증).
- `scanners.sast.run_semgrep` / `scanners.sca.run_osv` / `scanners.aggregate.aggregate` (P1 tools + judge).
- `--use-p2-sources` source root + inventory/runtime adapter override 계약 (P2).
- `model.trajectory.to_sft_sample()` 포맷 = P1 export 계약(**학습 아님 — few-shot 예시·평가
  trace 용으로 용도 변경**). 바꾸면 P1 export 도 따라 바뀜.

---

## 매일 리듬 체크리스트

1. **아침**: 이 문서 + 밤사이 갱신된 `docs/handoffs/*` 를 읽고 오늘 할 일 확정.
   내가 받아야 할 것(**72B endpoint**·P2 worktree gate 결과·P3 verify·P1 실 evidence)이 왔는지 먼저 확인.
2. **낮**: endpoint 없이 선행 가능한 것(배선·평가 하네스·리포트·목 렌더러)을 먼저.
   블로커는 담당자에게 **한 줄로** 즉시 요청하고 안 기다리는 일로 넘어간다.
3. **저녁**: 그 날 한 일을 **해당 D의 handoff**에 기록(§6 템플릿). 남에게 줄 것/받을 것 명시.
4. **커밋**: 내 파일만. 커밋 메시지는 실제 변경 기준. (git 실행은 내가 직접)
