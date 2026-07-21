# 남은 일 통합 계획 (단계별 · 팀원별 체크리스트)

> **작성 2026-07-21 (endpoint UP 직후).** `*_new_plan.md`의 체크박스 상당수가 stale이라, main 코드 +
> `TEAM_CONTRACT.md §6`(16:34) 기준으로 **실제 남은 일만** 추린 통합 뷰다. 계약·인터페이스의 최종
> 근거는 여전히 `TEAM_CONTRACT.md`. 여기는 "무엇을, 누가, 어떤 순서로"만 담는다.

## 지금 위치 (사실)
- ✅ **엔진 전부 완성** — verifier·judge(K)·llm_synth(S-1~4)·patch_client·RAG·배선(W-1~10)·승인흐름
  (`vc_export_patch`/`vc_resume_audit`)·lease·metadata. **568 tests.**
- ✅ **235B endpoint UP + 실 235B 패치 합성 증명** — Python SQLi를 파라미터 바인딩으로 정확히 수정.
  데모 2 핵심 주장("template 밖 3군을 235B가 패치")이 실모델로 성립.
- ✅ **c1-05 gold**(데모 1 fallback, 6게이트 全1 FIXED 유지) + **Juice Shop 등록·소스 bootstrap**.

→ "만드는" 단계는 끝. 남은 건 **완주 · 측정 · 안전완성 · 문서** 네 갈래.

---

## 팀원별 한눈 요약
- **[P1]** 데모 1/2 흐름 확인 + egress 동의 UI + patch diff/container log redaction + **SECURITY_POLICY/RUNBOOK 취합**.
- **[P2]** Juice Shop **Docker 실측** + **injection candidate seed 여부 결정**(seed 가능하면 최속) + 데모1 등록 런타임.
- **[P3]** **데모 2(J-3) 완주** — candidate gap 풀리면 실 235B로 FIXED 1회 + F-3 한계문서. (엔진·계약 P3 몫은 완료)
- **[P4]** **E-1 ablation 2회 주행**(endpoint UP이라 지금 가능) + **SARIF redaction**.

---

## 단계 0 — 지금 바로 (병렬 착수, endpoint UP 직후)
- [ ] **[P2]** injection candidate **seed 경로 결정** — 파이프라인이 injection candidate를 fixture/manifest로 seed 가능한가? (되면 최속) → P3에 회신
- [ ] **[P2]** Juice Shop **Docker build → start → health(`/rest/products/search?q=apple` 200) → reset** 실측
- [x] **[P3]** candidate gap 대응 — **해결(`b512141`)**. surface는 이미 Node를 파싱했고, 진짜 문제이던 `inject_param`(SQL 변수→HTTP 파라미터) 역추적을 `_http_param_for`로 수정. Juice Shop 구조 fixture에서 candidate 정상 생성 확인. P2 seed 불필요.
- [ ] **[P4]** **E-1 ablation `heuristic` 팔** 주행(`VIBECUTTER_LLM_DISABLE=1`, endpoint 무관 — 지금 가능)
- [ ] **[P4]** **E-1 ablation `rag-llm` 팔** 주행(endpoint UP이라 가능)
- [ ] **[P4]** **SARIF redaction** — `eval/report_export.py:render_sarif()`/`_finding_to_sarif_result`에 `redact()` 적용(현재 0건)

## 단계 1 — 데모 2 완주 (발표 핵심 증거)
> 전제: 단계 0의 candidate 경로 + Docker 완료.
- [ ] **[P3]** **J-3 완주 1회** — Juice Shop SQLi → verify(injection blind 차등) → localize → **235B 패치** → 6게이트 → **FIXED**. run_id 공유. **패치 경로는 코드 완결·오프라인 검증됨(`b512141`·`faf01ab`)** — endpoint 복귀 + Docker만 남음
- [ ] **[P1]** 완주가 **승인 흐름**(scan/verify → `PATCH_PROPOSED` 정지 → 사용자 승인 → `vc_resume_audit` → 6게이트)으로 도는지 확인
- [ ] **[P4]** 그 run의 metadata(`llm_used`/tier/health)로 ablation 표본에 반영
- [ ] **[P2]** 완주 후 `reset_run` + (write 없으니) baseline restore 불필요 확인, 슬롯 정리

## 단계 2 — 데모 1 완주 + 측정 집계
- [ ] **[P1]/[P2]** **데모 1 E2E** — 사용자 프로젝트 등록(`vc_register_local_target` confirmed) → registry snapshot → policy 통과 → 검사
- [ ] **[P3]** 그 위에서 verify/judge가 정상 판정하는지(데모 1 대상)
- [ ] **[P4]** **E-1 결과 집계** — `eval/compare.py`로 heuristic vs rag-llm (verified precision·patch 성공률·우선순위). **RQ3 근거**

## 단계 3 — 안전 완성 + 필수 문서 (§3A-10, §15)
- [ ] **[P1]** **egress 동의** — 등록/첫 LLM 호출 시 "코드 일부가 LLM 질의로 전송(secret 제거)" 1회 표시·기록
- [ ] **[P1]** patch diff / container log redaction (patch diff는 git apply 바이트정확성 때문에 별도 접근)
- [ ] **[P1]** **`SECURITY_POLICY.md`** — 승인모델·loopback 불변식·argv 승인·CF 전송범위·"제3자 LLM API 안 씀" (P2/P3 안전내용 취합)
- [ ] **[P2]/[P4]** **`RUNBOOK.md`** — P2 runtime(build/start/reset/lease) + P4 serving(endpoint/tier/degrade) 섹션
- [x] **[P3]** **F-3 한계 문서** — **완료** [`docs/P3_VERIFY_JUDGE_LIMITS.md`](docs/P3_VERIFY_JUDGE_LIMITS.md). injection positive=liveness / xss positive=benign·실행관찰 / running_local N/A 게이트 / static semgrep 의존. P1이 `SECURITY_POLICY.md`로 취합

## 단계 4 — E2E 검증 + 리허설
- [ ] **[전원]** **전체 E2E 시나리오** — 등록 → snapshot → scan/verify → `PATCH_PROPOSED` 승인 → 6게이트 → `FIXED` → **patch export(reset 뒤 artifact 보존)** → reset → (write면 baseline restore) 통과
- [ ] **[전원]** **데모 리허설** — 데모 1(제품 등록 검사) + 데모 2(Juice Shop SQLi→235B 패치→FIXED) + fallback(c1-05) 시연
- [ ] **[전원]** **발표 슬라이드 / MCP_SPEC** 취합

## 선택 / 소소 (여유 시)
- [ ] **[P1]** K-3 — running_local이 `PATCH_PROPOSED`에 멈춘 **사유를 사용자에게 표시**(report/tool 레이어)
- [ ] **[P4]** G-2 CodeIndex 캐시(경로+mtime), **패치 품질**(다중 후보·프롬프트·cross-file sink)
- [ ] **[P1]/[P2]** §3A-1/4 Git root preflight, §3A-9 write restore 호출 E2E 검증

---

## 크리티컬 패스 (endpoint UP 이후)
**단계 0(Docker·ablation·SARIF 병렬 — candidate gap은 `b512141`로 해결) → 단계 1(데모 2 완주) → 단계 2(데모 1 + 측정) → 단계 3(안전·문서) → 단계 4(E2E·리허설).**
candidate gap·패치 대상파일이 다 풀렸으니(코드+오프라인 검증), 이제 최대 리스크는 **환경 2개**: (1) **235B endpoint 복귀**(재확인 시 DOWN·key:no — P2 터널/env; E-1 rag-llm 팔·J-3 실패치 둘 다 종속), (2) **실 Juice Shop Docker 실측**(P2 단계 0). 이 둘이 서면 235B 패치→FIXED 완주(J-3)가 바로 가능. 나머지는 병렬로 수렴.
