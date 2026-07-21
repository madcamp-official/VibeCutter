# P4 — 2일 스프린트 계획

> 상위 문서: **[TEAM_CONTRACT.md](TEAM_CONTRACT.md)** — 충돌 시 그쪽이 이긴다.

## 내 역할 한 줄

**모델과 후보 품질의 소유자.** 235B를 실제로 돌게 만들고, RAG로 모델에 코드를 보여주고, 개선을 측정한다.

## 내 파일 (배타적)

`model/**`, `scanners/**`, `eval/**`

**남의 파일은 안 고친다.** `mcp_server/tools_repair.py` 배선은 P1, `repair/llm_synth.py`는 P3.

---

## P0 — 235B를 실제로 켜기 (지금 아무것도 안 돌고 있다)

**현재 모든 run이 휴리스틱으로 돌고 있다.** endpoint에 못 닿으면 3초 probe 후 조용히 degrade하는데, 그게 로그에 드러나지 않는다. 발표에서 "235B가 후보를 재정렬하고 패치를 만든다"고 말하려면 이게 한 번은 실제로 돌아야 한다. **이번 스프린트 최대 리스크다.**

- [x] **C-1. P2의 Cloudflare endpoint 연결** ✅ `.env` 배선(`VIBECUTTER_LLM_ENDPOINTS=https://organizer-naturally-ann-viewers.trycloudflare.com/v1`, model=qwen3-235b, key). ⚠️ Quick Tunnel이라 재시작 시 URL 바뀜 — 데모 직전 재확인
- [x] **C-2. `python -m model.endpoints`가 `[UP]`을 보이는지 확인** ✅ **`[UP] primary ... qwen3-235b key:yes` 확인 — 스프린트 분기점 통과.** 라이브 rerank 실증: 235B가 candidate를 severity/exploitability 순으로 실제 재정렬(injection/critical→idor→xss), T-1 관측도 `llm_used=True/tier=primary` 실측
- [x] **C-3. `model/patch_client.py` 신규** — 계약 3.3 ✅ **완료·커밋(`379ce8c`… 실제 patch_client는 `935e362`)**. `build_patch_model_client()` + `_ChatPatchClient`, max_tokens 2048(>512). P1 배선 확인됨: `tools_repair.py:418 synthesize_fn=make_llm_synthesizer(_get_llm_client(), context_provider=_code_context_for)`
  - P3의 `PatchModelClient` 프로토콜은 `synthesize_patch(prompt: str) -> str` 하나뿐이다. **어댑터를 새로 짜지 않는다** — P3가 이미 만들었다(`a189c17`)
- [x] **C-4. P1에게 "client 준비됨" 공지** ✅ 공지함 → P1이 배선 #7 완료

---

## P1 — 조용한 degrade를 드러내기 (측정의 전제)

터널/endpoint가 죽은 채로 돈 run이 ablation 표본에 섞이면 **측정이 통째로 무의미해진다.** 내가 이미 D5에 지적한 문제이기도 하다("health/readiness가 false였던 run은 비교 표본에서 빼야 한다").

- [x] **T-1. `make_chained_chat_fn(on_fallback=)` 훅 활용** ✅ **완료·커밋(`379ce8c`)**. `make_observed_chain`/`observed_chat_fn_from_env`/`LlmCallOutcome`. 실패 카운트로 답한 tier 복원. 테스트 19/19
- [x] **T-2. run 메타데이터에 남기기** ✅ **end-to-end 완료(rebase로 P1 W-10 배선 병합됨)**. ①관측 `observed_chat_fn_from_env`(P4) → ②`tools_analysis._store_scan_candidates`가 `record_trajectory_step(result={**summary, **llm_outcome().as_metadata()})`로 병합(P1) → ③`llm_usage_from_trajectories`로 되읽음(P4, T-3와 같은 함수). `driver._llm_endpoint_state_for`도 같은 판독 경로 공유. contracts freeze 안 건드림(result dict)
- [x] **T-3. `eval`에서 이 값으로 표본을 거른다** ✅ **완료·커밋(`379ce8c`)**. `eval/sample_filter.py`(`filter_llm_condition`/`llm_used_map`), 보수적 all 정책. 테스트 7/7

---

## P2 — RAG 품질 (이미 배선됨, 개선만)

`origin/rag`(c8e48f8)에 배선 완료. main 병합 후 다음을 개선한다.

- [x] **G-1. idor sink 어휘 변별력** ✅ **완료**. `rag_enrich._relevance`를 매칭 개수 → **가중 합**으로 변경. 범용 CRUD 토큰(find/get/where/user/id=0.4) 깎고 접근제어 토큰(owner/authorize/permission=1.2) 올림. 범용만 있는 청크 1.0→0.67로 하락, 접근제어 청크는 1.0 유지 → 순위 갈림. **가중 없는 injection/xss는 기존과 동일**(회귀 방지 테스트 포함). rag_enrich 12/12, aggregate 9/9, surface_idor 5/5
- [ ] **G-2. 인덱스 캐시**(선택) — `CodeIndex.build`가 2806 chunks에 0.6초. 급하진 않지만 scan tool 3개 + `repair.locator`가 run당 4~5회 빌드한다. 캐시 키는 **경로+mtime** — 패치 적용 후 worktree는 소스가 바뀌므로 경로만으로는 stale해진다
- [x] **G-3. P3와 컨텍스트 빌더 공유 확인** ✅ **코드 확인 완료**. `tools_repair.py:_code_context_for`(P1)가 내 `rag_enrich.code_context()`를 `make_llm_synthesizer(context_provider=...)`(P3, `llm_synth.py:203/221`)에 배선 → rerank와 패치 합성이 같은 스니펫 생성기 공유. 조치 불필요

---

## P3 — 측정 (재정의된 RQ3)

**RQ3는 2026-07-21 회의에서 재정의 확정됐다.** "LoRA 학습한 모델이 base보다 나은가"는 **폐기**. 다시 제안하지 않는다.

> 새 RQ3: **RAG 코드 컨텍스트 + LLM 재랭킹이 휴리스틱 대비 가설 우선순위·패치 성공률을 개선하는가**

- [x] **E-1. ablation** ✅ **올바른 하네스 구축 + 235B 라이브 검증**. ⚠️ **plan 원안 정정**: `run_baseline`(focus-set precision/recall)로는 못 잼 — rerank는 candidate SET을 안 바꾸고 ORDER만 바꿔(FP reject는 rerank 前) 두 팔 지표가 동일. RQ3 '우선순위'는 **순위 지표**로 재야 맞음 → `eval/priority_ablation.py`(first_true_rank/MRR, 테스트 6/6). **라이브 235B: 진짜 취약점 순위 heuristic 2위→rag-llm 1위, MRR 0.5→1.0(Δ+0.5).**
  - **남은 것(P2 필요)**: 16개 벤치 앱 소스가 로컬에 없음(`.vibecutter/targets/sources/` 비어있음) → 전체 벤치 실주행은 P2 runtime 소스 확보 후. 기제·지표는 준비 완료
- [x] **E-2. `eval/compare.py` 문구 정리** ✅ **완료**. module docstring·CLI help의 fine-tuned/QLoRA 전제를 ablation(base=heuristic vs full=rag-llm)으로 교체. 로직·파라미터명 무변경, test_compare 4/4 그대로
- [x] **E-3. `mcp_server/tools_analysis.py:187`의 "RQ3" 주석** — 확인 결과 현재 주석("모델=가설 우선순위, RQ3")은 **새 RQ3와 정합** → 폐기된 LoRA-RQ3 참조 아님. **조치 불필요**(P1 요청 취소)
- [x] **E-4. 학습 경로는 삭제하지 않는다** ✅ 준수 — `train_lora.py`·`export_training_dataset()`·`to_sft_sample()` 보존. "구현했으나 데이터 부족으로 접음"이 발표 근거

---

## P4 — SARIF (P1과 짝)

- [x] **R-1. `eval/report_export.py`의 `render_sarif`는 이미 동작한다** ✅ 확인 완료(SARIF 2.1.0 valid). 내 렌더러 쪽 조치 없음
- [ ] **R-2. tool 배선은 P1이 한다** — `vc_export_sarif` 배선. 렌더러는 내 것, 배선은 P1. **P1 대기**(P1의 `vc_export_patch`는 됐으나 SARIF export 배선은 미확인)

---

## 하지 말 것

- ❌ **판정 경로에 LLM 주입** — 안전 불변식 3
- ❌ `contracts/schemas.py` 필드 추가 — D1 오전 이후 freeze. trajectory `result` dict를 쓴다
- ❌ `mcp_server/**`·`repair/**` 직접 수정 — 요청하고 소유자가 고친다
- ❌ **LoRA 학습 재개 제안** — 회의에서 폐기 확정
- ❌ `llm_synth` 어댑터 재작성 — P3가 이미 만들었다. 나는 `PatchModelClient`만

## 보고

계약 규칙 3 형식. **C-2(`[UP]` 확인)와 C-4(client 준비)는 P1·P3가 대기 중이라 완료 즉시 공지.**
