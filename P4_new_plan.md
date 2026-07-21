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

- [ ] **C-1. P2의 Cloudflare endpoint 연결** — G-3으로 URL을 받으면 `.env`의 `VIBECUTTER_LLM_ENDPOINTS`만 바꾸면 된다. 티어 체인(235B → 7B fallback)·`<think>` 제거·600초 timeout은 이미 `model/endpoints.py`에 있다
- [ ] **C-2. `python -m model.endpoints`가 `[UP]`을 보이는지 확인** — 이게 초록이 되는 순간이 이번 스프린트의 분기점이다
- [ ] **C-3. `model/patch_client.py` 신규** — 계약 3.3
  ```python
  def build_patch_model_client() -> Optional[PatchModelClient]:
      """chat_fn_from_env() 위 얇은 래퍼. prompt 문자열 → messages 1개 → diff 포함 응답.
      endpoint 불가 시 None (P3 어댑터가 no-op → template-only degrade)."""
  ```
  - P3의 `PatchModelClient` 프로토콜은 `synthesize_patch(prompt: str) -> str` 하나뿐이다. **어댑터를 새로 짜지 않는다** — P3가 이미 만들었다(`a189c17`)
  - 패치 합성은 rerank보다 출력이 길다. `max_tokens`를 rerank 기본값(512)보다 크게 잡을 것
- [ ] **C-4. P1에게 "client 준비됨" 공지** — P1의 L-1/L-2 배선이 이걸 기다린다

---

## P1 — 조용한 degrade를 드러내기 (측정의 전제)

터널/endpoint가 죽은 채로 돈 run이 ablation 표본에 섞이면 **측정이 통째로 무의미해진다.** 내가 이미 D5에 지적한 문제이기도 하다("health/readiness가 false였던 run은 비교 표본에서 빼야 한다").

- [ ] **T-1. `make_chained_chat_fn(on_fallback=)` 훅 활용** — 이미 시그니처가 있다. 어느 tier가 응답했는지 기록
- [ ] **T-2. run 메타데이터에 남기기** — `llm_used`(bool), `tier`(primary/fallback/none), `endpoint_health`
  ⚠️ **`contracts/schemas.py`는 D1 오전 이후 freeze**다. 스키마 필드를 더하지 말고 **trajectory step의 `result` dict**에 담는다(추가 계약 불필요)
- [ ] **T-3. `eval`에서 이 값으로 표본을 거른다** — `llm_used=False`인 run은 LLM 조건 표본에서 제외

---

## P2 — RAG 품질 (이미 배선됨, 개선만)

`origin/rag`(c8e48f8)에 배선 완료. main 병합 후 다음을 개선한다.

- [ ] **G-1. idor sink 어휘 변별력** — 실측: `find/get/where/user/id`가 너무 일반적이라 청크의 **44%가 relevance 0.67 이상**을 받는다(injection 0.9%, xss 2.6%는 정상). 우선순위 신호로 쓰려면 순위가 갈려야 한다
  - `authorize/permission/owner` 쪽에 가중치를 주거나, `CodeIndex._idf`(이미 계산돼 있다)로 흔한 토큰을 깎는다
- [ ] **G-2. 인덱스 캐시**(선택) — `CodeIndex.build`가 2806 chunks에 0.6초. 급하진 않지만 scan tool 3개 + `repair.locator`가 run당 4~5회 빌드한다. 캐시 키는 **경로+mtime** — 패치 적용 후 worktree는 소스가 바뀌므로 경로만으로는 stale해진다
- [ ] **G-3. P3와 컨텍스트 빌더 공유 확인** — `code_context()`가 P3의 `build_prompt`에도 쓰이는지. 계약 3.4

---

## P3 — 측정 (재정의된 RQ3)

**RQ3는 2026-07-21 회의에서 재정의 확정됐다.** "LoRA 학습한 모델이 base보다 나은가"는 **폐기**. 다시 제안하지 않는다.

> 새 RQ3: **RAG 코드 컨텍스트 + LLM 재랭킹이 휴리스틱 대비 가설 우선순위·패치 성공률을 개선하는가**

- [ ] **E-1. ablation 2회 주행** — `--label heuristic`(`VIBECUTTER_LLM_DISABLE=1`) vs `--label rag-llm`
  - 하네스는 **코드 변경 없이 재사용된다** — `eval/run_baseline.py`가 `--label`로 임의 두 산출물을 비교
  - 벤치마크 정답: `datasets/inventory_benchmark.yaml`
- [ ] **E-2. `eval/compare.py` 문구 정리** — `compare(base, full)`은 순수 함수라 **로직은 라벨 무관**이다. `base`/`full`이라는 **이름과 docstring만** fine-tuned 전제라 문구만 고친다(동작 영향 없음)
- [ ] **E-3. `mcp_server/tools_analysis.py:187`의 "RQ3" 주석** — P1 파일이므로 **내가 고치지 않고** P1에게 요청
- [ ] **E-4. 학습 경로는 삭제하지 않는다** — `model/train_lora.py`, `export_training_dataset()`, `to_sft_sample()`. trajectory 기록은 감사·리포트에 계속 쓰이고, "구현했으나 데이터 부족으로 접었다"가 발표 근거가 된다

---

## P4 — SARIF (P1과 짝)

- [ ] **R-1. `eval/report_export.py`의 `render_sarif`는 이미 동작한다** — P3가 real evidence(`run-897ad65c686f`)로 검증했고 SARIF 2.1.0 valid, CWE-639 result 1개 확인
- [ ] **R-2. tool 배선은 P1이 한다** — `vc_export_sarif`가 `NotImplementedError`인 건 `mcp_server/tools_repair.py`(P1 소유). 렌더러는 내 것, 배선은 P1. **내가 그 파일을 고치지 않는다**

---

## 하지 말 것

- ❌ **판정 경로에 LLM 주입** — 안전 불변식 3
- ❌ `contracts/schemas.py` 필드 추가 — D1 오전 이후 freeze. trajectory `result` dict를 쓴다
- ❌ `mcp_server/**`·`repair/**` 직접 수정 — 요청하고 소유자가 고친다
- ❌ **LoRA 학습 재개 제안** — 회의에서 폐기 확정
- ❌ `llm_synth` 어댑터 재작성 — P3가 이미 만들었다. 나는 `PatchModelClient`만

## 보고

계약 규칙 3 형식. **C-2(`[UP]` 확인)와 C-4(client 준비)는 P1·P3가 대기 중이라 완료 즉시 공지.**
