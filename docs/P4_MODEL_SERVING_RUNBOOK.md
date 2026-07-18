# P4 Model Serving / 학습 런북

GPU 서버에서 **모델 서빙 → 파이프라인 훅 연결 → QLoRA 학습 → base vs full 평가**를
돌리는 순서. (통합 `RUNBOOK.md` 작성 시 이 문서를 P4 섹션으로 삽입 — plan.md §Day4.)

- **대상 하드웨어**: 24GB VRAM (3090/4090/A5000).
- **base 모델**: `Qwen/Qwen2.5-Coder-7B-Instruct` (코드/보안 추론, 4bit QLoRA).
- **Python**: 3.13 (팀 통일, `.python-version`). semgrep 등 공통 도구와 동일.
- GPU 서버 접속 정보는 P2 가 제공한다(`P2_TARGET_RUNTIME_RUNBOOK` §GPU).

---

## 0. 환경 준비 (GPU 서버, 최초 1회)

```bash
python3.13 -m venv .venv-gpu
source .venv-gpu/bin/activate
pip install -r requirements.txt -r requirements-gpu.txt
# torch CUDA 빌드가 안 잡히면:
#   pip install torch==2.5.1 --index-url https://download.pytorch.org/whl/cu121
nvidia-smi        # VRAM/드라이버 확인
```

> torch/vllm/bitsandbytes 는 **GPU 서버에서만** 설치한다. 공통 `requirements.txt`
> 에는 넣지 않는다(P1/P2/P3·Windows 머신 오염 방지). → `requirements-gpu.txt` 분리.

## 1. 모델 서빙 기동 (vLLM = OpenAI 호환 endpoint)

```bash
python -m vllm.entrypoints.openai.api_server \
    --model Qwen/Qwen2.5-Coder-7B-Instruct \
    --port 8000 --max-model-len 8192
# 24GB 에 7B bf16 ≈ 15GB. 학습과 동시 사용 시엔 4bit(AWQ) 가중치로 서빙.
```

기동 확인:
```bash
python -c "from model.serving import health_check; print(health_check('http://localhost:8000/v1'))"
# True 면 endpoint 정상. (Day1 완료기준 '모델 endpoint 응답' 충족)
```

## 2. 파이프라인 훅 연결 (서빙된 모델을 aggregate/code_index 에)

```python
from model.serving import openai_chat_fn, make_rerank_fn, openai_embed_call, make_embed_fn
from scanners.aggregate import aggregate
from model.code_index import CodeIndex

BASE = "http://localhost:8000/v1"

# (a) LLM 재랭킹 → aggregate 의 rerank_fn 자리
rerank = make_rerank_fn(openai_chat_fn(BASE, "Qwen/Qwen2.5-Coder-7B-Instruct"))
result = aggregate(sast_cands, sca_cands, rerank_fn=rerank)   # result.kept 가 LLM 재정렬됨

# (b) 임베딩 검색 → code_index.search 의 embed_fn 자리 (임베딩 모델을 별도 서빙한 경우)
embed = make_embed_fn(openai_embed_call(BASE_EMBED, "<embedding-model>"))
hits = CodeIndex.build(root).search("idor user id", k=5, embed_fn=embed)
```

- 훅 실패(endpoint down/파싱오류) 시 **비파괴**: rerank 는 입력 순서 유지, search 는
  embed_fn 없이 호출하면 BM25 로 자동 폴백. 데모 중 endpoint 죽어도 파이프라인은 산다.

## 3. QLoRA 학습 (D4 밤 메인)

**선행 조건**: 실제 `verified`/`fixed` evidence 가 나와서 P1 이
`core.trajectory.export_training_dataset()` 로 학습셋을 뽑아둔 상태
(`.vibecutter/trajectories/export/training_samples.jsonl`). — cowork_rule §5.

```bash
# 데이터 먼저 점검(GPU 불필요):
python -m model.train_lora --dry-run
# 학습:
python -m model.train_lora \
    --export .vibecutter/trajectories/export/training_samples.jsonl \
    --base-model Qwen/Qwen2.5-Coder-7B-Instruct \
    --output-dir .vibecutter/models/lora-7b --epochs 3
# → 어댑터가 .vibecutter/models/lora-7b 에 저장된다.
```

## 4. base vs fine-tuned 평가 (OWASP Benchmark)

fine-tuned 어댑터를 vLLM 로 서빙(`--enable-lora --lora-modules ...`)한 뒤,
`inventory_benchmark.yaml`(양성/음성 라벨: c2-04 IDOR양성, c1-05 IDOR양성/JWT,
c2-05 IDOR음성 …) 대상으로 파이프라인을 돌리고 두 후보셋을 비교:

```bash
# base 산출물:
python -m eval.run_baseline --candidates <base_candidates_dir> --label base \
    --benchmark datasets/inventory_benchmark.yaml
# fine-tuned 산출물:
python -m eval.run_baseline --candidates <full_candidates_dir> --label full \
    --benchmark datasets/inventory_benchmark.yaml
# eval.baseline 이 precision/recall/FPR/F1 과 OWASP Benchmark score(TPR-FPR) 산출.
# 같은 harness 로 base vs full 비교 → 발표 자료 표.
```

---

## 검증된 사실 / 주의

- **semgrep 은 3.11~3.13 정상, 3.14 만 실행 불가**(opentelemetry). SAST 실주행은 P4 가
  WSL/Linux(3.13)에서 담당. Windows 팀원은 WSL/Docker. (버전과 무관한 OS 문제)
- 서빙/학습 코드의 **순수 로직은 GPU 없이 유닛테스트**됨:
  `python -m model.test_serving`, `python -m model.test_train_lora`.
- 학습 프롬프트 템플릿은 `model.train_lora.sft_text()` 에 있다 — 바꾸면 여기와
  `to_sft_sample()` 계약을 함께 확인한다.
