# P4 Model Serving 런북

> ⚠️ **2026-07-21 방향 변경**: 팀이 **학습(QLoRA) 포기 + 외부 72B API + LLM patch closed-loop**로
> 전환했다. 아래 **3절(QLoRA 학습)·4절(base vs fine-tuned 평가)은 취소**다(보존만 — 아래 각 절 상단 참조).
> 서빙도 **P4가 직접 설치하지 않고**, 외주가 GPU 3대에 72B를 올린 endpoint를 훅에 배선한다(2절).
> 7B는 72B 작동 확인 전까지 fallback tier로 유지한다. 평가는 base(SAST/7B) vs full(72B+RAG)
> ablation(`eval/compare.py`)으로 대체. — `plan-p4.md` 방향변경 배너가 최종 기준.

GPU 서버에서 **모델 서빙 → 파이프라인 훅 연결**을 돌리는 순서(1·2절). ~~QLoRA 학습 → base vs
full 평가~~는 취소(3·4절, 보존용). (통합 `RUNBOOK.md` 작성 시 이 문서를 P4 섹션으로 삽입.)

- **대상 하드웨어**: RTX 3090 24GB × 3 (camp1/2/3). 7B bf16 ≈ 15GB → 여유 있음.
- **base 모델**: `Qwen/Qwen2.5-Coder-7B-Instruct` (코드/보안 추론).
- **GPU 서버 Python**: **3.10** (서버 기본). ⚠️ 팀 공통 3.13은 **랩탑의 스캐너/eval 용**이고,
  **GPU 서버 서빙 venv는 3.10**이다(vLLM이 3.10에서 돎, 서버에 3.11+ 없음). 둘을 혼동 말 것.
- 접속 정보·정리(지난 팀 서비스 stop+disable)는 `P2_TARGET_RUNTIME_RUNBOOK` / D-P4 handoff 참고.

> **아래는 2026-07-20 밤 camp1에서 실제로 성공한 레시피다(camp2/3도 동일).** 이상적 버전이
> 아니라 겪은 함정까지 반영한 실전 순서 — 재부팅/재현 시 그대로 따르면 된다.

---

## 0. 환경 준비 (GPU 서버, 최초 1회)

```bash
# python3.10-venv 없으면 먼저 설치(서버마다 다름 — camp2엔 없었다):
apt-get install -y python3.10-venv
python3.10 -m venv /root/vibe-gpu
/root/vibe-gpu/bin/pip install -U pip
/root/vibe-gpu/bin/pip install vllm hf_transfer   # 최신 vllm(0.25.x). requirements-gpu.txt의
                                                  # vllm==0.6.6 핀은 드라이버 595엔 너무 옛날 → 최신 설치.
nvidia-smi        # 드라이버/VRAM 확인 (드라이버만 있고 CUDA 툴킷=nvcc는 없다 — 아래 5절 함정)
```

## 1. 모델 다운로드 (서빙 전에 미리 — 중요)

vLLM 내장 다운로더는 flaky HF 네트워크에서 **같은 shard를 중복 재다운로드**만 하고 수렴 못 한다.
반드시 `hf download`로 먼저 받는다(resume·병렬, 안정적):
```bash
HF_HUB_ENABLE_HF_TRANSFER=1 /root/vibe-gpu/bin/hf download Qwen/Qwen2.5-Coder-7B-Instruct
# ~15GB. 완료 확인: snapshots/*/model-000{1..4}-of-00004.safetensors 4개 존재
```

## 2. 모델 서빙 기동 (systemd-run — ssh 끊겨도 유지)

⚠️ **`nohup`/`setsid`로 띄우면 ssh 세션 종료 시 프로세스가 죽는다. `pkill -f "vllm serve"`는
자기 ssh 스크립트까지 죽여 255를 낸다.** → **systemd-run 유닛으로 띄운다.**

```bash
systemd-run --unit=vibe-vllm --collect \
  --setenv=VLLM_USE_FLASHINFER_SAMPLER=0 \
  --setenv=VLLM_ATTENTION_BACKEND=FLASH_ATTN \
  /root/vibe-gpu/bin/vllm serve Qwen/Qwen2.5-Coder-7B-Instruct \
  --host 127.0.0.1 --port 8000 \
  --gpu-memory-utilization 0.9 --max-model-len 8192 --enforce-eager
```
- **`--enforce-eager`**: torch.compile/CUDA그래프 캡처(느리고 조용히 멈춤) 건너뜀.
- **`VLLM_USE_FLASHINFER_SAMPLER=0` + `VLLM_ATTENTION_BACKEND=FLASH_ATTN`**: 5절 nvcc 함정 회피.
- **`--host 127.0.0.1`**: 외부 노출 금지(공유 root 서버). 접근은 SSH 터널로만.

기동 확인:
```bash
curl -s http://127.0.0.1:8000/v1/models     # "id":"Qwen/Qwen2.5-Coder-7B-Instruct" 나오면 OK
# 랩탑에서: ~/.ssh/config에 LocalForward 8001 localhost:8000 두고 `ssh camp1` 후:
python -c "from model.serving import health_check; print(health_check('http://localhost:8001/v1'))"
```
관리: `systemctl restart vibe-vllm` / `journalctl -u vibe-vllm -f` / `systemctl stop vibe-vllm`.
⚠️ systemd-run **transient** 유닛이라 **재부팅하면 사라짐**(정식 서비스 파일 필요 시 별도).

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

## 3. QLoRA 학습 (D4 밤 메인) — ❌ 취소(2026-07-21, 보존용)

> **이 절은 학습 포기로 취소됐다.** 아래 절차는 실행하지 않는다(기록 보존용). `train_lora.py`도
> 미사용. 성공 등급 입증은 학습이 아니라 4절→**ablation + LLM patch 성공률**로 한다.

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

## 4. base vs full ablation 평가 (OWASP Benchmark) — 학습 없이 ablation으로 대체

> **~~base(7B) vs fine-tuned~~ 는 취소.** 학습 대신 **base(SAST단독/7B) vs full(72B+RAG+prompt)**
> ablation 으로 성공 등급을 입증한다. 하네스(`eval/compare.py`·`eval/run_baseline.py`)는 모델
> 무관이라 그대로 재사용 — **두 candidate 디렉토리만 바꿔 넣으면 된다**(fine-tuned 어댑터 서빙 불필요).

`inventory_benchmark.yaml`(양성/음성 라벨: c2-04 IDOR양성, c1-05 IDOR양성/JWT, c2-05 IDOR음성 …)
대상으로 두 구성을 각각 돌려 후보셋을 비교:

```bash
# base 산출물 (SAST 단독 또는 7B):
python -m eval.run_baseline --candidates <base_candidates_dir> --label base \
    --benchmark datasets/inventory_benchmark.yaml
# full 산출물 (72B + RAG rerank/embed 훅 연결):
python -m eval.run_baseline --candidates <full_candidates_dir> --label full \
    --benchmark datasets/inventory_benchmark.yaml
# eval.baseline 이 precision/recall/FPR/F1 과 OWASP Benchmark score(TPR-FPR) 산출.
# 같은 harness(eval.compare)로 base vs full 비교 → 발표 자료 표.
```

**추가**: LLM patch closed-loop 성공률(게이트별 통과율 + FIXED 성공률)은 별도 평가 하네스로
집계한다(`Validation` 6게이트 필드 소비 — `core.judge.compute_verdict` 와 같은 계약).

---

## 5. 함정 / 트러블슈팅 (2026-07-20 실전 기록)

| 증상 | 원인 | 해결 |
| --- | --- | --- |
| `RuntimeError: Could not find nvcc and default cuda_home` | 서버에 드라이버는 있으나 **CUDA 툴킷(nvcc) 없음**. vLLM `flashinfer.sampling`이 커널을 JIT 컴파일하려다 실패 | **`VLLM_USE_FLASHINFER_SAMPLER=0`** + **`VLLM_ATTENTION_BACKEND=FLASH_ATTN`** (native 샘플러 사용, nvcc 불필요) |
| ssh 끊으면 서빙 죽음, `nohup`도 안 먹힘 | 세션 종료 시 SIGHUP/프로세스그룹 정리 | **systemd-run 유닛**으로 기동 |
| ssh 명령이 계속 exit 255 | `pkill -f "vllm serve"`가 **자기 ssh 스크립트**(cmdline에 "vllm serve" 포함)를 죽임 | pkill 금지 → **PID로만 kill**(`nvidia-smi --query-compute-apps=pid`) |
| startup이 로그 없이 멈춤(`flash_attn`에서) | torch.compile/CUDA그래프 캡처가 느리고 조용함 | **`--enforce-eager`** |
| 다운로드가 수렴 못 하고 `.incomplete`만 쌓임 | vLLM 내장 다운로더가 flaky HF에서 중복 재시도 | 서빙 전에 **`hf download`**로 미리 받기 |
| 새 vllm이 "Free memory ... less than 0.9" 로 실패 | 이전 실행의 **orphan EngineCore**가 GPU 점유 | `nvidia-smi` PID kill 후 재기동 |
| `systemd-run` 이 "Unit already exists" | 이전 유닛 잔존 | `systemctl reset-failed vibe-vllm` 후 재시도 |
| 서버가 이미 VRAM 거의 참 | 지난 팀 systemd 서비스(vLLM/SD/Whisper) auto-restart | 해당 `.service` **stop + disable**(단 `gpu-manager.service`는 시스템 것, 건드리지 말 것) |

## 검증된 사실 / 주의

- **semgrep 은 3.11~3.13 정상, 3.14 만 실행 불가**(opentelemetry). SAST 실주행은 P4 가
  WSL/Linux(3.13)에서 담당. Windows 팀원은 WSL/Docker. (버전과 무관한 OS 문제)
- 서빙/학습 코드의 **순수 로직은 GPU 없이 유닛테스트**됨:
  `python -m model.test_serving`, `python -m model.test_train_lora`.
- 학습 프롬프트 템플릿은 `model.train_lora.sft_text()` 에 있다 — 바꾸면 여기와
  `to_sft_sample()` 계약을 함께 확인한다.
