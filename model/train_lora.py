"""7B QLoRA 학습 스크립트 (P4, GPU STEP / D4 밤 메인).

⚠️ **2026-07-21 팀 결정으로 학습(LoRA) 포기 — 이 스크립트는 미사용(보존용).**
방향이 "외부 72B API + LLM patch closed-loop"로 바뀌면서 fine-tuning 을 접었다. 파이프라인
어디에서도 import 하지 않는다(독립 실행 스크립트). 삭제하지 않는 이유: (1) GPU 학습
파이프라인까지 구축했다는 작업 증거, (2) 방향 전환의 근거 자료. 모델 배선은 이 스크립트가
아니라 `model/serving.py` 의 72B 훅(`make_chained_chat_fn` 등)으로 대체됐다.
평가도 "base(7B) vs fine-tuned" 가 아니라 "base(SAST/7B) vs full(72B+RAG)" ablation 이며,
`eval/compare.py` 가 그 용도로 재사용된다. — 자세한 건 `plan-p4.md` 방향변경 배너 참조.

입력: P1 이 `core.trajectory.export_training_dataset()` 로 뽑는
`.vibecutter/trajectories/export/training_samples.jsonl` — 각 줄이 P4 의
`model.trajectory.to_sft_sample()` 포맷(=이 저장소가 정한 학습 계약)이다.

이 스크립트는 두 층으로 나뉜다(프로젝트의 순수+wrapper 패턴):
- **순수 데이터 준비**(`load_sft_samples`/`sft_text`/`build_texts`): torch 불필요 →
  GPU 없이 유닛테스트. 프롬프트 템플릿을 여기서 확정한다.
- **학습**(`train`): torch/transformers/peft/trl 를 **함수 안에서 지연 import** →
  GPU 서버(requirements-gpu.txt)에서만 무거운 의존성을 요구한다.

대상: 24GB VRAM + Qwen2.5-Coder-7B-Instruct, 4bit QLoRA.
평가는 학습 후 `eval.baseline` 으로 base vs fine-tuned 를 OWASP Benchmark 비교한다.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable, Optional

DEFAULT_MODEL = "Qwen/Qwen2.5-Coder-7B-Instruct"
DEFAULT_EXPORT = ".vibecutter/trajectories/export/training_samples.jsonl"

# label → reward 기본값(reward 없이 label 만 있는 스텝의 학습 가중치 계산용, 참고).
_LABEL_REWARD = {"fixed": 1.0, "verified": 1.0, "rejected": 0.0, "human_review": 0.5}


# --- 순수 데이터 준비 (GPU 불필요) -----------------------------------------------------

def load_sft_samples(path: str | Path) -> list[dict]:
    """P1 export(JSONL, 줄마다 to_sft_sample dict) 를 읽는다."""
    p = Path(path)
    if not p.exists():
        raise SystemExit(
            f"export 가 아직 없다: {p}\n"
            "실제 verified/fixed evidence 가 나온 뒤 P1 의 "
            "core.trajectory.export_training_dataset() 를 먼저 돌려야 한다(cowork_rule §5)."
        )
    out: list[dict] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def _evidence_block(sample: dict) -> str:
    ev = sample.get("evidence") or []
    if not ev:
        return "(none)"
    return "\n".join(f"- {e.get('type')} {e.get('uri')} ({e.get('hash')})" for e in ev)


def sft_text(sample: dict) -> dict:
    """to_sft_sample dict → {prompt, completion, text}.

    prompt 는 (state, action, evidence) 를, completion 은 result(모델이 내야 할 것)를
    담는다. text 는 둘을 합친 SFT 단일 필드. 실제 특수토큰/채팅템플릿은 학습 시
    tokenizer.apply_chat_template 로 감쌀 수도 있으나, 여기선 모델 불문 텍스트로 둔다.
    """
    inp = sample.get("input", {})
    state = inp.get("state", "")
    action = inp.get("action", "")
    prompt = (
        f"### State\n{state}\n\n"
        f"### Evidence\n{_evidence_block(sample)}\n\n"
        f"### Action\n{action}\n\n"
        f"### Result\n"
    )
    completion = str(sample.get("output", "") or "")
    return {"prompt": prompt, "completion": completion, "text": prompt + completion}


def build_texts(samples: Iterable[dict]) -> list[dict]:
    """SFT 샘플들 → 학습용 {prompt,completion,text} 리스트. 빈 completion 은 제외."""
    rows = [sft_text(s) for s in samples]
    return [r for r in rows if r["completion"].strip()]


def dataset_label_stats(samples: Iterable[dict]) -> dict:
    """학습셋 row 수 + label 분포 (팀 요청 Task 3: 학습 시작 전 공유용).

    export(training_samples.jsonl)는 이미 `training_samples()`로 verified/fixed/rejected/
    human_review 만 남긴 상태다 — 여기서 그 분포를 센다."""
    from collections import Counter
    samples = list(samples)
    by_label = Counter(str(s.get("label") or "unlabeled") for s in samples)
    by_run = Counter(str(s.get("run_id") or "?") for s in samples)
    return {"rows": len(samples), "by_label": dict(sorted(by_label.items())),
            "by_run_id": dict(sorted(by_run.items()))}


def filter_by_run_ids(samples: Iterable[dict], run_ids: Optional[set[str]]) -> list[dict]:
    """실 run_id 로만 학습하도록 필터 (P3 데이터위생 요청: unittest 가 같은 trajectory
    디렉토리에 test-생성 궤적을 섞으므로, run_ids 를 주면 그 run 만 남긴다). None 이면 전부."""
    rows = list(samples)
    if not run_ids:
        return rows
    return [s for s in rows if str(s.get("run_id")) in run_ids]


def filter_by_labels(samples: Iterable[dict], labels: Optional[set[str]]) -> list[dict]:
    """지정 label 만 학습에 쓴다(예: verified,fixed,rejected,human_review — unlabeled 제외).

    export 는 reward 만 있고 label 이 없는 스텝도 포함하므로(`training_samples()` 규칙),
    라벨 품질을 올리려면 여기서 한 번 더 좁힌다. None 이면 전부."""
    rows = list(samples)
    if not labels:
        return rows
    return [s for s in rows if str(s.get("label") or "unlabeled") in labels]


# --- 학습 (GPU 전용, 지연 import) ------------------------------------------------------

def train(
    export_path: str | Path = DEFAULT_EXPORT,
    *,
    base_model: str = DEFAULT_MODEL,
    output_dir: str = ".vibecutter/models/lora-7b",
    epochs: float = 3.0,
    batch_size: int = 1,
    grad_accum: int = 16,
    lr: float = 2e-4,
    max_seq_len: int = 2048,
    run_ids: Optional[set[str]] = None,
    labels: Optional[set[str]] = None,
) -> str:
    """QLoRA(4bit) SFT. torch/transformers/peft/trl 필요(requirements-gpu.txt).

    반환: 어댑터가 저장된 output_dir.
    """
    # 무거운 의존성은 여기서만.
    import torch
    from datasets import Dataset
    from peft import LoraConfig, prepare_model_for_kbit_training
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        BitsAndBytesConfig,
    )
    from trl import SFTConfig, SFTTrainer

    samples = filter_by_labels(filter_by_run_ids(load_sft_samples(export_path), run_ids), labels)
    rows = build_texts(samples)
    if run_ids:
        print(f"[train] run_id 필터: {len(run_ids)}개 → {len(samples)} rows")
    if labels:
        print(f"[train] label 필터: {sorted(labels)} → {len(samples)} rows")
    if not rows:
        raise SystemExit(
            f"학습 샘플이 없다: {export_path}. 실제 verified/fixed evidence 가 나온 뒤 "
            "P1 export 를 먼저 돌려야 한다(cowork_rule §5)."
        )
    print(f"[train] samples={len(rows)} base={base_model}")

    bnb = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )
    tok = AutoTokenizer.from_pretrained(base_model)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    model = AutoModelForCausalLM.from_pretrained(
        base_model, quantization_config=bnb, device_map="auto", torch_dtype=torch.bfloat16,
    )
    model = prepare_model_for_kbit_training(model)

    peft_cfg = LoraConfig(
        r=16, lora_alpha=32, lora_dropout=0.05, bias="none", task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
    )
    ds = Dataset.from_list([{"text": r["text"]} for r in rows])
    # trl>=1.0 은 SFTConfig 인자가 max_seq_length → max_length 로 바뀌었다(GPU서버 실측:
    # trl 1.8). 구/신 버전 모두 지원하도록 있는 인자로 넣는다.
    import inspect
    _seq_kw = "max_length" if "max_length" in inspect.signature(SFTConfig).parameters \
        else "max_seq_length"
    cfg = SFTConfig(
        output_dir=output_dir, num_train_epochs=epochs,
        per_device_train_batch_size=batch_size, gradient_accumulation_steps=grad_accum,
        learning_rate=lr, bf16=True, **{_seq_kw: max_seq_len},
        logging_steps=5, save_strategy="epoch", report_to=[],
    )
    trainer = SFTTrainer(model=model, args=cfg, train_dataset=ds, peft_config=peft_cfg)
    trainer.train()
    trainer.save_model(output_dir)
    tok.save_pretrained(output_dir)
    print(f"[train] saved adapter → {output_dir}")
    return output_dir


def _main() -> None:
    ap = argparse.ArgumentParser(description="7B QLoRA 학습 (P4)")
    ap.add_argument("--export", default=DEFAULT_EXPORT, help="training_samples.jsonl 경로")
    ap.add_argument("--base-model", default=DEFAULT_MODEL)
    ap.add_argument("--output-dir", default=".vibecutter/models/lora-7b")
    ap.add_argument("--epochs", type=float, default=3.0)
    ap.add_argument("--run-ids", default=None,
                    help="실 run_id 만 학습(쉼표구분). P3 데이터위생: test 궤적 배제")
    ap.add_argument("--labels", default=None,
                    help="이 label 만 학습(쉼표구분, 예: verified,fixed,rejected,human_review)")
    ap.add_argument("--dry-run", action="store_true",
                    help="학습 없이 데이터 준비만 검증(GPU 불필요)")
    args = ap.parse_args()

    run_ids = {r.strip() for r in args.run_ids.split(",") if r.strip()} if args.run_ids else None
    labels = {l.strip() for l in args.labels.split(",") if l.strip()} if args.labels else None

    if args.dry_run:
        samples = filter_by_labels(filter_by_run_ids(load_sft_samples(args.export), run_ids), labels)
        rows = build_texts(samples)
        st = dataset_label_stats(samples)
        # Task 3(팀 요청): 학습 시작 전 dataset row 수 + label 분포 공유.
        print(f"[dry-run] dataset rows={st['rows']} (학습가능/completion有={len(rows)})"
              + (f" | run_id 필터={sorted(run_ids)}" if run_ids else " | run_id 필터 없음(전체)"))
        print(f"[dry-run] label 분포: {st['by_label']}")
        print(f"[dry-run] run_id별: {st['by_run_id']}")
        if rows:
            print("--- 첫 샘플 text ---")
            print(rows[0]["text"][:600])
        return
    train(args.export, base_model=args.base_model,
          output_dir=args.output_dir, epochs=args.epochs, run_ids=run_ids, labels=labels)


if __name__ == "__main__":
    _main()
