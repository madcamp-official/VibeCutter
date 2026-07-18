"""7B QLoRA 학습 스크립트 (P4, GPU STEP / D4 밤 메인).

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
from typing import Iterable

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

    rows = build_texts(load_sft_samples(export_path))
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
    cfg = SFTConfig(
        output_dir=output_dir, num_train_epochs=epochs,
        per_device_train_batch_size=batch_size, gradient_accumulation_steps=grad_accum,
        learning_rate=lr, max_seq_length=max_seq_len, bf16=True,
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
    ap.add_argument("--dry-run", action="store_true",
                    help="학습 없이 데이터 준비만 검증(GPU 불필요)")
    args = ap.parse_args()

    if args.dry_run:
        rows = build_texts(load_sft_samples(args.export))
        print(f"[dry-run] 학습 가능 샘플 {len(rows)}개")
        if rows:
            print("--- 첫 샘플 text ---")
            print(rows[0]["text"][:600])
        return
    train(args.export, base_model=args.base_model,
          output_dir=args.output_dir, epochs=args.epochs)


if __name__ == "__main__":
    _main()
