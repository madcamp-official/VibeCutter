"""model.train_lora 데이터 준비 단위 테스트 (torch/GPU 불필요).

train() 은 GPU 전용이라 여기선 순수 데이터 준비(load/sft_text/build_texts)만 검증한다.
실행: python -m model.test_train_lora
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from model.train_lora import build_texts, dataset_label_stats, load_sft_samples, sft_text

# to_sft_sample() 이 내는 형태와 동일한 샘플.
_SAMPLE = {
    "input": {"state": "VERIFYING", "action": "verify_idor(c2-04)"},
    "output": "verified: cross-user read confirmed",
    "label": "verified",
    "reward": 1.0,
    "run_id": "run-1",
    "evidence": [
        {"type": "http_pair", "uri": "art://ev/1", "hash": "abc", "producer": "P3"},
    ],
}


def test_sft_text_has_prompt_completion_and_evidence() -> None:
    out = sft_text(_SAMPLE)
    assert out["completion"] == "verified: cross-user read confirmed"
    assert "### State\nVERIFYING" in out["prompt"]
    assert "verify_idor(c2-04)" in out["prompt"]
    assert "http_pair art://ev/1 (abc)" in out["prompt"]      # evidence 조인됨
    assert out["text"] == out["prompt"] + out["completion"]


def test_sft_text_handles_missing_evidence() -> None:
    out = sft_text({"input": {"state": "S", "action": "A"}, "output": "R"})
    assert "(none)" in out["prompt"] and out["completion"] == "R"


def test_build_texts_drops_empty_completion() -> None:
    samples = [
        _SAMPLE,
        {"input": {"state": "S", "action": "A"}, "output": ""},   # completion 없음 → 제외
        {"input": {"state": "S", "action": "A"}, "output": "   "},  # 공백만 → 제외
    ]
    rows = build_texts(samples)
    assert len(rows) == 1 and rows[0]["completion"].startswith("verified")


def test_load_sft_samples_reads_jsonl() -> None:
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "training_samples.jsonl"
        p.write_text(json.dumps(_SAMPLE) + "\n\n" + json.dumps(_SAMPLE) + "\n",
                     encoding="utf-8")
        rows = load_sft_samples(p)
        assert len(rows) == 2 and rows[0]["run_id"] == "run-1"   # 빈 줄은 건너뜀


def test_dataset_label_stats() -> None:
    # 팀 요청 Task 3: row 수 + label 분포. export 는 이미 검증된 것만 포함.
    samples = [
        {"input": {}, "output": "x", "label": "verified"},
        {"input": {}, "output": "y", "label": "fixed"},
        {"input": {}, "output": "z", "label": "verified"},
        {"input": {}, "output": "w", "label": "rejected"},
        {"input": {}, "output": "v"},   # label 없음 → unlabeled
    ]
    st = dataset_label_stats(samples)
    assert st["rows"] == 5
    assert st["by_label"] == {"fixed": 1, "rejected": 1, "unlabeled": 1, "verified": 2}


def _run() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")


if __name__ == "__main__":
    _run()
