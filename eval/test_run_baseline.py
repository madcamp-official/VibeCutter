"""eval.run_baseline 단위 테스트. 실행: python -m eval.test_run_baseline"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from contracts.schemas import Candidate
from eval.run_baseline import (
    baseline_report,
    predictions_from_candidate_dir,
)


def _write_jsonl(path: Path, cands: list[Candidate]) -> None:
    path.write_text(
        "".join(json.dumps(c.model_dump(mode="json"), ensure_ascii=False) + "\n" for c in cands),
        encoding="utf-8",
    )


def _cand(id, focus=None, category_sca=False) -> Candidate:
    signals = ["semgrep:x"]
    if focus:
        signals.append(f"focus:{focus}")
    if category_sca:
        signals = ["sca:osv", "category:sca"]
    return Candidate(id=id, run_id="r", signals=signals)


def test_predictions_from_dir_group_focus_per_app() -> None:
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        _write_jsonl(d / "juice-shop.candidates.jsonl",
                     [_cand("a", "xss"), _cand("b", "injection"), _cand("c", category_sca=True)])
        _write_jsonl(d / "webgoat.candidates.jsonl", [_cand("d", "idor")])
        preds = predictions_from_candidate_dir(d)
        assert preds["juice-shop"] == {"xss", "injection"}   # sca 는 focus 없음 → 제외
        assert preds["webgoat"] == {"idor"}


def test_baseline_report_against_truth() -> None:
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        # juice-shop: 정답 {xss,injection,idor} 중 xss,injection 만 탐지(idor 미탐)
        _write_jsonl(d / "juice-shop.candidates.jsonl", [_cand("a", "xss"), _cand("b", "injection")])
        truth = {"juice-shop": {"xss", "injection", "idor"}}
        report = baseline_report(d, truth)
        o = report.overall
        assert (o.tp, o.fp, o.fn, o.tn) == (2, 0, 1, 0)   # idor 미탐 = FN 1
        assert report.per_group["idor"].fn == 1


def test_empty_dir_all_negative() -> None:
    with tempfile.TemporaryDirectory() as td:
        truth = {"juice-shop": {"xss"}}
        report = baseline_report(td, truth)   # 예측 파일 없음
        assert report.overall.fn == 1 and report.overall.tp == 0


def _run() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")


if __name__ == "__main__":
    _run()
