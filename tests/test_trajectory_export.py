"""core.trajectory.export_training_dataset (Day4, P4 밤 배치 전제) 테스트.

새 필터링/변환 로직을 만들지 않고 P4의 `model.trajectory.training_samples()`/
`to_sft_sample()`을 그대로 재사용하므로, 여기서는 "여러 run을 모아 하나로 묶고,
label 없는 스텝은 제외하고, evidence를 조인하는" 새로 추가된 부분만 확인한다.
"""

from __future__ import annotations

import json
import unittest
from tempfile import TemporaryDirectory
from pathlib import Path
from uuid import uuid4

from contracts.schemas import RunState
from core.evidence_store import write_artifact
from core.trajectory import TRAJECTORY_DIR, export_training_dataset, record_trajectory_step


def _run_id() -> str:
    return f"run-{uuid4().hex[:12]}"


class ExportTrainingDatasetTests(unittest.TestCase):
    def tearDown(self) -> None:
        # 이 테스트가 만든 run trajectory 파일을 지워 다른 테스트의 "모든 run" 스캔에
        # 섞여 들어가지 않게 한다.
        for path in getattr(self, "_created_paths", []):
            path.unlink(missing_ok=True)

    def _record(self, run_id: str, **kwargs) -> None:
        path = TRAJECTORY_DIR / f"{run_id}.jsonl"
        self._created_paths = getattr(self, "_created_paths", []) + [path]
        record_trajectory_step(run_id, **kwargs)

    def test_excludes_unlabeled_steps(self) -> None:
        run_id = _run_id()
        self._record(
            run_id,
            state=RunState.VERIFYING,
            action={"tool": "vc_verify_access_control"},
            result={"verified": True},
            next_state=RunState.VERIFIED,
            label=None,  # unlabeled — 제외돼야 한다
        )
        self._record(
            run_id,
            state=RunState.VALIDATING,
            action={"tool": "vc_build_and_test"},
            result={"verdict": "fixed"},
            next_state=RunState.FIXED,
            label="fixed",
        )

        with TemporaryDirectory() as tmp:
            out = export_training_dataset(Path(tmp) / "out.jsonl", run_ids=[run_id])
            lines = out.read_text(encoding="utf-8").splitlines()

        self.assertEqual(len(lines), 1)
        sample = json.loads(lines[0])
        self.assertEqual(sample["label"], "fixed")
        self.assertEqual(sample["run_id"], run_id)

    def test_joins_run_evidence(self) -> None:
        run_id = _run_id()
        artifact = write_artifact(
            run_id, observation_type="log", producer="test", data=b"evidence body"
        )
        self._record(
            run_id,
            state=RunState.VALIDATING,
            action={"tool": "vc_build_and_test"},
            result={"verdict": "fixed"},
            next_state=RunState.FIXED,
            label="fixed",
        )

        with TemporaryDirectory() as tmp:
            out = export_training_dataset(Path(tmp) / "out.jsonl", run_ids=[run_id])
            sample = json.loads(out.read_text(encoding="utf-8").splitlines()[0])

        evidence_ids = [e["hash"] for e in sample["evidence"]]
        self.assertIn(artifact.hash, evidence_ids)

    def test_combines_multiple_runs_in_one_file(self) -> None:
        run_a, run_b = _run_id(), _run_id()
        for run_id in (run_a, run_b):
            self._record(
                run_id,
                state=RunState.VALIDATING,
                action={"tool": "vc_build_and_test"},
                result={"verdict": "fixed"},
                next_state=RunState.FIXED,
                label="fixed",
            )

        with TemporaryDirectory() as tmp:
            out = export_training_dataset(Path(tmp) / "out.jsonl", run_ids=[run_a, run_b])
            samples = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]

        self.assertEqual({s["run_id"] for s in samples}, {run_a, run_b})

    def test_missing_run_id_is_skipped_not_erroring(self) -> None:
        with TemporaryDirectory() as tmp:
            out = export_training_dataset(Path(tmp) / "out.jsonl", run_ids=["run-does-not-exist"])
            self.assertEqual(out.read_text(encoding="utf-8"), "")

    def test_default_output_path_under_export_dir(self) -> None:
        run_id = _run_id()
        self._record(
            run_id,
            state=RunState.VALIDATING,
            action={"tool": "vc_build_and_test"},
            result={"verdict": "fixed"},
            next_state=RunState.FIXED,
            label="fixed",
        )

        out = export_training_dataset(run_ids=[run_id])
        try:
            self.assertTrue(out.is_relative_to(TRAJECTORY_DIR))
            self.assertTrue(out.exists())
        finally:
            out.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
