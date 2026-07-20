"""candidate-per-worker-Run 오케스트레이션 테스트 (Extra Day 1B).

`materialize_worker_run()`이 D5-P2.md 계약(worker Run 생성 + candidate 복제 + lineage 보존,
원본 불변)을 지키는지 확인한다.
"""

from __future__ import annotations

import unittest
from uuid import uuid4

from contracts.schemas import Candidate, Run, RunState
from core.evidence_store import get, save
from core.orchestrator import materialize_worker_run


def _scan_run(target_id: str = "26s-w1-c1-03") -> Run:
    run = Run(
        id=f"run-{uuid4().hex[:12]}",
        target_id=target_id,
        tool_versions={"semgrep": "1.90.0"},
        status=RunState.CANDIDATE_SCAN,
    )
    save(run)
    return run


def _scan_candidate(run_id: str) -> Candidate:
    candidate = Candidate(
        id=f"cand-{uuid4().hex[:12]}",
        run_id=run_id,
        cwe="CWE-639",
        vuln_class="idor",
        attack_params={"base_url": "http://127.0.0.1:14005", "victim_id": "42"},
    )
    save(candidate)
    return candidate


class MaterializeWorkerRunTests(unittest.TestCase):
    def test_creates_worker_run_sharing_target_in_candidate_scan(self) -> None:
        scan_run = _scan_run()
        scan_candidate = _scan_candidate(scan_run.id)

        worker_run, _ = materialize_worker_run(scan_run, scan_candidate)

        self.assertNotEqual(worker_run.id, scan_run.id)
        self.assertEqual(worker_run.target_id, scan_run.target_id)
        self.assertEqual(worker_run.tool_versions, scan_run.tool_versions)
        self.assertEqual(worker_run.status, RunState.CANDIDATE_SCAN)
        self.assertIsNotNone(worker_run.started_at)
        self.assertEqual(get(Run, worker_run.id).target_id, scan_run.target_id)

    def test_worker_candidate_copies_fields_and_preserves_lineage(self) -> None:
        scan_run = _scan_run()
        scan_candidate = _scan_candidate(scan_run.id)

        worker_run, worker_candidate = materialize_worker_run(scan_run, scan_candidate)

        self.assertNotEqual(worker_candidate.id, scan_candidate.id)
        self.assertEqual(worker_candidate.run_id, worker_run.id)
        self.assertEqual(worker_candidate.origin_candidate_id, scan_candidate.id)
        # typed 공격 파라미터/분류는 그대로 복제돼 verifier가 바로 소비 가능해야 한다.
        self.assertEqual(worker_candidate.vuln_class, "idor")
        self.assertEqual(worker_candidate.attack_params, scan_candidate.attack_params)
        self.assertEqual(worker_candidate.cwe, "CWE-639")
        # 저장까지 확인.
        reloaded = get(Candidate, worker_candidate.id)
        self.assertEqual(reloaded.origin_candidate_id, scan_candidate.id)

    def test_original_scan_candidate_and_run_are_untouched(self) -> None:
        scan_run = _scan_run()
        scan_candidate = _scan_candidate(scan_run.id)

        materialize_worker_run(scan_run, scan_candidate)

        # 원본 scan candidate: run_id를 덮어쓰지 않고, 자신은 lineage가 None.
        reloaded_candidate = get(Candidate, scan_candidate.id)
        self.assertEqual(reloaded_candidate.run_id, scan_run.id)
        self.assertIsNone(reloaded_candidate.origin_candidate_id)
        # scan Run은 CANDIDATE_SCAN에 그대로.
        self.assertEqual(get(Run, scan_run.id).status, RunState.CANDIDATE_SCAN)

    def test_two_candidates_get_independent_worker_runs(self) -> None:
        scan_run = _scan_run()
        c1 = _scan_candidate(scan_run.id)
        c2 = _scan_candidate(scan_run.id)

        wr1, wc1 = materialize_worker_run(scan_run, c1)
        wr2, wc2 = materialize_worker_run(scan_run, c2)

        self.assertNotEqual(wr1.id, wr2.id)
        self.assertNotEqual(wc1.id, wc2.id)
        self.assertEqual(wc1.origin_candidate_id, c1.id)
        self.assertEqual(wc2.origin_candidate_id, c2.id)


if __name__ == "__main__":
    unittest.main()
