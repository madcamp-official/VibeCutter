"""vc_run_sast/vc_run_sca MCP tool 실배선 (Day3, D2-P4.md 요청 (e)) 테스트.

실제 스캐너(`scanners.sast.run_semgrep`/`scanners.sca.run_osv`)는 P4가 이미 검증했으므로
mock으로 대체하고, P1이 배선한 부분(policy 검사, CANDIDATE_SCAN 전이, source_root 조회,
aggregate 후처리, candidate 저장, trajectory 기록)만 확인한다.
"""

from __future__ import annotations

import asyncio
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

from contracts.schemas import Candidate, Run, RunState
from core.evidence_store import get, save
from core.policy_engine import PolicyViolation
from core.trajectory import TRAJECTORY_DIR
from mcp_server.tools_analysis import _prepare_scan

# policies/scope.yaml에 실제로 등록된 target_id (Day2 섹션 1에서 등록).
REGISTERED_TARGET_ID = "26s-w1-c1-03"


def _run(target_id: str = REGISTERED_TARGET_ID, status: RunState = RunState.MAPPING) -> Run:
    run = Run(id=f"run-{uuid4().hex[:12]}", target_id=target_id, status=status)
    save(run)
    return run


class PrepareScanTests(unittest.TestCase):
    def test_rejects_unregistered_target(self) -> None:
        run = _run(target_id="not-in-scope-yaml")
        with self.assertRaises(PolicyViolation):
            _prepare_scan(run.id, tool_name="t")

    def test_rejects_unknown_run(self) -> None:
        with self.assertRaises(ValueError):
            _prepare_scan("run-does-not-exist", tool_name="t")

    def test_transitions_mapping_to_candidate_scan(self) -> None:
        run = _run(status=RunState.MAPPING)
        _prepare_scan(run.id, tool_name="t")
        self.assertEqual(get(Run, run.id).status, RunState.CANDIDATE_SCAN)

    def test_candidate_scan_is_idempotent_for_repeat_calls(self) -> None:
        run = _run(status=RunState.CANDIDATE_SCAN)
        _prepare_scan(run.id, tool_name="t")
        _prepare_scan(run.id, tool_name="t")
        self.assertEqual(get(Run, run.id).status, RunState.CANDIDATE_SCAN)

    def test_ready_cascades_through_mapping_to_candidate_scan(self) -> None:
        # Day4: mapping tool(vc_map_routes 등)이 아직 스텁이라, READY에서 곧장 들어와도
        # MAPPING을 거쳐 CANDIDATE_SCAN까지 이 함수가 대신 전이시킨다.
        run = _run(status=RunState.READY)
        _prepare_scan(run.id, tool_name="t")
        self.assertEqual(get(Run, run.id).status, RunState.CANDIDATE_SCAN)

    def test_rejects_run_in_unrelated_state(self) -> None:
        run = _run(status=RunState.BUILDING)
        with self.assertRaises(ValueError):
            _prepare_scan(run.id, tool_name="t")


class ScanToolWiringTests(unittest.TestCase):
    """실제 MCP call_tool 경로로 vc_run_sast/vc_run_sca 전체를 구동한다."""

    def _call(self, name: str, args: dict) -> object:
        from mcp_server.server import mcp

        return asyncio.run(mcp.call_tool(name, args))

    def _fake_service(self, source_root: Path) -> MagicMock:
        fake_service = MagicMock()
        fake_service.catalog.source_root_for.return_value = source_root
        return fake_service

    def test_vc_run_sast_stores_kept_candidates_and_records_trajectory(self) -> None:
        run = _run()
        kept = Candidate(
            id=f"cand-{uuid4().hex[:12]}",
            run_id=run.id,
            cwe="CWE-89",
            source_symbols=["src/app.py:10"],
            confidence=0.7,
            signals=["semgrep:sqli-rule", "severity:ERROR"],
        )
        rejected = Candidate(
            id=f"cand-{uuid4().hex[:12]}",
            run_id=run.id,
            cwe="CWE-89",
            source_symbols=["tests/fixtures/app.py:3"],
            confidence=0.9,
            signals=["semgrep:sqli-rule"],
        )
        fake_service = self._fake_service(Path(__file__).resolve().parent)
        with (
            patch("mcp_server.tools_analysis._service", return_value=fake_service),
            patch(
                "mcp_server.tools_analysis.run_semgrep",
                return_value=[kept, rejected],
            ),
        ):
            self._call("vc_run_sast", {"run_id": run.id})

        self.assertIsNotNone(get(Candidate, kept.id))
        self.assertIsNone(get(Candidate, rejected.id))
        self.assertEqual(get(Run, run.id).status, RunState.CANDIDATE_SCAN)
        traj_path = TRAJECTORY_DIR / f"{run.id}.jsonl"
        self.assertTrue(traj_path.exists())
        self.assertIn("vc_run_sast", traj_path.read_text(encoding="utf-8"))

    def test_vc_run_sca_stores_kept_candidates(self) -> None:
        run = _run()
        kept = Candidate(
            id=f"cand-{uuid4().hex[:12]}",
            run_id=run.id,
            cwe="CWE-1035",
            source_symbols=["package-lock.json"],
            confidence=0.8,
            signals=["sca:osv", "severity:CRITICAL"],
        )
        fake_service = self._fake_service(Path(__file__).resolve().parent)
        with (
            patch("mcp_server.tools_analysis._service", return_value=fake_service),
            patch("mcp_server.tools_analysis.run_osv", return_value=[kept]),
        ):
            _, structured = self._call("vc_run_sca", {"run_id": run.id})

        self.assertIsNotNone(get(Candidate, kept.id))
        self.assertIn(kept.id, structured["candidate_ids"])

    def test_unregistered_target_is_rejected_before_scanner_runs(self) -> None:
        run = _run(target_id="not-in-scope-yaml")
        from mcp.server.fastmcp.exceptions import ToolError

        with (
            patch("mcp_server.tools_analysis.run_semgrep") as mock_run,
            self.assertRaises(ToolError),
        ):
            self._call("vc_run_sast", {"run_id": run.id})
        mock_run.assert_not_called()


class RerankHookTests(unittest.TestCase):
    """D4-P4: LLM candidate 재랭킹 훅을 aggregate에 주입한다(8.4절 가설 우선순위)."""

    def test_no_endpoint_yields_none(self) -> None:
        import os
        from mcp_server.tools_analysis import _rerank_fn_from_env

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("VIBECUTTER_MODEL_ENDPOINT", None)
            self.assertIsNone(_rerank_fn_from_env())

    def test_endpoint_yields_callable_rerank_fn(self) -> None:
        import os
        from mcp_server.tools_analysis import _rerank_fn_from_env

        with patch.dict(os.environ, {"VIBECUTTER_MODEL_ENDPOINT": "http://127.0.0.1:8000/v1"}):
            self.assertTrue(callable(_rerank_fn_from_env()))

    def test_store_scan_candidates_passes_rerank_fn_to_aggregate(self) -> None:
        from mcp_server import tools_analysis

        run = _run(status=RunState.CANDIDATE_SCAN)
        sentinel = object()
        with (
            patch.object(tools_analysis, "_rerank_fn_from_env", return_value=sentinel),
            patch.object(tools_analysis, "aggregate") as mock_agg,
        ):
            mock_agg.return_value = MagicMock(kept=[], summary={})
            tools_analysis._store_scan_candidates(run, [], tool="vc_run_sast")
        mock_agg.assert_called_once()
        self.assertIs(mock_agg.call_args.kwargs["rerank_fn"], sentinel)


if __name__ == "__main__":
    unittest.main()
