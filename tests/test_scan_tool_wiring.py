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


def _candidate(run_id: str, loc: str) -> Candidate:
    """RAG 배선 테스트용 최소 candidate. `loc`이 `파일:줄`이면 인덱싱 대상이다."""
    return Candidate(id=f"cand-{uuid4().hex[:8]}", run_id=run_id, confidence=0.5,
                     vuln_class="injection", cwe="CWE-89", source_symbols=[loc],
                     signals=["focus:injection", "severity:ERROR"])


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
    """D4-P4: LLM candidate 재랭킹 훅을 aggregate에 주입한다(8.4절 가설 우선순위).

    W-10(T-2): `_rerank_hook_from_env()`는 이제 `(rerank_fn, outcome_fn)` 쌍을 준다 —
    endpoint가 없어도 `outcome_fn()`은 항상 `LlmCallOutcome`을 돌려줘 "이 run은 휴리스틱으로
    돌았다"를 trajectory에 명시적으로 남길 수 있다(T-3 표본 필터가 근거로 쓴다).
    """

    def test_disabled_yields_none_rerank_and_unavailable_outcome(self) -> None:
        import os
        from mcp_server.tools_analysis import _rerank_hook_from_env

        # DISABLE이면 네트워크를 아예 건드리지 않고 휴리스틱으로 떨어진다(CI 경로).
        with patch.dict(os.environ, {"VIBECUTTER_LLM_DISABLE": "1"}):
            rerank_fn, outcome_fn = _rerank_hook_from_env()
        self.assertIsNone(rerank_fn)
        outcome = outcome_fn()
        self.assertFalse(outcome.llm_used)
        self.assertEqual(outcome.tier, "none")

    def test_all_endpoints_down_yields_none_rerank_and_unavailable_outcome(self) -> None:
        from mcp_server.tools_analysis import _rerank_hook_from_env

        with patch("model.endpoints.liveness_check", return_value=False):
            rerank_fn, outcome_fn = _rerank_hook_from_env()
        self.assertIsNone(rerank_fn)
        self.assertFalse(outcome_fn().llm_used)

    def test_live_endpoint_yields_callable_rerank_fn_and_recorder(self) -> None:
        """U3: rerank가 코드 스니펫을 실제로 내보내려면 egress 동의가 있어야 한다."""
        from core.egress_consent import grant_consent, revoke_consent
        from mcp_server.tools_analysis import _rerank_hook_from_env

        grant_consent()
        self.addCleanup(revoke_consent)
        with patch("model.endpoints.liveness_check", return_value=True):
            rerank_fn, outcome_fn = _rerank_hook_from_env()
        self.assertTrue(callable(rerank_fn))
        self.assertTrue(callable(outcome_fn))

    def test_no_consent_yields_none_rerank_even_with_live_endpoint(self) -> None:
        """U3 완료 판정: 동의 없이는 LLM 합성/재랭킹 경로로 넘어가지 않는다."""
        from core.egress_consent import has_consented
        from mcp_server.tools_analysis import _rerank_hook_from_env

        self.assertFalse(has_consented())  # 이 테스트 프로세스 기본 상태
        with patch("model.endpoints.liveness_check", return_value=True) as mock_live:
            rerank_fn, outcome_fn = _rerank_hook_from_env()
        self.assertIsNone(rerank_fn)
        self.assertFalse(outcome_fn().llm_used)
        mock_live.assert_not_called()  # endpoint를 아예 probe하지 않았다

    def test_rag_enrich_is_nondestructive_when_index_fails(self) -> None:
        """RAG는 보정이지 필수 경로가 아니다 — 인덱싱이 깨져도 후보를 그대로 돌려준다."""
        from mcp_server.tools_analysis import _rag_enrich

        run = _run(status=RunState.CANDIDATE_SCAN)
        cands = [_candidate(run.id, "app/users.py:5")]
        with patch("model.code_index.CodeIndex.build", side_effect=OSError("no source")):
            out, contexts = _rag_enrich(run, cands)
        self.assertEqual(out, cands)
        self.assertEqual(contexts, {})

    def test_rag_enrich_skips_index_build_without_locations(self) -> None:
        """SCA 후보만 있으면 소스 트리를 아예 훑지 않는다(vc_run_sca 낭비 방지)."""
        from mcp_server.tools_analysis import _rag_enrich

        run = _run(status=RunState.CANDIDATE_SCAN)
        sca = _candidate(run.id, "pkg:npm/lodash@4.17.20")
        with patch("model.code_index.CodeIndex.build") as mock_build:
            out, contexts = _rag_enrich(run, [sca])
        mock_build.assert_not_called()
        self.assertEqual(out, [sca])
        self.assertEqual(contexts, {})

    def test_store_scan_candidates_enriches_before_aggregate(self) -> None:
        """RAG 보강이 aggregate보다 먼저 와야 rag:relevance가 우선순위에 반영된다."""
        from mcp_server import tools_analysis
        from model.endpoints import LlmCallOutcome

        run = _run(status=RunState.CANDIDATE_SCAN)
        enriched = [_candidate(run.id, "app/users.py:5")]
        with (
            patch.object(tools_analysis, "_rag_enrich",
                         return_value=(enriched, {"x": "CODE"})) as mock_enrich,
            patch.object(tools_analysis, "_rerank_hook_from_env",
                         return_value=(None, lambda: LlmCallOutcome.unavailable())) as mock_rerank,
            patch.object(tools_analysis, "aggregate") as mock_agg,
        ):
            mock_agg.return_value = MagicMock(kept=[], summary={})
            tools_analysis._store_scan_candidates(run, [], tool="vc_run_sast")
        mock_enrich.assert_called_once()
        self.assertIs(mock_agg.call_args.args[0], enriched)
        # 코드 스니펫 곁채널이 재랭킹 훅까지 전달된다(R-1).
        self.assertEqual(mock_rerank.call_args.args[0], {"x": "CODE"})

    def test_store_scan_candidates_passes_rerank_fn_to_aggregate(self) -> None:
        from mcp_server import tools_analysis
        from model.endpoints import LlmCallOutcome

        run = _run(status=RunState.CANDIDATE_SCAN)
        sentinel = object()
        with (
            patch.object(tools_analysis, "_rerank_hook_from_env",
                         return_value=(sentinel, lambda: LlmCallOutcome.unavailable())),
            patch.object(tools_analysis, "aggregate") as mock_agg,
        ):
            mock_agg.return_value = MagicMock(kept=[], summary={})
            tools_analysis._store_scan_candidates(run, [], tool="vc_run_sast")
        mock_agg.assert_called_once()
        self.assertIs(mock_agg.call_args.kwargs["rerank_fn"], sentinel)

    def test_store_scan_candidates_records_llm_outcome_in_trajectory(self) -> None:
        """W-10(T-2): outcome_fn()의 as_metadata()가 trajectory result에 병합된다 —
        `model.trajectory.llm_usage_from_trajectories()`가 이 값을 읽어 T-3 표본 필터가
        쓴다."""
        from mcp_server import tools_analysis
        from model.endpoints import LlmCallOutcome
        from model.trajectory import load_trajectories

        run = _run(status=RunState.CANDIDATE_SCAN)
        outcome = LlmCallOutcome(llm_used=True, tier="primary", tier_index=0)
        with (
            patch.object(tools_analysis, "_rerank_hook_from_env",
                         return_value=(MagicMock(), lambda: outcome)),
            patch.object(tools_analysis, "aggregate") as mock_agg,
        ):
            mock_agg.return_value = MagicMock(kept=[], summary={"kept": 0})
            tools_analysis._store_scan_candidates(run, [], tool="vc_run_sast")

        step = load_trajectories(TRAJECTORY_DIR / f"{run.id}.jsonl")[-1]
        self.assertTrue(step.result["llm_used"])
        self.assertEqual(step.result["tier"], "primary")
        self.assertEqual(step.result["endpoint_health"], "up")
        self.assertEqual(step.result["kept"], 0)  # aggregate summary도 그대로 남는다.

    def test_store_scan_candidates_records_unavailable_when_no_endpoint(self) -> None:
        """endpoint가 전부 죽었을 때도(조용히 휴리스틱으로 새지 않고) 그 사실이 남는다."""
        from mcp_server import tools_analysis
        from model.endpoints import LlmCallOutcome
        from model.trajectory import load_trajectories

        run = _run(status=RunState.CANDIDATE_SCAN)
        with (
            patch.object(tools_analysis, "_rerank_hook_from_env",
                         return_value=(None, lambda: LlmCallOutcome.unavailable())),
            patch.object(tools_analysis, "aggregate") as mock_agg,
        ):
            mock_agg.return_value = MagicMock(kept=[], summary={"kept": 0})
            tools_analysis._store_scan_candidates(run, [], tool="vc_run_sast")

        step = load_trajectories(TRAJECTORY_DIR / f"{run.id}.jsonl")[-1]
        self.assertFalse(step.result["llm_used"])
        self.assertEqual(step.result["tier"], "none")
        self.assertEqual(step.result["endpoint_health"], "down")


if __name__ == "__main__":
    unittest.main()
