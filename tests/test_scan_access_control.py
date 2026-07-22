"""vc_scan_access_control MCP tool 배선 (Day4, VERIFIER_BATCH_INTERFACE.md §3 4번) 테스트.

실제 suspect 탐지/provisioning 매칭(`surface.candidates.candidates_for_target`)은 P3
소유라 mock으로 대체하고, P1이 배선한 부분(policy 검사, READY→CANDIDATE_SCAN 전이,
source_root/provisioning 조회, candidate 저장, blocked 사유 trajectory 기록)만 확인한다.
"""

from __future__ import annotations

import asyncio
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

from contracts.schemas import Candidate, Run, RunState
from core.evidence_store import get, save
from core.trajectory import TRAJECTORY_DIR
from surface.candidates import BlockedTarget, BridgeResult

REGISTERED_TARGET_ID = "26s-w1-c1-03"


def _run(status: RunState = RunState.READY) -> Run:
    run = Run(id=f"run-{uuid4().hex[:12]}", target_id=REGISTERED_TARGET_ID, status=status)
    save(run)
    return run


def _fake_service() -> MagicMock:
    fake_service = MagicMock()
    fake_service.catalog.source_root_for.return_value = Path(__file__).resolve().parent
    fake_service.verifier_provisioning.return_value = MagicMock()
    return fake_service


class VcScanAccessControlTests(unittest.TestCase):
    def _call(self, args: dict) -> object:
        from mcp_server.server import mcp

        return asyncio.run(mcp.call_tool("vc_scan_access_control", args))

    def test_stores_candidates_and_transitions_run(self) -> None:
        run = _run(status=RunState.READY)
        candidate = Candidate(
            id=f"cand-{uuid4().hex[:12]}",
            run_id=run.id,
            cwe="CWE-639",
            vuln_class="idor",
            endpoint="/api/vocabs/{id}",
            attack_params={"base_url": "http://127.0.0.1:1", "auth_mode": "none"},
        )
        bridge_result = BridgeResult(candidates=[candidate])

        with (
            patch("mcp_server.tools_analysis._service", return_value=_fake_service()),
            patch("mcp_server.tools_analysis.candidates_for_target", return_value=bridge_result),
        ):
            self._call({"run_id": run.id})

        self.assertIsNotNone(get(Candidate, candidate.id))
        # READY로 들어와도 mapping gap을 이 tool이 대신 메워 CANDIDATE_SCAN까지 간다(Day4).
        self.assertEqual(get(Run, run.id).status, RunState.CANDIDATE_SCAN)

    def test_blocked_result_stores_no_candidates_but_records_reason(self) -> None:
        run = _run(status=RunState.CANDIDATE_SCAN)
        bridge_result = BridgeResult(
            blocked=[
                BlockedTarget(
                    target_id=REGISTERED_TARGET_ID,
                    strategy="fixture_contract_required",
                    reason="인증/seed 방식 미확정",
                    needed="P3가 role/resource/endpoint schema 제공",
                )
            ]
        )

        with (
            patch("mcp_server.tools_analysis._service", return_value=_fake_service()),
            patch("mcp_server.tools_analysis.candidates_for_target", return_value=bridge_result),
        ):
            _, structured = self._call({"run_id": run.id})

        self.assertEqual(structured["candidate_ids"], [])
        # candidate_ids가 비어 있는 게 "안전해서"가 아니라 "검증 준비가 안 돼 시도 못 함"임을
        # 호출자가 trajectory를 따로 뒤지지 않아도 반환값만으로 알 수 있어야 한다(2026-07-23 수정).
        self.assertEqual(len(structured["blocked"]), 1)
        self.assertIn("인증/seed 방식 미확정", structured["blocked"][0])
        self.assertIn("P3가 role/resource/endpoint schema 제공", structured["blocked"][0])
        traj_path = TRAJECTORY_DIR / f"{run.id}.jsonl"
        text = traj_path.read_text(encoding="utf-8")
        self.assertIn("blocked", text)
        self.assertIn("fixture_contract_required", text)

    def test_passes_source_root_and_provisioning_to_bridge(self) -> None:
        run = _run(status=RunState.CANDIDATE_SCAN)
        fake_service = _fake_service()
        source_root = Path(__file__).resolve().parent
        fake_service.catalog.source_root_for.return_value = source_root
        provisioning_sentinel = MagicMock(name="provisioning")
        fake_service.verifier_provisioning.return_value = provisioning_sentinel

        with (
            patch("mcp_server.tools_analysis._service", return_value=fake_service),
            patch(
                "mcp_server.tools_analysis.candidates_for_target", return_value=BridgeResult()
            ) as mock_bridge,
        ):
            self._call({"run_id": run.id})

        mock_bridge.assert_called_once_with(
            run.id, provisioning_sentinel, source_root, xss_fixture_hints=None
        )
        fake_service.verifier_provisioning.assert_called_once_with(REGISTERED_TARGET_ID)

    def test_unregistered_target_is_rejected_before_bridge_runs(self) -> None:
        run = Run(id=f"run-{uuid4().hex[:12]}", target_id="not-in-scope-yaml", status=RunState.READY)
        save(run)
        from mcp.server.fastmcp.exceptions import ToolError

        with (
            patch("mcp_server.tools_analysis.candidates_for_target") as mock_bridge,
            self.assertRaises(ToolError),
        ):
            self._call({"run_id": run.id})
        mock_bridge.assert_not_called()


if __name__ == "__main__":
    unittest.main()
