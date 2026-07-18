"""vc_generate_patch의 재시도 상한 배선(Day4, core/planner.py) 테스트.

기존 `tests/test_generate_patch.py`는 배선 자체(source_root 조회/상태 전이/저장)를
다루므로, 여기서는 attempt_no 계산 + 상한 초과 시 거부만 확인한다.
"""

from __future__ import annotations

import asyncio
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

from contracts.schemas import Finding, FindingStatus, Patch, Run, RunState
from core.evidence_store import get, save
from core.planner import MAX_PATCH_ATTEMPTS


def _run(status: RunState = RunState.VERIFIED) -> Run:
    run = Run(id=f"run-{uuid4().hex[:12]}", target_id="fake-target", status=status)
    save(run)
    return run


def _finding(run_id: str, status: FindingStatus = FindingStatus.VERIFIED) -> Finding:
    finding = Finding(id=f"finding-{uuid4().hex[:12]}", run_id=run_id, title="t", verification_state=status)
    save(finding)
    return finding


def _existing_patch(run_id: str, finding_id: str) -> Patch:
    p = Patch(id=f"patch-{uuid4().hex[:12]}", finding_id=finding_id, run_id=run_id, diff="d")
    save(p)
    return p


class VcGeneratePatchRetryBudgetTests(unittest.TestCase):
    def _call(self, args: dict) -> object:
        from mcp_server.server import mcp

        return asyncio.run(mcp.call_tool("vc_generate_patch", args))

    def _patched(self, fake_patch: Patch, generate_patch_mock: MagicMock | None = None):
        fake_service = MagicMock()
        fake_service.catalog.source_root_for.return_value = Path(__file__).resolve().parent
        gen_mock = generate_patch_mock or MagicMock(return_value=fake_patch)
        return (
            patch("mcp_server.tools_repair._service", return_value=fake_service),
            patch("mcp_server.tools_repair.localize", return_value=MagicMock(file="Foo.java")),
            patch("mcp_server.tools_repair.generate_patch", gen_mock),
        ), gen_mock

    def test_first_attempt_passes_attempt_no_1(self) -> None:
        run = _run(status=RunState.VERIFIED)
        finding = _finding(run.id)
        fake_patch = Patch(id=f"patch-{uuid4().hex[:12]}", finding_id=finding.id, run_id=run.id, diff="d")

        (p1, p2, p3), gen_mock = self._patched(fake_patch)
        with p1, p2, p3:
            self._call({"finding_id": finding.id})

        self.assertEqual(gen_mock.call_args.kwargs["attempt_no"], 1)

    def test_third_retry_attempt_passes_attempt_no_3_and_succeeds(self) -> None:
        run = _run(status=RunState.RETRY)
        finding = _finding(run.id)
        _existing_patch(run.id, finding.id)
        _existing_patch(run.id, finding.id)
        fake_patch = Patch(id=f"patch-{uuid4().hex[:12]}", finding_id=finding.id, run_id=run.id, diff="d")

        (p1, p2, p3), gen_mock = self._patched(fake_patch)
        with p1, p2, p3:
            self._call({"finding_id": finding.id})

        self.assertEqual(gen_mock.call_args.kwargs["attempt_no"], MAX_PATCH_ATTEMPTS)
        self.assertEqual(get(Run, run.id).status, RunState.PATCH_PROPOSED)

    def test_fourth_attempt_is_rejected_and_promotes_to_human_review(self) -> None:
        run = _run(status=RunState.RETRY)
        finding = _finding(run.id)
        for _ in range(MAX_PATCH_ATTEMPTS):
            _existing_patch(run.id, finding.id)
        fake_patch = Patch(id=f"patch-{uuid4().hex[:12]}", finding_id=finding.id, run_id=run.id, diff="d")

        from mcp.server.fastmcp.exceptions import ToolError

        (p1, p2, p3), gen_mock = self._patched(fake_patch)
        with p1, p2, p3, self.assertRaises(ToolError):
            self._call({"finding_id": finding.id})

        # 4번째 시도는 generate_patch()까지 도달하지 못하고 거부돼야 한다.
        gen_mock.assert_not_called()
        self.assertEqual(get(Finding, finding.id).verification_state, FindingStatus.HUMAN_REVIEW)
        self.assertEqual(get(Run, run.id).status, RunState.HUMAN_REVIEW)


if __name__ == "__main__":
    unittest.main()
