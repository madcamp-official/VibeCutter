"""vc_localize_root_cause MCP tool 배선 테스트 (D3-P3.md 요청).

실제 판정(`repair.locator.localize`)은 P3 소유라 mock으로 대체하고, P1이 배선한
finding → run → target(catalog) → source_root 경로만 검증한다. `_service()` 자체는
가벼운 mock으로 대체해 실제 target Docker/Git clone 없이도 배선 로직만 검증한다.
"""

from __future__ import annotations

import asyncio
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

from contracts.schemas import Finding, RootCause, Run, RunState
from core.evidence_store import save


def _run(target_id: str = "fake-target") -> Run:
    run = Run(id=f"run-{uuid4().hex[:12]}", target_id=target_id, status=RunState.LOCALIZING)
    save(run)
    return run


def _finding(run_id: str) -> Finding:
    finding = Finding(
        id=f"finding-{uuid4().hex[:12]}",
        run_id=run_id,
        title="t",
        affected_endpoint="GET /x",
    )
    save(finding)
    return finding


class VcLocalizeRootCauseWiringTests(unittest.TestCase):
    def _call(self, args: dict) -> object:
        from mcp_server.server import mcp

        return asyncio.run(mcp.call_tool("vc_localize_root_cause", args))

    def test_resolves_source_root_from_run_target_and_calls_locator(self) -> None:
        run = _run(target_id="fake-target")
        finding = _finding(run.id)

        fake_root_cause = RootCause(file="Foo.java", symbol="getX", rationale="mock")
        expected_root = Path(__file__).resolve().parent.parent / ".vibecutter/targets/sources/fake-target"
        fake_service = MagicMock()
        fake_service.catalog.source_root_for.return_value = expected_root

        with (
            patch("mcp_server.tools_repair._service", return_value=fake_service),
            patch("mcp_server.tools_repair.localize", return_value=fake_root_cause) as mock_localize,
        ):
            self._call({"finding_id": finding.id})

        fake_service.catalog.source_root_for.assert_called_once_with("fake-target")
        (called_finding,), kwargs = mock_localize.call_args
        self.assertEqual(called_finding.id, finding.id)
        self.assertEqual(kwargs["source_root"], expected_root)

    def test_unknown_finding_raises(self) -> None:
        from mcp.server.fastmcp.exceptions import ToolError

        with self.assertRaises(ToolError):
            self._call({"finding_id": "finding-does-not-exist"})

    def test_unknown_run_raises(self) -> None:
        from mcp.server.fastmcp.exceptions import ToolError

        finding = Finding(
            id=f"finding-{uuid4().hex[:12]}", run_id="run-does-not-exist", title="t"
        )
        save(finding)

        with self.assertRaises(ToolError):
            self._call({"finding_id": finding.id})


if __name__ == "__main__":
    unittest.main()
