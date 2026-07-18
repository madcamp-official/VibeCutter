"""Kill switch(`core/kill_switch.py`, Day4 10.2절) 테스트.

pause file 존재만으로 상태를 바꾸거나 실제 target/verifier를 건드리는 모든 tool
진입점이 즉시 거부되는지 확인한다. `vc_pause`/`vc_resume` 자체는 이 가드를 타지 않아야
한다 — pause 중에 resume을 못 하면 kill switch가 스스로를 잠근다.
"""

from __future__ import annotations

import asyncio
import unittest
from uuid import uuid4

from contracts.schemas import Candidate, Run, RunState
from core.evidence_store import save
from core.kill_switch import KillSwitchEngaged, check_not_paused, clear_pause, is_paused, pause_reason, request_pause
from mcp_server.tools_analysis import _prepare_scan, _prepare_verification

# policies/scope.yaml에 실제로 등록된 target_id (Day2 섹션 1에서 등록).
REGISTERED_TARGET_ID = "26s-w1-c1-03"


def _run(target_id: str = REGISTERED_TARGET_ID, status: RunState = RunState.CANDIDATE_SCAN) -> Run:
    run = Run(id=f"run-{uuid4().hex[:12]}", target_id=target_id, status=status)
    save(run)
    return run


def _candidate(run_id: str) -> Candidate:
    candidate = Candidate(id=f"cand-{uuid4().hex[:12]}", run_id=run_id, cwe="CWE-639")
    save(candidate)
    return candidate


class KillSwitchTests(unittest.TestCase):
    def tearDown(self) -> None:
        clear_pause()

    def test_not_paused_by_default(self) -> None:
        self.assertFalse(is_paused())
        self.assertIsNone(pause_reason())
        check_not_paused()  # 예외 없이 통과해야 한다.

    def test_request_pause_engages_and_records_reason(self) -> None:
        request_pause("팀 회의 중 target 실수 실행 방지")
        self.assertTrue(is_paused())
        self.assertEqual(pause_reason(), "팀 회의 중 target 실수 실행 방지")
        with self.assertRaises(KillSwitchEngaged):
            check_not_paused()

    def test_clear_pause_is_idempotent(self) -> None:
        clear_pause()  # 이미 꺼진 상태에서 호출해도 에러 없음.
        request_pause("x")
        clear_pause()
        clear_pause()
        self.assertFalse(is_paused())


class PrepareVerificationRespectsKillSwitchTests(unittest.TestCase):
    def tearDown(self) -> None:
        clear_pause()

    def test_prepare_verification_rejected_while_paused(self) -> None:
        run = _run()
        candidate = _candidate(run.id)
        request_pause("kill switch test")
        with self.assertRaises(KillSwitchEngaged):
            _prepare_verification(run.id, candidate.id, approved=True, tool_name="t")

    def test_prepare_verification_resumes_after_clear(self) -> None:
        run = _run()
        candidate = _candidate(run.id)
        request_pause("kill switch test")
        clear_pause()
        # 재개 후에는 kill switch가 아니라 정상 배선(승인/policy)만 남는다.
        _, returned_candidate, _finding = _prepare_verification(
            run.id, candidate.id, approved=True, tool_name="t"
        )
        self.assertEqual(returned_candidate.id, candidate.id)


class PrepareScanRespectsKillSwitchTests(unittest.TestCase):
    def tearDown(self) -> None:
        clear_pause()

    def test_prepare_scan_rejected_while_paused(self) -> None:
        run = _run(status=RunState.MAPPING)
        request_pause("kill switch test")
        with self.assertRaises(KillSwitchEngaged):
            _prepare_scan(run.id, tool_name="t")


class PauseResumeToolTests(unittest.TestCase):
    def tearDown(self) -> None:
        clear_pause()

    def _call(self, tool: str, args: dict):
        from mcp_server.server import mcp

        return asyncio.run(mcp.call_tool(tool, args))

    def test_vc_pause_then_vc_resume_round_trip(self) -> None:
        self._call("vc_pause", {"reason": "smoke test pause"})
        self.assertTrue(is_paused())
        self.assertEqual(pause_reason(), "smoke test pause")

        # vc_pause/vc_resume 자체는 kill switch에 걸리지 않는다 — pause 상태에서도 resume 가능.
        self._call("vc_resume", {})
        self.assertFalse(is_paused())


if __name__ == "__main__":
    unittest.main()
