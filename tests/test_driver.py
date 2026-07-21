"""batch 오케스트레이션 driver 테스트 (Extra Day 1B-3).

`run_target_audit`는 실제 tool을 `mcp.call_tool`로 부르지만, 여기서는 `invoke`를 tool 부작용을
흉내내는 fake로, `service`(P2 runtime)를 MagicMock으로 주입해 **driver가 내리는 결정**만
검증한다: 시작 시 sweep 1회, candidate마다 worker Run 1개, verified worker만 repair 루프+
overlay reset, rejected worker는 reset 미호출, 순차 실행 순서. 실제 tool 동작은 각 tool
테스트가 이미 커버한다.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock
from uuid import uuid4

from contracts.schemas import Candidate, Finding, FindingStatus, Patch, Run, RunState
from core.evidence_store import (
    find_or_create_finding,
    get,
    list_by_run,
    save,
    update_finding_status,
    write_artifact,
)
from mcp_server.driver import run_target_audit
from runtime.target_lease import TargetBusyError, TargetLeaseManager

REGISTERED_TARGET_ID = "26s-w1-c1-03"


class FakeToolRuntime:
    """tool 호출 부작용을 evidence_store에 흉내낸다.

    scan은 candidate 2개(verified될 것 + rejected될 것)를 만들고, verify는 candidate의
    `_verdict` 힌트대로 Finding을 승격/거부하며 RunState도 실제 tool처럼 전이시킨다.
    generate_patch는 Patch를 만든다. 나머지(localize/apply/build/replay/validate)는 no-op.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def invoke(self, tool: str, **args) -> None:
        self.calls.append((tool, dict(args)))
        handler = getattr(self, f"_on_{tool}", None)
        if handler is not None:
            handler(**args)

    def _on_vc_build_target(self, *, target_id: str) -> None:
        pass  # no-op — 실제로는 Docker build.

    def _on_vc_start_target(self, *, target_id: str) -> None:
        pass  # no-op — 실제로는 Docker start + health.

    def _on_vc_scan_access_control(self, *, run_id: str) -> None:
        # 실제 tool의 _prepare_scan이 READY→MAPPING→CANDIDATE_SCAN까지 전이시킨다.
        run = get(Run, run_id)
        run.status = RunState.CANDIDATE_SCAN
        save(run)
        for verdict in ("verified", "rejected"):
            save(
                Candidate(
                    id=f"scan-cand-{verdict}-{uuid4().hex[:6]}",
                    run_id=run_id,
                    cwe="CWE-639",
                    vuln_class="idor",
                    attack_params={"_verdict": verdict},
                )
            )

    def _verify(self, *, run_id: str, candidate_id: str, approved: bool) -> None:
        candidate = get(Candidate, candidate_id)
        finding = find_or_create_finding(run_id, candidate)
        obs = write_artifact(
            run_id, observation_type="http_exchange", producer="fake", data=b"x"
        )
        run = get(Run, run_id)
        if run.status == RunState.CANDIDATE_SCAN:  # 실제 _prepare_verification 흉내
            run.status = RunState.VERIFYING
            save(run)
        if candidate.attack_params.get("_verdict") == "verified":
            update_finding_status(finding.id, FindingStatus.VERIFIED, evidence_ids=[obs.id])
            run = get(Run, run_id)
            run.status = RunState.VERIFIED  # 실제 _finalize_verification_run 흉내
            save(run)
        else:
            update_finding_status(finding.id, FindingStatus.REJECTED, evidence_ids=[obs.id])

    # 세 verify tool 모두 같은 부작용(테스트 candidate는 전부 idor read).
    _on_vc_verify_access_control = _verify

    def _on_vc_generate_patch(self, *, finding_id: str) -> None:
        finding = get(Finding, finding_id)
        save(
            Patch(
                id=f"patch-{uuid4().hex[:8]}",
                finding_id=finding.id,
                run_id=finding.run_id,
                diff="--- a/x\n+++ b/x\n",
            )
        )


class RunTargetAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = MagicMock()
        self.service.reset_run.return_value = True
        self.runtime = FakeToolRuntime()
        self._lease_tmp = TemporaryDirectory()
        self.addCleanup(self._lease_tmp.cleanup)
        self.lease_manager = TargetLeaseManager(Path(self._lease_tmp.name))

    def _run(self):
        return run_target_audit(
            REGISTERED_TARGET_ID,
            service=self.service,
            invoke=self.runtime.invoke,
            lease_manager=self.lease_manager,
        )

    def test_rejects_unregistered_target_before_any_scan(self) -> None:
        from core.policy_engine import PolicyViolation

        with self.assertRaises(PolicyViolation):
            run_target_audit(
                "not-in-scope",
                service=self.service,
                invoke=self.runtime.invoke,
                lease_manager=self.lease_manager,
            )
        self.service.sweep_stale_run_overlays.assert_not_called()
        # 정책 게이트가 lease보다 먼저다 — 미등록 target은 lease조차 잡지 않는다.
        self.assertIsNone(self.lease_manager.get("not-in-scope"))

    def test_sweeps_once_before_batch(self) -> None:
        self._run()
        self.service.sweep_stale_run_overlays.assert_called_once_with(
            REGISTERED_TARGET_ID, active_run_ids=(), approved=True
        )

    def test_builds_and_starts_target_before_scan(self) -> None:
        self._run()
        tools = [t for t, _a in self.runtime.calls]
        # build → start → scan 순서(verify가 Connection refused로 막히지 않도록).
        self.assertLess(tools.index("vc_build_target"), tools.index("vc_start_target"))
        self.assertLess(tools.index("vc_start_target"), tools.index("vc_scan_access_control"))

    def test_runs_all_three_scan_tools_for_three_vuln_classes(self) -> None:
        # D5-P2 요청: injection/xss(SAST)와 IDOR/SCA를 단일 경로에서 모두 수집.
        self._run()
        tools = [t for t, _a in self.runtime.calls]
        for scan_tool in ("vc_scan_access_control", "vc_run_sast", "vc_run_sca"):
            self.assertIn(scan_tool, tools)

    def test_one_scanner_failure_does_not_abort_the_audit(self) -> None:
        # 한 스캐너(예: semgrep 미설치)가 예외를 던져도 배치는 나머지로 계속된다.
        def boom(**args):
            raise RuntimeError("SemgrepUnavailableError")

        self.runtime._on_vc_run_sast = boom
        report = self._run()  # 예외 전파 없이 완주
        # vc_scan_access_control이 만든 후보는 그대로 처리된다.
        self.assertEqual(len(report.worker_results), 2)

    def test_worker_pipeline_error_is_isolated_and_batch_continues(self) -> None:
        # verify가 예외를 던져도(target 미기동 등) 배치가 죽지 않고 그 worker만 error로 남는다.
        original_verify = self.runtime._on_vc_verify_access_control

        def boom(**args):
            raise ConnectionError("[Errno 61] Connection refused")

        self.runtime._on_vc_verify_access_control = boom
        report = self._run()
        # 두 후보 모두 결과가 남고(배치 완주), 둘 다 error가 채워진다.
        self.assertEqual(len(report.worker_results), 2)
        self.assertTrue(all(r.error is not None for r in report.worker_results))
        self.assertTrue(all("Connection refused" in r.error for r in report.worker_results))
        # 실패 worker는 apply까지 못 가 overlay가 없으니 reset_run도 안 부른다.
        self.service.reset_run.assert_not_called()
        self.runtime._on_vc_verify_access_control = original_verify

    def test_one_worker_run_per_candidate(self) -> None:
        report = self._run()
        self.assertEqual(len(report.worker_results), 2)
        # scan Run + worker Run 2개가 각각 다른 run id.
        run_ids = {r.worker_run_id for r in report.worker_results}
        self.assertEqual(len(run_ids), 2)
        self.assertNotIn(report.scan_run_id, run_ids)
        # 각 worker candidate가 원본 scan candidate lineage를 보존.
        for r in report.worker_results:
            self.assertIsNotNone(r.origin_candidate_id)
            worker_cand = next(
                c for c in list_by_run(Candidate, r.worker_run_id)
            )
            self.assertEqual(worker_cand.origin_candidate_id, r.origin_candidate_id)

    def test_scan_run_stays_in_candidate_scan(self) -> None:
        report = self._run()
        self.assertEqual(get(Run, report.scan_run_id).status, RunState.CANDIDATE_SCAN)

    def test_only_verified_worker_gets_reset_run(self) -> None:
        report = self._run()
        verified = [r for r in report.worker_results if r.verified]
        rejected = [r for r in report.worker_results if not r.verified]
        self.assertEqual(len(verified), 1)
        self.assertEqual(len(rejected), 1)

        # overlay를 만든(verified→apply까지 간) worker Run만 reset_run.
        self.service.reset_run.assert_called_once_with(
            REGISTERED_TARGET_ID, verified[0].worker_run_id, approved=True
        )
        self.assertTrue(verified[0].overlay_reset)
        # rejected worker는 overlay가 없으니 reset 대상이 아니다.
        self.assertIsNone(rejected[0].overlay_reset)

    def test_verified_worker_runs_repair_pipeline_in_order(self) -> None:
        self._run()
        # verified worker candidate에 대한 tool 호출만 순서대로 뽑는다.
        verified_cand = next(
            c
            for run_id in {a["run_id"] for t, a in self.runtime.calls if t.startswith("vc_verify")}
            for c in list_by_run(Candidate, run_id)
            if c.attack_params.get("_verdict") == "verified"
        )
        seq = [
            t
            for t, a in self.runtime.calls
            if a.get("run_id") == verified_cand.run_id
            or a.get("finding_id") is not None
            or a.get("patch_id") is not None
        ]
        # verify → localize → generate_patch → apply → build → replay → validate
        expected_tail = [
            "vc_verify_access_control",
            "vc_localize_root_cause",
            "vc_generate_patch",
            "vc_apply_patch",
            "vc_build_and_test",
            "vc_replay_attack",
            "vc_validate_regression",
        ]
        self.assertEqual(seq[-len(expected_tail):], expected_tail)

    def test_rejected_worker_skips_repair(self) -> None:
        self._run()
        tools_called = [t for t, _a in self.runtime.calls]
        # rejected worker는 verify만, patch 관련 tool은 verified worker 1개분(1회)만.
        self.assertEqual(tools_called.count("vc_generate_patch"), 1)
        self.assertEqual(tools_called.count("vc_apply_patch"), 1)


class TargetLeaseWiringTests(unittest.TestCase):
    """W-8: batch 전체 단위 lease acquire/renew/release 배선(§3A-8, P2 긴급 요청 3번)."""

    def setUp(self) -> None:
        self.service = MagicMock()
        self.service.reset_run.return_value = True
        self.runtime = FakeToolRuntime()
        self._lease_tmp = TemporaryDirectory()
        self.addCleanup(self._lease_tmp.cleanup)
        self.lease_manager = TargetLeaseManager(Path(self._lease_tmp.name))

    def _run(self):
        return run_target_audit(
            REGISTERED_TARGET_ID,
            service=self.service,
            invoke=self.runtime.invoke,
            lease_manager=self.lease_manager,
        )

    def test_lease_released_after_successful_batch(self) -> None:
        self._run()
        self.assertIsNone(self.lease_manager.get(REGISTERED_TARGET_ID))

    def test_lease_held_before_build_and_matches_scan_run_id(self) -> None:
        # build/start 시점에 이미 lease가 잡혀 있어야 한다(worker보다 훨씬 이전).
        observed: dict[str, str] = {}
        original_start = self.runtime._on_vc_start_target

        def check_lease_and_delegate(*, target_id: str) -> None:
            lease = self.lease_manager.get(target_id)
            self.assertIsNotNone(lease)
            observed["run_id"] = lease.run_id
            original_start(target_id=target_id)

        self.runtime._on_vc_start_target = check_lease_and_delegate
        report = self._run()
        # build 시점에 관찰한 lease 소유자가 최종 scan_run_id와 같다 — 배치 전체가 한 lease.
        self.assertEqual(observed["run_id"], report.scan_run_id)

    def test_renew_called_once_per_worker(self) -> None:
        real_renew = self.lease_manager.renew
        calls: list[str] = []

        def spy_renew(target_id: str, run_id: str, **kwargs):
            calls.append(run_id)
            return real_renew(target_id, run_id, **kwargs)

        self.lease_manager.renew = spy_renew  # type: ignore[method-assign]
        report = self._run()
        # 후보 2개(verified+rejected) → worker 2개 → renew 2회, 전부 같은 scan_run_id 소유.
        self.assertEqual(len(calls), len(report.worker_results))
        self.assertTrue(all(c == report.scan_run_id for c in calls))

    def test_busy_target_raises_and_never_reaches_build(self) -> None:
        # 다른 배치가 이미 이 target을 쥐고 있으면 build/start 전에 TargetBusyError로 실패해야 한다.
        self.lease_manager.acquire(REGISTERED_TARGET_ID, "other-run")
        with self.assertRaises(TargetBusyError):
            self._run()
        self.assertEqual(self.runtime.calls, [])  # build_target조차 호출 안 됨
        # 남의 lease를 우리가 release하지 않는다 — 여전히 other-run 소유로 남아 있어야 한다.
        lease = self.lease_manager.get(REGISTERED_TARGET_ID)
        self.assertIsNotNone(lease)
        self.assertEqual(lease.run_id, "other-run")

    def test_lease_released_even_if_scan_tool_raises_unexpectedly(self) -> None:
        # 스캐너 실패는 driver 내부에서 잡히지만(로깅만), 혹시 모를 완전 미예상 실패에서도
        # release가 finally로 보장되는지 build_target 자체를 깨뜨려 확인한다.
        def boom(*, target_id: str) -> None:
            raise RuntimeError("docker daemon unreachable")

        self.runtime._on_vc_build_target = boom
        with self.assertRaises(RuntimeError):
            self._run()
        self.assertIsNone(self.lease_manager.get(REGISTERED_TARGET_ID))


if __name__ == "__main__":
    unittest.main()
