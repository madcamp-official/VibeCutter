"""Write-IDOR(상태변화) oracle 배선 테스트.

`verifiers.access_control.verify_mutation()`/`MutationProbe`는 이미 구현돼 있었지만 어떤
MCP tool에도 연결돼 있지 않았다(26s-w1-c3-09/26s-w1-c2-08 감사 중 발견). 여기서는 그 사이를
잇는 3개 조각을 검증한다:

  1. `mutation_probe_from_candidate` — `Candidate.attack_params`(dict[str,str]) ↔
     `MutationProbe`(중첩 dict `extra_body` 포함) 변환.
  2. `verify_mutation_access_control` — `verify_mutation`을 `Verifier` 프로토콜 모양으로
     감싸는 어댑터(`vc_verify_mutation_access_control` tool과 `check_attack` 자동 재현
     양쪽이 주입할 수 있어야 한다).
  3. `vc_verify_mutation_access_control` MCP tool — `vc_verify_access_control`과 동일한
     policy/승인/RunState/Finding 배선.
  4. `core.judge.check_attack`가 candidate 모양만 보고 read/write oracle을 자동 선택하는지.

실제 HTTP 재현(`_replay_mutation_none`)은 목으로 대체한다 — 그건 이미 존재하는 로직이고
여기서 검증할 대상은 "새로 연결한 배선"이다.
"""

from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import patch
from uuid import uuid4

from contracts.schemas import Candidate, Finding, FindingStatus, Run, RunState, VerificationResult
from core.evidence_store import get, save, write_artifact
from core.judge import check_attack
from verifiers.access_control import MutationProbe, mutation_probe_from_candidate

REGISTERED_TARGET_ID = "26s-w1-c1-03"


def _run(target_id: str = REGISTERED_TARGET_ID, status: RunState = RunState.CANDIDATE_SCAN) -> Run:
    run = Run(id=f"run-{uuid4().hex[:12]}", target_id=target_id, status=status)
    save(run)
    return run


def _mutation_candidate(run_id: str, **overrides: str) -> Candidate:
    attack_params = {
        "base_url": "http://127.0.0.1:14023",
        "observe_path": "/api/reviews/1/",
        "mutation_method": "PATCH",
        "mutation_path": "/api/reviews/1/",
        "mutation_marker": "vc-write-idor-abc123",
        **overrides,
    }
    candidate = Candidate(
        id=f"cand-{uuid4().hex[:12]}", run_id=run_id, cwe="CWE-639",
        vuln_class="idor", attack_params=attack_params,
    )
    save(candidate)
    return candidate


def _read_candidate(run_id: str) -> Candidate:
    candidate = Candidate(id=f"cand-{uuid4().hex[:12]}", run_id=run_id, cwe="CWE-639")
    save(candidate)
    return candidate


class MutationProbeFromCandidateTests(unittest.TestCase):
    def test_builds_probe_from_required_fields_with_defaults(self) -> None:
        candidate = _mutation_candidate("run-x")
        probe = mutation_probe_from_candidate(candidate)
        self.assertEqual(probe.base_url, "http://127.0.0.1:14023")
        self.assertEqual(probe.observe_path, "/api/reviews/1/")
        self.assertEqual(probe.mutation_method, "PATCH")
        self.assertEqual(probe.mutation_path, "/api/reviews/1/")
        self.assertEqual(probe.mutation_marker, "vc-write-idor-abc123")
        self.assertEqual(probe.marker_field, "description")  # 기본값
        self.assertEqual(probe.extra_body, {})  # extra_body_json 없으면 빈 dict

    def test_decodes_extra_body_json_and_marker_field_override(self) -> None:
        candidate = _mutation_candidate(
            "run-x",
            marker_field="title",
            extra_body_json=json.dumps({"tags": "p2,p3"}),
        )
        probe = mutation_probe_from_candidate(candidate)
        self.assertEqual(probe.marker_field, "title")
        self.assertEqual(probe.extra_body, {"tags": "p2,p3"})

    def test_missing_required_field_raises(self) -> None:
        candidate = Candidate(
            id=f"cand-{uuid4().hex[:12]}", run_id="run-x",
            attack_params={"base_url": "http://127.0.0.1:1"},
        )
        with self.assertRaises(KeyError):
            mutation_probe_from_candidate(candidate)


class VerifyMutationAccessControlAdapterTests(unittest.TestCase):
    def test_delegates_to_verify_mutation_with_reconstructed_probe(self) -> None:
        from contracts.schemas import VerificationResult
        from verifiers import access_control

        candidate = _mutation_candidate("run-x")
        fake_result = VerificationResult(verified=True, evidence_ids=["obs-1"], reason="ok")

        captured: dict[str, object] = {}

        def fake_verify_mutation(run_id, probe, *, max_requests=10):
            captured["run_id"] = run_id
            captured["probe"] = probe
            captured["max_requests"] = max_requests
            return fake_result

        with patch("verifiers.access_control.verify_mutation", fake_verify_mutation):
            result = access_control.verify_mutation_access_control("run-x", candidate, max_requests=7)

        self.assertIs(result, fake_result)
        self.assertEqual(captured["run_id"], "run-x")
        self.assertIsInstance(captured["probe"], MutationProbe)
        self.assertEqual(captured["probe"].mutation_marker, "vc-write-idor-abc123")
        self.assertEqual(captured["max_requests"], 7)


class VcVerifyMutationAccessControlToolTests(unittest.TestCase):
    """실제 MCP call_tool 경로로 vc_verify_mutation_access_control 전체를 구동한다."""

    def _call(self, args: dict) -> object:
        from mcp_server.server import mcp

        return asyncio.run(mcp.call_tool("vc_verify_mutation_access_control", args))

    def test_verified_result_promotes_finding_and_records_evidence(self) -> None:
        run = _run()
        candidate = _mutation_candidate(run.id)
        obs = write_artifact(
            run.id, observation_type="http_exchange", producer="test", data=b"mock exchange"
        )
        fake_result = VerificationResult(
            verified=True, evidence_ids=[obs.id], reason="mocked: victim resource mutated"
        )
        with patch("mcp_server.tools_analysis.verify_mutation_access_control", return_value=fake_result):
            self._call(
                {"run_id": run.id, "candidate_id": candidate.id, "max_requests": 5, "approved": True}
            )

        from core.evidence_store import list_by_run

        finding = next(f for f in list_by_run(Finding, run.id) if f.candidate_id == candidate.id)
        self.assertEqual(finding.verification_state, FindingStatus.VERIFIED)
        self.assertIn(obs.id, finding.evidence_ids)

    def test_rejected_result_does_not_promote_finding(self) -> None:
        run = _run()
        candidate = _mutation_candidate(run.id)
        obs = write_artifact(
            run.id, observation_type="http_exchange", producer="test", data=b"mock exchange"
        )
        fake_result = VerificationResult(
            verified=False, evidence_ids=[obs.id], reason="mocked: victim resource unchanged"
        )
        with patch("mcp_server.tools_analysis.verify_mutation_access_control", return_value=fake_result):
            self._call(
                {"run_id": run.id, "candidate_id": candidate.id, "max_requests": 5, "approved": True}
            )

        from core.evidence_store import list_by_run

        finding = next(f for f in list_by_run(Finding, run.id) if f.candidate_id == candidate.id)
        self.assertEqual(finding.verification_state, FindingStatus.REJECTED)

    def test_unapproved_call_is_rejected_before_verifier_runs(self) -> None:
        from mcp.server.fastmcp.exceptions import ToolError

        run = _run()
        candidate = _mutation_candidate(run.id)
        with patch("mcp_server.tools_analysis.verify_mutation_access_control") as mock_verify:
            with self.assertRaises(ToolError):
                self._call({"run_id": run.id, "candidate_id": candidate.id, "approved": False})
        mock_verify.assert_not_called()

    def test_verified_result_transitions_run_to_verified(self) -> None:
        run = _run()
        candidate = _mutation_candidate(run.id)
        obs = write_artifact(
            run.id, observation_type="http_exchange", producer="test", data=b"mock exchange"
        )
        fake_result = VerificationResult(
            verified=True, evidence_ids=[obs.id], reason="mocked: victim resource mutated"
        )
        with patch("mcp_server.tools_analysis.verify_mutation_access_control", return_value=fake_result):
            self._call(
                {"run_id": run.id, "candidate_id": candidate.id, "max_requests": 5, "approved": True}
            )

        self.assertEqual(get(Run, run.id).status, RunState.VERIFIED)

    def test_rejected_result_leaves_run_in_verifying(self) -> None:
        run = _run()
        candidate = _mutation_candidate(run.id)
        obs = write_artifact(
            run.id, observation_type="http_exchange", producer="test", data=b"mock exchange"
        )
        fake_result = VerificationResult(
            verified=False, evidence_ids=[obs.id], reason="mocked: victim resource unchanged"
        )
        with patch("mcp_server.tools_analysis.verify_mutation_access_control", return_value=fake_result):
            self._call(
                {"run_id": run.id, "candidate_id": candidate.id, "max_requests": 5, "approved": True}
            )

        self.assertEqual(get(Run, run.id).status, RunState.VERIFYING)


class CheckAttackAutoDispatchTests(unittest.TestCase):
    """`check_attack`가 verifier를 명시하지 않으면 candidate 모양으로 read/write oracle을
    자동 선택하는지 확인한다(자동 재현 루프에는 Host가 tool을 골라줄 수 없어서 필요)."""

    def _finding_for(self, candidate: Candidate) -> Finding:
        finding = Finding(
            id=f"finding-{uuid4().hex[:12]}", run_id=candidate.run_id,
            candidate_id=candidate.id, title="t",
        )
        save(finding)
        return finding

    def test_picks_mutation_verifier_for_mutation_shaped_candidate(self) -> None:
        run_id = f"run-{uuid4().hex[:12]}"
        candidate = _mutation_candidate(run_id)
        finding = self._finding_for(candidate)

        with patch(
            "core.judge.verify_mutation_access_control",
            return_value=VerificationResult(verified=False, evidence_ids=[], reason="patched"),
        ) as mock_mutation, patch("core.judge.verify_access_control") as mock_read:
            self.assertTrue(check_attack(run_id, finding.id))

        mock_mutation.assert_called_once()
        mock_read.assert_not_called()

    def test_picks_read_oracle_verifier_for_ordinary_candidate(self) -> None:
        run_id = f"run-{uuid4().hex[:12]}"
        candidate = _read_candidate(run_id)
        finding = self._finding_for(candidate)

        with patch(
            "core.judge.verify_access_control",
            return_value=VerificationResult(verified=False, evidence_ids=[], reason="patched"),
        ) as mock_read, patch("core.judge.verify_mutation_access_control") as mock_mutation:
            self.assertTrue(check_attack(run_id, finding.id))

        mock_read.assert_called_once()
        mock_mutation.assert_not_called()

    def test_explicit_verifier_override_still_wins(self) -> None:
        run_id = f"run-{uuid4().hex[:12]}"
        candidate = _mutation_candidate(run_id)
        finding = self._finding_for(candidate)

        def fake_verifier(run_id, candidate, *, max_requests=10):
            return VerificationResult(verified=False, evidence_ids=[], reason="explicit override")

        self.assertTrue(check_attack(run_id, finding.id, verifier=fake_verifier))


if __name__ == "__main__":
    unittest.main()
