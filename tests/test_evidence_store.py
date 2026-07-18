from __future__ import annotations

import unittest
from uuid import uuid4

from contracts.schemas import Candidate, Finding, FindingStatus
from core.evidence_store import (
    InvalidEvidenceError,
    find_or_create_finding,
    get,
    save,
    update_finding_status,
    write_artifact,
)
from core.state_machine import MissingEvidenceError


def _finding(run_id: str) -> Finding:
    finding = Finding(id=f"finding-{uuid4().hex[:12]}", run_id=run_id, title="test finding")
    save(finding)
    return finding


class UpdateFindingStatusTests(unittest.TestCase):
    """D1-P3.md 구멍 ①(허구 evidence_id로도 verified 승격됨) 회귀 테스트."""

    def test_rejects_empty_evidence(self) -> None:
        run_id = f"run-{uuid4().hex[:12]}"
        finding = _finding(run_id)
        with self.assertRaises(MissingEvidenceError):
            update_finding_status(finding.id, FindingStatus.VERIFIED, evidence_ids=[])

    def test_rejects_nonexistent_evidence_id(self) -> None:
        run_id = f"run-{uuid4().hex[:12]}"
        finding = _finding(run_id)
        with self.assertRaises(InvalidEvidenceError):
            update_finding_status(
                finding.id, FindingStatus.VERIFIED, evidence_ids=["obs-does-not-exist"]
            )
        # 승격되지 않았어야 한다.
        self.assertEqual(get(Finding, finding.id).verification_state, FindingStatus.CANDIDATE)

    def test_rejects_evidence_from_a_different_run(self) -> None:
        run_a = f"run-{uuid4().hex[:12]}"
        run_b = f"run-{uuid4().hex[:12]}"
        finding = _finding(run_a)
        other_run_obs = write_artifact(
            run_b, observation_type="http_exchange", producer="test", data=b"hello"
        )
        with self.assertRaises(InvalidEvidenceError):
            update_finding_status(
                finding.id, FindingStatus.VERIFIED, evidence_ids=[other_run_obs.id]
            )

    def test_accepts_real_evidence_from_the_same_run(self) -> None:
        run_id = f"run-{uuid4().hex[:12]}"
        finding = _finding(run_id)
        obs = write_artifact(
            run_id, observation_type="http_exchange", producer="test", data=b"hello"
        )
        updated = update_finding_status(
            finding.id, FindingStatus.VERIFIED, evidence_ids=[obs.id]
        )
        self.assertEqual(updated.verification_state, FindingStatus.VERIFIED)
        self.assertIn(obs.id, updated.evidence_ids)


class WriteArtifactRedactionTests(unittest.TestCase):
    """D1-P3.md 구멍 ②(secret redaction이 어디에도 없음) 회귀 테스트."""

    def test_secret_is_not_stored_in_plaintext(self) -> None:
        run_id = f"run-{uuid4().hex[:12]}"
        secret_body = b'{"Authorization": "Bearer super-secret-token-123"}'
        obs = write_artifact(
            run_id, observation_type="http_exchange", producer="test", data=secret_body
        )
        stored = obs.artifact_uri.removeprefix("file://")
        with open(stored, "rb") as f:
            on_disk = f.read()
        self.assertNotIn(b"super-secret-token-123", on_disk)
        self.assertIn(b"<redacted>", on_disk)

    def test_hash_matches_the_redacted_bytes_actually_stored(self) -> None:
        from core.evidence_store import sha256_of

        run_id = f"run-{uuid4().hex[:12]}"
        obs = write_artifact(
            run_id,
            observation_type="http_exchange",
            producer="test",
            data=b'{"password": "hunter2"}',
        )
        stored = obs.artifact_uri.removeprefix("file://")
        with open(stored, "rb") as f:
            on_disk = f.read()
        self.assertEqual(obs.hash, sha256_of(on_disk))

    def test_non_utf8_binary_artifact_is_stored_unchanged(self) -> None:
        run_id = f"run-{uuid4().hex[:12]}"
        binary = b"\xff\xd8\xff\xe0not-a-valid-utf8-\x80\x81"
        obs = write_artifact(
            run_id, observation_type="browser_trace", producer="test", data=binary
        )
        stored = obs.artifact_uri.removeprefix("file://")
        with open(stored, "rb") as f:
            on_disk = f.read()
        self.assertEqual(on_disk, binary)


class FindOrCreateFindingVocabTests(unittest.TestCase):
    """D2-P4.md 채택: candidate signals → Finding.severity/owasp_category 자동 반영."""

    def test_severity_and_owasp_derived_from_candidate_signals(self) -> None:
        run_id = f"run-{uuid4().hex[:12]}"
        candidate = Candidate(
            id=f"cand-{uuid4().hex[:12]}",
            run_id=run_id,
            cwe="CWE-639",
            signals=["focus:idor", "severity:ERROR"],
        )
        save(candidate)
        finding = find_or_create_finding(run_id, candidate)
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.owasp_category, "A01:2021")

    def test_missing_signals_leave_severity_and_owasp_none(self) -> None:
        run_id = f"run-{uuid4().hex[:12]}"
        candidate = Candidate(id=f"cand-{uuid4().hex[:12]}", run_id=run_id, cwe="CWE-89")
        save(candidate)
        finding = find_or_create_finding(run_id, candidate)
        self.assertIsNone(finding.severity)
        self.assertIsNone(finding.owasp_category)


if __name__ == "__main__":
    unittest.main()
