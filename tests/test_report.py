"""core.report.build_run_report 테스트 (D2-P4.md 요청 (c) 응답).

P4의 HTML/SARIF export가 그대로 소비할 finding+evidence+patch+validation 조인이
run 단위로 정확히 묶이는지 확인한다.
"""

from __future__ import annotations

import unittest
from uuid import uuid4

from contracts.schemas import Finding, Patch, Validation
from core.evidence_store import save, write_artifact
from core.report import build_run_report


class BuildRunReportTests(unittest.TestCase):
    def test_joins_finding_evidence_patch_and_validation(self) -> None:
        run_id = f"run-{uuid4().hex[:12]}"
        obs = write_artifact(run_id, observation_type="http_exchange", producer="test", data=b"x")
        finding = Finding(
            id=f"finding-{uuid4().hex[:12]}", run_id=run_id, title="t", evidence_ids=[obs.id]
        )
        save(finding)
        validation = Validation(
            id=f"validation-{uuid4().hex[:12]}", run_id=run_id, patch_id="patch-x", verdict="FIXED"
        )
        save(validation)
        patch = Patch(
            id="patch-x",
            finding_id=finding.id,
            run_id=run_id,
            diff="d",
            validation_id=validation.id,
        )
        save(patch)

        report = build_run_report(run_id)

        self.assertEqual(report.run_id, run_id)
        self.assertEqual(len(report.findings), 1)
        entry = report.findings[0]
        self.assertEqual(entry.finding.id, finding.id)
        self.assertEqual([o.id for o in entry.evidence], [obs.id])
        self.assertEqual(entry.patch.id, patch.id)
        self.assertEqual(entry.validation.id, validation.id)

    def test_finding_without_patch_or_evidence_still_reported(self) -> None:
        run_id = f"run-{uuid4().hex[:12]}"
        finding = Finding(id=f"finding-{uuid4().hex[:12]}", run_id=run_id, title="t")
        save(finding)

        report = build_run_report(run_id)

        self.assertEqual(len(report.findings), 1)
        entry = report.findings[0]
        self.assertEqual(entry.evidence, [])
        self.assertIsNone(entry.patch)
        self.assertIsNone(entry.validation)

    def test_unknown_run_yields_empty_report(self) -> None:
        # 무작위 run_id 사용 — 다른 테스트 파일들이 공유 로컬 DB에 남기는 고정 문자열
        # "run-does-not-exist" 같은 fixture와 충돌하지 않도록 한다.
        report = build_run_report(f"run-{uuid4().hex[:12]}-does-not-exist")
        self.assertEqual(report.findings, [])


if __name__ == "__main__":
    unittest.main()
