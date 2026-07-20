"""core.report.build_run_report 테스트 (D2-P4.md 요청 (c) 응답).

P4의 HTML/SARIF export가 그대로 소비할 finding+evidence+patch+validation 조인이
run 단위로 정확히 묶이는지 확인한다.
"""

from __future__ import annotations

import asyncio
import unittest
from uuid import uuid4

from contracts.schemas import Finding, Patch, RootCause, Validation
from core.evidence_store import save, write_artifact
from core.report import build_run_report, render_html


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


class RenderHtmlTests(unittest.TestCase):
    def _report_with_finding(self):
        run_id = f"run-{uuid4().hex[:12]}"
        obs = write_artifact(run_id, observation_type="http_exchange", producer="verifier", data=b"x")
        finding = Finding(
            id=f"finding-{uuid4().hex[:12]}",
            run_id=run_id,
            title="IDOR in getProfile",
            cwe="CWE-639",
            severity="high",
            affected_roles=["USER_A", "USER_B"],
            evidence_ids=[obs.id],
            root_cause=RootCause(file="UserController.java", symbol="getProfile", rationale="no owner check"),
        )
        save(finding)
        validation = Validation(
            id=f"validation-{uuid4().hex[:12]}", run_id=run_id, patch_id="patch-x",
            build=True, attack=True, positive_test=True, regression=True, static=True, scope=True,
            verdict="FIXED",
        )
        save(validation)
        patch = Patch(
            id="patch-x", finding_id=finding.id, run_id=run_id,
            diff="--- a/UserController.java\n+++ b/UserController.java\n@@ <script>evil</script>",
            validation_id=validation.id,
        )
        save(patch)
        return build_run_report(run_id), finding

    def test_renders_finding_fields_and_escapes_diff(self) -> None:
        report, finding = self._report_with_finding()
        doc = render_html(report)

        self.assertIn("<!doctype html>", doc)
        self.assertIn(finding.title, doc)
        self.assertIn("CWE-639", doc)
        self.assertIn("UserController.java", doc)  # root cause
        self.assertIn("USER_A", doc)
        self.assertIn("PASS", doc)  # validation gate
        self.assertIn("FIXED", doc)  # verdict
        # diff의 <script>가 이스케이프돼 실제 태그로 들어가지 않는다.
        self.assertNotIn("<script>evil</script>", doc)
        self.assertIn("&lt;script&gt;evil&lt;/script&gt;", doc)

    def test_empty_report_renders_without_error(self) -> None:
        report = build_run_report(f"run-{uuid4().hex[:12]}-empty")
        doc = render_html(report)
        self.assertIn("finding이 없습니다", doc)


class VcGenerateReportToolTests(unittest.TestCase):
    def test_writes_html_file_and_returns_path(self) -> None:
        from mcp_server.server import mcp

        run_id = f"run-{uuid4().hex[:12]}"
        finding = Finding(id=f"finding-{uuid4().hex[:12]}", run_id=run_id, title="X", cwe="CWE-79")
        save(finding)

        _, structured = asyncio.run(mcp.call_tool("vc_generate_report", {"run_id": run_id}))

        self.assertEqual(structured["format"], "html")
        self.assertTrue(structured["artifact_uri"].endswith(f"runs/{run_id}/report.html"))
        from core.db import DATA_DIR

        path = DATA_DIR / "runs" / run_id / "report.html"
        self.addCleanup(path.unlink, missing_ok=True)
        self.assertTrue(path.exists())
        self.assertIn("CWE-79", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
