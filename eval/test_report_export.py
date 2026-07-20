"""eval.report_export 단위 테스트 (evidence_store/DB 불필요, 목 RunReport 주입).

실행: python -m eval.test_report_export
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from contracts.schemas import (
    ApprovalStatus,
    Finding,
    FindingStatus,
    Observation,
    ObservationType,
    Patch,
    Validation,
)
from core.report import FindingReportEntry, RunReport
from eval.report_export import (
    _split_location,
    export_report,
    render_sarif,
)


def _report() -> RunReport:
    finding = Finding(
        id="find-1", run_id="run-1", title="IDOR in /api/orders/{id}",
        cwe="CWE-639", owasp_category="A01:2021", severity="high",
        verification_state=FindingStatus.FIXED, affected_endpoint="/api/orders/{id}",
        affected_roles=["user_a", "user_b"], source_symbols=["app/api/orders.py:42"],
        reproduction_steps=["로그인 user_a", "user_b 자원 id로 GET", "200 + 타인 데이터"],
        impact="cross-user 주문 열람", confidence=0.9, evidence_ids=["obs-1"],
    )
    obs = Observation(
        id="obs-1", run_id="run-1", type=ObservationType.HTTP_EXCHANGE,
        artifact_uri="art://ev/1", hash="abcdef1234567890", producer="P3:idor_verifier",
    )
    patch = Patch(
        id="patch-1", finding_id="find-1", run_id="run-1",
        diff="--- a/app/api/orders.py\n+++ b/app/api/orders.py\n@@ -42 +42 @@\n- return order\n+ if order.owner != user: abort(403)",
        files=["app/api/orders.py"], approval=ApprovalStatus.APPROVED, attempt_no=1,
        validation_id="val-1",
    )
    validation = Validation(
        id="val-1", run_id="run-1", patch_id="patch-1",
        build=True, attack=True, positive_test=True, regression=True,
        static=None, scope=True, verdict="pass",
    )
    entry = FindingReportEntry(finding=finding, evidence=[obs], patch=patch, validation=validation)
    return RunReport(run_id="run-1", findings=[entry])


def test_split_location() -> None:
    assert _split_location("app/api/orders.py:42") == ("app/api/orders.py", 42)
    assert _split_location("app/api/orders.py") == ("app/api/orders.py", None)
    assert _split_location("C:/win/path.py:9") == ("C:/win/path.py", 9)   # rpartition


def test_render_sarif_structure_and_mapping() -> None:
    sarif = render_sarif(_report())
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "VibeCutter"
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {"CWE-639"}
    res = run["results"][0]
    assert res["ruleId"] == "CWE-639"
    assert res["level"] == "error"                   # high → error
    loc = res["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app/api/orders.py"
    assert loc["region"]["startLine"] == 42          # "파일:줄" 파싱
    assert res["properties"]["validation"]["attack"] is True
    assert res["properties"]["patched"] is True


def test_severity_level_mapping() -> None:
    for sev, lvl in [("critical", "error"), ("high", "error"),
                     ("medium", "warning"), ("low", "note"), ("info", "note")]:
        rep = _report()
        rep.findings[0].finding.severity = sev
        assert render_sarif(rep)["runs"][0]["results"][0]["level"] == lvl


def test_export_report_writes_both_files() -> None:
    with tempfile.TemporaryDirectory() as td:
        hp, sp = Path(td) / "r.html", Path(td) / "r.sarif"
        export_report("run-1", html_path=hp, sarif_path=sp, report=_report())
        assert hp.exists() and sp.exists()
        assert "IDOR" in hp.read_text(encoding="utf-8")
        sarif = json.loads(sp.read_text(encoding="utf-8"))
        assert sarif["runs"][0]["results"][0]["ruleId"] == "CWE-639"


def _run() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")


if __name__ == "__main__":
    _run()
