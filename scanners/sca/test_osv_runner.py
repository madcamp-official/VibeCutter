"""scanners.sca.osv_runner 단위 테스트 (osv-scanner 불필요, fixture 기반).

실행: python -m scanners.sca.test_osv_runner
"""

from __future__ import annotations

import json
from pathlib import Path

from contracts.schemas import Candidate
from scanners.sca.osv_runner import (
    OSVUnavailableError,
    parse_osv_output,
    run_osv,
)

FIXTURE = Path(__file__).with_name("testdata") / "sample_osv.json"


def _load() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_parse_maps_all_vulns() -> None:
    cands = parse_osv_output(_load(), run_id="r1")
    assert len(cands) == 3
    assert all(isinstance(c, Candidate) for c in cands)
    assert all(c.run_id == "r1" for c in cands)


def test_sca_candidates_have_no_focus_but_category_tag() -> None:
    cands = parse_osv_output(_load(), run_id="r1")
    for c in cands:
        assert "category:sca" in c.signals
        assert not any(s.startswith("focus:") for s in c.signals)


def test_source_symbol_and_pkg_signal() -> None:
    cands = parse_osv_output(_load(), run_id="r1")
    by_pkg = {c.source_symbols[0]: c for c in cands}
    assert "requirements.txt:flask@0.12.2" in by_pkg
    assert "package-lock.json:lodash@4.17.4" in by_pkg
    flask = by_pkg["requirements.txt:flask@0.12.2"]
    assert "pkg:flask@0.12.2" in flask.signals
    assert "ecosystem:PyPI" in flask.signals
    assert "alias:CVE-2018-1000656" in flask.signals


def test_severity_label_then_cvss_fallback() -> None:
    cands = parse_osv_output(_load(), run_id="r1")
    by_pkg = {c.source_symbols[0].split(":")[1].split("@")[0]: c for c in cands}
    assert by_pkg["flask"].confidence == 0.8     # database_specific HIGH
    assert by_pkg["lodash"].confidence == 0.9    # database_specific CRITICAL
    # jinja2 는 severity 라벨 없음 → group max_severity 8.6 → HIGH(0.8)
    assert by_pkg["jinja2"].confidence == 0.8
    assert "severity:HIGH" in by_pkg["jinja2"].signals


def test_cwe_extracted_when_present() -> None:
    cands = parse_osv_output(_load(), run_id="r1")
    by_pkg = {c.source_symbols[0].split(":")[1].split("@")[0]: c for c in cands}
    assert by_pkg["flask"].cwe == "CWE-400"
    assert by_pkg["lodash"].cwe is None  # cwe_ids 없음


def test_deterministic_ids() -> None:
    a = parse_osv_output(_load(), run_id="r1")
    b = parse_osv_output(_load(), run_id="r1")
    assert [c.id for c in a] == [c.id for c in b]
    assert all(c.id.startswith("cand-sca-") for c in a)


def test_empty() -> None:
    assert parse_osv_output({"results": []}, run_id="r1") == []
    assert parse_osv_output({}, run_id="r1") == []


def test_run_osv_missing_binary() -> None:
    try:
        run_osv(".", run_id="r1", osv_bin="definitely-not-osv-xyz")
    except OSVUnavailableError:
        return
    raise AssertionError("바이너리 부재 시 OSVUnavailableError")


def test_run_osv_missing_target() -> None:
    try:
        run_osv("/no/such/path/xyz", run_id="r1")
    except FileNotFoundError:
        return
    raise AssertionError("존재하지 않는 target 은 FileNotFoundError")


def _run() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")


if __name__ == "__main__":
    _run()
