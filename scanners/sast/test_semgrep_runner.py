"""scanners.sast.semgrep_runner 단위 테스트 (semgrep 바이너리 불필요, fixture 기반).

실행: python -m scanners.sast.test_semgrep_runner
"""

from __future__ import annotations

import json
from pathlib import Path

from contracts.schemas import Candidate
from scanners.sast.semgrep_runner import (
    SemgrepUnavailableError,
    parse_semgrep_output,
    run_semgrep,
)

FIXTURE = Path(__file__).with_name("testdata") / "sample_semgrep.json"


def _load() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_parse_maps_all_results_to_candidates() -> None:
    cands = parse_semgrep_output(_load(), run_id="r1")
    assert len(cands) == 3
    assert all(isinstance(c, Candidate) for c in cands)
    assert all(c.run_id == "r1" for c in cands)


def test_cwe_normalized_from_list_and_str() -> None:
    cands = parse_semgrep_output(_load(), run_id="r1")
    by_path = {c.source_symbols[0].split(":")[0]: c for c in cands}
    assert by_path["app/db/users.py"].cwe == "CWE-89"
    assert by_path["config/settings.py"].cwe == "CWE-798"  # str(비 list) 도 처리


def test_focus_inferred_from_metadata() -> None:
    cands = parse_semgrep_output(_load(), run_id="r1")
    by_path = {c.source_symbols[0].split(":")[0]: c for c in cands}
    assert "focus:injection" in by_path["app/db/users.py"].signals
    assert "focus:xss" in by_path["src/routes/profile.js"].signals


def test_vuln_class_set_from_focus_for_p3_dispatch() -> None:
    # P3 verifier 가 candidate.vuln_class 로 검증 모듈을 분기한다(verifiers/types.py).
    cands = parse_semgrep_output(_load(), run_id="r1")
    by_path = {c.source_symbols[0].split(":")[0]: c for c in cands}
    assert by_path["app/db/users.py"].vuln_class == "injection"
    assert by_path["src/routes/profile.js"].vuln_class == "xss"
    # 3군 밖(secret)은 vuln_class None
    assert by_path["config/settings.py"].vuln_class is None


def test_ruleset_focus_overrides_inference() -> None:
    cands = parse_semgrep_output(_load(), run_id="r1", ruleset_focus="idor")
    assert all("focus:idor" in c.signals for c in cands)


def test_confidence_from_severity_and_metadata() -> None:
    cands = parse_semgrep_output(_load(), run_id="r1")
    by_path = {c.source_symbols[0].split(":")[0]: c for c in cands}
    assert by_path["app/db/users.py"].confidence == 0.9  # metadata HIGH
    assert by_path["src/routes/profile.js"].confidence == 0.6  # metadata MEDIUM
    assert by_path["config/settings.py"].confidence == 0.3  # severity INFO, md 없음


def test_candidate_id_is_deterministic_and_stable() -> None:
    a = parse_semgrep_output(_load(), run_id="r1")
    b = parse_semgrep_output(_load(), run_id="r1")
    assert [c.id for c in a] == [c.id for c in b]
    # run_id 가 다르면 id 도 달라야 한다(같은 run 안에서만 dedup).
    c = parse_semgrep_output(_load(), run_id="r2")
    assert {x.id for x in a}.isdisjoint({x.id for x in c})
    assert all(c.id.startswith("cand-sast-") for c in a)


def test_empty_results_yields_no_candidates() -> None:
    assert parse_semgrep_output({"results": []}, run_id="r1") == []
    assert parse_semgrep_output({}, run_id="r1") == []


def test_run_semgrep_raises_when_binary_missing() -> None:
    try:
        run_semgrep(".", run_id="r1", semgrep_bin="definitely-not-semgrep-xyz")
    except SemgrepUnavailableError:
        return
    raise AssertionError("바이너리 부재 시 SemgrepUnavailableError 를 던져야 함")


def test_run_semgrep_raises_on_missing_target() -> None:
    try:
        run_semgrep("/no/such/path/xyz", run_id="r1")
    except FileNotFoundError:
        return
    raise AssertionError("존재하지 않는 target 은 FileNotFoundError")


def _run() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for t in tests:
        t()
        passed += 1
        print(f"  ok  {t.__name__}")
    print(f"\n{passed}/{len(tests)} passed")


if __name__ == "__main__":
    _run()
