"""XSS/Injection positive functionality 게이트 단위 테스트 (refined-(a), P3).

`repair.validators`의 클래스별 positive 게이트를 검증한다:
  - 순수 oracle(xss/injection_positive_gate_oracle) — 네트워크 없음.
  - `validate_patch` dispatch — vuln_class에 맞는 게이트로 라우팅(네트워크/DB 없이 monkeypatch).
  - 게이트 실행기(_xss/_injection_positive_gate) — 요청·evidence 계층을 monkeypatch해 헤르메틱.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from contracts.schemas import Candidate
from repair import validators


def _candidate(vuln_class: str, cwe: str, **extra_ap) -> Candidate:
    ap = {"base_url": "http://127.0.0.1:1", "inject_path": "/x", "inject_param": "q"}
    ap.update(extra_ap)
    return Candidate(
        id="cand-x", run_id="run-x", vuln_class=vuln_class, cwe=cwe,
        endpoint="/x", source_symbols=[], attack_params=ap,
    )


class XssPositiveOracleTests(unittest.TestCase):
    def test_2xx_and_reflected_passes(self):
        ok, _ = validators.xss_positive_gate_oracle(200, "vcb1", "hello vcb1 world")
        self.assertTrue(ok)

    def test_escaped_plaintext_still_present_passes(self):
        # 평문 marker는 HTML escape에 불변 → 그대로 존재 → 통과
        ok, _ = validators.xss_positive_gate_oracle(200, "vcb1", "<p>vcb1</p>")
        self.assertTrue(ok)

    def test_non_2xx_fails(self):
        ok, reason = validators.xss_positive_gate_oracle(500, "vcb1", "vcb1")
        self.assertFalse(ok)
        self.assertIn("overblocking", reason)

    def test_value_absent_fails(self):
        ok, _ = validators.xss_positive_gate_oracle(200, "vcb1", "nothing here")
        self.assertFalse(ok)


class InjectionPositiveOracleTests(unittest.TestCase):
    def test_2xx_nonempty_passes(self):
        ok, reason = validators.injection_positive_gate_oracle(200, "some rows")
        self.assertTrue(ok)
        self.assertIn("liveness", reason)

    def test_non_2xx_fails(self):
        ok, _ = validators.injection_positive_gate_oracle(500, "error")
        self.assertFalse(ok)

    def test_empty_body_fails(self):
        ok, _ = validators.injection_positive_gate_oracle(200, "   ")
        self.assertFalse(ok)


class ValidatePatchDispatchTests(unittest.TestCase):
    """validate_patch가 vuln_class로 올바른 positive 게이트를 고르는지 (네트워크/DB 없이)."""

    def test_routes_xss(self):
        cand = _candidate("xss", "CWE-79", context="reflected")
        with patch.object(validators, "_candidate_for_patch", return_value=cand), \
             patch.object(validators, "_xss_positive_gate") as xss_gate, \
             patch.object(validators, "_injection_positive_gate") as inj_gate, \
             patch.object(validators, "run_security_validation") as idor_run:
            xss_gate.return_value = validators.GateOutcome(
                gate="positive_functionality", passed=True, reason="ok"
            )
            self.assertTrue(validators.validate_patch("run-x", "patch-x"))
            xss_gate.assert_called_once()
            inj_gate.assert_not_called()
            idor_run.assert_not_called()

    def test_routes_injection(self):
        cand = _candidate("injection", "CWE-89")
        with patch.object(validators, "_candidate_for_patch", return_value=cand), \
             patch.object(validators, "_injection_positive_gate") as inj_gate, \
             patch.object(validators, "_xss_positive_gate") as xss_gate, \
             patch.object(validators, "run_security_validation") as idor_run:
            inj_gate.return_value = validators.GateOutcome(
                gate="positive_functionality", passed=False, reason="no"
            )
            self.assertFalse(validators.validate_patch("run-x", "patch-x"))
            inj_gate.assert_called_once()
            xss_gate.assert_not_called()
            idor_run.assert_not_called()

    def test_routes_idor_default(self):
        cand = _candidate("idor", "CWE-639")
        fake = validators.SecurityValidation(
            attack=validators.GateOutcome(gate="attack", passed=True, reason="a"),
            positive_functionality=validators.GateOutcome(
                gate="positive_functionality", passed=True, reason="p"
            ),
        )
        with patch.object(validators, "_candidate_for_patch", return_value=cand), \
             patch.object(validators, "run_security_validation", return_value=fake) as idor_run, \
             patch.object(validators, "_xss_positive_gate") as xss_gate:
            self.assertTrue(validators.validate_patch("run-x", "patch-x"))
            idor_run.assert_called_once()
            xss_gate.assert_not_called()


class XssPositiveGateTests(unittest.TestCase):
    """_xss_positive_gate: 요청·evidence를 monkeypatch해 헤르메틱하게 판정만 검증."""

    def test_benign_reflected_passes_and_stores_evidence(self):
        cand = _candidate("xss", "CWE-79", context="reflected")
        # benign 값이 응답에 그대로 들어오게 side_effect로 에코
        with patch.object(validators, "_send_xss_benign", side_effect=lambda p, v: (200, f"echo {v}")) as send, \
             patch.object(validators, "_store_positive_evidence", return_value="obs-1") as store:
            out = validators._xss_positive_gate("run-x", cand)
            self.assertTrue(out.passed)
            self.assertEqual(out.evidence_ids, ["obs-1"])
            send.assert_called_once()
            store.assert_called_once()

    def test_broken_page_fails(self):
        cand = _candidate("xss", "CWE-79", context="reflected")
        with patch.object(validators, "_send_xss_benign", return_value=(500, "")), \
             patch.object(validators, "_store_positive_evidence", return_value="obs-2"):
            out = validators._xss_positive_gate("run-x", cand)
            self.assertFalse(out.passed)


class InjectionPositiveGateTests(unittest.TestCase):
    """_injection_positive_gate: _send·evidence를 monkeypatch해 헤르메틱하게."""

    def test_liveness_pass(self):
        cand = _candidate("injection", "CWE-89", inject_path="/api/search")
        with patch.object(validators, "_send_injection", return_value=(200, "matching rows")), \
             patch.object(validators, "_store_positive_evidence", return_value="obs-3"):
            out = validators._injection_positive_gate("run-x", cand)
            self.assertTrue(out.passed)
            self.assertEqual(out.evidence_ids, ["obs-3"])

    def test_500_fails(self):
        cand = _candidate("injection", "CWE-89", inject_path="/api/search")
        with patch.object(validators, "_send_injection", return_value=(500, "boom")), \
             patch.object(validators, "_store_positive_evidence", return_value="obs-4"):
            out = validators._injection_positive_gate("run-x", cand)
            self.assertFalse(out.passed)


if __name__ == "__main__":
    unittest.main()
