"""verifiers/dispatch.py 단위 테스트 — vuln_class/CWE 라우팅 (네트워크/DB 없이 순수).

dispatch는 P3 verifier 진입점의 라우터다. 여기서 CWE→class 매핑이 조용히 빠지면 그 CWE
후보가 verify되지 않고 ValueError로 떨어져 **recall이 소리 없이 준다**. 그래서 전체 매핑과
class_of 우선순위(typed vuln_class > CWE 보정)를 회귀로 고정한다.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from contracts.schemas import Candidate
from verifiers import dispatch


class ClassOfTests(unittest.TestCase):
    def test_typed_vuln_class_takes_precedence_over_cwe(self) -> None:
        # vuln_class가 있으면 CWE와 어긋나도 vuln_class를 따른다(SAST가 채운 typed 신호 우선).
        c = Candidate(id="c", run_id="r", vuln_class="idor", cwe="CWE-89")
        self.assertEqual(dispatch.class_of(c), "idor")

    def test_cwe_used_when_vuln_class_absent(self) -> None:
        c = Candidate(id="c", run_id="r", cwe="CWE-79")
        self.assertEqual(dispatch.class_of(c), "xss")

    def test_none_when_neither_matches(self) -> None:
        self.assertIsNone(dispatch.class_of(Candidate(id="c", run_id="r", cwe="CWE-99999")))
        self.assertIsNone(dispatch.class_of(Candidate(id="c", run_id="r")))


class CweMapLockTests(unittest.TestCase):
    """CWE→class 매핑 전체 잠금 — 추가/삭제는 recall을 바꾸는 의식적 변경이라 이 표도 함께 고쳐야 한다."""

    EXPECTED = {
        "CWE-639": "idor",  # IDOR (User-Controlled Key)
        "CWE-284": "idor",  # Improper Access Control
        "CWE-862": "idor",  # Missing Authorization
        "CWE-863": "idor",  # Incorrect Authorization
        "CWE-566": "idor",  # Authorization Bypass (SQL Primary Key)
        "CWE-79": "xss",
        "CWE-89": "injection",
        "CWE-78": "injection",  # OS Command Injection — 현재 injection 오라클로 라우팅(설계상)
    }

    def test_map_matches_expected_exactly(self) -> None:
        self.assertEqual(dispatch._CWE_TO_CLASS, self.EXPECTED)

    def test_each_cwe_routes_via_class_of(self) -> None:
        for cwe, expected in self.EXPECTED.items():
            with self.subTest(cwe=cwe):
                self.assertEqual(dispatch.class_of(Candidate(id="c", run_id="r", cwe=cwe)), expected)


class VerifyCandidateRoutingTests(unittest.TestCase):
    def test_unknown_class_raises_value_error_not_guess(self) -> None:
        # 판별 불가면 아무 verifier나 부르지 않고 ValueError — 추측 재현 금지.
        c = Candidate(id="c", run_id="r", cwe="CWE-99999")
        with self.assertRaises(ValueError):
            dispatch.verify_candidate("run-x", c)

    def test_idor_read_routes_to_read_verify(self) -> None:
        c = Candidate(id="c", run_id="r", vuln_class="idor")  # idor_mode 없음 → read
        with patch.object(dispatch.access_control, "verify") as read_v, \
             patch.object(dispatch.access_control, "verify_mutation_access_control") as write_v:
            dispatch.verify_candidate("run-x", c)
            read_v.assert_called_once()
            write_v.assert_not_called()

    def test_idor_write_mode_routes_to_mutation_verify(self) -> None:
        c = Candidate(id="c", run_id="r", vuln_class="idor", attack_params={"idor_mode": "write"})
        with patch.object(dispatch.access_control, "verify") as read_v, \
             patch.object(dispatch.access_control, "verify_mutation_access_control") as write_v:
            dispatch.verify_candidate("run-x", c)
            write_v.assert_called_once()
            read_v.assert_not_called()

    def test_injection_routes_to_injection_verify(self) -> None:
        # _VERIFIERS는 import 시점에 injection.verify를 값으로 캡처하므로 dict 항목을 직접 patch한다.
        c = Candidate(id="c", run_id="r", vuln_class="injection")
        mock = MagicMock()
        with patch.dict(dispatch._VERIFIERS, {"injection": mock}):
            dispatch.verify_candidate("run-x", c)
        mock.assert_called_once()

    def test_xss_routes_to_xss_verify(self) -> None:
        c = Candidate(id="c", run_id="r", vuln_class="xss")
        mock = MagicMock()
        with patch.dict(dispatch._VERIFIERS, {"xss": mock}):
            dispatch.verify_candidate("run-x", c)
        mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
