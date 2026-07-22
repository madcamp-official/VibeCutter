"""XSS verifier 단위 테스트 (브라우저 없이): oracle / probe / dispatch 라우팅 / payload 안전성.

라이브 실행(격리 Playwright 브라우저) 검증은 별도 — 취약/안전 로컬 서버로 확인했다
(실행되는 XSS만 verified). 여기서는 브라우저 없이 도는 부분만 회귀로 고정한다.
"""

from __future__ import annotations

import json
import unittest

from contracts.schemas import Candidate
from verifiers import dispatch, xss
from verifiers.xss import _benign_payloads, _reflection_kind, xss_oracle, xss_probe_from_candidate


class XssOracleTests(unittest.TestCase):
    def test_executed_is_verified(self) -> None:
        ok, _ = xss_oracle(executed=True, raw_reflected=True, escaped_reflected=False)
        self.assertTrue(ok)

    def test_reflected_but_not_executed_is_not_verified(self) -> None:
        ok, reason = xss_oracle(executed=False, raw_reflected=True, escaped_reflected=False)
        self.assertFalse(ok)
        self.assertIn("실행", reason)

    def test_escaped_reflection_is_safe(self) -> None:
        ok, _ = xss_oracle(executed=False, raw_reflected=False, escaped_reflected=True)
        self.assertFalse(ok)

    def test_not_reflected_is_not_verified(self) -> None:
        ok, _ = xss_oracle(executed=False, raw_reflected=False, escaped_reflected=False)
        self.assertFalse(ok)


class XssProbeTests(unittest.TestCase):
    def test_from_candidate_reads_attack_params(self) -> None:
        c = Candidate(id="c", run_id="r", cwe="CWE-79", vuln_class="xss",
                      attack_params={"base_url": "http://127.0.0.1:8000", "context": "reflected",
                                     "inject_path": "/search", "inject_param": "q"})
        p = xss_probe_from_candidate(c)
        self.assertEqual(p.base_url, "http://127.0.0.1:8000")
        self.assertEqual(p.inject_param, "q")
        self.assertEqual(p.context, "reflected")

    def test_extra_params_json_is_decoded(self) -> None:
        c = Candidate(id="c", run_id="r", vuln_class="xss",
                      attack_params={"base_url": "http://x", "inject_path": "/", "inject_param": "q",
                                     "extra_params_json": json.dumps({"csrf": "tok"})})
        p = xss_probe_from_candidate(c)
        self.assertEqual(p.extra_params, {"csrf": "tok"})


class XssDispatchRoutingTests(unittest.TestCase):
    def test_xss_is_registered_and_routed(self) -> None:
        self.assertIs(dispatch._VERIFIERS["xss"], xss.verify)
        self.assertNotIn("xss", dispatch._NOT_READY)

    def test_cwe79_maps_to_xss(self) -> None:
        self.assertEqual(dispatch.class_of(Candidate(id="c", run_id="r", cwe="CWE-79")), "xss")


class XssPayloadSafetyTests(unittest.TestCase):
    """benign marker 원칙 강제: payload는 window 플래그만 세팅, 외부 통신/쿠키/지속성 금지."""

    def test_payloads_are_benign(self) -> None:
        forbidden = ("fetch(", "xmlhttprequest", "document.cookie", "localstorage",
                     "sessionstorage", "http://", "https://", "src=http", "navigator.send")
        for payload in _benign_payloads("__vc_xss_test"):
            low = payload.lower()
            for bad in forbidden:
                self.assertNotIn(bad, low, f"benign 위반: {payload!r} 에 {bad!r} 포함")
            self.assertIn("__vc_xss_test", payload, "payload는 지정된 marker 플래그만 세팅해야")

    def test_payloads_cover_filter_evasion_contexts(self) -> None:
        # script/img/svg를 블록리스트로 막는 앱에도 실행 근거를 얻도록 우회 컨텍스트를 포함해야 한다.
        joined = " ".join(_benign_payloads("__vc_xss_test"))
        self.assertIn("ontoggle", joined, "비-script 자동실행(details ontoggle) payload 없음")
        self.assertIn("svg/onload", joined, "슬래시 구분자 우회 payload 없음")
        self.assertIn("ScRiPt", joined, "대소문자 혼합 우회 payload 없음")


class XssReflectionKindTests(unittest.TestCase):
    def test_raw_reflection_detected(self) -> None:
        raw, esc = _reflection_kind("<div><script>window['f']=1</script></div>", "<script>window['f']=1</script>")
        self.assertTrue(raw)

    def test_named_entity_escaping_is_escaped_not_raw(self) -> None:
        body = "x &lt;script&gt;window['f']=1&lt;/script&gt; y"
        raw, esc = _reflection_kind(body, "<script>window['f']=1</script>")
        self.assertFalse(raw)
        self.assertTrue(esc)

    def test_numeric_entity_escaping_is_recognized(self) -> None:
        # 십진 수치 엔티티로 이스케이프한 앱도 안전(escaped)으로 정확히 분류해야 한다(강화 전엔 놓침).
        body = "x &#60;script&#62;window['f']=1&#60;/script&#62; y"
        raw, esc = _reflection_kind(body, "<script>window['f']=1</script>")
        self.assertFalse(raw)
        self.assertTrue(esc)


if __name__ == "__main__":
    unittest.main()
