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


class XssPlaywrightPreflightTests(unittest.TestCase):
    """X5: 격리 브라우저 미설치 시 verify()가 크래시·억지 verified 대신 명확한 사유로 degrade한다."""

    def test_verify_degrades_cleanly_when_browser_unavailable(self):
        from unittest.mock import patch

        c = Candidate(id="c", run_id="r", cwe="CWE-79", vuln_class="xss", attack_params={
            "base_url": "http://127.0.0.1:9", "context": "reflected", "inject_path": "/s", "inject_param": "q"})
        with patch("verifiers.xss._playwright_available", return_value=(False, "chromium 미설치")):
            out = xss.verify("run-x5", c)  # 브라우저 안 띄우고 즉시 degrade → evidence 미기록
        self.assertFalse(out.verified)
        self.assertIn("검증 불가", out.reason)
        self.assertIn("chromium", out.reason)
        self.assertEqual(out.evidence_ids, [])

    def test_preflight_returns_tuple(self):
        ok, why = xss._playwright_available()
        self.assertIsInstance(ok, bool)
        self.assertIsInstance(why, str)
        if not ok:
            self.assertTrue(why)  # 불가하면 사유가 있어야


class JuiceShopXssContractTests(unittest.TestCase):
    """P2 Juice Shop XSS 후보 1(reflected 검색)의 verify 계약 shape 잠금(docs/P3_JUICE_SHOP_XSS_CONTRACT.md).

    P2가 이 attack_params로 candidate를 seed하면 reflected oracle이 그대로 소비한다. 실제 verified는
    승인 runtime의 격리 Playwright로만 — 여기선 계약 shape·payload 안전성만 회귀 고정.
    """

    def test_juice_shop_stored_xss_contract_seed(self):
        # 후보 3(stored feedback): 계약-seed로 context=stored candidate가 render_path까지 정상 probe로.
        # 소스 자동생성(write→render 상관)은 follow-up; P2는 이 attack_params로 seed하면 된다.
        c = Candidate(id="c", run_id="r", cwe="CWE-79", vuln_class="xss", attack_params={
            "base_url": "http://127.0.0.1:14020", "context": "stored",
            "inject_path": "/api/Feedbacks", "inject_param": "comment", "inject_method": "POST",
            "render_path": "/#/about",
        })
        p = xss.xss_probe_from_candidate(c)
        self.assertEqual(p.context, "stored")
        self.assertEqual(p.inject_method, "POST")
        self.assertEqual(p.render_path, "/#/about")
        self.assertIn("stored", xss._REPLAY)  # 저장→렌더 재현기 등록됨
        # 저장 XSS도 실행 관찰로만 verified(반사·저장만으론 아님).
        self.assertFalse(xss_oracle(executed=False, raw_reflected=True, escaped_reflected=False)[0])

    def test_juice_shop_reflected_xss_contract(self):
        c = Candidate(id="c", run_id="r", cwe="CWE-79", vuln_class="xss", attack_params={
            "base_url": "http://127.0.0.1:14020", "context": "reflected",
            "inject_path": "/#/search", "inject_param": "q", "inject_method": "GET",
        })
        p = xss.xss_probe_from_candidate(c)
        self.assertEqual(p.context, "reflected")
        self.assertEqual(p.inject_param, "q")
        self.assertIn(p.context, xss._REPLAY)  # reflected 재현기 등록됨
        # bypassSecurityTrustHtml(innerHTML) 렌더에서 실행되는 payload가 세트에 있어야 트리거 가능.
        payloads = _benign_payloads("F")
        self.assertTrue(any("onerror" in pl or "onload" in pl for pl in payloads))
        # 반사만으로 verified 아님(실행돼야) — 계약 핵심.
        self.assertFalse(xss_oracle(executed=False, raw_reflected=True, escaped_reflected=False)[0])


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
