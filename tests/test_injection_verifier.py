"""Injection verifier 단위 테스트 — 브라우저/네트워크 없이 CI에서 돈다.

oracle(판정 로직)·probe 파싱·dispatch 라우팅·payload 안전성·비-GET 가드를 검증한다.
실제 대상 재현(verify end-to-end)은 통제 랩서버로 별도 확인(XSS와 동일 방침).
"""

import unittest

from contracts.schemas import Candidate
from verifiers import dispatch, injection


class InjectionOracleTests(unittest.TestCase):
    def test_size_delta_true_larger_is_injectable(self):
        # 참(OR 1=1)이 거짓(OR 1=2)보다 확연히 큼 = 결과셋이 열림
        verified, reason = injection.injection_oracle(200, "row" * 200, 200, "")
        self.assertTrue(verified)
        self.assertIn("CWE-89", reason)

    def test_status_split_is_injectable(self):
        # 거짓만 500 = 불리언이 쿼리 실행에 영향
        verified, _ = injection.injection_oracle(200, "x", 500, "server error")
        self.assertTrue(verified)

    def test_sanitized_equal_bodies_not_injectable(self):
        # 참 ≈ 거짓(한 글자 에코 차이) = 리터럴 처리(살균)
        verified, reason = injection.injection_oracle(200, "no results found", 200, "no results found!")
        self.assertFalse(verified)
        self.assertIn("살균", reason)

    def test_both_empty_not_injectable(self):
        verified, _ = injection.injection_oracle(200, "", 200, "")
        self.assertFalse(verified)

    def test_delta_below_threshold_not_injectable(self):
        # 임계(_MIN_DELTA) 미만 차이는 오탐하지 않는다(precision 우선)
        verified, _ = injection.injection_oracle(200, "a" * 20, 200, "")
        self.assertFalse(verified)

    def test_juice_shop_sqli_demo_pattern(self):
        # 데모 2 회귀 잠금 — J-2 실측(Juice Shop GET /rest/products/search?q=):
        # baseline apple=631B, true(OR 1=1)=18662B, false(AND 1=2)=30B, status 전부 200.
        # _MIN_DELTA 등 변경이 이 데모 verify 케이스를 깨면 여기서 실패한다.
        verified, reason = injection.injection_oracle(200, "x" * 18662, 200, "x" * 30, baseline_variance=0)
        self.assertTrue(verified)  # 취약: verified
        self.assertIn("CWE-89", reason)
        # 검색 응답이 요청마다 500B 흔들려도(노이즈) verified 유지 (18632 >> 임계 1048)
        verified_noise, _ = injection.injection_oracle(200, "x" * 18662, 200, "x" * 30, baseline_variance=500)
        self.assertTrue(verified_noise)
        # 패치(파라미터화) 후 true≈false → attack 게이트 통과(verified=False)
        verified_patched, _ = injection.injection_oracle(200, "x" * 631, 200, "x" * 631)
        self.assertFalse(verified_patched)

    def test_natural_variance_suppresses_false_positive(self):
        # 하드닝: 참-거짓 차이 120(옛 임계 48이면 탐지)이라도, 엔드포인트 자연 변동이 120이면
        # 노이즈 바닥(48 + 2×120)에 못 미쳐 오탐 안 함 — 타임스탬프/nonce/페이지네이션 방어.
        verified, reason = injection.injection_oracle(200, "a" * 120, 200, "", baseline_variance=120)
        self.assertFalse(verified)
        self.assertIn("자연 변동", reason)

    def test_stable_endpoint_still_detects_after_hardening(self):
        # 대조: 같은 120 차이라도 자연 변동 0(조용한 엔드포인트)이면 그대로 탐지 → 랩 TP 유지.
        verified, _ = injection.injection_oracle(200, "a" * 120, 200, "", baseline_variance=0)
        self.assertTrue(verified)

    def test_unstable_baseline_distrusts_status_split(self):
        # baseline 상태코드가 흔들리면(불안정) 상태 갈림 신호를 노이즈로 보고 신뢰하지 않는다.
        verified, _ = injection.injection_oracle(
            200, "x", 500, "err", baseline_status_stable=False)
        self.assertFalse(verified)


class InjectionProbeTests(unittest.TestCase):
    def test_probe_from_candidate_basic(self):
        c = Candidate(id="c", run_id="r", vuln_class="injection", attack_params={
            "base_url": "http://127.0.0.1:9",
            "inject_path": "/api/search", "inject_param": "q",
        })
        p = injection.injection_probe_from_candidate(c)
        self.assertEqual(p.inject_path, "/api/search")
        self.assertEqual(p.inject_method, "GET")   # 기본값
        self.assertEqual(p.inject_location, "query")

    def test_probe_extra_params_json_and_read_query_coercion(self):
        c = Candidate(id="c", run_id="r", vuln_class="injection", attack_params={
            "base_url": "http://127.0.0.1:9", "inject_path": "/api/auth/login",
            "inject_param": "username", "inject_method": "POST", "inject_location": "json",
            "read_query": "true", "extra_params_json": '{"password":"x"}',
        })
        p = injection.injection_probe_from_candidate(c)
        self.assertTrue(p.read_query)                       # 문자열 "true" → bool
        self.assertEqual(p.extra_params, {"password": "x"})  # extra_params_json 되풀림


class InjectionSafetyTests(unittest.TestCase):
    def test_payloads_are_boolean_only_no_destructive_tokens(self):
        # 파괴적/위험 토큰이 payload에 없어야 한다(스택쿼리·write DML·UNION·time-based·OS).
        forbidden = [";", "drop", "delete", "insert", "update", "union", "sleep",
                     "benchmark", "exec", "xp_", "load_file", "outfile", "waitfor"]
        for true_pl, false_pl in injection._PAYLOAD_PAIRS:
            for pl in (true_pl, false_pl):
                low = pl.lower()
                for tok in forbidden:
                    self.assertNotIn(tok, low, f"payload {pl!r}에 금지 토큰 {tok!r}")

    def test_pair_differs_by_minimal_chars(self):
        # 각 쌍은 거의 동일(불리언 결과만 토글) → 응답 차이가 SQL 해석의 증거가 되게.
        for true_pl, false_pl in injection._PAYLOAD_PAIRS:
            self.assertEqual(len(true_pl), len(false_pl))
            diff = sum(1 for a, b in zip(true_pl, false_pl) if a != b)
            self.assertLessEqual(diff, 1)

    def test_non_get_without_read_query_is_refused(self):
        # 비-GET은 read_query 보증 없이는 재현 거부(파괴적 쿼리에 불리언 payload 방지, 추측 금지).
        probe = injection.InjectionProbe(
            base_url="http://127.0.0.1:9", inject_path="/api/items", inject_param="q",
            inject_method="POST", read_query=False,
        )
        with self.assertRaises(NotImplementedError):
            injection._replay_injection(probe, max_requests=10)


class InjectionDispatchTests(unittest.TestCase):
    def test_vuln_class_injection_routes(self):
        c = Candidate(id="c", run_id="r", vuln_class="injection")
        self.assertEqual(dispatch.class_of(c), "injection")
        self.assertIn("injection", dispatch._VERIFIERS)
        self.assertEqual(len(dispatch._NOT_READY), 0)

    def test_cwe_89_corrects_to_injection(self):
        c = Candidate(id="c", run_id="r", cwe="CWE-89")
        self.assertEqual(dispatch.class_of(c), "injection")


if __name__ == "__main__":
    unittest.main()
