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


class InjectionContentDivergenceTests(unittest.TestCase):
    """I4: 길이-델타가 놓치는 '길이 우연 일치' 케이스를 콘텐츠 발산으로 잡되 precision은 지킨다."""

    def test_similar_length_divergent_bodies_is_injectable(self):
        # 참=행 목록, 거짓=없음 페이지 — byte 길이는 비슷(델타<임계)해도 구조가 크게 갈림 → verified.
        true_body = "<tr><td>row</td></tr>" * 12      # 결과셋 열림(행 반복)
        false_body = "no matching records found. " * 9  # 결과셋 닫힘(없음)
        self.assertLess(abs(len(true_body) - len(false_body)), injection._MIN_DELTA)  # 길이 델타로는 못 잡음
        verified, reason = injection.injection_oracle(200, true_body, 200, false_body)
        self.assertTrue(verified)
        self.assertIn("구조적으로", reason)
        self.assertIn("CWE-89", reason)

    def test_one_char_echo_similar_bodies_not_injectable(self):
        # 한 글자(payload) 에코만 다른 큰 본문 → 유사도 높음 → 발산 신호 안 걸림(precision).
        base = "search page content block " * 10
        verified, _ = injection.injection_oracle(200, base + "1", 200, base + "2")
        self.assertFalse(verified)

    def test_sanitized_same_notfound_page_not_injectable(self):
        # 살균 앱: 두 무효값이 같은 '없음' 페이지 → 유사도 높음 → 발산 안 걸림(precision).
        page = "No results were found for your query. Please try again. " * 6
        verified, _ = injection.injection_oracle(200, page, 200, page)
        self.assertFalse(verified)

    def test_noisy_baseline_suppresses_divergence(self):
        # 발산이 커도 benign 2-sample 유사도 바닥이 낮으면(노이즈 큰 엔드포인트) 신뢰하지 않는다.
        true_body = "<tr><td>row</td></tr>" * 12
        false_body = "no matching records found. " * 9
        verified, _ = injection.injection_oracle(
            200, true_body, 200, false_body, baseline_similarity=0.30)
        self.assertFalse(verified)

    def test_short_bodies_skip_divergence_signal(self):
        # 너무 짧은 본문(_SIM_MIN_BODY 미만)은 유사도 비율이 불안정 → 발산 신호 미적용.
        verified, _ = injection.injection_oracle(200, "rows", 200, "none")
        self.assertFalse(verified)

    def test_unstable_status_suppresses_divergence(self):
        # baseline 상태 불안정이면 발산 신호도 노이즈로 보고 쓰지 않는다.
        true_body = "<tr><td>row</td></tr>" * 12
        false_body = "no matching records found. " * 9
        verified, _ = injection.injection_oracle(
            200, true_body, 200, false_body, baseline_status_stable=False)
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

    def test_default_budget_pairs_cover_diverse_contexts(self):
        # 기본 예산(10 = baseline 2 + 4쌍×2)에서 시도되는 상위 4쌍이 문자열·숫자·괄호 컨텍스트를
        # 모두 덮어야 한다. 괄호로 감싼 WHERE(`(col='...')`)는 괄호를 닫아야 tautology가 성립 —
        # 이 컨텍스트가 예산 밖으로 밀리면 그런 앱에서 verify recall이 떨어진다(회귀 방지).
        top4 = injection._PAYLOAD_PAIRS[:(10 - 2) // 2]
        joined = " ".join(t for t, _ in top4)
        self.assertIn("(", joined, "괄호 닫기 컨텍스트가 기본 예산 상위 4쌍에 없음")
        self.assertIn("1 OR 1=1", joined, "숫자 컨텍스트가 상위 4쌍에 없음")
        self.assertTrue(any(t.startswith("'") for t, _ in top4), "홑따옴표 문자열 컨텍스트 없음")

    def test_non_get_without_read_query_is_refused(self):
        # 비-GET은 read_query 보증 없이는 재현 거부(파괴적 쿼리에 불리언 payload 방지, 추측 금지).
        probe = injection.InjectionProbe(
            base_url="http://127.0.0.1:9", inject_path="/api/items", inject_param="q",
            inject_method="POST", read_query=False,
        )
        with self.assertRaises(NotImplementedError):
            injection._replay_injection(probe, max_requests=10)


class JuiceShopInjectionContractTests(unittest.TestCase):
    """데모2(J-3) Juice Shop 검색 SQLi의 seed 계약 shape 잠금(docs/P3_JUICE_SHOP_INJECTION_CONTRACT.md).

    P2가 이 attack_params로 candidate를 seed하면 불리언 차등 오라클이 그대로 소비한다. 실제 verified는
    승인 runtime의 실 target 재현 + evidence로만 — 여기선 계약 shape·GET 안전 경계·오라클 회귀만 고정.
    """

    def test_juice_shop_injection_contract_shape(self):
        c = Candidate(id="c", run_id="r", cwe="CWE-89", vuln_class="injection", attack_params={
            "base_url": "http://127.0.0.1:14020", "inject_method": "GET", "inject_location": "query",
            "inject_path": "/rest/products/search", "inject_param": "q", "baseline_value": "apple",
        })
        p = injection.injection_probe_from_candidate(c)
        self.assertEqual(p.inject_path, "/rest/products/search")
        self.assertEqual(p.inject_param, "q")
        self.assertEqual(p.inject_method, "GET")       # 읽기 — 파괴적 아님
        self.assertEqual(p.inject_location, "query")
        self.assertEqual(p.baseline_value, "apple")
        self.assertFalse(p.read_query)                  # GET은 read_query 보증 불필요(자동 허용)
        self.assertEqual(dispatch.class_of(c), "injection")

    def test_juice_shop_contract_oracle_matches_measured(self):
        # J-2 실측(baseline 631 / true 18662 / false 30, 전부 200) → verified. 계약이 이 수치와 정합.
        verified, reason = injection.injection_oracle(200, "x" * 18662, 200, "x" * 30, baseline_variance=500)
        self.assertTrue(verified)
        self.assertIn("CWE-89", reason)
        # 파라미터화 패치 후(참≈거짓) → verify가 False로 뒤집혀 FIXED를 확증.
        self.assertFalse(injection.injection_oracle(200, "x" * 631, 200, "x" * 631)[0])


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
