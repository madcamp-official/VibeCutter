"""repair/locator.py 헤르메틱 단위 테스트 (P3 남은 일 #4).

locator의 코어 분기를 네트워크/실앱 없이 고정한다:
  - 심볼/경로 정규화 및 route 매칭(_normalize_path/_split_method_path/_match_route)
  - 수정 위치 계층 분류(controller hotfix vs service policy vs shared middleware, 우선순위)
  - SAST taint 교차검증(_sast_files/_files_agree + localize 근거 문구)
  - 프론트엔드 가드(_is_frontend_file)와 code_index 폴백/실패 시 ValueError

route 추출기(surface.routes.extract_routes)와 P4 code_index(model.code_index.CodeIndex)는
mock/픽스처로 대체해 locator 자신의 로직만 검사한다(대상 모듈은 수정하지 않는다).
"""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from contracts.schemas import Finding, RootCause
from repair import locator
from repair.locator import (
    _classify_layer,
    _files_agree,
    _is_frontend_file,
    _match_route,
    _normalize_path,
    _sast_files,
    _split_method_path,
    localize,
)
from surface.routes import Route


def _finding(endpoint: str | None, source_symbols: list[str] | None = None) -> Finding:
    return Finding(
        id="finding-x",
        run_id="run-x",
        title="idor",
        cwe="CWE-639",
        affected_endpoint=endpoint,
        source_symbols=source_symbols or [],
    )


def _route(method: str, path: str, handler: str, source: str, stack: str = "spring") -> Route:
    return Route(http_method=method, path=path, handler=handler, source=source, stack=stack)


class NormalizePathTests(unittest.TestCase):
    def test_brace_and_colon_params_normalize_to_same_route(self) -> None:
        # {userId} / {id} / :id 표기가 앱마다 달라도 같은 route로 매칭되어야 한다.
        self.assertEqual(_normalize_path("/IDOR/profile/{userId}"), "/IDOR/profile/{}")
        self.assertEqual(_normalize_path("/IDOR/profile/{id}"), "/IDOR/profile/{}")
        self.assertEqual(_normalize_path("/IDOR/profile/:id"), "/IDOR/profile/{}")

    def test_leading_trailing_slashes_are_canonicalized(self) -> None:
        self.assertEqual(_normalize_path("IDOR/profile/"), "/IDOR/profile")
        self.assertEqual(_normalize_path(""), "/")
        self.assertEqual(_normalize_path(None), "/")


class SplitMethodPathTests(unittest.TestCase):
    def test_method_and_path_split(self) -> None:
        self.assertEqual(_split_method_path("GET /a/{id}"), ("GET", "/a/{id}"))

    def test_lowercase_method_is_uppercased(self) -> None:
        self.assertEqual(_split_method_path("post /a"), ("POST", "/a"))

    def test_path_only_returns_none_method(self) -> None:
        self.assertEqual(_split_method_path("/a/{id}"), (None, "/a/{id}"))

    def test_empty_returns_none_and_empty_path(self) -> None:
        self.assertEqual(_split_method_path(None), (None, ""))


class MatchRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.routes = [
            _route("GET", "/IDOR/profile/{userId}", "UserController.get", "u.java:10"),
            _route("POST", "/IDOR/profile/{userId}", "UserController.update", "u.java:20"),
        ]

    def test_exact_method_and_normalized_path_match(self) -> None:
        r = _match_route(self.routes, "GET", "/IDOR/profile/{id}")
        self.assertIsNotNone(r)
        self.assertEqual(r.handler, "UserController.get")

    def test_method_mismatch_returns_none(self) -> None:
        self.assertIsNone(_match_route(self.routes, "DELETE", "/IDOR/profile/{id}"))

    def test_none_method_matches_any_method_route(self) -> None:
        # method 미지정(path만) 이면 method 조건을 건너뛰고 path만으로 매칭한다.
        r = _match_route(self.routes, None, "/IDOR/profile/:x")
        self.assertIsNotNone(r)

    def test_any_route_matches_any_requested_method(self) -> None:
        routes = [_route("ANY", "/thing/{id}", "T.h", "t.java:1")]
        self.assertIsNotNone(_match_route(routes, "GET", "/thing/{id}"))

    def test_path_mismatch_returns_none(self) -> None:
        self.assertIsNone(_match_route(self.routes, "GET", "/other/{id}"))


class ClassifyLayerTests(unittest.TestCase):
    def test_controller_hotfix(self) -> None:
        self.assertEqual(_classify_layer("UserController.get", "UserController.java"), "controller_hotfix")

    def test_service_policy(self) -> None:
        self.assertEqual(_classify_layer("UserService.load", "UserService.java"), "service_policy")

    def test_shared_middleware(self) -> None:
        self.assertEqual(_classify_layer("SecurityFilter.do", "SecurityFilter.java"), "shared_middleware")

    def test_middleware_wins_over_service_by_precedence(self) -> None:
        # "filter"(middleware)와 "service"(policy)가 둘 다 있으면 더 구체적인 middleware가 먼저다.
        self.assertEqual(_classify_layer("AuthFilterService", "x"), "shared_middleware")

    def test_unknown_defaults_to_controller_hotfix(self) -> None:
        self.assertEqual(_classify_layer("Frobnicate", "widget.py"), "controller_hotfix")


class SastCrossValidationTests(unittest.TestCase):
    def test_sast_files_extracts_only_file_part(self) -> None:
        f = _finding("GET /x", ["src/A.java:42", "src/B.java:7", "no-colon-token"])
        self.assertEqual(_sast_files(f), {"src/A.java", "src/B.java"})

    def test_files_agree_on_exact_and_suffix(self) -> None:
        self.assertTrue(_files_agree("app/src/UserController.java", {"src/UserController.java"}))
        self.assertTrue(_files_agree("UserController.java", {"app/UserController.java"}))
        self.assertTrue(_files_agree("src/A.java", {"src/A.java"}))

    def test_files_disagree(self) -> None:
        self.assertFalse(_files_agree("src/A.java", {"src/B.java"}))
        self.assertFalse(_files_agree("src/A.java", set()))


class FrontendGuardTests(unittest.TestCase):
    def test_frontend_extensions_flagged(self) -> None:
        for f in ("App.tsx", "x.jsx", "y.vue", "z.svelte", "a.css", "b.scss", "c.html"):
            self.assertTrue(_is_frontend_file(f), f)

    def test_frontend_directories_flagged(self) -> None:
        for f in ("frontend/api.js", "client/x.py", "static/s.js", "dist/bundle.js", "node_modules/pkg/i.js"):
            self.assertTrue(_is_frontend_file(f), f)

    def test_backend_files_not_flagged(self) -> None:
        for f in ("src/UserController.java", "app/api/users.py", "server/routes.js"):
            self.assertFalse(_is_frontend_file(f), f)

    def test_windows_separators_normalized(self) -> None:
        self.assertTrue(_is_frontend_file("frontend\\components\\App.js"))


class LocalizeRouteMatchTests(unittest.TestCase):
    def test_route_match_yields_handler_file_and_symbol(self) -> None:
        finding = _finding("GET /IDOR/profile/{id}", ["src/UserController.java:42"])
        routes = [_route("GET", "/IDOR/profile/{userId}", "UserController.getProfile",
                         "src/UserController.java:42")]
        with patch("repair.locator.extract_routes", return_value=routes):
            rc = localize(finding, source_root="/nonexistent")
        self.assertIsInstance(rc, RootCause)
        self.assertEqual(rc.file, "src/UserController.java")
        self.assertEqual(rc.symbol, "UserController.getProfile")
        self.assertIn("controller_hotfix", rc.rationale)

    def test_route_match_notes_sast_agreement(self) -> None:
        finding = _finding("GET /IDOR/profile/{id}", ["src/UserController.java:42"])
        routes = [_route("GET", "/IDOR/profile/{id}", "UserController.getProfile",
                         "src/UserController.java:42")]
        with patch("repair.locator.extract_routes", return_value=routes):
            rc = localize(finding, source_root="/nonexistent")
        self.assertIn("SAST 지목 위치와도 일치", rc.rationale)

    def test_route_match_omits_agreement_when_sast_points_elsewhere(self) -> None:
        finding = _finding("GET /IDOR/profile/{id}", ["totally/Other.java:9"])
        routes = [_route("GET", "/IDOR/profile/{id}", "UserController.getProfile",
                         "src/UserController.java:42")]
        with patch("repair.locator.extract_routes", return_value=routes):
            rc = localize(finding, source_root="/nonexistent")
        self.assertNotIn("SAST 지목 위치와도 일치", rc.rationale)

    def test_route_match_service_layer_classified(self) -> None:
        finding = _finding("GET /orders/{id}")
        routes = [_route("GET", "/orders/{id}", "OrderService.find", "app/OrderService.java:5")]
        with patch("repair.locator.extract_routes", return_value=routes):
            rc = localize(finding, source_root="/nonexistent")
        self.assertIn("service_policy", rc.rationale)


class LocalizeSastFallbackTests(unittest.TestCase):
    def test_no_route_uses_sorted_sast_file(self) -> None:
        finding = _finding("GET /no/match/{id}", ["b/Foo.py:10", "a/Bar.py:20"])
        with patch("repair.locator.extract_routes", return_value=[]):
            rc = localize(finding, source_root="/nonexistent")
        self.assertEqual(rc.file, "a/Bar.py")  # sorted(sast)[0] — IDOR은 알파벳(handler 아무거나로 충분)
        self.assertIsNone(rc.symbol)
        self.assertIn("SAST가 지목한 위치", rc.rationale)

    def test_sink_cwe_fallback_uses_source_order_not_alphabetical(self) -> None:
        # I5(cross-file): route 매핑 실패 + sink형(SQLi)에서 SAST가 여러 파일을 짚으면, 알파벳 첫
        # 파일(z...가 뒤)이 아니라 SAST 보고 순서의 첫 sink(쿼리 실행부)를 채택해야 한다.
        finding = Finding(
            id="f", run_id="r", title="sqli", cwe="CWE-89", affected_endpoint="GET /no/match",
            source_symbols=["z/query_exec.ts:9", "a/route_builder.ts:3"],  # 실행부가 보고 순 첫째
        )
        with patch("repair.locator.extract_routes", return_value=[]):
            rc = localize(finding, source_root="/nonexistent")
        self.assertEqual(rc.file, "z/query_exec.ts")  # source_symbols[0], NOT sorted()[0]="a/..."
        self.assertIn("z/query_exec.ts:9", rc.rationale)
        self.assertIn("a/route_builder.ts:3", rc.rationale)  # 다른 sink 후보도 노출
        self.assertIn("실행부", rc.rationale)  # cross-file 안내
        self.assertIn("파라미터", rc.rationale)  # SQLi 수정 힌트는 채택 파일(.ts) 기준

    def test_sink_cwe_single_sast_file_unchanged(self) -> None:
        # sink 파일이 하나면 기존과 동일(알파벳=순서=동일) — 무회귀, cross-file 노트도 없다.
        finding = Finding(
            id="f", run_id="r", title="xss", cwe="CWE-79", affected_endpoint="POST /no/match",
            source_symbols=["app/render.py:42"],
        )
        with patch("repair.locator.extract_routes", return_value=[]):
            rc = localize(finding, source_root="/nonexistent")
        self.assertEqual(rc.file, "app/render.py")
        self.assertNotIn("sink 후보(보고 순)", rc.rationale)
        self.assertIn("이스케이프/인코딩", rc.rationale)

    def test_idor_fallback_stays_alphabetical_with_multiple_files(self) -> None:
        # 비-sink형(IDOR)은 여러 파일이라도 기존 알파벳 선택 유지 — sink 개념이 없으므로.
        finding = _finding("GET /no/match", ["z/Late.java:9", "a/Early.java:3"])
        with patch("repair.locator.extract_routes", return_value=[]):
            rc = localize(finding, source_root="/nonexistent")
        self.assertEqual(rc.file, "a/Early.java")  # sorted(sast)[0], 순서 아님
        self.assertNotIn("sink 후보(실행부 우선)", rc.rationale)

    def test_route_matched_to_decoy_is_overridden_to_live_sink(self) -> None:
        # J-3 재재실행 발견(P1): extract_routes가 endpoint를 비실행 decoy(codefixes 사본)의 handler로
        # 매칭해도, 실행 우선순위 높은 SAST sink(routes/search.ts)가 있으면 root cause 앵커를 그쪽으로 옮긴다.
        finding = Finding(
            id="f", run_id="r", title="sqli", cwe="CWE-89",
            affected_endpoint="GET /rest/products/search",
            source_symbols=["data/static/codefixes/dbSchemaChallenge_1.ts:12", "routes/search.ts:40"],
        )
        # route가 decoy 파일을 handler로 잡은 상황을 재현.
        routes = [_route("GET", "/rest/products/search", "dbSchemaChallenge_1.handler",
                         "data/static/codefixes/dbSchemaChallenge_1.ts:12")]
        with patch("repair.locator.extract_routes", return_value=routes):
            rc = localize(finding, source_root="/nonexistent")
        self.assertEqual(rc.file, "routes/search.ts")   # 앵커가 실행 파일로 override됨
        self.assertIsNone(rc.symbol)                     # route 심볼은 더 이상 유효하지 않음
        self.assertIn("decoy", rc.rationale)
        self.assertIn("파라미터", rc.rationale)           # SQLi 힌트는 override된 실행 파일 기준

    def test_route_matched_to_real_handler_not_overridden(self) -> None:
        # 무회귀: route.source가 이미 실행 핸들러면(decoy 아님) override하지 않고 route 앵커/심볼 유지.
        finding = Finding(
            id="f", run_id="r", title="sqli", cwe="CWE-89", affected_endpoint="GET /search",
            source_symbols=["routes/search.ts:40"],
        )
        routes = [_route("GET", "/search", "SearchRoute.handler", "routes/search.ts:40")]
        with patch("repair.locator.extract_routes", return_value=routes):
            rc = localize(finding, source_root="/nonexistent")
        self.assertEqual(rc.file, "routes/search.ts")
        self.assertEqual(rc.symbol, "SearchRoute.handler")   # 그대로 유지
        self.assertNotIn("decoy", rc.rationale)

    def test_sink_cwe_prefers_live_handler_over_decoy_reference_copy(self) -> None:
        # J-3 라이브 발견: 같은 취약 SQL이 실행 핸들러(routes/search.ts)와 비실행 참고 사본
        # (data/static/codefixes/…)에 모두 있고, SAST가 decoy를 먼저 보고해도 locator는 실행 핸들러를 짚어야 한다.
        finding = Finding(
            id="f", run_id="r", title="sqli", cwe="CWE-89", affected_endpoint="GET /rest/products/search",
            source_symbols=["data/static/codefixes/dbSchemaChallenge_1.ts:12", "routes/search.ts:40"],
        )
        with patch("repair.locator.extract_routes", return_value=[]):  # route 매핑 실패 → SAST 폴백
            rc = localize(finding, source_root="/nonexistent")
        self.assertEqual(rc.file, "routes/search.ts")            # decoy 아니라 실행 핸들러
        self.assertIn("codefixes", rc.rationale)                 # 후보 목록엔 남되 후순위
        self.assertIn("실행부 우선", rc.rationale)


class SinkFilePriorityTests(unittest.TestCase):
    def test_handler_before_general_before_reference(self) -> None:
        from repair.locator import _sink_file_priority as pri
        self.assertEqual(pri("routes/search.ts"), 0)             # 실행 핸들러
        self.assertEqual(pri("src/db/query.ts"), 1)             # 일반
        self.assertEqual(pri("data/static/codefixes/x.ts"), 2)  # 비실행 decoy
        self.assertLess(pri("routes/search.ts"), pri("data/static/codefixes/x.ts"))

    def test_rank_sinks_stable_within_priority(self) -> None:
        from repair.locator import _rank_sinks
        ranked = _rank_sinks(["static/a.ts:1", "routes/b.ts:2", "lib/c.ts:3", "controllers/d.ts:4"])
        # 핸들러(routes/controllers) 먼저(보고 순 유지) → 일반(lib) → decoy(static) 마지막
        self.assertEqual(ranked, ["routes/b.ts:2", "controllers/d.ts:4", "lib/c.ts:3", "static/a.ts:1"])


class LocalizeVulnClassReasonTests(unittest.TestCase):
    """rationale 근본 원인 서술이 CWE(취약점 클래스)별로 갈리는지 — LLM 합성기가 근거로 소비.

    IDOR 전용 문구를 3군 전체에 쓰면 XSS/SQLi에서 모델이 소유권 가드를 만들어 attack 게이트가
    계속 reject한다(D6 LLM-patch 확장 대응).
    """

    def _finding_cwe(self, cwe: str, endpoint: str, sast: list[str] | None = None) -> Finding:
        return Finding(
            id="f", run_id="r", title="t", cwe=cwe,
            affected_endpoint=endpoint, source_symbols=sast or [],
        )

    def test_idor_reason_unchanged(self) -> None:
        finding = self._finding_cwe("CWE-639", "GET /orders/{id}")
        routes = [_route("GET", "/orders/{id}", "OrderController.get", "src/OrderController.java:5")]
        with patch("repair.locator.extract_routes", return_value=routes):
            rc = localize(finding, source_root="/nonexistent")
        self.assertIn("소유권/권한", rc.rationale)

    def test_xss_reason_is_output_encoding_not_ownership(self) -> None:
        finding = self._finding_cwe("CWE-79", "POST /comments")
        routes = [_route("POST", "/comments", "CommentController.add", "src/CommentController.java:8")]
        with patch("repair.locator.extract_routes", return_value=routes):
            rc = localize(finding, source_root="/nonexistent")
        self.assertIn("이스케이프/인코딩", rc.rationale)
        self.assertNotIn("소유권/권한", rc.rationale)

    def test_sqli_reason_is_parameterization(self) -> None:
        finding = self._finding_cwe("CWE-89", "GET /search")
        routes = [_route("GET", "/search", "SearchController.q", "src/SearchController.java:3")]
        with patch("repair.locator.extract_routes", return_value=routes):
            rc = localize(finding, source_root="/nonexistent")
        self.assertIn("파라미터", rc.rationale)
        self.assertNotIn("소유권/권한", rc.rationale)

    def test_xss_fix_hint_is_framework_specific(self) -> None:
        # X6: XSS rationale에 sink 파일 프레임워크별 올바른 수정 방향을 실어 235B가 접근제어 가드가
        # 아니라 이스케이프/정화 패치를 하게 한다.
        for sast_loc, expect in (("web/Comp.tsx:5", "DOMPurify"), ("app/views.py:5", "autoescape"),
                                 ("src/render.ts:5", "textContent")):
            finding = self._finding_cwe("CWE-79", "GET /c", [sast_loc])
            routes = [_route("GET", "/c", "H.get", "server.ts:1")]
            with patch("repair.locator.extract_routes", return_value=routes):
                rc = localize(finding, source_root="/nonexistent")
            self.assertIn(expect, rc.rationale, sast_loc)
            self.assertNotIn("소유권/권한", rc.rationale, sast_loc)

    def test_sqli_gets_parameterization_hint_not_xss(self) -> None:
        # SQLi는 파라미터화 수정 방향(_sqli_fix_hint)을 받되, XSS 전용 힌트(DOMPurify/autoescape)는 안 받는다.
        finding = self._finding_cwe("CWE-89", "GET /s", ["dao.py:5"])
        routes = [_route("GET", "/s", "S.q", "dao.py:3")]
        with patch("repair.locator.extract_routes", return_value=routes):
            rc = localize(finding, source_root="/nonexistent")
        self.assertIn("파라미터", rc.rationale)
        self.assertIn("execute(sql, params)", rc.rationale)  # Python 프레임워크별 파라미터화
        self.assertNotIn("DOMPurify", rc.rationale)
        self.assertNotIn("autoescape", rc.rationale)

    def test_sqli_fix_hint_is_framework_specific(self) -> None:
        for sast_loc, expect in (("routes/search.ts:8", "Sequelize"), ("Dao.java:12", "PreparedStatement")):
            finding = self._finding_cwe("CWE-89", "GET /s", [sast_loc])
            routes = [_route("GET", "/s", "S.q", "server.ts:1")]
            with patch("repair.locator.extract_routes", return_value=routes):
                rc = localize(finding, source_root="/nonexistent")
            self.assertIn(expect, rc.rationale, sast_loc)
            self.assertNotIn("소유권/권한", rc.rationale, sast_loc)

    def test_sast_fallback_carries_class_reason(self) -> None:
        finding = self._finding_cwe("CWE-79", "POST /no/match", ["app/render.py:42"])
        with patch("repair.locator.extract_routes", return_value=[]):
            rc = localize(finding, source_root="/nonexistent")
        self.assertIn("이스케이프/인코딩", rc.rationale)
        self.assertIn("SAST가 지목한 위치", rc.rationale)  # 기존 마커 보존

    def test_xss_route_match_surfaces_sast_sink(self) -> None:
        # route는 handler를 앵커로 주되, sink형(XSS)은 SAST가 짚은 sink 위치를 rationale에 실어야 한다.
        finding = self._finding_cwe("CWE-79", "POST /comments", ["templates/comment_view.py:88"])
        routes = [_route("POST", "/comments", "CommentController.add", "src/CommentController.java:8")]
        with patch("repair.locator.extract_routes", return_value=routes):
            rc = localize(finding, source_root="/nonexistent")
        self.assertEqual(rc.symbol, "CommentController.add")  # 앵커는 도달 증명된 handler 유지
        self.assertIn("sink", rc.rationale)
        self.assertIn("templates/comment_view.py:88", rc.rationale)  # sink 위치 노출

    def test_idor_route_match_has_no_sink_note(self) -> None:
        # IDOR은 고칠 곳이 handler(접근제어)라 sink 노트를 붙이지 않는다.
        finding = self._finding_cwe("CWE-639", "GET /orders/{id}", ["src/OrderController.java:5"])
        routes = [_route("GET", "/orders/{id}", "OrderController.get", "src/OrderController.java:5")]
        with patch("repair.locator.extract_routes", return_value=routes):
            rc = localize(finding, source_root="/nonexistent")
        self.assertNotIn("실제 취약 지점(sink)", rc.rationale)
        self.assertIn("SAST 지목 위치와도 일치", rc.rationale)  # 기존 동작(파일 일치) 유지

    def test_sqli_route_match_without_sast_is_unchanged(self) -> None:
        # SAST sink가 없으면 노트도 없다(무회귀) — 기존 클래스 서술만.
        finding = self._finding_cwe("CWE-89", "GET /search")
        routes = [_route("GET", "/search", "SearchController.q", "src/SearchController.java:3")]
        with patch("repair.locator.extract_routes", return_value=routes):
            rc = localize(finding, source_root="/nonexistent")
        self.assertNotIn("실제 취약 지점(sink)", rc.rationale)
        self.assertIn("파라미터", rc.rationale)


class LocalizeCodeIndexFallbackTests(unittest.TestCase):
    """route/SAST 모두 실패 → P4 code_index 폴백. 프론트엔드 후보는 건너뛰고 백엔드만 채택."""

    def _hits(self, *files: str) -> list[SimpleNamespace]:
        return [SimpleNamespace(chunk=SimpleNamespace(file=f)) for f in files]

    def test_skips_frontend_hit_and_adopts_backend(self) -> None:
        finding = _finding("GET /api/thing/{id}")  # source_symbols 비어 SAST 폴백 스킵
        fake_index = SimpleNamespace(search=lambda query, k=5: self._hits(
            "frontend/App.tsx", "server/api.py"
        ))
        with (
            patch("repair.locator.extract_routes", return_value=[]),
            patch("model.code_index.CodeIndex") as MockCI,
        ):
            MockCI.build.return_value = fake_index
            rc = localize(finding, source_root="/nonexistent")
        self.assertEqual(rc.file, "server/api.py")
        self.assertIsNone(rc.symbol)
        self.assertIn("code_index", rc.rationale)

    def test_all_frontend_hits_raise_value_error(self) -> None:
        finding = _finding("GET /api/thing/{id}")
        fake_index = SimpleNamespace(search=lambda query, k=5: self._hits(
            "frontend/App.tsx", "client/store.ts"
        ))
        with (
            patch("repair.locator.extract_routes", return_value=[]),
            patch("model.code_index.CodeIndex") as MockCI,
        ):
            MockCI.build.return_value = fake_index
            with self.assertRaises(ValueError):
                localize(finding, source_root="/nonexistent")

    def test_no_hits_raise_value_error(self) -> None:
        finding = _finding("GET /api/thing/{id}")
        fake_index = SimpleNamespace(search=lambda query, k=5: [])
        with (
            patch("repair.locator.extract_routes", return_value=[]),
            patch("model.code_index.CodeIndex") as MockCI,
        ):
            MockCI.build.return_value = fake_index
            with self.assertRaises(ValueError):
                localize(finding, source_root="/nonexistent")

    def test_uses_chunk_path_attr_when_no_file_attr(self) -> None:
        # hit.chunk.file 이 없으면 .path 로 폴백한다.
        finding = _finding("GET /api/thing/{id}")
        hits = [SimpleNamespace(chunk=SimpleNamespace(path="server/handler.py"))]
        fake_index = SimpleNamespace(search=lambda query, k=5: hits)
        with (
            patch("repair.locator.extract_routes", return_value=[]),
            patch("model.code_index.CodeIndex") as MockCI,
        ):
            MockCI.build.return_value = fake_index
            rc = localize(finding, source_root="/nonexistent")
        self.assertEqual(rc.file, "server/handler.py")


class LocalizeExhaustedTests(unittest.TestCase):
    def test_raises_when_code_index_unavailable_and_no_other_signal(self) -> None:
        # code_index import가 실패(선택적 의존)하면 _locate_by_code_index가 None → localize ValueError.
        finding = _finding("GET /api/thing/{id}")
        with (
            patch("repair.locator.extract_routes", return_value=[]),
            patch.dict("sys.modules", {"model.code_index": None}),
        ):
            with self.assertRaises(ValueError):
                localize(finding, source_root="/nonexistent")


if __name__ == "__main__":
    unittest.main()
