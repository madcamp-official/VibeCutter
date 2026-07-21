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
        self.assertEqual(rc.file, "a/Bar.py")  # sorted(sast)[0]
        self.assertIsNone(rc.symbol)
        self.assertIn("SAST가 지목한 위치", rc.rationale)


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

    def test_sast_fallback_carries_class_reason(self) -> None:
        finding = self._finding_cwe("CWE-79", "POST /no/match", ["app/render.py:42"])
        with patch("repair.locator.extract_routes", return_value=[]):
            rc = localize(finding, source_root="/nonexistent")
        self.assertIn("이스케이프/인코딩", rc.rationale)
        self.assertIn("SAST가 지목한 위치", rc.rationale)  # 기존 마커 보존


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
