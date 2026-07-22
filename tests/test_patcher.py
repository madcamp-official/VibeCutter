"""repair/patcher.py 오프라인 템플릿 합성기 단위 테스트 (네트워크/모델 없이 순수).

`template_synthesize`는 LLM endpoint가 없을 때(현재 235B DOWN 다수) 도는 **기본 합성 경로**다 —
Spring IDOR handler에 소유권 가드를 삽입하는 결정적 diff를 만든다. LLM 경로(test_llm_synth.py)와
달리 이 결정적 경로와 그 헬퍼(_find_method_span 선언/호출부 판별, _extract_owner_key)는 직접
테스트가 없었다. Java 소스 문자열 조작이라 전부 헤르메틱하게 고정한다.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from contracts.schemas import Finding, RootCause
from repair.patcher import (
    PatchCandidate,
    _extract_owner_key,
    _find_method_span,
    rank,
    template_synthesize,
)


def _finding(cwe: str = "CWE-639") -> Finding:
    return Finding(id="f", run_id="r", title="idor", cwe=cwe)


class FindMethodSpanTests(unittest.TestCase):
    def test_finds_declaration_span_params(self) -> None:
        text = "class C {\n    Profile getProfile(Long userId) {\n        return 1;\n    }\n}\n"
        span = _find_method_span(text, "getProfile")
        self.assertIsNotNone(span)
        po, pc, bo = span
        self.assertEqual(text[po + 1 : pc], "Long userId")  # 파라미터 슬라이스 정확

    def test_skips_callsite_and_matches_declaration(self) -> None:
        # 같은 이름의 '호출부'가 '선언'보다 먼저 나와도, ')' 뒤가 '{'가 아니면 걸러지고 선언을 잡는다.
        text = (
            "class C {\n"
            "    void caller() { this.getThing(5); }\n"
            "    Thing getThing(Long id) { return repo.find(id); }\n"
            "}\n"
        )
        span = _find_method_span(text, "getThing")
        self.assertIsNotNone(span)
        po, pc, _ = span
        self.assertEqual(text[po + 1 : pc], "Long id")  # 호출부(5) 아니라 선언(Long id)

    def test_nested_parens_in_params_do_not_confuse_matching(self) -> None:
        # 파라미터 안의 ')'(@RequestParam(defaultValue="x"))에 속지 않고 진짜 닫는 ')'를 찾는다.
        text = 'class C {\n    R q(@RequestParam(defaultValue="x") String s) {\n        return s;\n    }\n}\n'
        span = _find_method_span(text, "q")
        self.assertIsNotNone(span)
        po, pc, _ = span
        self.assertEqual(text[po + 1 : pc], '@RequestParam(defaultValue="x") String s')

    def test_throws_clause_between_paren_and_brace_accepted(self) -> None:
        text = "class C {\n    void m(Long id) throws Exception {\n        return;\n    }\n}\n"
        self.assertIsNotNone(_find_method_span(text, "m"))

    def test_missing_method_returns_none(self) -> None:
        self.assertIsNone(_find_method_span("class C {\n    void other() {}\n}\n", "getProfile"))


class ExtractOwnerKeyTests(unittest.TestCase):
    def test_pathvariable_preferred(self) -> None:
        self.assertEqual(_extract_owner_key("@PathVariable Long userId"), "userId")

    def test_pathvariable_with_parens(self) -> None:
        self.assertEqual(_extract_owner_key('@PathVariable("id") Long userId'), "userId")

    def test_requestparam_fallback(self) -> None:
        self.assertEqual(_extract_owner_key("@RequestParam Long ownerId"), "ownerId")

    def test_plain_first_param_fallback(self) -> None:
        self.assertEqual(_extract_owner_key("Long id"), "id")

    def test_empty_param_list_returns_none(self) -> None:
        self.assertIsNone(_extract_owner_key(""))


class TemplateSynthesizeTests(unittest.TestCase):
    _JAVA = (
        "package com.example;\n"
        "import org.springframework.web.bind.annotation.*;\n"
        "@RestController\n"
        "public class ProfileController {\n"
        "    @GetMapping(\"/profile/{userId}\")\n"
        "    public Profile getProfile(@PathVariable Long userId) {\n"
        "        return service.getProfile(userId);\n"
        "    }\n"
        "}\n"
    )

    def _synth(self, java: str, *, file: str = "ProfileController.java",
               symbol: str = "ProfileController.getProfile") -> PatchCandidate | None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / file).write_text(java, encoding="utf-8")
            rc = RootCause(file=file, symbol=symbol, rationale="x")
            return template_synthesize(_finding(), rc, root)

    def test_happy_path_inserts_ownership_guard(self) -> None:
        cand = self._synth(self._JAVA)
        self.assertIsNotNone(cand)
        self.assertIn("IDOR guard", cand.diff)
        self.assertIn("FORBIDDEN", cand.diff)
        self.assertIn("userId", cand.diff)                 # owner_key로 비교
        self.assertIn("principal.getName()", cand.diff)
        self.assertIn("java.security.Principal principal", cand.diff)  # Principal 파라미터 추가
        self.assertEqual(cand.files, ["ProfileController.java"])
        self.assertEqual(cand.new_dependency_risk, 0.0)    # FQN 사용, import 없음
        self.assertGreater(cand.patch_size, 0)

    def test_non_java_file_returns_none(self) -> None:
        self.assertIsNone(self._synth("def f(): pass\n", file="views.py",
                                      symbol="views.getProfile"))

    def test_missing_symbol_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "C.java").write_text(self._JAVA, encoding="utf-8")
            rc = RootCause(file="C.java", symbol=None, rationale="x")
            self.assertIsNone(template_synthesize(_finding(), rc, root))

    def test_method_not_in_file_returns_none(self) -> None:
        self.assertIsNone(self._synth(self._JAVA, symbol="ProfileController.deleteEverything"))

    def test_no_owner_key_returns_none(self) -> None:
        # 파라미터가 없는 handler → 소유자 식별자를 못 찾으므로 추측으로 가드를 짓지 않는다.
        java = ("public class C {\n"
                "    public Profile getProfile() {\n"
                "        return service.mine();\n"
                "    }\n"
                "}\n")
        self.assertIsNone(self._synth(java, file="C.java", symbol="C.getProfile"))

    def test_existing_principal_not_duplicated(self) -> None:
        java = ("public class C {\n"
                "    public Profile getProfile(@PathVariable Long userId, java.security.Principal principal) {\n"
                "        return service.get(userId);\n"
                "    }\n"
                "}\n")
        cand = self._synth(java, file="C.java", symbol="C.getProfile")
        self.assertIsNotNone(cand)
        # 이미 있는 Principal을 또 추가하지 않는다(파라미터에 principal 선언이 하나만).
        self.assertNotIn("Principal principal, java.security.Principal principal", cand.diff)
        self.assertIn("IDOR guard", cand.diff)


class RankTests(unittest.TestCase):
    def _cand(self, layer: str, sec: float) -> PatchCandidate:
        return PatchCandidate(
            layer=layer, diff="d", files=["f"], rationale="r",
            security_correctness=sec, regression_safety=0.5, architectural_fit=0.5,
            patch_size=1, unrelated_changes=0, new_dependency_risk=0.0,
        )

    def test_highest_score_wins(self) -> None:
        low, high = self._cand("controller_hotfix", 0.1), self._cand("service_policy", 0.9)
        self.assertIs(rank([low, high]), high)

    def test_tie_prefers_first(self) -> None:
        a, b = self._cand("controller_hotfix", 0.5), self._cand("service_policy", 0.5)
        self.assertIs(rank([a, b]), a)


if __name__ == "__main__":
    unittest.main()
