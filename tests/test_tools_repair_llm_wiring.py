"""P1 배선 #7 고정 테스트 — `vc_generate_patch`가 실제로 `synthesize_fn`을 받는 지점.

P3(2026-07-21)가 "배선 #7이 J-3(LLM 패치) + #5(code_context) 둘 다 푸는 linchpin"이라고
재차 요청했다 — 이 파일은 그 배선을 이루는 세 조각(`_get_llm_client` 캐시,
`_line_for_root_cause`, `_code_context_for` 어댑터)을 헤르메틱하게 고정한다.
`make_llm_synthesizer` 자체의 계약(injection guard/redaction/폴백)은 `test_llm_synth.py`가
이미 덮으므로 여기서는 tools_repair 쪽 어댑터만 검증한다.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from contracts.schemas import Finding, RootCause
from mcp_server import tools_repair


def _finding(source_symbols: list[str] | None = None) -> Finding:
    return Finding(
        id="f1", run_id="r1", title="SQLi", cwe="CWE-89",
        affected_endpoint="/orders/{id}", source_symbols=source_symbols or [],
    )


class LineForRootCauseTests(unittest.TestCase):
    def test_exact_file_match_returns_line(self) -> None:
        finding = _finding(["src/app.py:42", "other.py:10"])
        rc = RootCause(file="src/app.py", symbol="handler")
        self.assertEqual(tools_repair._line_for_root_cause(finding, rc), 42)

    def test_suffix_match_returns_line(self) -> None:
        # SAST가 절대/다른 루트 기준 경로("repo/src/app.py")를 낼 수 있어 접미 일치도 허용한다.
        finding = _finding(["repo/src/app.py:7"])
        rc = RootCause(file="src/app.py", symbol="handler")
        self.assertEqual(tools_repair._line_for_root_cause(finding, rc), 7)

    def test_no_match_returns_none(self) -> None:
        finding = _finding(["unrelated.py:5"])
        rc = RootCause(file="src/app.py", symbol="handler")
        self.assertIsNone(tools_repair._line_for_root_cause(finding, rc))

    def test_no_source_symbols_returns_none(self) -> None:
        finding = _finding([])
        rc = RootCause(file="src/app.py", symbol="handler")
        self.assertIsNone(tools_repair._line_for_root_cause(finding, rc))


class CodeContextForTests(unittest.TestCase):
    def _source_root(self, tmp: str) -> Path:
        root = Path(tmp)
        body = "\n".join(f"line{i}" for i in range(1, 60))
        (root / "app.py").write_text(body + "\n", encoding="utf-8")
        return root

    def test_returns_snippet_around_line_when_found(self) -> None:
        with TemporaryDirectory() as tmp:
            root = self._source_root(tmp)
            finding = _finding(["app.py:30"])
            rc = RootCause(file="app.py", symbol="handler")
            snippet = tools_repair._code_context_for(finding, rc, root)
            self.assertIsNotNone(snippet)
            self.assertIn("30 | line30", snippet)  # P4 code_context의 절대 줄번호 형식

    def test_returns_none_when_line_unresolvable(self) -> None:
        with TemporaryDirectory() as tmp:
            root = self._source_root(tmp)
            finding = _finding([])  # source_symbols 없음 → 줄을 못 찾음
            rc = RootCause(file="app.py", symbol="handler")
            self.assertIsNone(tools_repair._code_context_for(finding, rc, root))

    def test_returns_none_when_file_missing_from_index(self) -> None:
        with TemporaryDirectory() as tmp:
            root = self._source_root(tmp)
            finding = _finding(["missing.py:1"])
            rc = RootCause(file="missing.py", symbol="handler")
            self.assertIsNone(tools_repair._code_context_for(finding, rc, root))


class LlmClientCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        tools_repair._reset_llm_client_cache()
        self.addCleanup(tools_repair._reset_llm_client_cache)

    def test_build_patch_model_client_called_once(self) -> None:
        with patch.object(tools_repair, "build_patch_model_client", return_value="client") as m:
            self.assertEqual(tools_repair._get_llm_client(), "client")
            self.assertEqual(tools_repair._get_llm_client(), "client")
            m.assert_called_once()

    def test_none_result_is_cached_not_recomputed(self) -> None:
        """endpoint 전부 DOWN(`None`)도 유효한 캐시 값이다 — 매번 재확인하지 않는다."""
        with patch.object(tools_repair, "build_patch_model_client", return_value=None) as m:
            self.assertIsNone(tools_repair._get_llm_client())
            self.assertIsNone(tools_repair._get_llm_client())
            m.assert_called_once()

    def test_reset_forces_recompute(self) -> None:
        with patch.object(tools_repair, "build_patch_model_client", return_value="a") as m:
            tools_repair._get_llm_client()
        tools_repair._reset_llm_client_cache()
        with patch.object(tools_repair, "build_patch_model_client", return_value="b") as m:
            self.assertEqual(tools_repair._get_llm_client(), "b")
            m.assert_called_once()


if __name__ == "__main__":
    unittest.main()
