"""audit log 데코레이터 테스트 (Extra Day 1-2, 부록 C-6 / 10.2절).

`@audited` wrapper가 (a) 변경 파일(Patch.files 등)을 audit log에 남기는지, (b) 예외 메시지의
secret을 redaction하는지 확인한다. 실제 tool을 띄우지 않고 데코레이터만 직접 구동한다.
"""

from __future__ import annotations

import unittest

from core.audit_log import audited, list_entries


class AuditChangedFilesTests(unittest.TestCase):
    def test_records_files_from_patch_like_output(self) -> None:
        class _Patchish:
            files = ["backend/src/UserController.java", "backend/src/Auth.java"]

        @audited
        def some_tool(patch_id: str):
            return _Patchish()

        some_tool("patch-1")
        entry = list_entries(1)[0]
        self.assertEqual(entry.tool, "some_tool")
        self.assertEqual(entry.result, "ok")
        self.assertEqual(
            entry.changed_files,
            ["backend/src/UserController.java", "backend/src/Auth.java"],
        )

    def test_output_without_files_records_empty_changed_files(self) -> None:
        @audited
        def plain_tool(x: str):
            return "pong"

        plain_tool("x")
        entry = list_entries(1)[0]
        self.assertEqual(entry.changed_files, [])

    def test_non_list_files_attribute_is_ignored(self) -> None:
        class _Weird:
            files = "not-a-list"

        @audited
        def weird_tool(x: str):
            return _Weird()

        weird_tool("x")
        entry = list_entries(1)[0]
        self.assertEqual(entry.changed_files, [])


class AuditRunIdTests(unittest.TestCase):
    """D5-P2: run_id 전용 컬럼 — run 단위 안전지표 집계용."""

    def test_run_id_from_arguments(self) -> None:
        @audited
        def some_tool(run_id: str):
            return "ok"

        some_tool(run_id="run-abc123")
        self.assertEqual(list_entries(1)[0].run_id, "run-abc123")

    def test_run_id_from_output_when_not_in_args(self) -> None:
        # localize/generate/apply처럼 finding_id/patch_id만 받는 tool은 반환 객체의 run_id로.
        class _PatchLike:
            run_id = "run-xyz789"
            files = None

        @audited
        def patch_tool(patch_id: str):
            return _PatchLike()

        patch_tool("p1")
        self.assertEqual(list_entries(1)[0].run_id, "run-xyz789")

    def test_run_id_none_when_absent(self) -> None:
        @audited
        def read_tool(finding_id: str):
            return "plain"

        read_tool("f1")
        self.assertIsNone(list_entries(1)[0].run_id)


class AuditErrorRedactionTests(unittest.TestCase):
    def test_error_message_is_redacted(self) -> None:
        @audited
        def failing_tool(x: str):
            raise ValueError("git apply failed: Authorization: Bearer abc123.def456.ghi789 rejected")

        with self.assertRaises(ValueError):
            failing_tool("x")

        entry = list_entries(1)[0]
        self.assertEqual(entry.result, "error")
        self.assertIn("<redacted>", entry.error)
        self.assertNotIn("abc123.def456.ghi789", entry.error)

    def test_jwt_in_error_is_redacted(self) -> None:
        jwt = "eyJhbGciOi.eyJzdWIiOi.SflKxwRJ"

        @audited
        def failing_tool(x: str):
            raise RuntimeError(f"token leaked in body: {jwt}")

        with self.assertRaises(RuntimeError):
            failing_tool("x")

        entry = list_entries(1)[0]
        self.assertNotIn(jwt, entry.error)
        self.assertIn("<redacted-jwt>", entry.error)


if __name__ == "__main__":
    unittest.main()
