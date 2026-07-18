from __future__ import annotations

import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from runtime.lifecycle import ApprovalRequired, LifecycleManager, VIBECUTTER_PYTHON
from runtime.manifest import TargetManifest
from runtime.worktree import WorktreeManager


def manifest_for_python_commands() -> TargetManifest:
    argv = [sys.executable, "-c", "print('ok')"]
    return TargetManifest.model_validate(
        {
            "manifest_version": 1,
            "id": "demo-api",
            "display_name": "Demo API",
            "adapter": "fastapi",
            "source_dir": ".",
            "base_url": "http://127.0.0.1:18080",
            "commands": {
                "build": {"argv": argv},
                "start": {"argv": argv},
                "stop": {"argv": argv},
                "reset": {"argv": argv},
                "test": {"argv": argv},
            },
            "reset": {"command_id": "reset"},
            "test_suites": [{"name": "unit", "command_id": "test"}],
        }
    )


class LifecycleTests(unittest.TestCase):
    def test_manifest_command_executes_without_shell(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = LifecycleManager(manifest_for_python_commands(), Path(temp_dir))
            result = manager.build()
        self.assertEqual(result.status, "passed")
        self.assertEqual(result.stdout.strip(), "ok")

    def test_runtime_python_token_uses_the_vibecutter_interpreter(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest = manifest_for_python_commands()
            manifest.commands["build"].argv = [VIBECUTTER_PYTHON, "-c", "print('token-ok')"]
            result = LifecycleManager(manifest, Path(temp_dir)).build()
        self.assertEqual(result.status, "passed")
        self.assertEqual(result.stdout.strip(), "token-ok")

    def test_utf8_command_output_does_not_depend_on_windows_console_code_page(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manifest = manifest_for_python_commands()
            manifest.commands["build"].argv = [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write('✅ build'.encode('utf-8'))",
            ]
            result = LifecycleManager(manifest, Path(temp_dir)).build()
        self.assertEqual(result.status, "passed")
        self.assertEqual(result.stdout, "✅ build")

    def test_reset_requires_explicit_approval(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = LifecycleManager(manifest_for_python_commands(), Path(temp_dir))
            with self.assertRaises(ApprovalRequired):
                manager.reset(approved=False)

    def test_test_suites_return_structured_results(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = LifecycleManager(manifest_for_python_commands(), Path(temp_dir))
            results = manager.run_test_suites()
        self.assertEqual([(result.command_id, result.status) for result in results], [("test", "passed")])

    def test_command_can_use_a_trusted_repository_working_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "orchestration").mkdir()
            manifest = manifest_for_python_commands()
            manifest.commands["build"].argv = [sys.executable, "-c", "import os; print(os.getcwd())"]
            manifest.commands["build"].working_dir = "orchestration"
            result = LifecycleManager(manifest, root).build()
        self.assertEqual(result.status, "passed")
        self.assertEqual(Path(result.stdout.strip()).name, "orchestration")

    def test_healthcheck_accepts_configured_http_error_status(self) -> None:
        class UnauthorizedHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 - required stdlib handler name.
                self.send_response(401)
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), UnauthorizedHandler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            manifest = manifest_for_python_commands()
            manifest.base_url = f"http://127.0.0.1:{server.server_port}"
            manifest.healthcheck.expected_status = 401
            result = LifecycleManager(manifest, Path.cwd()).check_health()
        finally:
            server.shutdown()
            thread.join()
            server.server_close()
        self.assertEqual(result.status, "ready")
        self.assertEqual(result.observed_status, 401)

    def test_worktree_path_rejects_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = WorktreeManager(Path(temp_dir))
            with self.assertRaises(ValueError):
                manager.path_for("../escape")

    def test_worktree_rejects_untrusted_revision_syntax(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = WorktreeManager(Path(temp_dir))
            with self.assertRaises(ValueError):
                manager.create("run-1", "--upload-pack=unexpected")
