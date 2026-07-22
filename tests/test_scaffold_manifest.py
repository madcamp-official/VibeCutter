"""U1: vc_scaffold_manifest 커버리지 (REMAINING_PLAN.md 5절).

핵심 완료 판정(U1): docker-compose 프로젝트에 대해 도구가 유효한 manifest 초안 + 근거를
내고, 그 초안이 vc_register_local_target의 미리보기로 그대로 넘어간다. 이 파일의
`RegisterPreviewIntegrationTests`가 그 판정을 문자 그대로 확인한다.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from pydantic import ValidationError

from mcp_server.scaffold import scaffold_manifest
from runtime.manifest import TargetManifest


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class ComposeScaffoldTests(unittest.TestCase):
    def test_node_service_with_fixed_port_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "docker-compose.yml", """\
services:
  db:
    image: postgres:15
  web:
    build:
      context: .
    ports:
      - "3000:3000"
""")
            _write(root / "package.json", json.dumps({"name": "demo", "scripts": {"start": "node index.js"}}))

            result = scaffold_manifest(root)

        self.assertTrue(result.detected)
        self.assertIsNotNone(result.manifest)
        self.assertEqual(result.manifest["adapter"], "node")
        self.assertEqual(result.manifest["base_url"], "http://127.0.0.1:3000")
        self.assertEqual(result.manifest["kind"], "compose_project")
        self.assertIn("build", result.manifest["commands"])
        self.assertIn("start", result.manifest["commands"])
        self.assertIn("stop", result.manifest["commands"])
        self.assertIn("reset", result.manifest["commands"])
        # 근거: db가 아니라 web을 주 서비스로 선택했다는 사실이 남아야 한다.
        self.assertIn("web", result.evidence["adapter/service"])
        self.assertIn("base_url", result.evidence)

    def test_infra_only_compose_is_not_falsely_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "docker-compose.yml", """\
services:
  db:
    image: postgres:15
  cache:
    image: redis:7
""")
            result = scaffold_manifest(root)

        self.assertFalse(result.detected)
        self.assertIsNone(result.manifest)
        self.assertTrue(result.warnings)

    def test_env_var_port_falls_back_with_warning_instead_of_guessing_wrong(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "docker-compose.yml", """\
services:
  app:
    build: .
    ports:
      - "${PORT}:3000"
""")
            result = scaffold_manifest(root)

        self.assertTrue(result.detected)
        self.assertEqual(result.manifest["base_url"], "http://127.0.0.1:18080")
        self.assertTrue(any("고정 호스트 포트를 찾지 못해" in w for w in result.warnings))

    def test_test_suite_is_detected_when_npm_test_script_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "docker-compose.yml", """\
services:
  web:
    build: .
    ports:
      - "8080:8080"
""")
            _write(root / "package.json", json.dumps({"scripts": {"start": "node index.js", "test": "jest"}}))

            result = scaffold_manifest(root)

        self.assertIn("test", result.manifest["commands"])
        self.assertEqual(result.manifest["test_suites"], [{"name": "unit", "command_id": "test"}])

    def test_scaffolded_compose_manifest_is_schema_valid(self) -> None:
        """draft가 TargetManifest 검증을 그대로 통과해야 한다 — 이게 '유효한 초안'의 뜻이다."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "docker-compose.yml", """\
services:
  web:
    build: .
    ports:
      - "5000:5000"
""")
            _write(root / "requirements.txt", "fastapi\nuvicorn\npytest\n")

            result = scaffold_manifest(root)

        validated = TargetManifest.model_validate(result.manifest)
        self.assertEqual(validated.adapter.value, "fastapi")


class SingleServiceFallbackTests(unittest.TestCase):
    def test_node_without_compose(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "package.json", json.dumps({"scripts": {"start": "node server.js"}}))
            result = scaffold_manifest(root)

        self.assertTrue(result.detected)
        self.assertEqual(result.manifest["adapter"], "node")
        self.assertEqual(result.manifest["kind"], "running_local")
        self.assertNotIn("stop", result.manifest["commands"])
        TargetManifest.model_validate(result.manifest)  # must still validate

    def test_fastapi_without_compose(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "requirements.txt", "fastapi\n")
            result = scaffold_manifest(root)

        self.assertEqual(result.manifest["adapter"], "fastapi")
        self.assertEqual(result.manifest["base_url"], "http://127.0.0.1:8000")
        TargetManifest.model_validate(result.manifest)

    def test_spring_boot_without_compose(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "pom.xml", "<project></project>")
            result = scaffold_manifest(root)

        self.assertEqual(result.manifest["adapter"], "spring-boot")
        self.assertEqual(result.manifest["base_url"], "http://127.0.0.1:8080")
        TargetManifest.model_validate(result.manifest)

    def test_nothing_detected_returns_no_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = scaffold_manifest(Path(tmp))

        self.assertFalse(result.detected)
        self.assertIsNone(result.manifest)
        self.assertTrue(any("generic-docker" in w for w in result.warnings))

    def test_non_directory_source_path_is_reported_not_raised(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "does-not-exist"
            result = scaffold_manifest(missing)

        self.assertFalse(result.detected)
        self.assertTrue(result.warnings)


class RegisterPreviewIntegrationTests(unittest.TestCase):
    """U1 완료 판정 문구를 그대로 확인: 초안이 등록 미리보기로 넘어간다."""

    def _git_repo(self, path: Path) -> None:
        for args in (["init"], ["config", "user.email", "t@e.com"], ["config", "user.name", "t"]):
            subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(path), "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(path), "commit", "-m", "init"], check=True, capture_output=True)

    def test_scaffolded_draft_reaches_registration_preview_without_blockers(self) -> None:
        from mcp_server.tools_inventory import _build_preview

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "docker-compose.yml", """\
services:
  web:
    build: .
    ports:
      - "4000:4000"
""")
            _write(root / "package.json", json.dumps({"scripts": {"start": "node index.js"}}))
            self._git_repo(root)

            scaffolded = scaffold_manifest(root)
            self.assertIsNotNone(scaffolded.manifest)
            # id가 임시 디렉터리 이름에서 생성되므로 collision 걱정 없이 바로 검증한다.
            validated = TargetManifest.model_validate(scaffolded.manifest)
            preview = _build_preview(validated, root, confirmed=False)

        self.assertEqual(preview.blockers, [])
        self.assertEqual(preview.base_url, "http://127.0.0.1:4000")
        self.assertIn("build", preview.commands)
        self.assertFalse(preview.registered)  # confirmed=False라 아무것도 저장되지 않았다


if __name__ == "__main__":
    unittest.main()
