"""P1 R1: 정책 이중 출처(built-in scope.yaml + 사용자 로컬 승인 레지스트리) 테스트.

P2의 `runtime.registry`가 아직 main에 없어도 이 테스트는 돈다 — P1은 TEAM_CONTRACT 3.1의
Protocol에만 의존하고 구현 클래스를 import 하지 않기 때문이다. 여기서는 그 Protocol을
만족하는 가짜 레지스트리를 주입해 P1 쪽 계약을 고정한다.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from dataclasses import dataclass, field
from pathlib import Path

from core.policy_engine import (
    PolicyViolation,
    is_target_allowed,
    require_host_allowed,
    require_target_allowed,
)

# policies/scope.yaml에 실제로 있는 built-in demo target.
BUILTIN_TARGET_ID = "26s-w1-c1-03"


@dataclass
class FakeApproved:
    target_id: str
    allowed_hosts: list[str] = field(default_factory=lambda: ["127.0.0.1"])
    base_url: str = "http://127.0.0.1:3000"


class FakeRegistry:
    def __init__(self, approved: dict[str, FakeApproved] | None = None) -> None:
        self._approved = approved or {}

    def get(self, target_id: str):
        return self._approved.get(target_id)


class DualSourcePolicyTests(unittest.TestCase):
    def test_builtin_target_still_allowed(self) -> None:
        """c1-05 gold가 fallback이므로 built-in 경로는 절대 깨지면 안 된다."""
        entry = require_target_allowed(BUILTIN_TARGET_ID, registry=FakeRegistry())
        self.assertIn("allowed_hosts", entry)

    def test_user_registered_target_allowed(self) -> None:
        registry = FakeRegistry({"my-app": FakeApproved("my-app")})
        entry = require_target_allowed("my-app", registry=registry)
        self.assertEqual(entry["allowed_hosts"], ["127.0.0.1"])
        self.assertEqual(entry["source"], "user_registry")

    def test_unknown_target_rejected_in_both_sources(self) -> None:
        with self.assertRaises(PolicyViolation) as ctx:
            require_target_allowed("nobody-approved-this", registry=FakeRegistry())
        # 사용자가 다음에 뭘 해야 하는지 알려주는 메시지여야 한다.
        self.assertIn("vc_register_local_target", str(ctx.exception))

    def test_builtin_wins_over_user_registry_on_id_collision(self) -> None:
        """사용자가 실수로 같은 id를 등록해도 팀이 체크인한 정의가 이긴다."""
        registry = FakeRegistry({BUILTIN_TARGET_ID: FakeApproved(BUILTIN_TARGET_ID, ["evil.example"])})
        entry = require_target_allowed(BUILTIN_TARGET_ID, registry=registry)
        self.assertNotIn("evil.example", entry["allowed_hosts"])

    def test_host_check_works_for_user_registered_target(self) -> None:
        registry = FakeRegistry({"my-app": FakeApproved("my-app", ["127.0.0.1"])})
        require_host_allowed("my-app", "http://127.0.0.1:3000", registry=registry)
        with self.assertRaises(PolicyViolation):
            require_host_allowed("my-app", "http://10.0.0.5:3000", registry=registry)

    def test_is_target_allowed_covers_both(self) -> None:
        registry = FakeRegistry({"my-app": FakeApproved("my-app")})
        self.assertTrue(is_target_allowed(BUILTIN_TARGET_ID, registry=registry))
        self.assertTrue(is_target_allowed("my-app", registry=registry))
        self.assertFalse(is_target_allowed("nope", registry=registry))

    def test_missing_registry_degrades_to_builtin_only(self) -> None:
        """레지스트리가 없어도(P2 미도입/오프라인) built-in 판정은 계속 동작한다."""
        self.assertTrue(is_target_allowed(BUILTIN_TARGET_ID, registry=None))


class GitPreconditionTests(unittest.TestCase):
    """등록 전제조건: 사용자 프로젝트는 git 저장소여야 한다(worktree 패치 경로 때문)."""

    def _git(self, path: Path, *args: str) -> None:
        subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True)

    def test_non_git_directory_is_blocked(self) -> None:
        from mcp_server.tools_inventory import _git_state

        with tempfile.TemporaryDirectory() as tmp:
            blockers, _ = _git_state(Path(tmp))
        self.assertTrue(blockers)
        self.assertIn("git init", blockers[0])

    def test_git_repo_without_commit_is_blocked(self) -> None:
        from mcp_server.tools_inventory import _git_state

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            self._git(path, "init")
            blockers, _ = _git_state(path)
        self.assertTrue(any("커밋" in b for b in blockers))

    def test_clean_git_repo_passes(self) -> None:
        from mcp_server.tools_inventory import _git_state

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            self._git(path, "init")
            self._git(path, "config", "user.email", "t@example.com")
            self._git(path, "config", "user.name", "t")
            (path / "app.py").write_text("print('hi')\n", encoding="utf-8")
            self._git(path, "add", "-A")
            self._git(path, "commit", "-m", "init")
            blockers, warnings = _git_state(path)
        self.assertEqual(blockers, [])
        self.assertEqual(warnings, [])

    def _dirty_repo(self, path: Path) -> None:
        self._git(path, "init")
        self._git(path, "config", "user.email", "t@example.com")
        self._git(path, "config", "user.name", "t")
        (path / "app.py").write_text("print('hi')\n", encoding="utf-8")
        self._git(path, "add", "-A")
        self._git(path, "commit", "-m", "init")
        (path / "app.py").write_text("print('changed')\n", encoding="utf-8")

    def test_dirty_worktree_blocks_closed_loop(self) -> None:
        """계약 3A-4: dirty면 verify한 코드와 패치한 코드가 달라진다 — 정합성 결함."""
        from mcp_server.tools_inventory import _git_state

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            self._dirty_repo(path)
            blockers, _ = _git_state(path)
        self.assertTrue(any("커밋하거나 stash" in b for b in blockers))

    def test_dirty_worktree_only_warns_for_scan_only(self) -> None:
        """패치를 만들지 않는 조회는 경고만 — 정합성 문제가 생기지 않는다."""
        from mcp_server.tools_inventory import _git_state

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            self._dirty_repo(path)
            blockers, warnings = _git_state(path, for_closed_loop=False)
        self.assertEqual(blockers, [])
        self.assertTrue(warnings)


class TargetIdCollisionTests(unittest.TestCase):
    """계약 3A-3: built-in과 id가 겹치면 등록을 거부한다."""

    def _manifest(self, target_id: str):
        from runtime.manifest import TargetManifest

        return TargetManifest.model_validate({
            "id": target_id, "display_name": "x", "adapter": "node",
            "base_url": "http://127.0.0.1:3000",
            "commands": {
                "build": {"argv": ["true"]}, "start": {"argv": ["true"]},
                "stop": {"argv": ["true"]}, "reset": {"argv": ["true"]},
            },
            "reset": {"command_id": "reset"},
        })

    def test_collision_with_builtin_is_blocked(self) -> None:
        from mcp_server.tools_inventory import _build_preview

        with tempfile.TemporaryDirectory() as tmp:
            preview = _build_preview(
                self._manifest(BUILTIN_TARGET_ID), Path(tmp), confirmed=True
            )
        self.assertTrue(any("built-in demo target과 겹칩니다" in b for b in preview.blockers))
        self.assertFalse(preview.registered)

    def test_distinct_id_has_no_collision_blocker(self) -> None:
        from mcp_server.tools_inventory import _build_preview

        with tempfile.TemporaryDirectory() as tmp:
            preview = _build_preview(self._manifest("local-my-app"), Path(tmp), confirmed=False)
        self.assertFalse(any("겹칩니다" in b for b in preview.blockers))


class KindReachesJudgeTests(unittest.TestCase):
    """P3 요청(2026-07-21 05:07): judge가 `kind`를 읽을 수 있는 경로를 계약으로 고정한다.

    `contracts.schemas.Target`에는 `kind`가 없고 그 스키마는 freeze 대상이다. 대신
    `catalog.get(target_id).manifest`가 built-in은 체크인 manifest를, 사용자 target은
    **승인 시점 snapshot**을 돌려주므로 양쪽 모두 `.manifest.kind`로 읽으면 된다.

    이 테스트가 깨지면 P3의 `core/judge.py`가 조용히 잘못된 kind로 판정하게 된다.
    """

    ACCESSOR = "catalog.get(target_id).manifest.kind"

    def _catalog_with_user_target(self, tmp_root: Path, source: Path):
        from runtime.catalog import TargetCatalog
        from runtime.manifest import TargetManifest
        from runtime.registry import LocalRegistry

        manifest = TargetManifest.model_validate({
            "id": "local-my-app", "display_name": "My App", "adapter": "node",
            "kind": "running_local", "base_url": "http://127.0.0.1:3000",
            "commands": {"reset": {"argv": ["docker", "compose", "restart"]}},
            "reset": {"command_id": "reset"},
        })
        registry = LocalRegistry.load(tmp_root)
        registry.approve(manifest, source_path=source)

        repo = Path(__file__).resolve().parent.parent
        catalog = TargetCatalog(
            manifest_root=repo / "targets" / "manifests",
            repository_root=repo,
            registry=registry,
        )
        catalog.load()
        return catalog

    def _git_repo(self, path: Path) -> None:
        for args in (["init"], ["config", "user.email", "t@e.com"],
                     ["config", "user.name", "t"]):
            subprocess.run(["git", "-C", str(path), *args], check=True, capture_output=True)
        (path / "app.py").write_text("print(1)\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(path), "add", "-A"], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(path), "commit", "-m", "init"],
                       check=True, capture_output=True)

    def test_kind_readable_for_builtin_and_user_targets(self) -> None:
        with tempfile.TemporaryDirectory() as reg_root, tempfile.TemporaryDirectory() as src:
            source = Path(src)
            self._git_repo(source)
            catalog = self._catalog_with_user_target(Path(reg_root), source)

            # built-in은 기본값 compose_project — 기존 20개 동작 불변
            self.assertEqual(catalog.get(BUILTIN_TARGET_ID).manifest.kind, "compose_project")
            # 사용자 target은 승인 snapshot의 kind가 그대로 도달한다
            self.assertEqual(catalog.get("local-my-app").manifest.kind, "running_local")

    def test_running_local_has_no_build_command(self) -> None:
        """§3A-5: build를 못 돌리면 judge가 build 게이트를 None으로 두고 FIXED를 막는다."""
        with tempfile.TemporaryDirectory() as reg_root, tempfile.TemporaryDirectory() as src:
            source = Path(src)
            self._git_repo(source)
            catalog = self._catalog_with_user_target(Path(reg_root), source)

            user = catalog.get("local-my-app").manifest
            self.assertNotIn("build", user.commands)
            self.assertIn("reset", user.commands)      # 재시작 방법은 필수
            builtin = catalog.get(BUILTIN_TARGET_ID).manifest
            self.assertIn("build", builtin.commands)   # compose는 현행 유지


if __name__ == "__main__":
    unittest.main()
