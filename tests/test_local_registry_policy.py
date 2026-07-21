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

    def test_dirty_worktree_warns_but_does_not_block(self) -> None:
        from mcp_server.tools_inventory import _git_state

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            self._git(path, "init")
            self._git(path, "config", "user.email", "t@example.com")
            self._git(path, "config", "user.name", "t")
            (path / "app.py").write_text("print('hi')\n", encoding="utf-8")
            self._git(path, "add", "-A")
            self._git(path, "commit", "-m", "init")
            (path / "app.py").write_text("print('changed')\n", encoding="utf-8")
            blockers, warnings = _git_state(path)
        self.assertEqual(blockers, [])
        self.assertTrue(warnings)


if __name__ == "__main__":
    unittest.main()
