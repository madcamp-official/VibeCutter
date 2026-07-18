"""Run-scoped Git worktrees; original branches are never patched by P2."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path


_RUN_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
_REVISION = re.compile(r"^(HEAD|[0-9a-f]{7,64}|refs/[A-Za-z0-9._/-]+)$")


class WorktreeManager:
    def __init__(self, repository_root: Path, artifact_root: Path | None = None) -> None:
        self.repository_root = repository_root.resolve()
        self.artifact_root = (artifact_root or self.repository_root / ".vibecutter" / "worktrees").resolve()

    def path_for(self, run_id: str) -> Path:
        if not _RUN_ID.fullmatch(run_id):
            raise ValueError("run_id must be a lowercase slug")
        path = (self.artifact_root / run_id).resolve()
        if self.artifact_root not in path.parents:
            raise ValueError("worktree path escapes artifact root")
        return path

    def create(self, run_id: str, revision: str = "HEAD") -> Path:
        path = self.path_for(run_id)
        if not _REVISION.fullmatch(revision):
            raise ValueError("revision must be HEAD, a commit hash, or a local refs/* name")
        if path.exists():
            raise FileExistsError(f"worktree already exists for run {run_id}")
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "git",
                "-c",
                "core.autocrlf=false",
                "-C",
                str(self.repository_root),
                "worktree",
                "add",
                "--detach",
                str(path),
                revision,
            ],
            check=True,
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return path

    def remove(self, run_id: str, *, approved: bool) -> None:
        if not approved:
            raise PermissionError("worktree removal requires explicit approval")
        path = self.path_for(run_id)
        subprocess.run(
            ["git", "-C", str(self.repository_root), "worktree", "remove", "--force", str(path)],
            check=True,
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
