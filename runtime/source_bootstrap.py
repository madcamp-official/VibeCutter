"""Safe bootstrap and inspection of ignored P2 target source clones."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from typing import Callable, Literal

from .source_lock import SourceLock, SourceRevision


SourceStatus = Literal[
    "ready",
    "missing",
    "invalid_repository",
    "dirty",
    "origin_mismatch",
    "revision_mismatch",
]


@dataclass(frozen=True)
class SourceCheck:
    target_id: str
    status: SourceStatus
    repository_path: Path
    expected_revision: str
    observed_revision: str | None = None
    reason: str | None = None

    @property
    def ready(self) -> bool:
        return self.status == "ready"


class SourceBootstrapError(RuntimeError):
    """A target source could not be prepared without mutating an existing clone."""


GitRunner = Callable[[list[str], int], subprocess.CompletedProcess[str]]


def _run_git(argv: list[str], timeout_seconds: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        capture_output=True,
        check=False,
        shell=False,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
    )


class TargetSourceBootstrapper:
    """Resolve URL, revision, and destination from a trusted target ID only."""

    def __init__(
        self,
        repository_root: Path,
        source_lock: SourceLock,
        *,
        run_git: GitRunner = _run_git,
    ) -> None:
        self.repository_root = repository_root.resolve()
        self.sources_root = (
            self.repository_root / ".vibecutter" / "targets" / "sources"
        ).resolve()
        self.source_lock = source_lock
        self._run_git = run_git

    def path_for(self, target_id: str) -> Path:
        self.source_lock.get(target_id)
        path = (self.sources_root / target_id).resolve()
        if path.parent != self.sources_root:
            raise ValueError("target source path escapes managed source root")
        return path

    def inspect(self, target_id: str) -> SourceCheck:
        return self._inspect_path(
            self.path_for(target_id), self.source_lock.get(target_id)
        )

    def bootstrap(self, target_id: str, *, approved: bool) -> SourceCheck:
        """Create only a missing clone; never rewrite, fetch, or reset an existing clone."""
        if not approved:
            raise PermissionError("target source bootstrap requires explicit approval")
        entry = self.source_lock.get(target_id)
        destination = self.path_for(target_id)
        if destination.exists():
            current = self.inspect(target_id)
            if current.ready:
                return current
            raise SourceBootstrapError(
                f"existing target source {target_id} is {current.status}; refusing to mutate it"
            )

        self.sources_root.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(
            prefix=f".bootstrap-{target_id}-", dir=self.sources_root
        ) as temp_dir:
            checkout = Path(temp_dir) / target_id
            clone = self._run_git(
                [
                    "git",
                    "-c",
                    "protocol.file.allow=never",
                    "-c",
                    "core.longpaths=true",
                    "clone",
                    "--no-checkout",
                    entry.repository,
                    str(checkout),
                ],
                900,
            )
            if clone.returncode != 0:
                raise SourceBootstrapError(
                    f"source clone failed for target {target_id}"
                )
            checkout_result = self._run_git(
                [
                    "git",
                    "-c",
                    "core.longpaths=true",
                    "-C",
                    str(checkout),
                    "checkout",
                    "--detach",
                    entry.revision,
                ],
                300,
            )
            if checkout_result.returncode != 0:
                raise SourceBootstrapError(
                    f"locked source checkout failed for target {target_id}"
                )
            verified = self._inspect_path(checkout, entry)
            if not verified.ready:
                raise SourceBootstrapError(
                    f"bootstrapped target source {target_id} failed verification: {verified.status}"
                )
            if destination.exists():
                raise SourceBootstrapError(
                    f"target source appeared concurrently: {target_id}"
                )
            os.replace(checkout, destination)
        return self.inspect(target_id)

    def _inspect_path(self, path: Path, entry: SourceRevision) -> SourceCheck:
        if not path.exists():
            return SourceCheck(
                target_id=entry.target_id,
                status="missing",
                repository_path=path,
                expected_revision=entry.revision,
                reason="managed source checkout does not exist",
            )
        if not path.is_dir():
            return SourceCheck(
                target_id=entry.target_id,
                status="invalid_repository",
                repository_path=path,
                expected_revision=entry.revision,
                reason="managed source path is not a directory",
            )

        top = self._run_git(
            ["git", "-C", str(path), "rev-parse", "--show-toplevel"], 30
        )
        if top.returncode != 0 or Path(top.stdout.strip()).resolve() != path.resolve():
            return SourceCheck(
                target_id=entry.target_id,
                status="invalid_repository",
                repository_path=path,
                expected_revision=entry.revision,
                reason="managed source path is not the target Git repository root",
            )
        origin = self._run_git(
            ["git", "-C", str(path), "remote", "get-url", "origin"], 30
        )
        if origin.returncode != 0 or origin.stdout.strip() != entry.repository:
            return SourceCheck(
                target_id=entry.target_id,
                status="origin_mismatch",
                repository_path=path,
                expected_revision=entry.revision,
                reason="Git origin does not match checked-in source lock",
            )
        head = self._run_git(["git", "-C", str(path), "rev-parse", "HEAD"], 30)
        observed = head.stdout.strip() if head.returncode == 0 else None
        if observed != entry.revision:
            return SourceCheck(
                target_id=entry.target_id,
                status="revision_mismatch",
                repository_path=path,
                expected_revision=entry.revision,
                observed_revision=observed,
                reason="Git HEAD does not match checked-in source lock",
            )
        dirty = self._run_git(["git", "-C", str(path), "status", "--porcelain"], 30)
        if dirty.returncode != 0 or dirty.stdout.strip():
            return SourceCheck(
                target_id=entry.target_id,
                status="dirty",
                repository_path=path,
                expected_revision=entry.revision,
                observed_revision=observed,
                reason="managed target source has uncommitted changes",
            )
        return SourceCheck(
            target_id=entry.target_id,
            status="ready",
            repository_path=path,
            expected_revision=entry.revision,
            observed_revision=observed,
        )
