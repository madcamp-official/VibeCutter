"""P2 catalog of checked-in manifests for P1 target-id based tool wiring."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import subprocess
from typing import TYPE_CHECKING

from contracts.schemas import Target

from .lifecycle import LifecycleManager
from .manifest import TargetManifest, load_manifest
from .readiness import TargetReadiness, TargetRuntimeInspector
from .registry import LocalRegistry
from .registration import load_contract_target
from .source_bootstrap import SourceCheck, TargetSourceBootstrapper
from .source_lock import SourceLock, SourceRevision
from .test_runner import RunScopedTestRunner

if TYPE_CHECKING:
    from adapters.base import TargetAdapter


def _git_head(source: Path) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(source), "rev-parse", "HEAD"],
        capture_output=True,
        check=False,
        shell=False,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


@dataclass(frozen=True)
class RegisteredRuntimeTarget:
    """One trusted manifest and its P1-facing Target projection."""

    manifest_path: Path
    manifest: TargetManifest
    contract_target: Target
    user_registered: bool = False


class TargetCatalog:
    """Discover built-in manifests and explicitly approved local targets."""

    def __init__(
        self,
        *,
        manifest_root: Path,
        repository_root: Path,
        source_commit: str | None = None,
        source_lock_path: Path | None = None,
        registry: LocalRegistry | None = None,
    ) -> None:
        self.manifest_root = manifest_root.resolve()
        self.repository_root = repository_root.resolve()
        self.source_commit = source_commit
        default_source_lock = self.repository_root / "targets" / "source-lock.yaml"
        self.source_lock_path = (
            source_lock_path.resolve()
            if source_lock_path is not None
            else default_source_lock.resolve()
            if default_source_lock.is_file()
            else None
        )
        self.registry = registry or LocalRegistry.load()
        self._targets: dict[str, RegisteredRuntimeTarget] = {}
        self._source_lock: SourceLock | None = None
        self._user_target_ids: set[str] = set()

    def load(self) -> None:
        """Atomically load built-ins plus approved user registry snapshots."""
        if not self.manifest_root.is_dir():
            raise FileNotFoundError(
                f"manifest root does not exist: {self.manifest_root}"
            )
        builtins: dict[str, RegisteredRuntimeTarget] = {}
        for path in sorted(self.manifest_root.glob("*.yaml")):
            resolved = path.resolve()
            if self.manifest_root not in resolved.parents:
                raise ValueError("manifest path escapes manifest root")
            manifest = load_manifest(resolved)
            if manifest.id in builtins:
                raise ValueError(f"duplicate target manifest id: {manifest.id}")
            builtins[manifest.id] = RegisteredRuntimeTarget(
                manifest_path=resolved,
                manifest=manifest,
                contract_target=load_contract_target(
                    resolved, source_commit=self.source_commit
                ),
            )
        # Built-ins are authoritative on an ID collision. Registration normally
        # rejects the collision, but this second layer prevents a stale registry
        # entry from silently redirecting an audit to a user project.
        users: dict[str, RegisteredRuntimeTarget] = {}
        for target_id in self.registry.list_ids():
            if target_id in builtins:
                continue
            approved = self.registry.get(target_id)
            if approved is None:
                continue
            manifest = self.registry.manifest_for(target_id)
            snapshot_path = self.registry.root / target_id / "manifest.yaml"
            users[target_id] = RegisteredRuntimeTarget(
                manifest_path=snapshot_path,
                manifest=manifest,
                contract_target=Target(
                    id=manifest.id,
                    manifest_hash=approved.manifest_sha256,
                    source_commit=_git_head(approved.source_path),
                    adapter=manifest.adapter.value,
                    allowed_hosts=list(approved.allowed_hosts),
                ),
                user_registered=True,
            )
        discovered = dict(builtins)
        if self.source_lock_path is None:
            self._targets = {**discovered, **users}
            self._user_target_ids = set(users)
            self._source_lock = None
            return

        source_lock = SourceLock.load(
            self.source_lock_path, expected_target_ids=set(builtins)
        )
        if self.source_commit is not None:
            raise ValueError(
                "source_commit cannot be combined with a per-target source lock"
            )
        # The source lock, rather than a caller-provided catalog hint, is the
        # immutable source identity recorded in P1's Target projection.
        locked_builtins = {
            target_id: RegisteredRuntimeTarget(
                manifest_path=target.manifest_path,
                manifest=target.manifest,
                contract_target=load_contract_target(
                    target.manifest_path,
                    source_commit=source_lock.get(target_id).revision,
                ),
            )
            for target_id, target in builtins.items()
        }
        self._targets = {**locked_builtins, **users}
        self._user_target_ids = set(users)
        self._source_lock = source_lock

    def list(self) -> tuple[RegisteredRuntimeTarget, ...]:
        return tuple(self._targets[target_id] for target_id in sorted(self._targets))

    def get(self, target_id: str) -> RegisteredRuntimeTarget:
        try:
            return self._targets[target_id]
        except KeyError as exc:
            raise KeyError(
                f"target_id is not registered in the P2 catalog: {target_id}"
            ) from exc

    def lifecycle_for(self, target_id: str) -> LifecycleManager:
        self.require_ready_source(target_id)
        target = self.get(target_id)
        # `source_root_for()` already resolves `source_repo / manifest.source_dir` for a
        # user-registered target, so passing manifest.source_dir through unchanged makes
        # LifecycleManager apply it a second time (2026-07-22 live discovery, IDOR fixture
        # prep on a user target with source_dir="backend" tried to open ".../backend/backend").
        # Mirrors `core.judge.check_build`'s existing `source_dir: "."` override for the same
        # already-resolved-root situation.
        if target.user_registered:
            root = self.source_root_for(target_id)
            manifest = target.manifest.model_copy(update={"source_dir": "."})
        else:
            root = self.repository_root
            manifest = target.manifest
        return LifecycleManager(manifest, root)

    @property
    def source_lock(self) -> SourceLock:
        if self._source_lock is None:
            raise RuntimeError(
                "target catalog must be loaded before accessing its source lock"
            )
        return self._source_lock

    def source_revision_for(self, target_id: str) -> SourceRevision:
        self.get(target_id)
        if target_id in self._user_target_ids:
            raise ValueError(f"user target {target_id!r} has no built-in source lock")
        return self.source_lock.get(target_id)

    def source_bootstrapper(self) -> TargetSourceBootstrapper:
        return TargetSourceBootstrapper(self.repository_root, self.source_lock)

    def source_check_for(self, target_id: str) -> SourceCheck:
        if target_id in self._user_target_ids:
            raise ValueError(f"user target {target_id!r} uses its approved local source path")
        self.get(target_id)
        return self.source_bootstrapper().inspect(target_id)

    def bootstrap_source(self, target_id: str, *, approved: bool) -> SourceCheck:
        if target_id in self._user_target_ids:
            raise ValueError(f"user target {target_id!r} uses its approved local source path")
        self.get(target_id)
        return self.source_bootstrapper().bootstrap(target_id, approved=approved)

    def require_ready_source(self, target_id: str) -> SourceCheck | None:
        if target_id in self._user_target_ids:
            self._require_user_source(target_id)
            return None
        if self._source_lock is None:
            return None
        check = self.source_check_for(target_id)
        if not check.ready:
            raise ValueError(
                f"managed source for {target_id} is not ready: {check.status}"
            )
        return check

    def source_root_for(self, target_id: str) -> Path:
        """Return a built-in locked or user-approved target source directory."""
        target = self.get(target_id)
        if target.user_registered:
            approved = self.registry.get(target_id)
            if approved is None:
                raise ValueError(f"registry approval disappeared for {target_id}")
            source_repo = approved.source_path.resolve()
            source_root = (source_repo / target.manifest.source_dir).resolve()
            if source_root != source_repo and source_repo not in source_root.parents:
                raise ValueError("user target source directory escapes approved repository")
            if not source_root.is_dir():
                raise FileNotFoundError(f"target source directory does not exist: {source_root}")
            return source_root
        checked_source = self.require_ready_source(target_id)
        manifest = target.manifest
        source_root = (self.repository_root / manifest.source_dir).resolve()
        if (
            source_root != self.repository_root
            and self.repository_root not in source_root.parents
        ):
            raise ValueError("target source directory escapes repository root")
        if not source_root.is_dir():
            raise FileNotFoundError(
                f"target source directory does not exist: {source_root}"
            )
        if (
            checked_source is not None
            and checked_source.repository_path not in source_root.parents
            and source_root != checked_source.repository_path
        ):
            raise ValueError(
                "manifest source directory is outside the locked target repository"
            )
        return source_root

    def source_repository_for(self, target_id: str) -> Path:
        """Resolve the Git repository that owns a target source subdirectory."""
        source_root = self.source_root_for(target_id)
        result = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", "--show-toplevel"],
            capture_output=True,
            check=False,
            shell=False,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if result.returncode != 0:
            raise ValueError(f"target source is not a Git repository: {source_root}")
        repository = Path(result.stdout.strip()).resolve()
        if target_id in self._user_target_ids:
            approved = self.registry.get(target_id)
            if approved is None:
                raise ValueError(f"registry approval disappeared for {target_id}")
            if repository != approved.source_path.resolve():
                raise ValueError("user target Git repository does not match approved source path")
        elif self._source_lock is not None:
            expected_repository = self.source_bootstrapper().path_for(target_id)
            if repository != expected_repository:
                raise ValueError(
                    "target Git repository does not match the locked managed source clone"
                )
        else:
            sources_root = (
                self.repository_root / ".vibecutter" / "targets" / "sources"
            ).resolve()
            if repository != sources_root and sources_root not in repository.parents:
                raise ValueError(
                    "target Git repository is outside managed source clones"
                )
        return repository

    def source_relative_path_for(self, target_id: str) -> Path:
        """Return manifest.source_dir relative to the managed target Git repository."""
        source_root = self.source_root_for(target_id)
        repository = self.source_repository_for(target_id)
        try:
            return source_root.relative_to(repository)
        except ValueError as exc:
            raise ValueError(
                "target source directory is outside its Git repository"
            ) from exc

    def run_source_root_for(self, target_id: str, run_id: str) -> Path:
        """Return the manifest source directory inside a run-scoped target worktree."""
        worktree_path = self.worktree_manager_for(target_id).path_for(run_id).resolve()
        run_source_root = (
            worktree_path / self.source_relative_path_for(target_id)
        ).resolve()
        if (
            run_source_root != worktree_path
            and worktree_path not in run_source_root.parents
        ):
            raise ValueError("run source directory escapes target worktree")
        return run_source_root

    def worktree_manager_for(self, target_id: str):
        """Create run worktrees from the target app repository, not VibeCutter itself."""
        from .worktree import WorktreeManager

        # User-registered (local registry) targets have no built-in source-lock pin —
        # they use whatever revision is currently at HEAD in the user's own approved
        # repository (2026-07-22, U4 live discovery: this unconditionally called
        # `source_revision_for`, which raises for any user target, so `vc_apply_patch`
        # could never create a worktree for an arbitrary local project). Mirrors the
        # `target_id in self._user_target_ids` guard already used by `source_root_for`/
        # `source_check_for`/`bootstrap_source` above.
        locked_revision = (
            self.source_revision_for(target_id).revision
            if self._source_lock is not None and target_id not in self._user_target_ids
            else None
        )
        return WorktreeManager(
            self.source_repository_for(target_id),
            artifact_root=self.repository_root
            / ".vibecutter"
            / "worktrees"
            / target_id,
            locked_revision=locked_revision,
        )

    def run_overlay_for(self, target_id: str, run_id: str):
        """Project a checked-in Compose runtime onto an existing target worktree."""
        from .run_overlay import RunComposeOverlay

        worktrees = self.worktree_manager_for(target_id)
        return RunComposeOverlay(
            self.get(target_id).manifest,
            self.repository_root,
            self.source_repository_for(target_id),
            worktrees.path_for(run_id),
            run_id,
            project_root=(self.source_repository_for(target_id) if self.get(target_id).user_registered else None),
        )

    def readiness_for(self, target_id: str) -> TargetReadiness:
        target = self.get(target_id)
        runtime_root = self.source_root_for(target_id) if target.user_registered else self.repository_root
        readiness = TargetRuntimeInspector(
            target.manifest, runtime_root
        ).check_readiness()
        if self._source_lock is None or target.user_registered:
            return readiness
        source = self.source_check_for(target_id)
        if source.ready:
            return readiness
        issues = [*readiness.issues, f"source lock: {source.status}"]
        return readiness.model_copy(update={"ready": False, "issues": issues})

    def _require_user_source(self, target_id: str) -> None:
        """Validate an approved user repository without source-lock bootstrap."""
        target = self.get(target_id)
        approved = self.registry.get(target_id)
        if approved is None:
            raise ValueError(f"registry approval disappeared for {target_id}")
        source = approved.source_path.resolve()
        if not source.is_dir() or _git_head(source) is None:
            raise ValueError(f"approved user source is not a Git repository: {source}")

    def adapter_for(self, target_id: str) -> "TargetAdapter":
        # Imported lazily to keep the runtime core independent from adapter imports.
        from adapters.registry import adapter_for

        target = self.get(target_id)
        return adapter_for(target.manifest.adapter, self.lifecycle_for(target_id))

    def test_runner_for(self, target_id: str) -> RunScopedTestRunner:
        """Return the P1 regression-gate runner for an approved target ID."""
        locked_revision = (
            self.source_revision_for(target_id).revision
            if self._source_lock is not None
            else None
        )
        return RunScopedTestRunner(
            self.get(target_id).manifest,
            self.source_repository_for(target_id),
            artifact_root=self.repository_root
            / ".vibecutter"
            / "worktrees"
            / target_id,
            locked_revision=locked_revision,
        )

    def verifier_provisioning_for(self, target_id: str):
        """Return trusted P2 replay provisioning metadata for P1/P3."""
        from .provisioning import ProvisioningRegistry

        registry = ProvisioningRegistry(self.repository_root)
        registry.load()
        return registry.plan_for(self.get(target_id).manifest)
