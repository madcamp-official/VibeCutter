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
from .registration import load_contract_target
from .source_bootstrap import SourceCheck, TargetSourceBootstrapper
from .source_lock import SourceLock, SourceRevision
from .test_runner import RunScopedTestRunner

if TYPE_CHECKING:
    from adapters.base import TargetAdapter


@dataclass(frozen=True)
class RegisteredRuntimeTarget:
    """One trusted manifest and its P1-facing Target projection."""

    manifest_path: Path
    manifest: TargetManifest
    contract_target: Target


class TargetCatalog:
    """Discovers only repository-controlled YAML manifests, keyed by ``Target.id``."""

    def __init__(
        self,
        *,
        manifest_root: Path,
        repository_root: Path,
        source_commit: str | None = None,
        source_lock_path: Path | None = None,
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
        self._targets: dict[str, RegisteredRuntimeTarget] = {}
        self._source_lock: SourceLock | None = None

    def load(self) -> None:
        """Atomically replace the catalog with manifests currently under manifest_root."""
        if not self.manifest_root.is_dir():
            raise FileNotFoundError(
                f"manifest root does not exist: {self.manifest_root}"
            )
        discovered: dict[str, RegisteredRuntimeTarget] = {}
        for path in sorted(self.manifest_root.glob("*.yaml")):
            resolved = path.resolve()
            if self.manifest_root not in resolved.parents:
                raise ValueError("manifest path escapes manifest root")
            manifest = load_manifest(resolved)
            if manifest.id in discovered:
                raise ValueError(f"duplicate target manifest id: {manifest.id}")
            discovered[manifest.id] = RegisteredRuntimeTarget(
                manifest_path=resolved,
                manifest=manifest,
                contract_target=load_contract_target(
                    resolved, source_commit=self.source_commit
                ),
            )
        if self.source_lock_path is None:
            self._targets = discovered
            self._source_lock = None
            return

        source_lock = SourceLock.load(
            self.source_lock_path, expected_target_ids=set(discovered)
        )
        if self.source_commit is not None:
            raise ValueError(
                "source_commit cannot be combined with a per-target source lock"
            )
        # The source lock, rather than a caller-provided catalog hint, is the
        # immutable source identity recorded in P1's Target projection.
        self._targets = {
            target_id: RegisteredRuntimeTarget(
                manifest_path=target.manifest_path,
                manifest=target.manifest,
                contract_target=load_contract_target(
                    target.manifest_path,
                    source_commit=source_lock.get(target_id).revision,
                ),
            )
            for target_id, target in discovered.items()
        }
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
        return LifecycleManager(self.get(target_id).manifest, self.repository_root)

    @property
    def source_lock(self) -> SourceLock:
        if self._source_lock is None:
            raise RuntimeError(
                "target catalog must be loaded before accessing its source lock"
            )
        return self._source_lock

    def source_revision_for(self, target_id: str) -> SourceRevision:
        self.get(target_id)
        return self.source_lock.get(target_id)

    def source_bootstrapper(self) -> TargetSourceBootstrapper:
        return TargetSourceBootstrapper(self.repository_root, self.source_lock)

    def source_check_for(self, target_id: str) -> SourceCheck:
        self.get(target_id)
        return self.source_bootstrapper().inspect(target_id)

    def bootstrap_source(self, target_id: str, *, approved: bool) -> SourceCheck:
        self.get(target_id)
        return self.source_bootstrapper().bootstrap(target_id, approved=approved)

    def require_ready_source(self, target_id: str) -> SourceCheck | None:
        if self._source_lock is None:
            return None
        check = self.source_check_for(target_id)
        if not check.ready:
            raise ValueError(
                f"managed source for {target_id} is not ready: {check.status}"
            )
        return check

    def source_root_for(self, target_id: str) -> Path:
        """Return the checked-in target source directory, never an MCP-supplied path."""
        checked_source = self.require_ready_source(target_id)
        manifest = self.get(target_id).manifest
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
        if self._source_lock is not None:
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

        locked_revision = (
            self.source_revision_for(target_id).revision
            if self._source_lock is not None
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
        )

    def readiness_for(self, target_id: str) -> TargetReadiness:
        readiness = TargetRuntimeInspector(
            self.get(target_id).manifest, self.repository_root
        ).check_readiness()
        if self._source_lock is None:
            return readiness
        source = self.source_check_for(target_id)
        if source.ready:
            return readiness
        issues = [*readiness.issues, f"source lock: {source.status}"]
        return readiness.model_copy(update={"ready": False, "issues": issues})

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
