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
    ) -> None:
        self.manifest_root = manifest_root.resolve()
        self.repository_root = repository_root.resolve()
        self.source_commit = source_commit
        self._targets: dict[str, RegisteredRuntimeTarget] = {}

    def load(self) -> None:
        """Atomically replace the catalog with manifests currently under manifest_root."""
        if not self.manifest_root.is_dir():
            raise FileNotFoundError(f"manifest root does not exist: {self.manifest_root}")
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
                contract_target=load_contract_target(resolved, source_commit=self.source_commit),
            )
        self._targets = discovered

    def list(self) -> tuple[RegisteredRuntimeTarget, ...]:
        return tuple(self._targets[target_id] for target_id in sorted(self._targets))

    def get(self, target_id: str) -> RegisteredRuntimeTarget:
        try:
            return self._targets[target_id]
        except KeyError as exc:
            raise KeyError(f"target_id is not registered in the P2 catalog: {target_id}") from exc

    def lifecycle_for(self, target_id: str) -> LifecycleManager:
        return LifecycleManager(self.get(target_id).manifest, self.repository_root)

    def source_root_for(self, target_id: str) -> Path:
        """Return the checked-in target source directory, never an MCP-supplied path."""
        manifest = self.get(target_id).manifest
        source_root = (self.repository_root / manifest.source_dir).resolve()
        if source_root != self.repository_root and self.repository_root not in source_root.parents:
            raise ValueError("target source directory escapes repository root")
        if not source_root.is_dir():
            raise FileNotFoundError(f"target source directory does not exist: {source_root}")
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
        sources_root = (self.repository_root / ".vibecutter" / "targets" / "sources").resolve()
        if repository != sources_root and sources_root not in repository.parents:
            raise ValueError("target Git repository is outside managed source clones")
        return repository

    def worktree_manager_for(self, target_id: str):
        """Create run worktrees from the target app repository, not VibeCutter itself."""
        from .worktree import WorktreeManager

        return WorktreeManager(
            self.source_repository_for(target_id),
            artifact_root=self.repository_root / ".vibecutter" / "worktrees" / target_id,
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
        return TargetRuntimeInspector(self.get(target_id).manifest, self.repository_root).check_readiness()

    def adapter_for(self, target_id: str) -> "TargetAdapter":
        # Imported lazily to keep the runtime core independent from adapter imports.
        from adapters.registry import adapter_for

        target = self.get(target_id)
        return adapter_for(target.manifest.adapter, self.lifecycle_for(target_id))

    def test_runner_for(self, target_id: str) -> RunScopedTestRunner:
        """Return the P1 regression-gate runner for an approved target ID."""
        return RunScopedTestRunner(
            self.get(target_id).manifest,
            self.source_repository_for(target_id),
            artifact_root=self.repository_root / ".vibecutter" / "worktrees" / target_id,
        )
