"""P2 catalog of checked-in manifests for P1 target-id based tool wiring."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from contracts.schemas import Target

from .lifecycle import LifecycleManager
from .manifest import TargetManifest, load_manifest
from .readiness import TargetReadiness, TargetRuntimeInspector
from .registration import load_contract_target

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

    def readiness_for(self, target_id: str) -> TargetReadiness:
        return TargetRuntimeInspector(self.get(target_id).manifest, self.repository_root).check_readiness()

    def adapter_for(self, target_id: str) -> "TargetAdapter":
        # Imported lazily to keep the runtime core independent from adapter imports.
        from adapters.registry import adapter_for

        target = self.get(target_id)
        return adapter_for(target.manifest.adapter, self.lifecycle_for(target_id))
