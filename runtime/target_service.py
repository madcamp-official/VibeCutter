"""P2 target onboarding and lifecycle service, guarded by P1 policy engine."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

from contracts.schemas import Run, RunState, Target
from core.evidence_store import save
from core.policy_engine import (
    PolicyViolation,
    require_host_allowed,
    require_target_allowed,
    require_valid_command,
)
from core.state_machine import transition

from .catalog import RegisteredRuntimeTarget, TargetCatalog
from .lifecycle import ApprovalRequired
from .manifest import TargetManifest


class TargetOperationError(RuntimeError):
    """A manifest-defined target command failed without exposing its raw output."""


class TargetRuntimeService:
    """P2 implementation behind inventory/lifecycle MCP tools.

    A caller never supplies a command, source path, or network destination.
    It can only name an already checked-in, policy-allowed target ID.
    """

    def __init__(
        self,
        catalog: TargetCatalog,
        *,
        scope_path: Path | None = None,
        commands_path: Path | None = None,
        save_target: Callable[[Target], None] = save,
        save_run: Callable[[Run], None] = save,
    ) -> None:
        self.catalog = catalog
        self.scope_path = scope_path
        self.commands_path = commands_path
        self._save_target = save_target
        self._save_run = save_run

    @classmethod
    def from_repository_root(cls, repository_root: Path) -> "TargetRuntimeService":
        root = repository_root.resolve()
        catalog = TargetCatalog(manifest_root=root / "targets" / "manifests", repository_root=root)
        catalog.load()
        return cls(catalog)

    def register(self, submitted_manifest: Mapping[str, object]) -> Target:
        """Register only a byte-for-byte equivalent checked-in target configuration."""
        submitted = TargetManifest.model_validate(dict(submitted_manifest))
        registered = self._require_authorized(submitted.id)
        if submitted.model_dump(mode="json") != registered.manifest.model_dump(mode="json"):
            raise PolicyViolation("submitted manifest differs from the checked-in approved manifest")
        self._save_target(registered.contract_target)
        return registered.contract_target

    def inspect_stack(self, target_id: str) -> tuple[str, ...]:
        target = self._require_authorized(target_id)
        return (target.manifest.adapter.value,)

    def check_readiness(self, target_id: str):
        self._require_authorized(target_id)
        return self.catalog.readiness_for(target_id)

    def build(self, target_id: str) -> Run:
        target = self._require_operation(target_id, "build_target")
        run = Run(
            id=f"run-{uuid4().hex[:12]}",
            target_id=target_id,
            tool_versions=self.catalog.lifecycle_for(target_id).tool_versions,
            status=RunState.BUILDING,
            started_at=datetime.utcnow(),
        )
        self._save_run(run)
        result = self.catalog.adapter_for(target_id).build()
        if result.status != "passed":
            run.ended_at = datetime.utcnow()
            self._save_run(run)
            raise TargetOperationError(f"build failed for target {target.id}")
        run.status = transition(run.status, RunState.READY)
        self._save_run(run)
        return run

    def start(self, target_id: str) -> tuple[str, bool]:
        target = self._require_operation(target_id, "start_target")
        adapter = self.catalog.adapter_for(target_id)
        started = adapter.start()
        if started.status != "passed":
            return target.manifest.base_url, False
        health = adapter.health()
        return target.manifest.base_url, health.status == "ready"

    def reset(self, target_id: str, *, approved: bool) -> bool:
        self._require_operation(target_id, "reset_target")
        if not approved:
            raise ApprovalRequired("vc_reset_target requires explicit approval")
        return self.catalog.adapter_for(target_id).reset(approved=True).status == "passed"

    def _require_operation(self, target_id: str, command_id: str) -> RegisteredRuntimeTarget:
        target = self._require_authorized(target_id)
        self._require_command(command_id, {"target_id": target_id})
        return target

    def _require_authorized(self, target_id: str) -> RegisteredRuntimeTarget:
        target = self.catalog.get(target_id)
        scope = self._require_target(target_id)
        self._require_host(target_id, target.manifest.base_url)
        configured_port = scope.get("port")
        actual_port = urlparse(target.manifest.base_url).port
        if not isinstance(configured_port, int) or configured_port != actual_port:
            raise PolicyViolation(
                f"target_id={target_id!r} port must match policy scope port={configured_port!r}"
            )
        return target

    def _require_target(self, target_id: str) -> dict:
        if self.scope_path is None:
            return require_target_allowed(target_id)
        return require_target_allowed(target_id, path=self.scope_path)

    def _require_host(self, target_id: str, base_url: str) -> None:
        if self.scope_path is None:
            require_host_allowed(target_id, base_url)
        else:
            require_host_allowed(target_id, base_url, path=self.scope_path)

    def _require_command(self, command_id: str, args: dict[str, str]) -> None:
        if self.commands_path is None:
            require_valid_command(command_id, args)
        else:
            require_valid_command(command_id, args, path=self.commands_path)
