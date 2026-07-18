"""P2 verifier provisioning contract for trusted local targets.

The contract exposes only replay metadata: a loopback base URL, authentication
mode, role-fixture names, and an optional ignored fixture artifact path.  It
never stores credentials, tokens, or arbitrary commands.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .manifest import TargetManifest


class ProvisioningStrategy(StrEnum):
    """How P3 obtains two roles for a verifier replay."""

    FIXTURE_FILE = "fixture_file"
    SELF_SIGNUP = "self_signup"
    FIXTURE_CONTRACT_REQUIRED = "fixture_contract_required"
    CONTRACT_REQUIRED = "contract_required"


class ProvisioningOverride(BaseModel):
    """Checked-in override for a target with a known verifier provisioning path."""

    model_config = ConfigDict(extra="forbid")

    strategy: Literal[ProvisioningStrategy.FIXTURE_FILE, ProvisioningStrategy.SELF_SIGNUP]
    auth_mode: Literal["none", "bearer", "session_form"]
    fixture_command_id: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{1,62}$")
    fixture_path: str | None = Field(default=None, max_length=240)
    notes: str = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def fixture_file_requires_trusted_artifact(self) -> "ProvisioningOverride":
        if self.strategy is ProvisioningStrategy.FIXTURE_FILE:
            if self.fixture_command_id is None or self.fixture_path is None:
                raise ValueError("fixture_file provisioning requires fixture_command_id and fixture_path")
        elif self.fixture_command_id is not None or self.fixture_path is not None:
            raise ValueError("self_signup provisioning cannot declare a fixture command or path")
        return self


class VerifierProvisioning(BaseModel):
    """P1/P3-facing provisioning information for one policy-allowed target."""

    model_config = ConfigDict(extra="forbid")

    target_id: str
    base_url: str
    auth_mode: str
    strategy: ProvisioningStrategy
    role_fixture_names: list[str] = Field(default_factory=list)
    fixture_command_id: str | None = None
    fixture_path: str | None = None
    fixture_available: bool = False
    notes: str


class ProvisioningRegistry:
    """Load only repository-controlled verifier provisioning declarations."""

    def __init__(self, repository_root: Path, path: Path | None = None) -> None:
        self.repository_root = repository_root.resolve()
        self.path = (path or self.repository_root / "targets" / "verifier_provisioning.yaml").resolve()
        self._overrides: dict[str, ProvisioningOverride] = {}

    def load(self) -> None:
        if not self.path.is_file():
            self._overrides = {}
            return
        data = yaml.safe_load(self.path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("verifier provisioning registry must be a mapping")
        targets = data.get("targets", {})
        if not isinstance(targets, dict):
            raise ValueError("verifier provisioning targets must be a mapping")
        self._overrides = {
            str(target_id): ProvisioningOverride.model_validate(value)
            for target_id, value in targets.items()
        }

    def plan_for(self, manifest: TargetManifest) -> VerifierProvisioning:
        override = self._overrides.get(manifest.id)
        roles = [fixture.name for fixture in manifest.role_fixtures]
        if override is None:
            strategy = (
                ProvisioningStrategy.FIXTURE_CONTRACT_REQUIRED
                if roles
                else ProvisioningStrategy.CONTRACT_REQUIRED
            )
            return VerifierProvisioning(
                target_id=manifest.id,
                base_url=manifest.base_url,
                auth_mode="unknown",
                strategy=strategy,
                role_fixture_names=roles,
                notes="P3 must provide an authentication/seed fixture contract before verifier replay.",
            )

        fixture_available = False
        if override.fixture_path is not None:
            fixture = self._resolve_fixture_path(override.fixture_path)
            fixture_available = fixture.is_file()
        if override.fixture_command_id is not None and override.fixture_command_id not in manifest.commands:
            raise ValueError(
                f"provisioning command {override.fixture_command_id!r} is not registered for {manifest.id}"
            )
        return VerifierProvisioning(
            target_id=manifest.id,
            base_url=manifest.base_url,
            auth_mode=override.auth_mode,
            strategy=override.strategy,
            role_fixture_names=roles,
            fixture_command_id=override.fixture_command_id,
            fixture_path=override.fixture_path,
            fixture_available=fixture_available,
            notes=override.notes,
        )

    def _resolve_fixture_path(self, value: str) -> Path:
        path = Path(value)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("fixture path must remain repository-relative")
        allowed_root = (self.repository_root / ".vibecutter" / "fixtures").resolve()
        resolved = (self.repository_root / path).resolve()
        if resolved != allowed_root and allowed_root not in resolved.parents:
            raise ValueError("fixture path must remain under .vibecutter/fixtures")
        return resolved
