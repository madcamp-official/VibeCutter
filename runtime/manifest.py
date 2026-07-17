"""Trusted target-manifest schema and loader.

The manifest is repository-controlled configuration, not an MCP tool input.
Callers select a registered ``target_id`` and a fixed operation only.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Annotated
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


TargetId = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")]
CommandId = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{1,62}$")]
RelativePath = Annotated[str, Field(min_length=1, max_length=240)]


class AdapterKind(str, Enum):
    SPRING_BOOT = "spring-boot"
    FASTAPI = "fastapi"
    NODE = "node"
    GENERIC_DOCKER = "generic-docker"


class CommandSpec(BaseModel):
    """A fixed argument vector executed without a shell."""

    model_config = ConfigDict(extra="forbid")

    argv: list[Annotated[str, Field(min_length=1, max_length=500)]] = Field(min_length=1, max_length=32)
    timeout_seconds: int = Field(default=300, ge=1, le=3600)
    environment: dict[str, str] = Field(default_factory=dict)

    @field_validator("argv")
    @classmethod
    def argv_must_not_embed_shell(cls, argv: list[str]) -> list[str]:
        # The runner always uses shell=False. Reject common shell syntax too so
        # a manifest cannot accidentally encode a shell pipeline.
        prohibited = ("|", "&&", ";", "`", "$(")
        if any(any(token in arg for token in prohibited) for arg in argv):
            raise ValueError("command argv must not contain shell syntax")
        return argv


class HealthCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str = Field(default="/health", pattern=r"^/")
    expected_status: int = Field(default=200, ge=100, le=599)
    timeout_seconds: int = Field(default=20, ge=1, le=120)


class ResetSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command_id: CommandId
    snapshot_name: str | None = Field(default=None, max_length=120)


class RoleFixture(BaseModel):
    """Fixture metadata only; secrets and tokens belong in ignored .env files."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,62}$")
    description: str = Field(min_length=1, max_length=500)
    secret_env_names: list[str] = Field(default_factory=list, max_length=10)

    @field_validator("secret_env_names")
    @classmethod
    def environment_names_only(cls, names: list[str]) -> list[str]:
        if any(not name.startswith("VIBECUTTER_") for name in names):
            raise ValueError("fixture secrets must reference VIBECUTTER_* environment variable names")
        return names


class TestSuite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,62}$")
    command_id: CommandId


class TargetManifest(BaseModel):
    """The versioned P2 contract for one approved, loopback-only target."""

    model_config = ConfigDict(extra="forbid")

    manifest_version: int = Field(default=1, ge=1, le=1)
    target_id: TargetId
    display_name: str = Field(min_length=1, max_length=120)
    adapter: AdapterKind
    source_dir: RelativePath = "."
    base_url: str
    commands: dict[CommandId, CommandSpec]
    healthcheck: HealthCheck = Field(default_factory=HealthCheck)
    reset: ResetSpec
    role_fixtures: list[RoleFixture] = Field(default_factory=list, max_length=20)
    test_suites: list[TestSuite] = Field(default_factory=list, max_length=20)
    log_paths: list[RelativePath] = Field(default_factory=list, max_length=20)

    @field_validator("source_dir")
    @classmethod
    def source_dir_must_be_relative(cls, value: str) -> str:
        _validate_relative_path(value, "source_dir")
        return value

    @field_validator("log_paths")
    @classmethod
    def log_paths_must_be_relative(cls, values: list[str]) -> list[str]:
        for value in values:
            _validate_relative_path(value, "log path")
        return values

    @field_validator("base_url")
    @classmethod
    def base_url_must_be_loopback_http(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme != "http" or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("base_url must be a plain http loopback URL")
        if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("base_url host must be localhost, 127.0.0.1, or ::1")
        if parsed.port is None:
            raise ValueError("base_url must include an explicit port")
        return value.rstrip("/")

    @model_validator(mode="after")
    def referenced_commands_must_exist(self) -> "TargetManifest":
        required = {"build", "start", "stop", self.reset.command_id}
        required.update(suite.command_id for suite in self.test_suites)
        missing = required.difference(self.commands)
        if missing:
            raise ValueError(f"commands missing from manifest: {', '.join(sorted(missing))}")
        return self


def _validate_relative_path(value: str, label: str) -> None:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{label} must stay within the repository")


def load_manifest(path: Path) -> TargetManifest:
    """Load a checked-in YAML manifest and validate its entire schema."""
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError("manifest must contain a YAML mapping")
    return TargetManifest.model_validate(data)
