"""Read-only target readiness and log-location checks for P2 lifecycle tools."""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .compose_isolation import ComposeIsolationInspector, ComposeIsolationReport
from .lifecycle import VIBECUTTER_PYTHON, _resolve_within_root
from .manifest import TargetManifest


class RoleFixtureStatus(BaseModel):
    """Reports fixture configuration without ever exposing secret values."""

    model_config = ConfigDict(extra="forbid")

    name: str
    configured_env_names: list[str] = Field(default_factory=list)
    missing_env_names: list[str] = Field(default_factory=list)


class LogLocation(BaseModel):
    """Path metadata only; callers must redact content before evidence storage."""

    model_config = ConfigDict(extra="forbid")

    configured_path: str
    resolved_path: str | None
    status: Literal["present", "missing", "outside_target"]
    size_bytes: int | None = None


class TargetReadiness(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_id: str
    ready: bool
    source_dir: str
    source_dir_exists: bool
    unavailable_executables: list[str] = Field(default_factory=list)
    fixtures: list[RoleFixtureStatus] = Field(default_factory=list)
    logs: list[LogLocation] = Field(default_factory=list)
    docker_isolation: ComposeIsolationReport | None = None
    issues: list[str] = Field(default_factory=list)


class TargetRuntimeInspector:
    """Performs no build/start/reset action and accepts no raw caller input."""

    def __init__(self, manifest: TargetManifest, repository_root: Path) -> None:
        self.manifest = manifest
        self.repository_root = repository_root.resolve()
        self.source_dir = _resolve_within_root(self.repository_root, manifest.source_dir)

    def check_readiness(self) -> TargetReadiness:
        source_dir_exists = self.source_dir.is_dir()
        unavailable_executables = sorted(
            {
                spec.argv[0]
                for spec in self.manifest.commands.values()
                if not _is_executable_available(spec.argv[0], source_dir=self.source_dir)
            }
        )
        fixtures = [
            RoleFixtureStatus(
                name=fixture.name,
                configured_env_names=fixture.secret_env_names,
                missing_env_names=[name for name in fixture.secret_env_names if not os.environ.get(name)],
            )
            for fixture in self.manifest.role_fixtures
        ]
        logs = self.log_locations()
        isolation = ComposeIsolationInspector(self.manifest, self.repository_root).inspect()
        issues: list[str] = []
        if not source_dir_exists:
            issues.append("target source directory does not exist")
        if unavailable_executables:
            issues.append(f"unavailable executables: {', '.join(unavailable_executables)}")
        missing_fixture_names = [fixture.name for fixture in fixtures if fixture.missing_env_names]
        if missing_fixture_names:
            issues.append(f"role fixture environment not configured: {', '.join(missing_fixture_names)}")
        if any(location.status == "outside_target" for location in logs):
            issues.append("one or more configured log paths escape the target source directory")
        if isolation.status not in {"not_configured", "compliant"}:
            issues.extend(f"docker isolation: {issue}" for issue in isolation.issues or [isolation.status])
        return TargetReadiness(
            target_id=self.manifest.id,
            ready=not issues,
            source_dir=str(self.source_dir),
            source_dir_exists=source_dir_exists,
            unavailable_executables=unavailable_executables,
            fixtures=fixtures,
            logs=logs,
            docker_isolation=isolation,
            issues=issues,
        )

    def log_locations(self) -> list[LogLocation]:
        locations: list[LogLocation] = []
        for configured_path in self.manifest.log_paths:
            try:
                resolved = _resolve_within_root(self.source_dir, configured_path)
            except ValueError:
                locations.append(
                    LogLocation(configured_path=configured_path, resolved_path=None, status="outside_target")
                )
                continue
            if not resolved.exists():
                locations.append(
                    LogLocation(configured_path=configured_path, resolved_path=str(resolved), status="missing")
                )
                continue
            locations.append(
                LogLocation(
                    configured_path=configured_path,
                    resolved_path=str(resolved),
                    status="present",
                    size_bytes=resolved.stat().st_size if resolved.is_file() else None,
                )
            )
        return locations


def _is_executable_available(executable: str, *, source_dir: Path) -> bool:
    if executable == VIBECUTTER_PYTHON:
        return True
    path = Path(executable)
    if path.is_absolute():
        return path.is_file()
    if path.name != executable:
        # 경로 구분자가 있는 상대경로(예: "./gradlew", "bin/mvnw")는 PATH에서 찾는 명령이
        # 아니라 프로젝트 안의 래퍼 스크립트다. 실제 실행 시 `LifecycleManager._run()`이
        # `cwd=source_dir`로 돌리므로(runtime/lifecycle.py), 그 규칙과 똑같이 source_dir
        # 기준으로 존재 여부를 확인한다 — PATH로 찾으면 항상 "unavailable" 오탐이 난다.
        return (source_dir / path).is_file()
    return shutil.which(executable) is not None
