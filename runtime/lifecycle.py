"""Safe manifest-driven build, start, reset, health, and test operations."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Literal
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from pydantic import BaseModel, ConfigDict, Field

from .manifest import CommandSpec, TargetManifest


class ApprovalRequired(PermissionError):
    """Raised when a reset is requested without an explicit approval gate."""


class _RejectRedirects(HTTPRedirectHandler):
    """A loopback health check must never follow a target-controlled redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class CommandResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    command_id: str
    status: Literal["passed", "failed", "timed_out"]
    exit_code: int | None
    duration_ms: int = Field(ge=0)
    stdout: str
    stderr: str


class HealthResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["ready", "not_ready"]
    attempts: int = Field(ge=1)
    observed_status: int | None = None
    reason: str | None = None


class LifecycleManager:
    """Runs only command IDs defined by a validated manifest."""

    def __init__(self, manifest: TargetManifest, repository_root: Path) -> None:
        self.manifest = manifest
        self.repository_root = repository_root.resolve()
        self.source_dir = _resolve_within_root(self.repository_root, manifest.source_dir)

    def execute(self, command_id: str) -> CommandResult:
        try:
            spec = self.manifest.commands[command_id]
        except KeyError as exc:
            raise KeyError(f"command_id is not registered for {self.manifest.target_id}: {command_id}") from exc
        return self._run(command_id, spec)

    def build(self) -> CommandResult:
        return self.execute("build")

    def start(self) -> CommandResult:
        return self.execute("start")

    def stop(self) -> CommandResult:
        return self.execute("stop")

    def reset(self, *, approved: bool) -> CommandResult:
        if not approved:
            raise ApprovalRequired("reset requires explicit run-level approval")
        return self.execute(self.manifest.reset.command_id)

    def run_test_suites(self) -> list[CommandResult]:
        return [self.execute(suite.command_id) for suite in self.manifest.test_suites]

    def check_health(self) -> HealthResult:
        url = f"{self.manifest.base_url}{self.manifest.healthcheck.path}"
        deadline = time.monotonic() + self.manifest.healthcheck.timeout_seconds
        attempts = 0
        last_status: int | None = None
        last_reason: str | None = None
        while True:
            attempts += 1
            try:
                request = Request(url, method="GET", headers={"User-Agent": "VibeCutter/0.1"})
                opener = build_opener(_RejectRedirects())
                with opener.open(request, timeout=2) as response:  # nosec B310: URL is validated manifest data.
                    last_status = response.status
                    if response.status == self.manifest.healthcheck.expected_status:
                        return HealthResult(status="ready", attempts=attempts, observed_status=last_status)
                    last_reason = f"expected HTTP {self.manifest.healthcheck.expected_status}, received {last_status}"
            except HTTPError as exc:
                last_status = exc.code
                last_reason = f"received HTTP {exc.code}"
            except (URLError, TimeoutError, OSError) as exc:
                last_reason = str(exc)
            if time.monotonic() >= deadline:
                return HealthResult(
                    status="not_ready", attempts=attempts, observed_status=last_status, reason=last_reason
                )
            time.sleep(0.2)

    def _run(self, command_id: str, spec: CommandSpec) -> CommandResult:
        environment = os.environ.copy()
        environment.update(spec.environment)
        started = time.monotonic()
        try:
            completed = subprocess.run(
                spec.argv,
                cwd=self.source_dir,
                env=environment,
                capture_output=True,
                text=True,
                timeout=spec.timeout_seconds,
                shell=False,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(
                command_id=command_id,
                status="timed_out",
                exit_code=None,
                duration_ms=_duration_ms(started),
                stdout=_as_text(exc.stdout),
                stderr=_as_text(exc.stderr),
            )
        return CommandResult(
            command_id=command_id,
            status="passed" if completed.returncode == 0 else "failed",
            exit_code=completed.returncode,
            duration_ms=_duration_ms(started),
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


def _resolve_within_root(root: Path, relative_path: str) -> Path:
    resolved = (root / relative_path).resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError("manifest source_dir escapes repository root")
    return resolved


def _duration_ms(started: float) -> int:
    return round((time.monotonic() - started) * 1000)


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode(errors="replace") if isinstance(value, bytes) else value
