"""Read-only, worker-local preflight for the checked-in GPU runtime queue.

This module is intentionally not a scheduler or remote dispatcher.  A caller
already on a GPU worker supplies its worker ID; preflight verifies that the
selected targets belong to that worker and that their local prerequisites are
safe to use before a lifecycle build/start command is issued.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import socket
import subprocess
import sys
from typing import Callable, Literal, Sequence
from urllib.parse import urlparse

from pydantic import BaseModel

from .batch_queue import load_runtime_batch_queue
from .catalog import TargetCatalog
from .readiness import TargetReadiness
from .source_bootstrap import SourceCheck, TargetSourceBootstrapper
from .source_lock import SourceLock


DockerInfo = Callable[[], tuple[bool, str | None]]
PortExpectation = Literal["available", "listening"]
PortProbe = Callable[[str, int, PortExpectation], tuple[bool, str | None]]


@dataclass(frozen=True)
class WorkerTargetPreflight:
    """Read-only readiness facts for one target assigned to this worker."""

    target_id: str
    assigned: bool
    source: SourceCheck
    readiness: TargetReadiness
    docker_available: bool
    docker_version: str | None
    expected_port_state: PortExpectation
    port_ready: bool
    port_reason: str | None
    issues: tuple[str, ...]

    @property
    def ready(self) -> bool:
        return not self.issues


@dataclass(frozen=True)
class WorkerRuntimePreflight:
    """Preflight result for all requested targets on one local worker."""

    worker_id: str
    targets: tuple[WorkerTargetPreflight, ...]

    @property
    def ready(self) -> bool:
        return all(target.ready for target in self.targets)


def _docker_info() -> tuple[bool, str | None]:
    """Ask the local Docker CLI whether it can reach its local daemon."""
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            check=False,
            shell=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, None
    if result.returncode != 0:
        return False, None
    version = result.stdout.strip()
    return bool(version), version or None


def _probe_loopback_port(
    host: str, port: int, expected_state: PortExpectation
) -> tuple[bool, str | None]:
    """Check whether the loopback port is ready for launch or audit replay."""
    if expected_state == "listening":
        try:
            with socket.create_connection((host, port), timeout=1):
                return True, None
        except OSError as exc:
            return (
                False,
                f"configured loopback port is not listening: {exc.strerror or exc.__class__.__name__}",
            )

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            probe.bind((host, port))
    except OSError as exc:
        return (
            False,
            f"configured loopback port is unavailable: {exc.strerror or exc.__class__.__name__}",
        )
    return True, None


class WorkerRuntimePreflightRunner:
    """Run local-only queue, checkout, static readiness, Docker, and port checks."""

    def __init__(
        self,
        repository_root: Path,
        *,
        queue_path: Path | None = None,
        source_lock_path: Path | None = None,
        docker_info: DockerInfo = _docker_info,
        port_probe: PortProbe = _probe_loopback_port,
    ) -> None:
        self.repository_root = repository_root.resolve()
        self.queue_path = (
            queue_path
            or self.repository_root / "targets" / "runtime_batches" / "gpu_3way.yaml"
        )
        self.source_lock_path = (
            source_lock_path or self.repository_root / "targets" / "source-lock.yaml"
        )
        self._docker_info = docker_info
        self._port_probe = port_probe

        self.catalog = TargetCatalog(
            manifest_root=self.repository_root / "targets" / "manifests",
            repository_root=self.repository_root,
        )
        self.catalog.load()
        self.queue = load_runtime_batch_queue(
            self.queue_path,
            allowed_target_ids=set(self._policy_target_ids()),
        )
        self.source_lock = SourceLock.load(self.source_lock_path)
        self.sources = TargetSourceBootstrapper(self.repository_root, self.source_lock)

    def _policy_target_ids(self) -> tuple[str, ...]:
        """Use the repository policy as the queue's authoritative allowlist."""
        # Import lazily because the policy module's default path is anchored to
        # this repository, while tests provide an isolated repository root.
        import yaml

        scope = self.repository_root / "policies" / "scope.yaml"
        document = yaml.safe_load(scope.read_text(encoding="utf-8")) or {}
        targets = document.get("targets") if isinstance(document, dict) else None
        if not isinstance(targets, dict):
            raise ValueError("policy scope must declare a targets mapping")
        return tuple(targets)

    def run(
        self,
        worker_id: str,
        *,
        target_ids: Sequence[str] | None = None,
        expected_port_state: PortExpectation = "listening",
    ) -> WorkerRuntimePreflight:
        if expected_port_state not in {"available", "listening"}:
            raise ValueError("expected_port_state must be available or listening")
        assigned = self.queue.targets_for(
            worker_id
        )  # validates worker ID before any local probes
        requested = tuple(assigned if target_ids is None else target_ids)
        if not requested:
            raise ValueError("at least one target must be selected for preflight")
        for target_id in requested:
            self.queue.require_assignment(worker_id, target_id)

        docker_available, docker_version = self._docker_info()
        reports = tuple(
            self._target_report(
                target_id,
                docker_available,
                docker_version,
                expected_port_state,
            )
            for target_id in requested
        )
        return WorkerRuntimePreflight(worker_id=worker_id, targets=reports)

    def _target_report(
        self,
        target_id: str,
        docker_available: bool,
        docker_version: str | None,
        expected_port_state: PortExpectation,
    ) -> WorkerTargetPreflight:
        registered = self.catalog.get(target_id)
        source = self.sources.inspect(target_id)
        readiness = self.catalog.readiness_for(target_id)
        parsed = urlparse(registered.manifest.base_url)
        assert (
            parsed.hostname is not None and parsed.port is not None
        )  # manifest validation guarantees both
        port_ready, port_reason = self._port_probe(
            parsed.hostname, parsed.port, expected_port_state
        )

        issues: list[str] = []
        if not source.ready:
            issues.append(f"source: {source.status}")
        if not readiness.ready:
            issues.extend(f"readiness: {issue}" for issue in readiness.issues)
        if not docker_available:
            issues.append("Docker daemon is unavailable")
        if not port_ready:
            issues.append(port_reason or "configured loopback port is unavailable")
        return WorkerTargetPreflight(
            target_id=target_id,
            assigned=True,
            source=source,
            readiness=readiness,
            docker_available=docker_available,
            docker_version=docker_version,
            expected_port_state=expected_port_state,
            port_ready=port_ready,
            port_reason=port_reason,
            issues=tuple(issues),
        )


def _json_default(value: object) -> object:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    raise TypeError(f"cannot serialize {type(value).__name__}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run local GPU worker runtime preflight; never dispatch remotely."
    )
    parser.add_argument("--worker-id", required=True)
    parser.add_argument("--target-id", action="append", dest="target_ids")
    parser.add_argument(
        "--expect-port-state",
        choices=("available", "listening"),
        default="listening",
        help="Use listening before an audit replay; use available before lifecycle start.",
    )
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)

    report = WorkerRuntimePreflightRunner(args.repository_root).run(
        args.worker_id,
        target_ids=args.target_ids,
        expected_port_state=args.expect_port_state,
    )
    print(
        json.dumps(
            asdict(report), default=_json_default, ensure_ascii=False, sort_keys=True
        )
    )
    return 0 if report.ready else 1


if __name__ == "__main__":  # pragma: no cover - exercised through main() tests
    sys.exit(main())
