"""Static Docker Compose isolation checks used before target execution."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from .manifest import DockerIsolationSpec, TargetManifest


class ComposeIsolationReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["compliant", "non_compliant", "not_configured", "missing_file", "invalid_compose"]
    compose_file: str | None = None
    issues: list[str] = Field(default_factory=list)

    @property
    def compliant(self) -> bool:
        return self.status == "compliant"


class ComposeIsolationInspector:
    """Reads only a checked-in compose file; it never starts Docker or a container."""

    def __init__(
        self,
        manifest: TargetManifest,
        repository_root: Path,
        *,
        compose_path: Path | None = None,
    ) -> None:
        self.manifest = manifest
        self.repository_root = repository_root.resolve()
        self.compose_path = compose_path.resolve() if compose_path is not None else None

    def inspect(self) -> ComposeIsolationReport:
        spec = self.manifest.docker_isolation
        if spec is None:
            return ComposeIsolationReport(status="not_configured")
        compose_path = self.compose_path or _resolve_within_root(self.repository_root, spec.compose_file)
        if compose_path != self.repository_root and self.repository_root not in compose_path.parents:
            raise ValueError("compose file escapes repository root")
        if not compose_path.is_file():
            return ComposeIsolationReport(status="missing_file", compose_file=str(compose_path))
        try:
            document = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            return ComposeIsolationReport(status="invalid_compose", compose_file=str(compose_path), issues=[str(exc)])
        if not isinstance(document, dict):
            return ComposeIsolationReport(
                status="invalid_compose", compose_file=str(compose_path), issues=["compose document must be a mapping"]
            )
        issues = _inspect_document(document, spec)
        return ComposeIsolationReport(
            status="compliant" if not issues else "non_compliant",
            compose_file=str(compose_path),
            issues=issues,
        )


def _inspect_document(document: dict, spec: DockerIsolationSpec) -> list[str]:
    issues: list[str] = []
    networks = document.get("networks")
    network = networks.get(spec.internal_network) if isinstance(networks, dict) else None
    if not isinstance(network, dict) or not _blocks_egress(network):
        issues.append(
            f"network {spec.internal_network!r} must declare internal: true "
            "or disable bridge NAT masquerading"
        )

    services = document.get("services")
    if not isinstance(services, dict) or not services:
        return [*issues, "compose file must declare at least one service"]
    for service_name, service in services.items():
        if not isinstance(service, dict):
            issues.append(f"service {service_name!r} must be a mapping")
            continue
        if service.get("privileged") is True:
            issues.append(f"service {service_name!r} must not set privileged: true")
        if "network_mode" in service:
            issues.append(f"service {service_name!r} must not use network_mode")
        if not _uses_network(service.get("networks"), spec.internal_network):
            issues.append(f"service {service_name!r} must join internal network {spec.internal_network!r}")
        if spec.require_loopback_port_bindings:
            for port in service.get("ports") or []:
                if not _is_loopback_port_binding(port):
                    issues.append(f"service {service_name!r} exposes a non-loopback port binding: {port!r}")
    return issues


def _uses_network(value: object, expected_network: str) -> bool:
    if isinstance(value, list):
        return expected_network in value
    if isinstance(value, dict):
        return expected_network in value
    return False


def _blocks_egress(network: dict) -> bool:
    """Accept Docker's two local-network modes that block container egress.

    A Compose ``internal: true`` bridge prevents egress, but Docker Desktop
    also prevents host loopback ingress to published service ports on that
    bridge.  For targets that P3 must reach through a loopback base URL, a
    bridge with NAT masquerading disabled preserves host ingress while packets
    cannot be source-NATed onto external networks.
    """

    if network.get("internal") is True:
        return True
    if network.get("driver", "bridge") != "bridge":
        return False
    options = network.get("driver_opts")
    if not isinstance(options, dict):
        return False
    return options.get("com.docker.network.bridge.enable_ip_masquerade") in {False, "false", "False", "0"}


def _is_loopback_port_binding(port: object) -> bool:
    if isinstance(port, str):
        return port.startswith("127.0.0.1:") or port.startswith("[::1]:")
    if isinstance(port, dict):
        return port.get("host_ip") in {"127.0.0.1", "::1"}
    return False


def _resolve_within_root(root: Path, relative_path: str) -> Path:
    resolved = (root / relative_path).resolve()
    if resolved != root and root not in resolved.parents:
        raise ValueError("compose file escapes repository root")
    return resolved
