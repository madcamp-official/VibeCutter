"""P2 bridge from a trusted manifest to P1's immutable Target contract."""

from __future__ import annotations

import hashlib
from pathlib import Path

from contracts.schemas import Target

from .manifest import TargetManifest, load_manifest


def manifest_sha256(path: Path) -> str:
    """Return the SHA-256 of the exact YAML file used to register a target."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def to_contract_target(
    manifest: TargetManifest,
    *,
    manifest_hash: str,
    source_commit: str | None = None,
) -> Target:
    """Create P1's Target model without redefining or modifying its schema."""
    return Target(
        id=manifest.id,
        manifest_hash=manifest_hash,
        source_commit=source_commit,
        adapter=manifest.adapter.value,
        allowed_hosts=[manifest.allowed_host],
    )


def load_contract_target(path: Path, *, source_commit: str | None = None) -> Target:
    """Load, hash, and convert one checked-in manifest for P1 registration."""
    return to_contract_target(
        load_manifest(path), manifest_hash=manifest_sha256(path), source_commit=source_commit
    )
