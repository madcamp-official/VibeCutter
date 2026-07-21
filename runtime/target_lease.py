"""Per-target lifecycle lease for fixed-port runtimes.

Only one run may mutate a target runtime at a time. The lease is deliberately
kept outside the evidence database so a stale process cannot leave a half-written
transaction behind. Orchestration owns when to acquire/release it; this module
only provides the atomic ownership primitive.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import tempfile
from typing import Optional


class TargetBusyError(RuntimeError):
    """Raised when a target lease is unavailable to the requesting run."""


# Compatibility alias for callers written against the initial P2 primitive.
TargetLeaseError = TargetBusyError


@dataclass(frozen=True)
class TargetLease:
    target_id: str
    run_id: str
    acquired_at: datetime
    expires_at: datetime


class TargetLeaseManager:
    """Acquire/release one lease per target using atomic directory creation."""

    DEFAULT_ROOT = Path.home() / ".vibecutter" / "leases"

    def __init__(self, root: Path | None = None) -> None:
        self.root = (root or self.DEFAULT_ROOT).expanduser().resolve()

    def acquire(
        self, target_id: str, run_id: str, *, ttl_seconds: float = 900.0
    ) -> TargetLease:
        _validate_slug(target_id, "target_id")
        _validate_slug(run_id, "run_id")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")

        self.root.mkdir(parents=True, exist_ok=True)
        lease_dir = self._path_for(target_id)
        now = datetime.now(timezone.utc)
        lease = TargetLease(
            target_id=target_id,
            run_id=run_id,
            acquired_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )

        try:
            lease_dir.mkdir()
        except FileExistsError:
            existing = self._read(lease_dir)
            if existing is not None and existing.expires_at > now:
                raise TargetBusyError(
                    f"target {target_id!r} is leased by run {existing.run_id!r} "
                    f"until {existing.expires_at.isoformat()}"
                )
            # The lease is stale. It is safe to remove only this controlled
            # lease directory, then retry acquisition once.
            if lease_dir.is_dir():
                shutil.rmtree(lease_dir)
            lease_dir.mkdir()

        _atomic_write_json(lease_dir / "lease.json", _lease_payload(lease))
        return lease

    def get(self, target_id: str) -> Optional[TargetLease]:
        _validate_slug(target_id, "target_id")
        lease = self._read(self._path_for(target_id))
        if lease is None:
            return None
        if lease.expires_at <= datetime.now(timezone.utc):
            return None
        return lease

    def release(self, target_id: str, run_id: str) -> bool:
        """Release only the lease owned by ``run_id``; return whether removed."""
        _validate_slug(target_id, "target_id")
        _validate_slug(run_id, "run_id")
        lease_dir = self._path_for(target_id)
        current = self._read(lease_dir)
        if current is None:
            return False
        if current.run_id != run_id:
            raise TargetBusyError(
                f"target {target_id!r} is owned by run {current.run_id!r}, not {run_id!r}"
            )
        shutil.rmtree(lease_dir)
        return True

    def renew(
        self, target_id: str, run_id: str, *, ttl_seconds: float = 900.0
    ) -> TargetLease:
        """Extend an active lease owned by ``run_id`` and return its new value."""
        _validate_slug(target_id, "target_id")
        _validate_slug(run_id, "run_id")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        lease_dir = self._path_for(target_id)
        current = self._read(lease_dir)
        now = datetime.now(timezone.utc)
        if current is None or current.expires_at <= now:
            raise TargetBusyError(f"target {target_id!r} has no active lease to renew")
        if current.run_id != run_id:
            raise TargetBusyError(
                f"target {target_id!r} is owned by run {current.run_id!r}, not {run_id!r}"
            )
        renewed = TargetLease(
            target_id=current.target_id,
            run_id=current.run_id,
            acquired_at=current.acquired_at,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
        _atomic_write_json(lease_dir / "lease.json", _lease_payload(renewed))
        return renewed

    def reap_stale(self, target_id: str) -> bool:
        """Remove one expired lease and report whether anything was removed."""
        _validate_slug(target_id, "target_id")
        lease_dir = self._path_for(target_id)
        current = self._read(lease_dir)
        if current is None or current.expires_at > datetime.now(timezone.utc):
            return False
        shutil.rmtree(lease_dir)
        return True

    def _path_for(self, target_id: str) -> Path:
        path = (self.root / target_id).resolve()
        if path.parent != self.root:
            raise ValueError("target lease path escapes lease root")
        return path

    @staticmethod
    def _read(lease_dir: Path) -> TargetLease | None:
        path = lease_dir / "lease.json"
        if not path.is_file():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            return TargetLease(
                target_id=str(payload["target_id"]),
                run_id=str(payload["run_id"]),
                acquired_at=datetime.fromisoformat(payload["acquired_at"]),
                expires_at=datetime.fromisoformat(payload["expires_at"]),
            )
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise TargetBusyError(f"invalid lease artifact: {path}") from exc


def _validate_slug(value: str, label: str) -> None:
    if not value or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for ch in value):
        raise ValueError(f"{label} must be a simple lease slug")


def _lease_payload(lease: TargetLease) -> dict[str, str]:
    return {
        "target_id": lease.target_id,
        "run_id": lease.run_id,
        "acquired_at": lease.acquired_at.isoformat(),
        "expires_at": lease.expires_at.isoformat(),
    }


def _atomic_write_json(path: Path, payload: dict[str, str]) -> None:
    content = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}-", delete=False
    ) as handle:
        handle.write(content)
        temporary = Path(handle.name)
    temporary.replace(path)
