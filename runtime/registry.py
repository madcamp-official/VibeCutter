"""User-owned approval registry for local target projects.

The checked-in demo catalog remains available, but a user's own project must not
require a pull request to this repository.  ``LocalRegistry`` stores the
user-approved target identity, immutable command/manifest hashes, and an
approval-time manifest snapshot under ``~/.vibecutter/registry``. It deliberately does not decide whether approval
is appropriate; the MCP/P1 layer owns the human confirmation step.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import shutil
import tempfile
from typing import Literal, Optional
from urllib.parse import urlparse

import yaml

from .manifest import TargetManifest


TargetKind = Literal["compose_project", "running_local"]


@dataclass(frozen=True)
class ApprovedTarget:
    target_id: str
    kind: TargetKind
    base_url: str
    allowed_hosts: list[str]
    source_path: Path
    manifest_sha256: str
    commands_sha256: str
    approved_at: datetime


class LocalRegistry:
    """Read/write user-approved targets outside the repository evidence store.

    New approvals use a per-target directory containing an immutable manifest
    snapshot and approval metadata. Legacy JSON entries remain readable so an
    upgrade does not silently lose a user's registration.
    """

    DEFAULT_ROOT = Path.home() / ".vibecutter" / "registry"

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()

    @classmethod
    def load(cls, root: Optional[Path] = None) -> "LocalRegistry":
        """Create a registry handle without creating files until approval."""
        return cls(root or cls.DEFAULT_ROOT)

    def get(self, target_id: str) -> Optional[ApprovedTarget]:
        path = self._approval_path_for(target_id)
        legacy_path = self._legacy_path_for(target_id)
        if not path.is_file() and not legacy_path.is_file():
            return None
        try:
            if path.is_file():
                payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            else:
                payload = json.loads(legacy_path.read_text(encoding="utf-8"))
            return self._from_json(payload)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            current = path if path.is_file() else legacy_path
            raise ValueError(f"invalid local target registry entry: {current}") from exc

    def manifest_for(self, target_id: str) -> TargetManifest:
        """Load the immutable manifest captured at approval time.

        This additive helper keeps the frozen ``ApprovedTarget`` policy projection
        small. Runtime/catalog consumers must use this snapshot instead of
        re-reading a mutable user manifest file.
        """
        path = self._target_dir_for(target_id) / "manifest.yaml"
        if not path.is_file():
            raise ValueError(
                f"target {target_id!r} has no approval-time manifest snapshot; re-approval required"
            )
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            return TargetManifest.model_validate(payload)
        except (OSError, ValueError, TypeError) as exc:
            raise ValueError(f"invalid manifest snapshot for target {target_id!r}") from exc

    def list_ids(self) -> tuple[str, ...]:
        if not self.root.is_dir():
            return ()
        ids: set[str] = set()
        for path in self.root.iterdir():
            if path.is_dir() and (path / "approval.yaml").is_file():
                ids.add(path.name)
            elif path.is_file() and path.suffix == ".json":
                ids.add(path.stem)
        return tuple(sorted(ids))

    def approve(self, manifest: TargetManifest, *, source_path: Path) -> ApprovedTarget:
        """Persist a target after schema, source, and loopback checks.

        This method records an already-confirmed approval; it never infers user
        intent.  The source must be an existing Git repository because patch
        application and regression gates use detached worktrees.
        """
        if not isinstance(manifest, TargetManifest):
            manifest = TargetManifest.model_validate(manifest)
        source = source_path.expanduser().resolve()
        self._require_git_repository(source)

        parsed = urlparse(manifest.base_url)
        if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("approved target base_url must be loopback")
        if parsed.port is None:
            raise ValueError("approved target base_url must include an explicit port")

        # A dirty source is usable for registration, but worktrees are based on
        # the current commit.  Keep the warning visible to the approving caller.
        if self._git(source, ["status", "--porcelain"]).stdout.strip():
            import warnings

            warnings.warn(
                "target source has uncommitted changes; commit them before auditing",
                UserWarning,
                stacklevel=2,
            )

        approved = ApprovedTarget(
            target_id=manifest.id,
            kind=manifest.kind,
            base_url=manifest.base_url,
            # Policy compares hostnames. The explicit port remains part of the
            # approved base_url and is never inferred from a tool-supplied URL.
            allowed_hosts=[parsed.hostname or ""],
            source_path=source,
            manifest_sha256=manifest_content_sha256(manifest),
            commands_sha256=commands_sha256(manifest),
            approved_at=datetime.utcnow(),
        )
        self.root.mkdir(parents=True, exist_ok=True)
        target_dir = self._target_dir_for(manifest.id)
        target_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write_yaml(target_dir / "manifest.yaml", manifest.model_dump(mode="json"))
        _atomic_write_yaml(target_dir / "approval.yaml", _to_json(approved))
        # Remove a pre-snapshot entry only after the new snapshot is complete.
        self._legacy_path_for(manifest.id).unlink(missing_ok=True)
        return approved

    def revoke(self, target_id: str) -> None:
        target_dir = self._target_dir_for(target_id)
        if target_dir.is_dir():
            shutil.rmtree(target_dir)
        self._legacy_path_for(target_id).unlink(missing_ok=True)

    def _target_dir_for(self, target_id: str) -> Path:
        if not target_id or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for ch in target_id):
            raise ValueError("target_id must be a lowercase local registry slug")
        path = (self.root / target_id).resolve()
        if path.parent != self.root:
            raise ValueError("local registry path escapes registry root")
        return path

    def _approval_path_for(self, target_id: str) -> Path:
        return self._target_dir_for(target_id) / "approval.yaml"

    def _legacy_path_for(self, target_id: str) -> Path:
        if not target_id or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for ch in target_id):
            raise ValueError("target_id must be a lowercase local registry slug")
        return (self.root / f"{target_id}.json").resolve()

    @staticmethod
    def _require_git_repository(source: Path) -> None:
        if not source.is_dir():
            raise ValueError(f"target source directory does not exist: {source}")
        result = LocalRegistry._git(source, ["rev-parse", "--show-toplevel"])
        if result.returncode != 0 or Path(result.stdout.strip()).resolve() != source:
            raise ValueError(
                f"target source must be a Git repository root: {source}; "
                "run git init and commit the baseline before registering"
            )

    @staticmethod
    def _git(source: Path, args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(source), *args],
            capture_output=True,
            check=False,
            shell=False,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

    @staticmethod
    def _from_json(payload: dict) -> ApprovedTarget:
        return ApprovedTarget(
            target_id=str(payload["target_id"]),
            kind=payload["kind"],
            base_url=str(payload["base_url"]),
            allowed_hosts=list(payload["allowed_hosts"]),
            source_path=Path(payload["source_path"]).expanduser().resolve(),
            manifest_sha256=str(payload["manifest_sha256"]),
            commands_sha256=str(payload["commands_sha256"]),
            approved_at=datetime.fromisoformat(payload["approved_at"]),
        )


def _to_json(target: ApprovedTarget) -> dict:
    payload = asdict(target)
    payload["source_path"] = str(target.source_path)
    payload["approved_at"] = target.approved_at.isoformat()
    return payload


def _atomic_write_yaml(path: Path, payload: dict) -> None:
    """Write one registry artifact without exposing a partial file to readers."""
    content = yaml.safe_dump(payload, allow_unicode=True, sort_keys=False)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}-", delete=False
    ) as handle:
        handle.write(content)
        temporary = Path(handle.name)
    temporary.replace(path)


def _canonical_manifest(manifest: TargetManifest) -> bytes:
    return json.dumps(
        manifest.model_dump(mode="json"), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def manifest_content_sha256(manifest: TargetManifest) -> str:
    return hashlib.sha256(_canonical_manifest(manifest)).hexdigest()


def commands_sha256(manifest: TargetManifest) -> str:
    commands = {
        name: spec.model_dump(mode="json")
        for name, spec in sorted(manifest.commands.items())
    }
    canonical = json.dumps(commands, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
