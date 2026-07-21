"""User-owned approval registry for local target projects.

The checked-in demo catalog remains available, but a user's own project must not
require a pull request to this repository.  ``LocalRegistry`` stores only the
user-approved target identity and immutable command/manifest hashes under
``~/.vibecutter/registry``.  It deliberately does not decide whether approval
is appropriate; the MCP/P1 layer owns the human confirmation step.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from typing import Literal, Optional
from urllib.parse import urlparse

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
    """Read/write user-approved targets outside the repository evidence store."""

    DEFAULT_ROOT = Path.home() / ".vibecutter" / "registry"

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()

    @classmethod
    def load(cls, root: Optional[Path] = None) -> "LocalRegistry":
        """Create a registry handle without creating files until approval."""
        return cls(root or cls.DEFAULT_ROOT)

    def get(self, target_id: str) -> Optional[ApprovedTarget]:
        path = self._path_for(target_id)
        if not path.is_file():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            return self._from_json(payload)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise ValueError(f"invalid local target registry entry: {path}") from exc

    def list_ids(self) -> tuple[str, ...]:
        if not self.root.is_dir():
            return ()
        ids: list[str] = []
        for path in self.root.glob("*.json"):
            if path.is_file():
                ids.append(path.stem)
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
            allowed_hosts=[manifest.allowed_host],
            source_path=source,
            manifest_sha256=manifest_content_sha256(manifest),
            commands_sha256=commands_sha256(manifest),
            approved_at=datetime.utcnow(),
        )
        self.root.mkdir(parents=True, exist_ok=True)
        destination = self._path_for(manifest.id)
        payload = json.dumps(_to_json(approved), ensure_ascii=False, indent=2, sort_keys=True)
        # Replace atomically so a concurrent MCP read never sees partial JSON.
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=self.root, prefix=f".{manifest.id}-", delete=False
        ) as handle:
            handle.write(payload)
            temporary = Path(handle.name)
        temporary.replace(destination)
        return approved

    def revoke(self, target_id: str) -> None:
        self._path_for(target_id).unlink(missing_ok=True)

    def _path_for(self, target_id: str) -> Path:
        if not target_id or any(ch not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for ch in target_id):
            raise ValueError("target_id must be a lowercase local registry slug")
        path = (self.root / f"{target_id}.json").resolve()
        if path.parent != self.root:
            raise ValueError("local registry path escapes registry root")
        return path

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
