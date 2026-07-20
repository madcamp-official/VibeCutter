"""Checked-in source identity contract for P2-managed target clones."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

import yaml


_TARGET_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY_PREFIX = "https://github.com/madcamp-official/"


@dataclass(frozen=True)
class SourceRevision:
    target_id: str
    repository: str
    revision: str


class SourceLock:
    """Validated target ID -> canonical repository/exact commit mapping."""

    def __init__(self, entries: dict[str, SourceRevision]) -> None:
        self._entries = dict(entries)

    @classmethod
    def load(
        cls,
        path: Path,
        *,
        expected_target_ids: set[str] | None = None,
    ) -> "SourceLock":
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict) or set(document) != {
            "lock_version",
            "targets",
        }:
            raise ValueError("source lock must contain only lock_version and targets")
        if document.get("lock_version") != 1:
            raise ValueError("source lock must declare lock_version: 1")
        targets = document.get("targets")
        if not isinstance(targets, dict) or not targets:
            raise ValueError("source lock must declare at least one target")

        entries: dict[str, SourceRevision] = {}
        for target_id, value in targets.items():
            if not isinstance(target_id, str) or not _TARGET_ID.fullmatch(target_id):
                raise ValueError(f"invalid source lock target ID: {target_id!r}")
            if not isinstance(value, dict) or set(value) != {"repository", "revision"}:
                raise ValueError(
                    f"source lock entry {target_id!r} must contain only repository and revision"
                )
            repository = value.get("repository")
            revision = value.get("revision")
            expected_repository = f"{_REPOSITORY_PREFIX}{target_id}.git"
            if repository != expected_repository:
                raise ValueError(
                    f"source lock repository for {target_id} must be {expected_repository!r}"
                )
            if not isinstance(revision, str) or not _REVISION.fullmatch(revision):
                raise ValueError(
                    f"source lock revision for {target_id} must be 40 lowercase hex"
                )
            entries[target_id] = SourceRevision(
                target_id=target_id,
                repository=repository,
                revision=revision,
            )

        if expected_target_ids is not None and set(entries) != expected_target_ids:
            missing = sorted(expected_target_ids - set(entries))
            extra = sorted(set(entries) - expected_target_ids)
            raise ValueError(
                f"source lock must cover target manifests exactly; missing={missing}, extra={extra}"
            )
        return cls(entries)

    def get(self, target_id: str) -> SourceRevision:
        try:
            return self._entries[target_id]
        except KeyError as exc:
            raise KeyError(
                f"target_id is not registered in source lock: {target_id}"
            ) from exc

    @property
    def target_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._entries))
