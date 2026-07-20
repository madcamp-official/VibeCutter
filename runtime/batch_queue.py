"""Trusted P2 queue definitions for distributing local target runtimes.

The queue only assigns checked-in target IDs to named workers.  It contains no
host address, URL, shell command, or credential: every actual lifecycle action
continues to be resolved through the target manifest and policy layer.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class RuntimeBatchQueue:
    """Validated target assignment for a fixed set of batch workers."""

    workers: dict[str, tuple[str, ...]]

    def targets_for(self, worker_id: str) -> tuple[str, ...]:
        try:
            return self.workers[worker_id]
        except KeyError as exc:
            raise KeyError(
                f"worker is not registered in runtime batch queue: {worker_id}"
            ) from exc

    def require_assignment(self, worker_id: str, target_id: str) -> None:
        """Reject a local worker attempting to operate another worker's target.

        The queue is placement metadata only.  This method deliberately makes
        no network call and accepts no host address: it is a guard for code
        already running on a named local GPU worker.
        """
        if target_id not in self.targets_for(worker_id):
            raise PermissionError(
                f"target {target_id!r} is not assigned to runtime batch worker {worker_id!r}"
            )

    @property
    def target_ids(self) -> tuple[str, ...]:
        return tuple(
            target_id for targets in self.workers.values() for target_id in targets
        )


def load_runtime_batch_queue(
    path: Path, *, allowed_target_ids: set[str]
) -> RuntimeBatchQueue:
    """Load a repository-controlled queue and reject incomplete/unsafe mappings."""
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("queue_version") != 1:
        raise ValueError("runtime batch queue must declare queue_version: 1")
    workers = document.get("workers")
    if not isinstance(workers, dict) or not workers:
        raise ValueError("runtime batch queue must declare at least one worker")

    normalized: dict[str, tuple[str, ...]] = {}
    assigned: list[str] = []
    for worker_id, value in workers.items():
        if not isinstance(worker_id, str) or not worker_id:
            raise ValueError("runtime batch worker IDs must be non-empty strings")
        if not isinstance(value, dict) or not isinstance(value.get("targets"), list):
            raise ValueError(
                f"runtime batch worker {worker_id!r} must declare a target list"
            )
        targets = tuple(value["targets"])
        if not targets or any(
            not isinstance(target_id, str) or not target_id for target_id in targets
        ):
            raise ValueError(
                f"runtime batch worker {worker_id!r} has an invalid target ID"
            )
        normalized[worker_id] = targets
        assigned.extend(targets)

    assigned_set = set(assigned)
    if len(assigned_set) != len(assigned):
        raise ValueError("a target may appear in only one runtime batch worker")
    if assigned_set != allowed_target_ids:
        missing = sorted(allowed_target_ids - assigned_set)
        unknown = sorted(assigned_set - allowed_target_ids)
        raise ValueError(
            f"runtime batch queue must cover allowlisted targets exactly; missing={missing}, unknown={unknown}"
        )
    return RuntimeBatchQueue(workers=normalized)
