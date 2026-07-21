"""Secret-free per-run runtime metadata for evaluation and audit joins."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from core.db import DATA_DIR


DEFAULT_RUNTIME_METADATA_PATH = DATA_DIR / "runtime_metadata.jsonl"
_SLUG = re.compile(r"^[A-Za-z0-9_-]+$")


class RuntimeMetadata(BaseModel):
    """One public, secret-free runtime observation keyed by ``run_id``."""

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=1, ge=1)
    run_id: str
    target_id: str
    source_commit: str | None = None
    base_url: str
    health: bool
    readiness: bool
    gpu_worker: str | None = None
    llm_endpoint_state: str = "unknown"
    reset_result: bool | None = None
    remaining_containers: list[str] = Field(default_factory=list)
    remaining_worktrees: list[str] = Field(default_factory=list)
    remaining_ports: list[int] = Field(default_factory=list)
    lease_run_id: str | None = None
    lease_expires_at: datetime | None = None
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def model_post_init(self, __context: Any) -> None:
        for name in ("run_id", "target_id"):
            value = getattr(self, name)
            if not _SLUG.fullmatch(value):
                raise ValueError(f"{name} must be a simple runtime slug")
        if "?" in self.base_url or "#" in self.base_url:
            raise ValueError("base_url must not contain query or fragment secrets")


def append_runtime_metadata(
    metadata: RuntimeMetadata,
    output_path: Path | str | None = None,
) -> Path:
    """Append one JSONL record without exposing credentials or raw logs."""

    path = Path(output_path) if output_path is not None else DEFAULT_RUNTIME_METADATA_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(metadata.model_dump(mode="json"), ensure_ascii=False, sort_keys=True))
        handle.write("\n")
    return path


def load_runtime_metadata(path: Path | str | None = None) -> list[RuntimeMetadata]:
    """Load metadata records for P4/report joins; blank lines are ignored."""

    source = Path(path) if path is not None else DEFAULT_RUNTIME_METADATA_PATH
    if not source.exists():
        return []
    return [
        RuntimeMetadata.model_validate(json.loads(line))
        for line in source.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
