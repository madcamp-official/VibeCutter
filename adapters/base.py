"""Stable P2 adapter interface consumed by lifecycle tools."""

from __future__ import annotations

from typing import Protocol

from runtime.lifecycle import CommandResult, HealthResult


class TargetAdapter(Protocol):
    """Expose only manifest-defined target operations."""

    def build(self) -> CommandResult: ...

    def start(self) -> CommandResult: ...

    def stop(self) -> CommandResult: ...

    def health(self) -> HealthResult: ...

    def reset(self, *, approved: bool) -> CommandResult: ...

    def test(self) -> list[CommandResult]: ...
