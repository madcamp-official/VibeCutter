"""Adapter implementation shared by Spring, FastAPI, and Node targets.

Stack differences belong in a trusted target manifest.  This adapter never
accepts a raw command or URL from an MCP caller.
"""

from __future__ import annotations

from runtime.lifecycle import CommandResult, HealthResult, LifecycleManager


class ManifestCommandAdapter:
    def __init__(self, lifecycle: LifecycleManager) -> None:
        self._lifecycle = lifecycle

    def build(self) -> CommandResult:
        return self._lifecycle.execute("build")

    def start(self) -> CommandResult:
        return self._lifecycle.execute("start")

    def stop(self) -> CommandResult:
        return self._lifecycle.execute("stop")

    def health(self) -> HealthResult:
        return self._lifecycle.check_health()

    def reset(self, *, approved: bool) -> CommandResult:
        return self._lifecycle.reset(approved=approved)

    def test(self) -> list[CommandResult]:
        return self._lifecycle.run_test_suites()
