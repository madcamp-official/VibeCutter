"""Adapter registry.  Stack adapters share the safe manifest command runner."""

from __future__ import annotations

from .command_adapter import ManifestCommandAdapter
from runtime.lifecycle import LifecycleManager
from runtime.manifest import AdapterKind


def adapter_for(kind: AdapterKind, lifecycle: LifecycleManager) -> ManifestCommandAdapter:
    """Return a lifecycle adapter for a supported target stack.

    The manifest controls fixed commands; this registry is intentionally small
    until a stack requires a genuine implementation difference.
    """
    if kind not in {AdapterKind.SPRING_BOOT, AdapterKind.FASTAPI, AdapterKind.NODE, AdapterKind.GENERIC_DOCKER}:
        raise ValueError(f"unsupported adapter: {kind}")
    return ManifestCommandAdapter(lifecycle)
