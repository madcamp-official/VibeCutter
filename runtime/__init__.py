"""P2 runtime primitives: trusted manifests, lifecycle, worktrees, and tests."""

from .catalog import RegisteredRuntimeTarget, TargetCatalog
from .lifecycle import ApprovalRequired, LifecycleManager
from .manifest import TargetManifest, load_manifest
from .registration import load_contract_target, manifest_sha256, to_contract_target

__all__ = [
    "ApprovalRequired",
    "LifecycleManager",
    "RegisteredRuntimeTarget",
    "TargetManifest",
    "TargetCatalog",
    "load_manifest",
    "load_contract_target",
    "manifest_sha256",
    "to_contract_target",
]
