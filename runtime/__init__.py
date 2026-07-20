"""P2 runtime primitives: trusted manifests, lifecycle, worktrees, and tests."""

from .catalog import RegisteredRuntimeTarget, TargetCatalog
from .batch_queue import RuntimeBatchQueue, load_runtime_batch_queue
from .compose_isolation import ComposeIsolationInspector, ComposeIsolationReport
from .lifecycle import ApprovalRequired, LifecycleManager
from .manifest import TargetManifest, load_manifest
from .provisioning import ProvisioningStrategy, VerifierProvisioning
from .readiness import TargetReadiness, TargetRuntimeInspector
from .registration import load_contract_target, manifest_sha256, to_contract_target
from .source_bootstrap import (
    SourceBootstrapError,
    SourceCheck,
    TargetSourceBootstrapper,
)
from .source_lock import SourceLock, SourceRevision
from .test_runner import RunScopedTestRunner, TestRunSummary
from .target_service import (
    BaselineRestoreResult,
    TargetOperationError,
    TargetRuntimeService,
)

__all__ = [
    "ApprovalRequired",
    "RuntimeBatchQueue",
    "BaselineRestoreResult",
    "ComposeIsolationInspector",
    "ComposeIsolationReport",
    "LifecycleManager",
    "RegisteredRuntimeTarget",
    "TargetManifest",
    "TargetCatalog",
    "load_manifest",
    "load_runtime_batch_queue",
    "load_contract_target",
    "manifest_sha256",
    "to_contract_target",
    "TargetReadiness",
    "ProvisioningStrategy",
    "VerifierProvisioning",
    "TargetRuntimeInspector",
    "RunScopedTestRunner",
    "SourceBootstrapError",
    "SourceCheck",
    "SourceLock",
    "SourceRevision",
    "TargetSourceBootstrapper",
    "TestRunSummary",
    "TargetOperationError",
    "TargetRuntimeService",
]
