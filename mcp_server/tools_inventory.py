"""Inventory + Lifecycle 카테고리 MCP tools (기획서 11.2절 repo 구조 기준 3-file 그룹핑).

vc_register_target, vc_inspect_stack, vc_check_readiness (Inventory)
vc_build_target, vc_start_target, vc_reset_target (Lifecycle)

Lifecycle 도구의 실제 빌드/실행/reset 로직은 P2(target manifest/adapter) 소유다.
여기서는 부록 A 방식으로 스키마만 고정하고 본문은 NotImplementedError로 남겨둔다.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from contracts.schemas import Run, Target
from core.audit_log import audited
from runtime.target_service import TargetRuntimeService
from runtime.provisioning import VerifierProvisioning


class StackInfo(BaseModel):
    target_id: str
    stack: list[str] = Field(default_factory=list)
    detected_by: str


class ReadinessResult(BaseModel):
    target_id: str
    ready: bool
    reasons: list[str] = Field(default_factory=list)


class RuntimeHandleInfo(BaseModel):
    target_id: str
    base_url: str | None = None
    healthy: bool = False


class ResetResult(BaseModel):
    target_id: str
    ok: bool


class FixturePreparationResult(BaseModel):
    target_id: str
    fixture_available: bool
    fixture_path: str | None = None


class RegistrationPreview(BaseModel):
    """사용자에게 보여줄 등록 미리보기. **승인 전에는 아무것도 저장되지 않는다.**

    `commands`는 **요약하지 않고 argv 전문**을 담는다 — 이 표시가 기존 "우리 저장소에
    커밋되고 PR로 리뷰됐다"를 대체하는 승인 근거이기 때문이다(TEAM_CONTRACT 안전 불변식 2).
    등록을 승인한다는 것은 곧 **이 명령들이 사용자 머신에서 실행되는 것을 승인**하는 것이다.
    """

    target_id: str
    kind: str
    base_url: str
    source_path: str
    commands: dict[str, list[str]] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    blockers: list[str] = Field(default_factory=list)
    confirmed: bool = False
    registered: bool = False


def _service() -> TargetRuntimeService:
    """Create a fresh catalog so newly checked-in manifests are visible immediately."""
    from pathlib import Path

    return TargetRuntimeService.from_repository_root(Path(__file__).resolve().parent.parent)


# --- 사용자 로컬 프로젝트 등록 (TEAM_CONTRACT 3.1 / P1 R1-2) ---------------------------


def _git_state(source_path: Path, *, for_closed_loop: bool = True) -> tuple[list[str], list[str]]:
    """(blockers, warnings). 사용자 프로젝트가 패치 경로를 탈 수 있는지 확인한다.

    **git 저장소는 선택이 아니라 전제다.** `runtime/worktree.py:43`이 대상 소스에
    `git worktree add`를 하고, 패치 apply와 6게이트 전체가 그 worktree 위에서 돈다
    (`catalog.py:234` — "run worktrees from the target app repository"). git이 아니면
    추측으로 진행하지 않고 명확한 사유로 막는다.

    `for_closed_loop=True`(기본)면 **dirty worktree도 차단**한다(계약 3A-4). 실행 중인
    서비스는 dirty 코드인데 worktree는 마지막 commit이라, 그대로 두면 **verify한 코드와
    패치한 코드가 다르다** — 편의 문제가 아니라 정합성 결함이다. 패치를 만들지 않는
    scan/verify 전용 조회라면 `False`로 낮춰 경고만 남긴다.
    """
    import subprocess

    blockers: list[str] = []
    warnings: list[str] = []

    if not source_path.is_dir():
        return [f"source_path가 디렉터리가 아닙니다: {source_path}"], warnings

    def _git(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", "-C", str(source_path), *args],
            capture_output=True, text=True, timeout=10, check=False,
        )

    try:
        if _git("rev-parse", "--git-dir").returncode != 0:
            blockers.append(
                f"{source_path}는 git 저장소가 아닙니다. 패치는 원본을 건드리지 않고 "
                f"run별 git worktree에만 적용되므로 git이 필요합니다 — "
                f"`git init && git add -A && git commit -m init` 후 다시 등록하세요."
            )
            return blockers, warnings

        if _git("rev-parse", "HEAD").returncode != 0:
            blockers.append(
                "커밋이 하나도 없습니다. worktree는 커밋된 상태를 기준으로 만들어집니다 — "
                "최초 커밋을 만든 뒤 다시 등록하세요."
            )
        elif _git("status", "--porcelain").stdout.strip():
            message = (
                "커밋되지 않은 변경이 있습니다. worktree는 마지막 커밋을 기준으로 만들어지므로, "
                "지금 실행 중인 서비스의 코드와 검사·패치 대상이 서로 다를 수 있습니다 "
                "— 커밋하거나 stash한 뒤 다시 시도하세요."
            )
            (blockers if for_closed_loop else warnings).append(message)
    except (OSError, subprocess.SubprocessError) as exc:
        blockers.append(f"git 상태를 확인하지 못했습니다: {exc}")

    return blockers, warnings


def _builtin_target_ids() -> set[str]:
    """`policies/scope.yaml`의 built-in demo target id 집합."""
    from core.policy_engine import load_scope

    return set(load_scope())


def _build_preview(manifest, source_path: Path, *, confirmed: bool) -> RegistrationPreview:
    blockers, warnings = _git_state(source_path)

    # 계약 3A-3: built-in과 id가 겹치면 조회 시 built-in이 이겨서 **사용자 프로젝트가 아닌
    # 것이 검사된다**. 조용히 틀린 대상을 스캔하는 것보다 등록을 거부하는 편이 안전하다.
    if manifest.id in _builtin_target_ids():
        blockers.append(
            f"target_id={manifest.id!r}는 built-in demo target과 겹칩니다. "
            f"그대로 두면 이 프로젝트가 아니라 데모 target이 검사됩니다 — "
            f"'local-{manifest.id}' 처럼 다른 id를 쓰세요."
        )

    return RegistrationPreview(
        target_id=manifest.id,
        kind=getattr(manifest, "kind", "compose_project"),
        base_url=manifest.base_url,
        source_path=str(source_path),
        # argv 전문. 요약·생략하지 않는다 — 이게 승인의 실질이다.
        commands={cid: list(spec.argv) for cid, spec in manifest.commands.items()},
        warnings=warnings,
        blockers=blockers,
        confirmed=confirmed,
        registered=False,
    )


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    @audited
    def vc_register_target(manifest: dict) -> Target:
        """**built-in demo target 전용 확인 tool.** 새 target을 만들지 않는다.

        제출한 manifest가 저장소에 체크인된 승인 manifest와 **byte 단위로 동일한지**만
        확인한다(`runtime/target_service.py:111`). 이름과 달리 "등록"이 아니라 "등록 확인"에
        가깝다 — 기존 20개 데모 target의 무결성 검사용이다.

        사용자 자신의 로컬 프로젝트를 등록하려면 `vc_register_local_target`을 쓴다.
        """
        return _service().register(manifest)

    @mcp.tool()
    @audited
    def vc_register_local_target(
        manifest: dict, source_path: str, confirmed: bool = False
    ) -> RegistrationPreview:
        """사용자의 로컬 프로젝트를 **명시 승인**으로 등록한다 (2단계).

        `confirmed=False`(기본)면 **아무것도 저장하지 않고** 미리보기만 돌려준다:
        base_url, source_path, git 상태, 그리고 **실행될 argv 전문**. 사용자가 그것을 보고
        `confirmed=True`로 다시 부를 때만 로컬 레지스트리에 기록된다.
        `vc_apply_patch(confirmed=True)`가 diff를 보여주고 승인받는 것과 같은 패턴이다.

        **왜 이 승인이 필요한가**: manifest는 `argv`를 직접 공급하고(`runtime/manifest.py:31`)
        `subprocess.run(argv, shell=False)`로 실행된다(`runtime/lifecycle.py:130`). 지금까지
        그 argv를 신뢰한 근거는 "우리 저장소에 커밋됐고 PR로 리뷰됐다"였다. 등록을 사용자에게
        열면 그 근거가 사라지므로, **사용자가 argv 전문을 보고 승인하는 것**이 그 자리를 대신한다.
        모델이 만든 manifest를 그대로 승인시키지 않는다 — prompt injection으로 악성 argv가
        들어오는 confused deputy가 실제 위협이다(기획서 10.3절).

        **안전 성질은 그대로다**: `TargetManifest` 스키마 검증기가 loopback이 아닌 base_url을
        구조적으로 거부하므로(`runtime/manifest.py:154`), 등록을 열어도 "남의 서비스 공격 불가"는
        유지된다. 바뀌는 것은 승인 목록의 **소유자**뿐이다.
        """
        from pathlib import Path

        from runtime.manifest import TargetManifest

        # 1) 스키마 검증 — 여기서 loopback이 강제된다. 실패하면 저장 시도조차 하지 않는다.
        validated = TargetManifest.model_validate(dict(manifest))
        resolved_source = Path(source_path).expanduser().resolve()

        preview = _build_preview(validated, resolved_source, confirmed=confirmed)
        if not confirmed or preview.blockers:
            return preview

        # 2) 승인 기록 — 사용자 판단은 이미 끝났고, 레지스트리는 기록만 한다.
        try:
            from core.policy_engine import reset_registry_cache
            from runtime.registry import LocalRegistry
        except ImportError as exc:  # P2의 registry가 아직 main에 없는 경우
            preview.blockers.append(
                f"로컬 레지스트리(runtime.registry)를 사용할 수 없습니다: {exc}. "
                f"미리보기까지는 정상이며, 승인 기록은 레지스트리 도입 후 가능합니다."
            )
            return preview

        LocalRegistry.load().approve(validated, source_path=resolved_source)
        reset_registry_cache()  # 방금 승인한 target이 즉시 정책 게이트를 통과하도록
        preview.registered = True
        return preview

    @mcp.tool()
    @audited
    def vc_inspect_stack(target_id: str) -> StackInfo:
        """target의 실행 스택을 탐지한다. P2 adapter.detect() 소유."""
        return StackInfo(target_id=target_id, stack=list(_service().inspect_stack(target_id)), detected_by="manifest")

    @mcp.tool()
    @audited
    def vc_check_readiness(target_id: str) -> ReadinessResult:
        """target이 등록/빌드/실행 가능한 상태인지 확인한다."""
        readiness = _service().check_readiness(target_id)
        return ReadinessResult(target_id=target_id, ready=readiness.ready, reasons=readiness.issues)

    @mcp.tool()
    @audited
    def vc_get_verifier_provisioning(target_id: str) -> VerifierProvisioning:
        """P2 replay contract: fixed base URL, auth mode, fixture strategy, and no-secret metadata only."""
        return _service().verifier_provisioning(target_id)

    @mcp.tool()
    @audited
    def vc_prepare_verifier_fixture(target_id: str, approved: bool) -> FixturePreparationResult:
        """Create a manifest-declared verifier fixture; explicit approval is required."""
        provisioning = _service().prepare_verifier_fixture(target_id, approved=approved)
        return FixturePreparationResult(
            target_id=target_id,
            fixture_available=provisioning.fixture_available,
            fixture_path=provisioning.fixture_path,
        )

    @mcp.tool()
    @audited
    def vc_build_target(target_id: str) -> Run:
        """target을 빌드한다(BUILDING→READY). P2 adapter.build() 소유."""
        return _service().build(target_id)

    @mcp.tool()
    @audited
    def vc_start_target(target_id: str) -> RuntimeHandleInfo:
        """격리 환경에서 target을 실행한다. P2 adapter.start() 소유."""
        base_url, healthy = _service().start(target_id)
        return RuntimeHandleInfo(target_id=target_id, base_url=base_url, healthy=healthy)

    @mcp.tool()
    @audited
    def vc_reset_target(target_id: str, approved: bool) -> ResetResult:
        """DB seed/volume snapshot을 복원한다. explicit approval이 필수다."""
        return ResetResult(target_id=target_id, ok=_service().reset(target_id, approved=approved))
