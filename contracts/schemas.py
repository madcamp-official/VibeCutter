"""공통 계약: Target/Run/Observation/Candidate/Finding/Patch/Validation/Trajectory.

기획서(Vibe_Cutter_MCP_심화_기획_및_구현_보고서.docx) 11.3절 Entity 표, 부록 A Tool
Schema, 부록 B Finding Report Schema, 5.2절 상태 머신, cowork_rule.md 3절 "고정 공통
언어"를 근거로 한다. 상태 이름과 Finding 상태값은 팀 전체가 공유하는 고정 계약이므로
조용히 변경하지 않는다(cowork_rule.md 2절·6절) — 바꿀 경우 docs/handoffs/에 영향 범위를
남긴다.

11.3절 표는 "주요 필드"만 나열한 요약이라, 모든 엔티티에 id/created_at(감사 추적용)을
추가하고 Validation에는 7.6절이 요구하는 6번째 게이트인 scope를 추가했다.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Optional

from pydantic import BaseModel, Field


def _now() -> datetime:
    return datetime.utcnow()


# --- 고정 공통 언어 (cowork_rule.md 3절, 기획서 5.2절) ---------------------------------


class RunState(StrEnum):
    """Run(감사 실행) 전체 파이프라인 단계. 이름은 고정 계약이며 순서를 바꾸지 않는다."""

    REGISTERED = "REGISTERED"
    BUILDING = "BUILDING"
    READY = "READY"
    MAPPING = "MAPPING"
    CANDIDATE_SCAN = "CANDIDATE_SCAN"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    LOCALIZING = "LOCALIZING"
    PATCH_PROPOSED = "PATCH_PROPOSED"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    PATCH_APPLIED = "PATCH_APPLIED"
    VALIDATING = "VALIDATING"
    FIXED = "FIXED"
    RETRY = "RETRY"
    HUMAN_REVIEW = "HUMAN_REVIEW"


class FindingStatus(StrEnum):
    """개별 Finding의 판정 상태. deterministic judge만 전이시킨다(5.3절)."""

    CANDIDATE = "candidate"
    VERIFIED = "verified"
    REJECTED = "rejected"
    FIXED = "fixed"
    HUMAN_REVIEW = "human_review"


class ApprovalStatus(StrEnum):
    """Patch apply는 explicit user confirmation 없이는 PENDING을 벗어나지 못한다."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class ObservationType(StrEnum):
    """Observation.type의 고정 값 집합 (D1-P3.md 계약 이견 3).

    자유 문자열로 두면 P4의 D4 밤 trajectory 조인이 값 표기 드리프트로 깨질 수 있어
    Day2에 고정했다. `http_exchange`는 `verifiers/access_control.py`가 이미 쓰고 있는
    값이라 그대로 포함했다 — 기존 코드는 변경 없이 계속 동작한다.
    """

    HTTP_EXCHANGE = "http_exchange"
    DB_DIFF = "db_diff"
    BROWSER_TRACE = "browser_trace"
    LOG = "log"
    ROUTE_MAP = "route_map"
    ROLE_MAP = "role_map"


# --- Entity 모델 (기획서 11.3절) -------------------------------------------------------


class Target(BaseModel):
    """등록된 로컬/격리 target. id는 target manifest의 id와 동일한 값을 사용한다(9.3절)."""

    id: str
    manifest_hash: str
    source_commit: Optional[str] = None
    adapter: str
    allowed_hosts: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_now)


class Run(BaseModel):
    """한 target에 대한 감사 실행 1회."""

    id: str
    target_id: str
    model_version: Optional[str] = None
    tool_versions: dict[str, str] = Field(default_factory=dict)
    status: RunState = RunState.REGISTERED
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=_now)


class Observation(BaseModel):
    """모든 evidence의 기본 단위. Finding/Candidate/Validation의 evidence_ids가 참조한다."""

    id: str
    run_id: str
    type: ObservationType
    artifact_uri: str
    hash: str
    producer: str
    timestamp: datetime = Field(default_factory=_now)


class Candidate(BaseModel):
    """CANDIDATE_SCAN 단계에서 나온, 아직 검증되지 않은 취약점 가설.

    `vuln_class`/`attack_params`는 Day2에 추가했다(D1-P3.md 계약 이견 1) — IDOR 검증에
    필요한 HTTP method/역할/대상 자원 같은 정보를 지금은 `signals`에 `"key=value"` 문자열로
    욱여넣어 파싱하는 우회가 있어서다(`verifiers/access_control.py:probe_from_candidate`).
    **기존 `signals` 필드는 그대로 둔다** — P3/P4가 이미 이 필드로 동작하는 코드를 갖고
    있어(verifier 파싱, SAST/SCA candidate의 `focus:`/`severity:` 태그) 제거하면 깨진다.
    새 typed 필드는 추가적(additive)이며, `signals` 우회를 실제로 걷어내는 건 verifier를
    다시 쓰는 작업이라 P3와 조율 후 별도로 진행한다.

    `origin_candidate_id`는 Extra Day에 추가했다(D5-P2.md candidate-per-worker-Run 계약 ②,
    additive). scan Run이 만든 후보를 검증용 worker Run으로 materialize할 때, 그 worker
    Candidate가 자신이 유래한 원본 scan Candidate id를 여기 보존한다 — 원본 후보의 `run_id`는
    절대 덮어쓰지 않고, report/dataset에서 scan↔worker lineage를 추적할 수 있게 한다.
    원본 scan Candidate 자신은 이 필드가 None이다.
    """

    id: str
    run_id: str
    cwe: Optional[str] = None
    endpoint: Optional[str] = None
    source_symbols: list[str] = Field(default_factory=list)
    confidence: Optional[float] = None
    signals: list[str] = Field(default_factory=list)
    vuln_class: Optional[str] = None
    attack_params: dict[str, str] = Field(default_factory=dict)
    origin_candidate_id: Optional[str] = None
    created_at: datetime = Field(default_factory=_now)


class VerificationResult(BaseModel):
    """Verification 카테고리 tool(`vc_verify_access_control` 등)의 outputSchema이자,
    verifier(`verifiers/*.py`)가 P1의 tool 배선에 돌려주는 결과 타입.

    부록 A outputSchema와 동일한 3필드. `evidence_ids`에 기본값을 두지 않는다 —
    verified=false인 경우에도 부록 A는 이 필드를 required로 명시하므로(빈 배열이라도
    명시적으로), 구현부가 항상 채우도록 강제한다.

    **evidence_ids는 반드시 evidence_store에 실제로 기록된 Observation의 id여야 한다**
    (D1-P3.md 구멍 ① — 존재하지 않는 id는 `evidence_store.update_finding_status()`가
    `InvalidEvidenceError`로 거부한다). 이전에는 `mcp_server/tools_analysis.py`의
    `VerifyResult`와 `verifiers/types.py`의 `VerifierOutput`이 필드가 완전히 같은 채로
    중복 정의돼 있었다(D1-P3.md 지적) — 여기 공통 계약으로 통합했다.
    """

    verified: bool
    evidence_ids: list[str]
    reason: str


class RootCause(BaseModel):
    """Finding.root_cause — root-cause locator(7.4절) 산출물."""

    file: str
    symbol: Optional[str] = None
    rationale: Optional[str] = None


class Validation(BaseModel):
    """Deterministic Security Judge의 6개 게이트 결과(7.6절)와 최종 verdict."""

    id: str
    run_id: str
    patch_id: str
    build: Optional[bool] = None
    attack: Optional[bool] = None
    positive_test: Optional[bool] = None
    regression: Optional[bool] = None
    static: Optional[bool] = None
    scope: Optional[bool] = None
    verdict: Optional[str] = None  # RunState.FIXED / RETRY / HUMAN_REVIEW 값 중 하나
    created_at: datetime = Field(default_factory=_now)


class Patch(BaseModel):
    """vc_generate_patch 산출물. apply는 별도 도구+명시적 승인 후 worktree에만 적용."""

    id: str
    finding_id: str
    run_id: str
    diff: str
    files: list[str] = Field(default_factory=list)
    rationale: Optional[str] = None
    approval: ApprovalStatus = ApprovalStatus.PENDING
    attempt_no: int = 1
    validation_id: Optional[str] = None
    created_at: datetime = Field(default_factory=_now)


class Finding(BaseModel):
    """부록 B Finding Report Schema 기준. 11.3절 표의 verification_state 필드명을 그대로 쓴다.

    `affected_roles`는 Day2에 단수 `affected_role`에서 복수로 바꿨다(D1-P3.md 계약 이견 2)
    — IDOR은 본질적으로 victim/attacker 최소 2개 역할이 관여해 단수로는 표현이 안 됐다.
    이전 필드는 어디서도 쓰인 적이 없어(schema 정의 외 참조 0건) 마이그레이션 없이 바로 바꿨다.
    """

    id: str
    run_id: str
    target_commit: Optional[str] = None
    candidate_id: Optional[str] = None

    title: str
    cwe: Optional[str] = None
    owasp_category: Optional[str] = None
    severity: Optional[str] = None

    verification_state: FindingStatus = FindingStatus.CANDIDATE

    affected_endpoint: Optional[str] = None
    affected_roles: list[str] = Field(default_factory=list)
    source_symbols: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    reproduction_steps: list[str] = Field(default_factory=list)

    evidence_ids: list[str] = Field(default_factory=list)
    impact: Optional[str] = None
    confidence: Optional[float] = None
    reproducibility: Optional[bool] = None

    root_cause: Optional[RootCause] = None
    patch_ids: list[str] = Field(default_factory=list)
    selected_patch_id: Optional[str] = None
    validation_id: Optional[str] = None

    limitations: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)


class Trajectory(BaseModel):
    """Run 내 상태 전이 1스텝. P4의 LoRA 학습 샘플(4.5절)은 이 레코드들을 조인해 만든다."""

    id: str
    run_id: str
    state: RunState
    action: dict = Field(default_factory=dict)  # {"tool": ..., "arguments": {...}}
    result: dict = Field(default_factory=dict)
    next_state: RunState
    reward: Optional[float] = None
    label: Optional[str] = None
    created_at: datetime = Field(default_factory=_now)
