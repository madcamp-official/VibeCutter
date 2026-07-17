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
    type: str
    artifact_uri: str
    hash: str
    producer: str
    timestamp: datetime = Field(default_factory=_now)


class Candidate(BaseModel):
    """CANDIDATE_SCAN 단계에서 나온, 아직 검증되지 않은 취약점 가설."""

    id: str
    run_id: str
    cwe: Optional[str] = None
    endpoint: Optional[str] = None
    source_symbols: list[str] = Field(default_factory=list)
    confidence: Optional[float] = None
    signals: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_now)


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
    """부록 B Finding Report Schema 기준. 11.3절 표의 verification_state 필드명을 그대로 쓴다."""

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
    affected_role: Optional[str] = None
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
