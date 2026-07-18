"""Evidence store: SQLite 기반 영속화 계층.

Observation/Candidate/Finding/Patch/Validation/Trajectory 등 공통 계약 엔티티를 저장하고
조회한다. 공개 함수는 항상 `contracts.schemas`의 Pydantic 모델만 입출력한다 — 내부
SQLModel 테이블은 구현 세부사항이며 호출자가 알 필요 없다.

모든 artifact는 SHA-256 hash + 생성 tool(=producer)과 함께 저장해 재현성을 보장한다
(5.3절). Finding 상태 전이는 `core.state_machine.transition_finding`을 통해서만
일어나므로, evidence 없이는 이 store를 거쳐도 verified/fixed로 승격될 수 없다.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from datetime import datetime
from uuid import uuid4

from sqlmodel import JSON, Column, Field, Session, SQLModel, select

from contracts.schemas import (
    ApprovalStatus,
    Candidate,
    Finding,
    FindingStatus,
    Observation,
    Patch,
    Run,
    RunState,
    Target,
    Trajectory,
    Validation,
)
from core.db import DATA_DIR, get_engine
from core.redaction import redact
from core.state_machine import transition_finding


def sha256_of(data: bytes) -> str:
    """artifact 저장 전 hash를 계산한다 (5.3절 재현성 요구사항)."""
    return hashlib.sha256(data).hexdigest()


def _redact_bytes(data: bytes) -> bytes:
    """UTF-8 텍스트로 디코딩되는 artifact에만 redaction을 적용한다.

    디코딩되지 않는 바이너리(스크린샷 등)는 원본 그대로 저장한다 — 현재 redaction 규칙은
    텍스트 패턴(JSESSIONID/Bearer/password/JWT) 기준이라 바이너리에는 적용할 방법이 없다.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data
    return redact(text).encode("utf-8")


# --- 내부 SQLModel 테이블 (구현 세부사항, 외부에 노출하지 않는다) -----------------------


class TargetRow(SQLModel, table=True):
    __tablename__ = "target"
    id: str = Field(primary_key=True)
    manifest_hash: str
    source_commit: str | None = None
    adapter: str
    allowed_hosts: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=datetime.utcnow)


class RunRow(SQLModel, table=True):
    __tablename__ = "run"
    id: str = Field(primary_key=True)
    target_id: str = Field(index=True)
    model_version: str | None = None
    tool_versions: dict = Field(default_factory=dict, sa_column=Column(JSON))
    status: str = RunState.REGISTERED.value
    started_at: datetime | None = None
    ended_at: datetime | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ObservationRow(SQLModel, table=True):
    __tablename__ = "observation"
    id: str = Field(primary_key=True)
    run_id: str = Field(index=True)
    type: str
    artifact_uri: str
    hash: str
    producer: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class CandidateRow(SQLModel, table=True):
    __tablename__ = "candidate"
    id: str = Field(primary_key=True)
    run_id: str = Field(index=True)
    cwe: str | None = None
    endpoint: str | None = None
    source_symbols: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    confidence: float | None = None
    signals: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=datetime.utcnow)


class FindingRow(SQLModel, table=True):
    __tablename__ = "finding"
    id: str = Field(primary_key=True)
    run_id: str = Field(index=True)
    target_commit: str | None = None
    candidate_id: str | None = None
    title: str
    cwe: str | None = None
    owasp_category: str | None = None
    severity: str | None = None
    verification_state: str = FindingStatus.CANDIDATE.value
    affected_endpoint: str | None = None
    affected_role: str | None = None
    source_symbols: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    preconditions: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    reproduction_steps: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    evidence_ids: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    impact: str | None = None
    confidence: float | None = None
    reproducibility: bool | None = None
    root_cause: dict | None = Field(default=None, sa_column=Column(JSON))
    patch_ids: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    selected_patch_id: str | None = None
    validation_id: str | None = None
    limitations: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class PatchRow(SQLModel, table=True):
    __tablename__ = "patch"
    id: str = Field(primary_key=True)
    finding_id: str = Field(index=True)
    run_id: str = Field(index=True)
    diff: str
    files: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    rationale: str | None = None
    approval: str = ApprovalStatus.PENDING.value
    attempt_no: int = 1
    validation_id: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ValidationRow(SQLModel, table=True):
    __tablename__ = "validation"
    id: str = Field(primary_key=True)
    run_id: str = Field(index=True)
    patch_id: str = Field(index=True)
    build: bool | None = None
    attack: bool | None = None
    positive_test: bool | None = None
    regression: bool | None = None
    static: bool | None = None
    scope: bool | None = None
    verdict: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class TrajectoryRow(SQLModel, table=True):
    __tablename__ = "trajectory"
    id: str = Field(primary_key=True)
    run_id: str = Field(index=True)
    state: str
    action: dict = Field(default_factory=dict, sa_column=Column(JSON))
    result: dict = Field(default_factory=dict, sa_column=Column(JSON))
    next_state: str
    reward: float | None = None
    label: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


_ROW_CLASSES: dict[type, type[SQLModel]] = {
    Target: TargetRow,
    Run: RunRow,
    Observation: ObservationRow,
    Candidate: CandidateRow,
    Finding: FindingRow,
    Patch: PatchRow,
    Validation: ValidationRow,
    Trajectory: TrajectoryRow,
}

# --- 공개 API: contracts.schemas 모델만 입출력한다 -------------------------------------


def save(entity: Target | Run | Observation | Candidate | Finding | Patch | Validation | Trajectory) -> None:
    """upsert. id가 같으면 덮어쓴다."""
    row_cls = _ROW_CLASSES[type(entity)]
    with Session(get_engine()) as session:
        session.merge(row_cls(**entity.model_dump()))
        session.commit()


def get(model_cls: type, entity_id: str):
    """model_cls는 contracts.schemas의 엔티티 클래스(Target, Finding 등)."""
    row_cls = _ROW_CLASSES[model_cls]
    with Session(get_engine()) as session:
        row = session.get(row_cls, entity_id)
        return model_cls(**row.model_dump()) if row else None


def list_by_run(model_cls: type, run_id: str) -> list:
    """Target/Run을 제외한, run_id를 갖는 엔티티(Observation/Candidate/Finding/Patch/Validation/Trajectory)에만 쓴다."""
    row_cls = _ROW_CLASSES[model_cls]
    with Session(get_engine()) as session:
        rows = session.exec(select(row_cls).where(row_cls.run_id == run_id)).all()
        return [model_cls(**row.model_dump()) for row in rows]


def write_artifact(
    run_id: str,
    *,
    observation_type: str,
    producer: str,
    data: bytes,
    observation_id: str | None = None,
) -> Observation:
    """artifact 파일을 `.vibecutter/runs/{run_id}/artifacts/`에 쓰고 SHA-256 hash와 함께
    Observation으로 기록한다. 재현성 확보를 위해 hash와 producer(생성 tool)를 항상 남긴다.

    저장 직전에 `core.redaction.redact()`를 거쳐 secret/token을 지운다(구멍 ② 방어,
    cowork_rule.md 4절). hash는 실제로 저장되는(redaction 적용 후) bytes 기준이다 —
    재현성 검증 시 저장된 파일과 hash가 항상 일치해야 하므로.
    """
    obs_id = observation_id or f"obs-{uuid4().hex[:12]}"
    data = _redact_bytes(data)
    digest = sha256_of(data)
    artifact_dir = DATA_DIR / "runs" / run_id / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / f"{obs_id}.bin"
    artifact_path.write_bytes(data)

    observation = Observation(
        id=obs_id,
        run_id=run_id,
        type=observation_type,
        artifact_uri=f"file://{artifact_path}",
        hash=digest,
        producer=producer,
    )
    save(observation)
    return observation


class InvalidEvidenceError(ValueError):
    """evidence_ids 중 evidence_store에 실제로 존재하지 않거나 다른 run 소속인 id가 있을 때 발생한다.

    D1-P3.md 구멍 ①: `transition_finding()`은 evidence_ids가 "비어 있지 않은지"만 검사하고
    실존 여부는 보지 않아, 존재하지 않는 id로도 verified 승격이 통과했다(재현 확인됨).
    이 검사는 store 계층(여기)에서만 하고 `transition_finding()`은 순수 함수로 그대로 둔다.
    """

    def __init__(self, finding_id: str, run_id: str, bad_ids: Sequence[str]):
        super().__init__(
            f"finding {finding_id}(run={run_id})의 evidence_ids 중 존재하지 않거나 다른"
            f" run 소속인 id: {list(bad_ids)}"
        )
        self.finding_id = finding_id
        self.run_id = run_id
        self.bad_ids = list(bad_ids)


def update_finding_status(
    finding_id: str,
    target_status: FindingStatus,
    *,
    evidence_ids: Sequence[str],
) -> Finding:
    """evidence 없이는 Finding.verification_state를 바꿀 수 없다.

    `core.state_machine.transition_finding`에 위임해 evidence_ids가 비어 있지 않은지,
    상태 전이 자체가 허용되는지 먼저 검사한다. 그 다음 각 evidence_id가 evidence_store에
    실제로 존재하고 이 finding과 같은 run 소속인지 확인한다(구멍 ① 방어) — 그렇지 않으면
    `InvalidEvidenceError`. 이 함수를 거치지 않고 Finding row를 직접 고쳐서 verified/fixed를
    만드는 것 외에는 우회 경로가 없다.
    """
    finding = get(Finding, finding_id)
    if finding is None:
        raise ValueError(f"finding {finding_id} not found")

    new_status = transition_finding(
        finding.verification_state, target_status, evidence_ids=evidence_ids
    )

    bad_ids = [
        eid
        for eid in evidence_ids
        if (obs := get(Observation, eid)) is None or obs.run_id != finding.run_id
    ]
    if bad_ids:
        raise InvalidEvidenceError(finding_id, finding.run_id, bad_ids)

    finding.verification_state = new_status
    finding.evidence_ids = list(dict.fromkeys([*finding.evidence_ids, *evidence_ids]))
    finding.updated_at = datetime.utcnow()
    save(finding)
    return finding
