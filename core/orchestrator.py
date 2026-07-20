"""candidate-per-worker-Run 오케스트레이션 (Extra Day, D5-P2.md 공통 계약).

scan Run이 후보를 수집(`CANDIDATE_SCAN`에서 종료)하면, 후보마다 별도 worker Run을 만들어
verify→localize→patch→validate 파이프라인을 독립적으로 돌린다. 하나의 Run에 여러 verified
candidate가 섞이지 않게 하기 위해서다 — `VERIFIED`는 `LOCALIZING`으로만 진행하는 고정
상태라, Run 하나가 candidate 하나를 끝까지 끌고 가야 상태 머신/patch/validation/evidence가
분리된다(D5-P2.md 계약 ①~③). P2 worktree/generated Compose overlay도 `target_id + run_id`
단위라 이 경계가 격리·reset 경계와 정확히 일치한다.

`materialize_worker_run()`은 그 경계 생성만 담당한다(순수 상태/저장 계층). 실제 tool을
순서대로 부르는 batch 루프와 P2 runtime(sweep/reset_run) 배선은 `run_target_audit()`
(1B-3)에 있다 — 여기서는 tool/서비스에 의존하지 않아 단위 테스트가 가볍다.
"""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from contracts.schemas import Candidate, Run, RunState
from core.evidence_store import save


def materialize_worker_run(scan_run: Run, scan_candidate: Candidate) -> tuple[Run, Candidate]:
    """scan candidate 하나를 검증용 worker Run으로 materialize한다(D5-P2.md 계약 ②).

    새 worker Run(scan Run과 같은 target_id, `CANDIDATE_SCAN`에서 시작 — target은 scan Run이
    이미 build/start 했으므로 worker는 verify 단계부터 붙는다)을 만들고, scan candidate를
    복제해 worker Run에 넣는다. 원본 scan candidate id는 worker candidate의
    `origin_candidate_id`(lineage)로 보존하고, **원본 scan candidate와 scan Run은 절대
    건드리지 않는다**(계약 ②: 기존 Candidate의 run_id를 덮어쓰지 않음). 이후 verify/localize/
    patch/validate는 전부 반환된 worker Run/Candidate에서만 일어난다(계약 ③).
    """
    worker_run = Run(
        id=f"run-{uuid4().hex[:12]}",
        target_id=scan_run.target_id,
        model_version=scan_run.model_version,
        tool_versions=dict(scan_run.tool_versions),
        status=RunState.CANDIDATE_SCAN,
        started_at=datetime.utcnow(),
    )
    save(worker_run)

    worker_candidate = scan_candidate.model_copy(
        update={
            "id": f"cand-{uuid4().hex[:12]}",
            "run_id": worker_run.id,
            "origin_candidate_id": scan_candidate.id,
        }
    )
    save(worker_candidate)
    return worker_run, worker_candidate
