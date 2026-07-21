"""model.trajectory 단위 테스트. 실행: python -m model.test_trajectory"""

from __future__ import annotations

import tempfile
from pathlib import Path

from contracts.schemas import Observation, RunState, Trajectory
from model.trajectory import (
    OBSERVATION_TYPES,
    TrajectoryRecorder,
    is_evidence_type,
    llm_usage_from_trajectories,
    load_trajectories,
    stats,
    to_sft_sample,
    training_samples,
    valid_evidence,
)


def _llm_step(run_id, seq, *, llm_used, tier) -> Trajectory:
    return Trajectory(
        id=f"{run_id}-{seq}", run_id=run_id, state=RunState.MAPPING, action={},
        result={"llm_used": llm_used, "tier": tier}, next_state=RunState.CANDIDATE_SCAN)


def _obs(id, type_) -> Observation:
    return Observation(id=id, run_id="r", type=type_, artifact_uri=f"vibecutter://ev/{id}",
                       hash="deadbeef", producer="verifier")


def _step(**kw) -> dict:
    base = dict(
        run_id="r1",
        state=RunState.VERIFYING,
        action={"tool": "vc_verify_access_control", "arguments": {}},
        result={"verified": True},
        next_state=RunState.VERIFIED,
    )
    base.update(kw)
    return base


def test_record_and_load_roundtrip() -> None:
    with tempfile.TemporaryDirectory() as td:
        rec = TrajectoryRecorder(Path(td) / "t.jsonl")
        rec.record_step(**_step(label="verified"))
        rec.record_step(**_step(state=RunState.CANDIDATE_SCAN, next_state=RunState.VERIFYING))
        loaded = load_trajectories(Path(td) / "t.jsonl")
        assert len(loaded) == 2
        assert all(isinstance(t, Trajectory) for t in loaded)
        assert loaded[0].label == "verified"
        assert loaded[0].id == "r1-step-0" and loaded[1].id == "r1-step-1"


def test_training_samples_requires_evidence_link() -> None:
    trajs = [
        Trajectory(id="1", run_id="r", state=RunState.VERIFYING, action={}, result={},
                   next_state=RunState.VERIFIED, label="verified"),   # 학습 가능
        Trajectory(id="2", run_id="r", state=RunState.MAPPING, action={}, result={},
                   next_state=RunState.CANDIDATE_SCAN),                # label/reward 없음 → 제외
        Trajectory(id="3", run_id="r", state=RunState.VALIDATING, action={}, result={},
                   next_state=RunState.FIXED, reward=1.0),             # reward 있음 → 포함
    ]
    kept = training_samples(trajs)
    assert {t.id for t in kept} == {"1", "3"}
    # require_label=False 면 전부 통과
    assert len(training_samples(trajs, require_label=False)) == 3


def test_unlearnable_label_excluded() -> None:
    t = Trajectory(id="x", run_id="r", state=RunState.MAPPING, action={}, result={},
                   next_state=RunState.CANDIDATE_SCAN, label="in_progress")
    assert training_samples([t]) == []


def test_to_sft_sample_shape() -> None:
    t = Trajectory(id="1", run_id="r", state=RunState.VERIFYING,
                   action={"tool": "x"}, result={"verified": True},
                   next_state=RunState.VERIFIED, label="verified")
    s = to_sft_sample(t)
    assert s["input"]["action"] == {"tool": "x"}
    assert s["output"] == {"verified": True}
    assert s["label"] == "verified"
    assert "evidence" not in s   # observations 미제공 시 evidence 키 없음


def test_observation_type_value_set_matches_contract_enum() -> None:
    # P1 이 contracts.ObservationType enum 으로 정식 채택 → 우리 집합은 거기서 파생.
    from contracts.schemas import ObservationType
    assert set(OBSERVATION_TYPES) == {t.value for t in ObservationType}
    assert is_evidence_type("http_exchange") and not is_evidence_type("bogus")


def test_invalid_observation_type_rejected_by_schema() -> None:
    # 이제 스키마(enum)가 잘못된 type 을 생성 단계에서 막는다.
    try:
        _obs("x", "bad_type")
    except Exception:
        return
    raise AssertionError("잘못된 Observation.type 은 pydantic 이 거부해야 함")


def test_valid_evidence_passes_all_valid() -> None:
    obs = [_obs("1", "http_exchange"), _obs("2", "db_diff")]
    ok, unknown = valid_evidence(obs)
    assert {o.id for o in ok} == {"1", "2"}
    assert unknown == []                       # enum 강제라 unknown 없음


def test_to_sft_sample_joins_evidence() -> None:
    t = Trajectory(id="1", run_id="r", state=RunState.VERIFYING, action={}, result={},
                   next_state=RunState.VERIFIED, label="verified")
    obs = [_obs("e1", "http_exchange"), _obs("e2", "db_diff")]
    s = to_sft_sample(t, observations=obs)
    assert len(s["evidence"]) == 2
    assert s["evidence"][0]["type"] == "http_exchange"
    assert s["evidence"][0]["hash"] == "deadbeef"
    assert "evidence_warnings" not in s          # 전부 valid


def test_stats() -> None:
    with tempfile.TemporaryDirectory() as td:
        rec = TrajectoryRecorder(Path(td) / "t.jsonl")
        rec.record_step(**_step(label="verified"))
        rec.record_step(**_step(label="rejected"))
        rec.record_step(**_step())  # unlabeled
        s = stats(load_trajectories(Path(td) / "t.jsonl"))
        assert s["total"] == 3 and s["learnable"] == 2
        assert s["by_label"]["unlabeled"] == 1


def test_llm_usage_ignores_steps_without_llm_meta() -> None:
    # llm 메타 없는 스텝(일반 verify 등)은 세지 않는다.
    trajs = [Trajectory(id="1", run_id="rA", state=RunState.VERIFYING, action={},
                        result={"verified": True}, next_state=RunState.VERIFIED)]
    assert llm_usage_from_trajectories(trajs) == {}


def test_llm_usage_all_used_when_every_touchpoint_answers() -> None:
    trajs = [_llm_step("rA", 0, llm_used=True, tier="primary"),
             _llm_step("rA", 1, llm_used=True, tier="primary")]
    usage = llm_usage_from_trajectories(trajs)["rA"]
    assert usage.calls == 2 and usage.used == 2
    assert usage.all_used is True and usage.any_used is True


def test_llm_usage_degrade_makes_all_used_false_but_any_true() -> None:
    # rerank 는 LLM, patch 합성은 endpoint 죽어 none → 오염된 run.
    trajs = [_llm_step("rB", 0, llm_used=True, tier="primary"),
             _llm_step("rB", 1, llm_used=False, tier="none")]
    usage = llm_usage_from_trajectories(trajs)["rB"]
    assert usage.calls == 2 and usage.used == 1
    assert usage.all_used is False   # 하나라도 degrade → 보수적으로 오염
    assert usage.any_used is True and "none" in usage.tiers


def test_llm_usage_separates_runs() -> None:
    trajs = [_llm_step("rA", 0, llm_used=True, tier="primary"),
             _llm_step("rB", 0, llm_used=False, tier="none")]
    out = llm_usage_from_trajectories(trajs)
    assert out["rA"].all_used is True and out["rB"].any_used is False


def _run() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")


if __name__ == "__main__":
    _run()
