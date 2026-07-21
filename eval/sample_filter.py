"""LLM 조건 표본 무결성 필터 (P4, T-3).

ablation(E-1)의 'rag-llm' 팔은 **235B 가 실제로 쓰인 run 만** 담아야 한다. endpoint 가
죽어 조용히 heuristic 으로 degrade 한 run(llm_used=False)이 섞이면, 두 팔(heuristic vs
rag-llm)의 차이가 희석돼 측정이 통째로 무의미해진다 — D5 에 P4 가 지적한 문제
("health/readiness 가 false 였던 run 은 비교 표본에서 빼야 한다").

이 모듈은 **판정하지 않는다**(6게이트는 결정론). 단지 오염된 표본을 제외한다:
- 입력: 앱/런 키로 된 예측 dict + 같은 키의 llm_used bool 맵.
- 출력: LLM 이 실제로 쓰인 키만 남긴 예측 + 제외된 키 목록(투명성).

usage bool 맵은 `model.trajectory.llm_usage_from_trajectories()` 결과에서 만든다
(`llm_used_map(usage, policy=...)`). 키(app_id/run_id)는 예측과 **같은 기준**이어야 한다.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, TypeVar

from model.trajectory import RunLlmUsage

K = TypeVar("K")


@dataclass(frozen=True)
class FilteredSample:
    """LLM 조건으로 거른 결과. `excluded` 는 왜 표본이 줄었는지 드러내기 위한 것."""

    kept: dict            # {key: 예측} — LLM 이 실제로 쓰인 것만
    excluded: list        # 제외된 key(정렬됨) — llm_used=False 또는 usage 정보 없음

    @property
    def note(self) -> str:
        if not self.excluded:
            return f"LLM 조건: {len(self.kept)}개 전부 유효(제외 0)."
        return (f"LLM 조건: {len(self.kept)}개 유효, {len(self.excluded)}개 제외"
                f"(LLM 미사용/degrade): {', '.join(map(str, self.excluded))}")


def llm_used_map(
    usage: Mapping[K, RunLlmUsage], *, policy: str = "all",
) -> dict[K, bool]:
    """`RunLlmUsage` 맵 → {key: llm_used bool}. policy 로 보수성 선택.

    - "all"(기본): 그 run 의 **모든** LLM 접점이 실제로 답해야 True(하나라도 degrade 면 오염).
    - "any": 한 번이라도 실제로 답했으면 True(느슨).
    ablation 무결성에는 "all" 을 권장한다.
    """
    if policy not in ("all", "any"):
        raise ValueError(f"policy 는 'all' 또는 'any' (got {policy!r})")
    pick = (lambda u: u.all_used) if policy == "all" else (lambda u: u.any_used)
    return {key: pick(u) for key, u in usage.items()}


def filter_llm_condition(
    predictions: Mapping[K, object], llm_used: Mapping[K, bool],
) -> FilteredSample:
    """LLM 이 실제로 쓰인 키만 남긴다. usage 정보가 없는 키는 **보수적으로 제외**한다.

    (rag-llm 팔에서 usage 가 없다는 건 관측이 안 붙었거나 LLM 접점이 없었다는 뜻 →
    'LLM 조건'으로 신뢰할 수 없으므로 뺀다.)
    """
    kept = {k: v for k, v in predictions.items() if llm_used.get(k, False)}
    excluded = sorted((k for k in predictions if not llm_used.get(k, False)), key=str)
    return FilteredSample(kept=kept, excluded=excluded)
