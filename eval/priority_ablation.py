"""가설 우선순위 ablation (P4, E-1) — RQ3의 '우선순위' 측면.

RQ3(2026-07-21): RAG 코드 컨텍스트 + LLM 재랭킹이 휴리스틱 대비 **가설 우선순위**를 개선하는가.

왜 `run_baseline`(precision/recall)로는 못 재나:
  rerank(`aggregate(rerank_fn=)`)는 kept candidate SET 을 바꾸지 않고 **순서만** 바꾼다
  (FP reject 는 rerank 이전 단계라 LLM 과 무관). 그래서 focus-set 기반 지표는 두 팔에서
  동일하게 나온다. 우선순위 개선은 **순위 지표**로만 드러난다.

지표(진짜 취약점 = candidate.focus ∈ 그 앱의 정답 focus 집합):
  - first_true_rank : 첫 참 candidate 의 1-based 순위(없으면 None).
  - reciprocal_rank : 1/rank (참이 없으면 0).
  - MRR             : 앱 평균 reciprocal_rank. heuristic 대비 rag-llm 의 MRR 상승이 근거.

입력은 **정렬된 candidate 목록 두 벌**(heuristic 순서 vs rag-llm 순서). 두 순서는 각각
`aggregate(...)`(rerank_fn 없음/있음)로 만든다 — 이 모듈은 순서를 소비만 한다(모델 비의존).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping, Optional, Sequence

from contracts.schemas import Candidate


def _focus_of(candidate: Candidate) -> Optional[str]:
    """candidate 의 focus 군(`focus:<g>` signal 우선, 없으면 vuln_class)."""
    for s in candidate.signals:
        if s.startswith("focus:"):
            return s.split(":", 1)[1]
    return candidate.vuln_class


def is_true(candidate: Candidate, truth_focuses: Iterable[str]) -> bool:
    """candidate 가 그 앱의 정답 focus 집합에 드는가(= 진짜 취약점 후보)."""
    focus = _focus_of(candidate)
    return focus is not None and focus in set(truth_focuses)


def first_true_rank(
    ordered: Sequence[Candidate], truth_focuses: Iterable[str]
) -> Optional[int]:
    """정렬된 목록에서 첫 참 candidate 의 1-based 순위. 참이 없으면 None."""
    truth = set(truth_focuses)
    for i, c in enumerate(ordered, start=1):
        if is_true(c, truth):
            return i
    return None


def reciprocal_rank(ordered: Sequence[Candidate], truth_focuses: Iterable[str]) -> float:
    """1/first_true_rank (참이 없으면 0.0)."""
    rank = first_true_rank(ordered, truth_focuses)
    return 1.0 / rank if rank else 0.0


@dataclass(frozen=True)
class AppRank:
    app_id: str
    heuristic_rank: Optional[int]
    ragllm_rank: Optional[int]

    @property
    def improved(self) -> bool:
        """rag-llm 이 진짜 취약점을 더 위로 올렸는가(순위 숫자가 작아짐)."""
        if self.ragllm_rank is None:
            return False
        if self.heuristic_rank is None:
            return True
        return self.ragllm_rank < self.heuristic_rank


@dataclass(frozen=True)
class PriorityAblationReport:
    per_app: list[AppRank]
    heuristic_mrr: float
    ragllm_mrr: float

    @property
    def mrr_delta(self) -> float:
        return self.ragllm_mrr - self.heuristic_mrr

    def improved_apps(self) -> list[str]:
        return sorted(a.app_id for a in self.per_app if a.improved)

    def render(self) -> str:
        lines = [
            "가설 우선순위 ablation (MRR, 높을수록 좋음)",
            f"  heuristic MRR : {self.heuristic_mrr:.3f}",
            f"  rag-llm   MRR : {self.ragllm_mrr:.3f}",
            f"  Δ(rag-llm − heuristic): {self.mrr_delta:+.3f}",
            f"  진짜 취약점 순위가 오른 앱({len(self.improved_apps())}): "
            f"{', '.join(self.improved_apps()) or '-'}",
        ]
        return "\n".join(lines)


def compare_orderings(
    heuristic: Mapping[str, Sequence[Candidate]],
    ragllm: Mapping[str, Sequence[Candidate]],
    truth: Mapping[str, Iterable[str]],
) -> PriorityAblationReport:
    """두 정렬(앱별) + 정답 focus → 순위 ablation 리포트.

    정답(truth)이 있는 앱만 센다. MRR 은 그 앱들의 reciprocal_rank 평균.
    """
    apps = sorted(a for a in truth if a in heuristic and a in ragllm)
    per_app: list[AppRank] = []
    h_rr: list[float] = []
    r_rr: list[float] = []
    for app in apps:
        t = truth[app]
        per_app.append(AppRank(
            app_id=app,
            heuristic_rank=first_true_rank(heuristic[app], t),
            ragllm_rank=first_true_rank(ragllm[app], t),
        ))
        h_rr.append(reciprocal_rank(heuristic[app], t))
        r_rr.append(reciprocal_rank(ragllm[app], t))
    n = len(apps) or 1
    return PriorityAblationReport(
        per_app=per_app,
        heuristic_mrr=sum(h_rr) / n,
        ragllm_mrr=sum(r_rr) / n,
    )
