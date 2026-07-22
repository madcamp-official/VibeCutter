"""클래스별 패치 성공률 집계 (P4, REMAINING_PLAN M2).

RQ3의 '패치 성공률' 축: idor/injection/xss 각각 `verified → FIXED` 성공률과 6게이트별
통과율을 낸다. 발표 자료의 클래스별 표가 목표.

FIXED 판정은 `core.judge.compute_verdict`와 **같은 규칙**: 6게이트가 전부 True 여야 FIXED
(하나라도 False/None 이면 아님). 게이트: build/attack/positive_test/regression/static/scope.

이 모듈은 **판정하지 않는다**(6게이트는 결정론) — 이미 나온 Validation 을 클래스별로 집계만
한다. 입력은 `(vuln_class, validation)` 쌍이며 validation 은 6게이트 bool 속성을 가진
객체(`contracts.schemas.Validation`)면 된다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Mapping

# core.judge._GATE_FIELDS 와 동일 순서·이름(계약 일치). 바꾸면 judge 와 함께 확인.
GATES = ("build", "attack", "positive_test", "regression", "static", "scope")


def gate_passed(validation, gate: str) -> bool:
    """게이트가 '통과(True)'인가. None(미실행/미해당)·False 는 미통과로 본다(judge 와 동일)."""
    return getattr(validation, gate, None) is True


def is_fixed(validation) -> bool:
    """6게이트 전부 통과 → FIXED (compute_verdict 와 같은 규칙)."""
    return all(gate_passed(validation, g) for g in GATES)


@dataclass
class ClassPatchStats:
    vuln_class: str
    total: int = 0                                   # 패치+검증까지 간 finding 수
    fixed: int = 0                                   # 6게이트 전부 통과
    gate_pass: dict[str, int] = field(default_factory=lambda: {g: 0 for g in GATES})

    @property
    def fixed_rate(self) -> float:
        return self.fixed / self.total if self.total else 0.0

    def gate_rate(self, gate: str) -> float:
        return self.gate_pass[gate] / self.total if self.total else 0.0


def aggregate_patch_success(
    records: Iterable[tuple[str, object]],
) -> dict[str, ClassPatchStats]:
    """`(vuln_class, validation)` 들 → 클래스별 통계.

    vuln_class 가 None/빈값이면 'unknown' 으로 묶는다(집계에서 조용히 버리지 않음).
    """
    out: dict[str, ClassPatchStats] = {}
    for vuln_class, validation in records:
        key = vuln_class or "unknown"
        stats = out.setdefault(key, ClassPatchStats(vuln_class=key))
        stats.total += 1
        if is_fixed(validation):
            stats.fixed += 1
        for g in GATES:
            if gate_passed(validation, g):
                stats.gate_pass[g] += 1
    return out


def render(stats_by_class: Mapping[str, ClassPatchStats]) -> str:
    """클래스별 FIXED 성공률 + 게이트별 통과율 표."""
    head = f"{'class':<12}{'n':>4}{'FIXED':>8}{'rate':>7}  " + "".join(f"{g[:6]:>8}" for g in GATES)
    lines = ["클래스별 패치 성공률 (verified→FIXED, 6게이트 통과율)", head, "-" * len(head)]
    for key in sorted(stats_by_class):
        s = stats_by_class[key]
        cells = "".join(f"{s.gate_rate(g):>8.2f}" for g in GATES)
        lines.append(f"{s.vuln_class:<12}{s.total:>4}{s.fixed:>8}{s.fixed_rate:>7.2f}  {cells}")
    return "\n".join(lines)
