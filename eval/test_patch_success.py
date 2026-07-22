"""eval.patch_success 단위 테스트 (M2). 실행: python -m eval.test_patch_success"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from eval.patch_success import GATES, aggregate_patch_success, is_fixed, render


@dataclass
class _Val:
    """Validation 스텁 — 6게이트 bool 속성만 있으면 된다."""
    build: Optional[bool] = True
    attack: Optional[bool] = True
    positive_test: Optional[bool] = True
    regression: Optional[bool] = True
    static: Optional[bool] = True
    scope: Optional[bool] = True


def test_is_fixed_requires_all_gates_true() -> None:
    assert is_fixed(_Val())                          # 전부 True
    assert not is_fixed(_Val(attack=False))          # 하나 False
    assert not is_fixed(_Val(static=None))           # None 도 미통과(judge 규칙)


def test_gate_field_names_match_judge() -> None:
    from core.judge import _GATE_FIELDS
    assert GATES == _GATE_FIELDS                      # 계약 일치(드리프트 방지)


def test_aggregate_per_class_fixed_rate() -> None:
    records = [
        ("idor", _Val()),                            # FIXED
        ("idor", _Val(attack=False)),                # 공격 게이트 실패 → not fixed
        ("injection", _Val()),                       # FIXED
    ]
    stats = aggregate_patch_success(records)
    assert stats["idor"].total == 2 and stats["idor"].fixed == 1
    assert stats["idor"].fixed_rate == 0.5
    assert stats["injection"].fixed_rate == 1.0
    # 게이트별: idor 의 attack 통과율 = 1/2
    assert stats["idor"].gate_rate("attack") == 0.5
    assert stats["idor"].gate_rate("build") == 1.0   # 둘 다 build 통과


def test_none_class_bucketed_as_unknown() -> None:
    stats = aggregate_patch_success([(None, _Val()), ("", _Val())])
    assert stats["unknown"].total == 2


def test_render_has_per_class_rows() -> None:
    out = render(aggregate_patch_success([("xss", _Val()), ("idor", _Val(scope=False))]))
    assert "xss" in out and "idor" in out and "FIXED" in out


def _run() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")


if __name__ == "__main__":
    _run()
