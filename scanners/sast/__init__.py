"""P4(Model·Eval) 소유: SAST(Semgrep) candidate 생성.

Semgrep 결과를 공통 계약 `contracts.schemas.Candidate` 로 정규화한다.
기획서 7.2절(Candidate Generation), 12.2절 B1 baseline, docs/handoffs/D1-P1.md 의
`vc_run_sast → Candidate[]` 계약을 근거로 한다.
"""

from scanners.sast.semgrep_runner import (
    FOCUS_RULESETS,
    SemgrepUnavailableError,
    parse_semgrep_output,
    run_semgrep,
)

__all__ = [
    "FOCUS_RULESETS",
    "SemgrepUnavailableError",
    "parse_semgrep_output",
    "run_semgrep",
]
