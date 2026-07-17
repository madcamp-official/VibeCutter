"""P4(Model·Eval) 소유: SCA(OSV-Scanner) candidate 생성.

의존성 취약점(known vulnerable package)을 공통 계약 Candidate 로 정규화한다.
기획서 7.2절 Dependency/SBOM 신호.
"""

from scanners.sca.osv_runner import (
    OSVUnavailableError,
    parse_osv_output,
    run_osv,
)

__all__ = ["OSVUnavailableError", "parse_osv_output", "run_osv"]
