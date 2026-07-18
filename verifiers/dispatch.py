"""vuln_class 기반 verifier 라우팅 (D2-P4 최우선 요청 대응).

P4의 SAST가 이제 `candidate.vuln_class`(idor/xss/injection)를 채운다
(`scanners/sast/semgrep_runner.py:171` — "P3 verifier가 vuln_class로 검증 모듈을 분기"). 그래서
verifier 선택을 `signals` 문자열 파싱이 아니라 typed `vuln_class`로 한다. 후보의 공격 파라미터도
typed `attack_params`에서 읽는다(`access_control.probe_from_candidate`) — D1-P3 이견1 / D2-P3
signals 우회 제거.

verify 대상 후보는 raw 목록이 아니라 `scanners.aggregate.aggregate(...).kept`(중복·FP 제거·
우선순위순, P4 소유)를 순회하면 된다 — kept의 원소는 그대로 `contracts.schemas.Candidate`다.

P1은 이 `verify_candidate`를 단일 진입점으로 쓰거나(aggregate.kept 순회), 기존 per-class tool
(`vc_verify_access_control` 등)을 유지해도 된다 — 둘 다 결국 같은 함수(access_control.verify)를 부른다.
"""

from __future__ import annotations

from contracts.schemas import Candidate
from verifiers import access_control, xss
from verifiers.types import MAX_REQUESTS_DEFAULT, VerifierOutput

def _idor_verifier(
    run_id: str,
    candidate: Candidate,
    *,
    max_requests: int = MAX_REQUESTS_DEFAULT,
) -> VerifierOutput:
    """IDOR 후보를 read/write oracle로 분기한다.

    `attack_params.idor_mode == "write"`면 상태변화(write) oracle(`verify_mutation_access_control`)로,
    아니면 read oracle(`verify`)로 보낸다. write 후보는 `surface.candidates.write_candidate_from_fixture`가
    `idor_mode=write`로 표시한다. 표시가 없는 기존 read 후보는 그대로 read verify로 간다(하위호환).
    """
    if candidate.attack_params.get("idor_mode") == "write":
        return access_control.verify_mutation_access_control(run_id, candidate, max_requests=max_requests)
    return access_control.verify(run_id, candidate, max_requests=max_requests)


# 구현된 verifier만 등록. injection은 아직 스캐폴딩(verifiers/injection.py, docstring뿐).
_VERIFIERS = {
    "idor": _idor_verifier,
    "xss": xss.verify,  # 격리 브라우저 실행 oracle (verifiers/xss.py)
}
_NOT_READY = frozenset({"injection"})

# vuln_class가 비어 있을 때 CWE로 보정(SAST는 채우지만 hand-built 후보 대비).
_CWE_TO_CLASS = {
    "CWE-639": "idor",  # Authorization Bypass Through User-Controlled Key (IDOR)
    "CWE-284": "idor",  # Improper Access Control
    "CWE-862": "idor",  # Missing Authorization
    "CWE-863": "idor",  # Incorrect Authorization
    "CWE-566": "idor",  # Authorization Bypass Through User-Controlled SQL Primary Key
    "CWE-79": "xss",
    "CWE-89": "injection",
    "CWE-78": "injection",
}


def class_of(candidate: Candidate) -> str | None:
    """후보의 취약점군을 판별한다. typed vuln_class 우선, 없으면 CWE로 보정."""
    if candidate.vuln_class:
        return candidate.vuln_class
    return _CWE_TO_CLASS.get(candidate.cwe or "")


def verify_candidate(
    run_id: str,
    candidate: Candidate,
    *,
    max_requests: int = MAX_REQUESTS_DEFAULT,
) -> VerifierOutput:
    """candidate.vuln_class로 알맞은 verifier를 골라 호출한다.

    실패/예외:
      - 미구현 군(xss/injection) → `NotImplementedError`
      - 판별 불가(vuln_class·cwe 둘 다 매칭 안 됨) → `ValueError` (추측으로 아무 verifier나 부르지 않는다)
    """
    vuln = class_of(candidate)
    verifier = _VERIFIERS.get(vuln)
    if verifier is not None:
        return verifier(run_id, candidate, max_requests=max_requests)
    if vuln in _NOT_READY:
        raise NotImplementedError(f"{vuln} verifier는 아직 미구현 (verifiers/{vuln}.py 스캐폴딩 단계)")
    raise ValueError(
        f"vuln_class를 판별할 수 없어 verifier를 고를 수 없다 "
        f"(vuln_class={candidate.vuln_class!r}, cwe={candidate.cwe!r})"
    )
