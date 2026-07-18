"""정적 attack-surface 기반 IDOR 탐지 후보 (P4, B1 baseline 개선 ①).

배경: B1(Semgrep-only) 실측에서 **IDOR = 0/13**. SAST 는 인가(authz) 로직을 이해 못 해
IDOR 를 구조적으로 못 잡는다(eval/results/B1_baseline.md). 그 빈칸을 메우려고, P3 의
정적 프리필터 `surface.graph.find_idor_suspects(source_root)`(소스만으로 IDOR 의심
endpoint 추출)를 **P4 candidate 형식으로 변환**한다.

주의:
- 이건 **정적 탐지 후보(suspect)** 지 verified 가 아니다 — 실제 IDOR 여부는 P3 verifier +
  role fixture 로 동적 확인해야 한다(surface/candidates.py 의 런타임 경로). 여기 후보는
  "verify 대상 목록"을 SAST 밖에서 공급하는 역할(detection recall 개선).
- P3 소유 파일은 건드리지 않는다 — `find_idor_suspects` 를 읽기 전용으로 소비만 한다.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from contracts.schemas import Candidate
from surface.graph import find_idor_suspects


def _cand_id(run_id: str, file: str, endpoint: str) -> str:
    h = hashlib.sha1(f"{run_id}|{file}|{endpoint}".encode()).hexdigest()[:12]
    return f"cand-surface-{h}"


def run_surface_idor(
    source_root: str | Path, *, run_id: str, min_score: float = 0.0,
) -> list[Candidate]:
    """source_root 정적 분석 → IDOR 탐지 후보(vuln_class=idor). run_semgrep 과 같은 계약.

    min_score: IdorSuspect.score 하한(노이즈 컷). 기본 0(전부).
    """
    out: list[Candidate] = []
    for s in find_idor_suspects(source_root):
        if s.score < min_score:
            continue
        # score(대략 0~1+) → confidence(0~1) 클램프.
        conf = max(0.0, min(1.0, s.score))
        signals = [
            "focus:idor",
            f"surface:{s.id_signal}",       # path | signature
            f"score:{s.score:.3f}",
        ]
        if s.id_param:
            signals.append(f"id_param:{s.id_param}")
        out.append(
            Candidate(
                id=_cand_id(run_id, s.file, s.endpoint),
                run_id=run_id,
                cwe="CWE-639",              # Authorization Bypass Through User-Controlled Key
                vuln_class="idor",
                confidence=conf,
                endpoint=s.endpoint,
                source_symbols=[s.file] if s.file else [],
                signals=signals,
            )
        )
    return out
