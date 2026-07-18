"""Semgrep 실행 → 공통 계약 `Candidate` 정규화 (P4 소유).

두 개의 층으로 나눈다:

- `parse_semgrep_output(...)` — **순수 함수**. semgrep `--json` 산출물(dict)을
  `contracts.schemas.Candidate[]` 로 매핑한다. semgrep 바이너리 없이도
  fixture 로 단위 테스트 가능(scanners/sast/testdata/sample_semgrep.json).
- `run_semgrep(...)` — semgrep CLI 를 subprocess 로 호출하는 얇은 래퍼.
  바이너리가 없으면 `SemgrepUnavailableError`.

계약 근거: docs/handoffs/D1-P1.md (`vc_run_sast → Candidate[]`), 기획서 7.2절
(SAST 신호 = 사용자 입력이 SQL/HTML/command sink 로 흐름 → 후보 생성).

Candidate 필드 매핑:
  cwe            ← semgrep result.extra.metadata.cwe (첫 CWE-NNN 만 정규화)
  endpoint       ← None (SAST 는 route 를 모른다; P3 route mapper 가 채운다)
  source_symbols ← ["<path>:<start_line>"]
  confidence     ← severity + metadata.confidence 를 [0,1] 로 매핑
  signals        ← ["semgrep:<rule_id>", "severity:<sev>", "focus:<group>", ...]

MCP 배선(`mcp_server/tools_analysis.py` 의 vc_run_sast)은 P1 소유 스켈레톤이라
여기서 건드리지 않는다. P1 은 `run_semgrep(target_root, run_id)` 를 그대로 호출하면
`Candidate[]` 를 받는다(docs/handoffs/D1-P4.md 참조).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable, Optional

from contracts.schemas import Candidate

# 3군(cowork_rule 3절 focus)별 semgrep registry 규칙 셋. 최종 실행 규칙은 P4 가
# 조정하되, 여기 매핑으로 각 finding 을 focus 그룹에 태깅한다.
FOCUS_RULESETS: dict[str, tuple[str, ...]] = {
    "injection": ("p/sql-injection", "p/command-injection"),
    "xss": ("p/xss",),
    "idor": ("p/insecure-access-control",),
}

# semgrep severity → confidence 기본값. metadata.confidence(HIGH/MEDIUM/LOW)가
# 있으면 그걸 우선한다.
_SEVERITY_CONFIDENCE = {"ERROR": 0.8, "WARNING": 0.5, "INFO": 0.3}
_METADATA_CONFIDENCE = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.35}

# CWE 번호 → 3군. 가장 정확한 신호라 먼저 본다. (OWASP A03 "Injection" 범주는
# XSS 까지 포함해 너무 거칠어서 focus 추론에는 쓰지 않는다.)
_CWE_TO_FOCUS = {
    "CWE-79": "xss",
    "CWE-80": "xss",
    "CWE-83": "xss",
    "CWE-89": "injection",  # SQL
    "CWE-78": "injection",  # OS command
    "CWE-77": "injection",  # command
    "CWE-90": "injection",  # LDAP
    "CWE-943": "injection",  # NoSQL
    "CWE-639": "idor",  # BOLA/IDOR
    "CWE-862": "idor",  # missing authorization
    "CWE-863": "idor",  # incorrect authorization
    "CWE-284": "idor",  # improper access control
    "CWE-285": "idor",  # improper authorization
    "CWE-566": "idor",
}

# CWE 로 못 잡으면 rule_id/category 문자열 부분 매칭으로 폴백. 순서 = 우선순위.
_KEYWORD_TO_FOCUS = (
    ("xss", "xss"),
    ("cross-site-scripting", "xss"),
    ("sql-injection", "injection"),
    ("sqli", "injection"),
    ("command-injection", "injection"),
    ("injection", "injection"),
    ("access-control", "idor"),
    ("broken-access", "idor"),
    ("authorization", "idor"),
    ("idor", "idor"),
)


class SemgrepUnavailableError(RuntimeError):
    """semgrep CLI 가 PATH 에 없을 때. D1 밤 배치는 이 예외를 잡아 스킵/재시도한다."""


def _candidate_id(run_id: str, rule_id: str, path: str, start_line: int) -> str:
    """(rule, 위치) 기준 결정적 id. 재현성(cowork_rule 4절) + 재실행 시 dedup 용."""
    digest = hashlib.sha1(
        f"{run_id}|{rule_id}|{path}|{start_line}".encode("utf-8")
    ).hexdigest()[:12]
    return f"cand-sast-{digest}"


def _normalize_cwe(raw: Any) -> Optional[str]:
    """metadata.cwe 는 "CWE-89: ..." 또는 그 list. 첫 값에서 'CWE-89' 만 뽑는다."""
    if isinstance(raw, (list, tuple)):
        raw = raw[0] if raw else None
    if not isinstance(raw, str):
        return None
    token = raw.strip().split(":", 1)[0].strip()
    return token or None


def _infer_focus(rule_id: str, metadata: dict, ruleset_focus: Optional[str]) -> Optional[str]:
    """focus 추론 우선순위: 실행 규칙셋 > CWE 번호 > rule_id/category 키워드."""
    if ruleset_focus in FOCUS_RULESETS:
        return ruleset_focus
    for raw in _as_iterable(metadata.get("cwe")):
        cwe = _normalize_cwe(raw)
        if cwe in _CWE_TO_FOCUS:
            return _CWE_TO_FOCUS[cwe]
    haystack = f"{rule_id.lower()} {str(metadata.get('category', '')).lower()}"
    for needle, focus in _KEYWORD_TO_FOCUS:
        if needle in haystack:
            return focus
    return None


def _as_iterable(value: Any) -> Iterable[Any]:
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return value
    return (value,)


def _confidence(severity: str, metadata: dict) -> float:
    md_conf = str(metadata.get("confidence", "")).upper()
    if md_conf in _METADATA_CONFIDENCE:
        return _METADATA_CONFIDENCE[md_conf]
    return _SEVERITY_CONFIDENCE.get(severity.upper(), 0.4)


def parse_semgrep_output(
    data: dict,
    *,
    run_id: str,
    ruleset_focus: Optional[str] = None,
) -> list[Candidate]:
    """semgrep `--json` dict → Candidate[]. 순수 함수(부작용/네트워크 없음).

    ruleset_focus: 이 실행이 특정 focus 규칙셋(FOCUS_RULESETS)으로 돌았다면 그 값을
    넘겨 모든 finding 을 해당 그룹으로 태깅. 여러 규칙셋을 한 번에 돌렸으면 None.
    """
    results = data.get("results") or []
    candidates: list[Candidate] = []
    for r in results:
        rule_id = r.get("check_id") or "unknown-rule"
        path = r.get("path") or "<unknown>"
        start_line = int((r.get("start") or {}).get("line") or 0)
        extra = r.get("extra") or {}
        metadata = extra.get("metadata") or {}
        severity = str(extra.get("severity") or "INFO")

        focus = _infer_focus(rule_id, metadata, ruleset_focus)
        signals = [f"semgrep:{rule_id}", f"severity:{severity.upper()}"]
        if focus:
            signals.append(f"focus:{focus}")
        owasp = list(_as_iterable(metadata.get("owasp")))
        if owasp:
            signals.append(f"owasp:{owasp[0]}")

        candidates.append(
            Candidate(
                id=_candidate_id(run_id, rule_id, path, start_line),
                run_id=run_id,
                cwe=_normalize_cwe(metadata.get("cwe")),
                vuln_class=focus,  # P3 verifier 가 vuln_class 로 검증 모듈을 분기(verifiers/types.py)
                endpoint=None,
                source_symbols=[f"{path}:{start_line}"],
                confidence=_confidence(severity, metadata),
                signals=signals,
            )
        )
    return candidates


def run_semgrep(
    target_root: Path | str,
    *,
    run_id: str,
    config: str = "auto",
    ruleset_focus: Optional[str] = None,
    timeout: int = 600,
    semgrep_bin: str = "semgrep",
) -> list[Candidate]:
    """`semgrep --json` 을 target_root 에서 실행하고 Candidate[] 로 반환.

    - 바이너리가 없으면 SemgrepUnavailableError.
    - semgrep 은 정상 종료(0)든 finding 발견(1)이든 JSON 을 stdout 으로 낸다.
      그 외 종료코드는 stderr 와 함께 CalledProcessError.
    - stdout 에는 반드시 JSON 만 온다(--json). MCP 서버 stdout 오염과는 무관하게
      subprocess 캡처라 안전.
    """
    root = Path(target_root)
    if not root.exists():
        raise FileNotFoundError(f"target_root 없음: {root}")
    if shutil.which(semgrep_bin) is None:
        raise SemgrepUnavailableError(
            f"'{semgrep_bin}' 가 PATH 에 없음. `pip install semgrep` 후 재시도."
        )

    cmd = [semgrep_bin, "--json", "--quiet", "--config", config, str(root)]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if proc.returncode not in (0, 1):  # 0=clean, 1=findings; 그 외=실제 오류
        raise subprocess.CalledProcessError(
            proc.returncode, cmd, output=proc.stdout, stderr=proc.stderr
        )
    data = json.loads(proc.stdout or "{}")
    return parse_semgrep_output(data, run_id=run_id, ruleset_focus=ruleset_focus)


def _main() -> None:
    parser = argparse.ArgumentParser(description="Semgrep → Candidate[] (P4 SAST)")
    parser.add_argument("--target", help="스캔할 소스 루트 경로")
    parser.add_argument("--run-id", default="run-local", help="Candidate.run_id 값")
    parser.add_argument("--config", default="auto", help="semgrep --config (기본 auto)")
    parser.add_argument("--focus", choices=sorted(FOCUS_RULESETS), help="focus 태깅")
    parser.add_argument(
        "--fixture",
        help="semgrep 바이너리 대신 기존 --json 파일을 파싱(오프라인/테스트용)",
    )
    args = parser.parse_args()

    if args.fixture:
        data = json.loads(Path(args.fixture).read_text(encoding="utf-8"))
        cands = parse_semgrep_output(data, run_id=args.run_id, ruleset_focus=args.focus)
    else:
        if not args.target:
            parser.error("--target 또는 --fixture 중 하나는 필요")
        cands = run_semgrep(
            args.target, run_id=args.run_id, config=args.config, ruleset_focus=args.focus
        )

    print(json.dumps([c.model_dump(mode="json") for c in cands], ensure_ascii=False, indent=2))
    print(f"\n# {len(cands)}개 Candidate", flush=True)


if __name__ == "__main__":
    _main()
