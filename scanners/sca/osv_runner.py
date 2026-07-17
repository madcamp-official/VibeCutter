"""OSV-Scanner 실행 → 공통 계약 `Candidate` 정규화 (P4 소유, SCA).

기획서 7.2절 "Dependency/SBOM → known vulnerable package → SCA finding" 신호를
담당한다. SAST(코드 흐름)와 달리 **의존성 취약점**이라 3군(idor/xss/injection) focus
태그를 붙이지 않는다(`signals` 에 `category:sca` 로 구분).

층 분리는 sast.semgrep_runner 와 동일:
- `parse_osv_output(...)` — 순수 함수. osv-scanner `--format json` dict → Candidate[].
  바이너리 없이 fixture(scanners/sca/testdata/sample_osv.json)로 단위 테스트.
- `run_osv(...)` — osv-scanner CLI subprocess 래퍼. 바이너리 없으면 `OSVUnavailableError`.

Candidate 매핑:
  cwe            ← vuln.database_specific.cwe_ids 첫 값(있으면), 없으면 None
  endpoint       ← None (SCA 는 route 무관)
  source_symbols ← ["<lockfile경로>:<pkg>@<version>"]
  confidence     ← severity(HIGH/MODERATE/LOW) 또는 CVSS 점수 → [0,1]
  signals        ← ["sca:osv","category:sca","vuln:<id>","pkg:<name>@<ver>",
                    "ecosystem:<eco>","severity:<sev>","alias:<CVE>"...]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional

from contracts.schemas import Candidate

# osv-scanner 는 lockfile/manifest 를 재귀 탐색한다. 기획서 tech stack 의
# "Trivy/OSV-Scanner(선택)" 중 OSV 를 1차로 통합(경량·JSON·의존성 특화).
_SEVERITY_CONFIDENCE = {"CRITICAL": 0.9, "HIGH": 0.8, "MODERATE": 0.5, "MEDIUM": 0.5, "LOW": 0.3}


class OSVUnavailableError(RuntimeError):
    """osv-scanner CLI 가 PATH 에 없을 때. 밤 SCA 배치는 이 예외를 잡아 스킵/재시도한다."""


def _candidate_id(run_id: str, vuln_id: str, pkg: str, version: str) -> str:
    digest = hashlib.sha1(
        f"{run_id}|{vuln_id}|{pkg}|{version}".encode("utf-8")
    ).hexdigest()[:12]
    return f"cand-sca-{digest}"


def _first_cwe(vuln: dict) -> Optional[str]:
    ds = vuln.get("database_specific") or {}
    cwes = ds.get("cwe_ids")
    if isinstance(cwes, (list, tuple)) and cwes:
        return str(cwes[0])
    return None


def _severity(vuln: dict, group: dict) -> tuple[Optional[str], float]:
    """(라벨, confidence). database_specific.severity 우선, 없으면 group CVSS 점수."""
    ds = vuln.get("database_specific") or {}
    label = ds.get("severity")
    if isinstance(label, str) and label.upper() in _SEVERITY_CONFIDENCE:
        return label.upper(), _SEVERITY_CONFIDENCE[label.upper()]
    # group.max_severity 는 CVSS base score 문자열("7.5") 인 경우가 많다.
    raw = (group or {}).get("max_severity")
    try:
        score = float(raw)
    except (TypeError, ValueError):
        return None, 0.4
    if score >= 9.0:
        return "CRITICAL", 0.9
    if score >= 7.0:
        return "HIGH", 0.8
    if score >= 4.0:
        return "MODERATE", 0.5
    return "LOW", 0.3


def parse_osv_output(data: dict, *, run_id: str) -> list[Candidate]:
    """osv-scanner `--format json` dict → Candidate[]. 순수 함수."""
    candidates: list[Candidate] = []
    for result in data.get("results") or []:
        source_path = ((result.get("source") or {}).get("path")) or "<unknown>"
        for pkg_entry in result.get("packages") or []:
            pkg = pkg_entry.get("package") or {}
            name = pkg.get("name") or "<pkg>"
            version = str(pkg.get("version") or "?")
            ecosystem = pkg.get("ecosystem") or "?"
            # group 은 같은 취약점을 묶는데, severity 조회용으로 첫 group 을 참조.
            groups = pkg_entry.get("groups") or []
            group0 = groups[0] if groups else {}
            for vuln in pkg_entry.get("vulnerabilities") or []:
                vuln_id = vuln.get("id") or "UNKNOWN"
                sev_label, conf = _severity(vuln, group0)
                signals = [
                    "sca:osv",
                    "category:sca",
                    f"vuln:{vuln_id}",
                    f"pkg:{name}@{version}",
                    f"ecosystem:{ecosystem}",
                ]
                if sev_label:
                    signals.append(f"severity:{sev_label}")
                for alias in vuln.get("aliases") or []:
                    if isinstance(alias, str) and alias.startswith("CVE-"):
                        signals.append(f"alias:{alias}")
                candidates.append(
                    Candidate(
                        id=_candidate_id(run_id, vuln_id, name, version),
                        run_id=run_id,
                        cwe=_first_cwe(vuln),
                        endpoint=None,
                        source_symbols=[f"{source_path}:{name}@{version}"],
                        confidence=conf,
                        signals=signals,
                    )
                )
    return candidates


def run_osv(
    target_root: Path | str,
    *,
    run_id: str,
    timeout: int = 600,
    osv_bin: str = "osv-scanner",
) -> list[Candidate]:
    """`osv-scanner --format json -r <root>` 실행 → Candidate[].

    - 바이너리 없으면 OSVUnavailableError.
    - osv-scanner 는 취약점 발견 시 exit code 1 을 낸다(0/1 정상, 그 외 오류).
    """
    root = Path(target_root)
    if not root.exists():
        raise FileNotFoundError(f"target_root 없음: {root}")
    if shutil.which(osv_bin) is None:
        raise OSVUnavailableError(
            f"'{osv_bin}' 가 PATH 에 없음. https://google.github.io/osv-scanner 설치 후 재시도."
        )
    cmd = [osv_bin, "--format", "json", "-r", str(root)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode not in (0, 1):
        raise subprocess.CalledProcessError(
            proc.returncode, cmd, output=proc.stdout, stderr=proc.stderr
        )
    data = json.loads(proc.stdout or "{}")
    return parse_osv_output(data, run_id=run_id)


def _main() -> None:
    parser = argparse.ArgumentParser(description="OSV-Scanner → Candidate[] (P4 SCA)")
    parser.add_argument("--target", help="스캔할 프로젝트 루트")
    parser.add_argument("--run-id", default="run-local")
    parser.add_argument("--fixture", help="osv-scanner json 파일 파싱(오프라인/테스트용)")
    args = parser.parse_args()

    if args.fixture:
        data = json.loads(Path(args.fixture).read_text(encoding="utf-8"))
        cands = parse_osv_output(data, run_id=args.run_id)
    else:
        if not args.target:
            parser.error("--target 또는 --fixture 중 하나는 필요")
        cands = run_osv(args.target, run_id=args.run_id)

    print(json.dumps([c.model_dump(mode="json") for c in cands], ensure_ascii=False, indent=2))
    print(f"\n# {len(cands)}개 Candidate", flush=True)


if __name__ == "__main__":
    _main()
