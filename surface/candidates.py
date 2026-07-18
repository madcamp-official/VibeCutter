"""suspect → verifiable Candidate 브리지 (배치 통합 1단계, 7.1→7.3 연결).

`surface.graph.find_idor_suspects`가 준 IDOR 의심 endpoint(패턴)를, `verifiers`가 바로 검증할 수
있는 `contracts.schemas.Candidate`로 바꾼다. 이게 "내가 손으로 candidate를 만들던 일"의 자동화 —
audit 배치가 앱마다 (프리필터 → 이 브리지 → verifier)로 findings를 자동 생산하게 하는 연결 고리.

두 입력을 합친다:
  1. suspect  — 어느 endpoint가 IDOR 의심인가 (패턴, 예: `/vocabs/{vocabulary_id}/words/`)
  2. provisioning — 실제 자원 2개(공격자/피해자)와 base_url·인증 (P2 fixture에서 옴)

provisioning(정규화) 스키마 — P2↔P3 배치 계약:
{
  "base_url": "http://127.0.0.1:14017",
  "auth": {"mode": "none"},          # 또는 {"mode":"bearer","signup_path":...,"token_key":...} 등
  "resources": {
    "vocab": {"attacker_id": 5, "victim_id": 4,
              "victim_marker": "victim-…", "owner_marker": "attacker-…"}
  }
}
프리필터가 여러 vocab endpoint를 찾으면(words/description/public/…), 이 브리지가 자원 id를 각 패턴에
대입해 **fixture가 미리 만들지 않은 endpoint까지** candidate로 만든다(수동 대비 커버리지 확장).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from uuid import uuid4

from contracts.schemas import Candidate

from surface.graph import IdorSuspect

_ID_PLACEHOLDER = re.compile(r"\{[^}]+\}|:[A-Za-z_]\w*|<[^>]+>")


def _singularize(seg: str) -> str:
    seg = seg.strip("/").lower()
    if seg.endswith("ies"):
        return seg[:-3] + "y"
    return seg[:-1] if seg.endswith("s") else seg


def _resource_kind(path: str) -> str:
    """path에서 id 앞 세그먼트를 자원 종류로 추정. /vocabs/{id}/words → 'vocab'."""
    segs = [s for s in path.split("/") if s]
    for i, s in enumerate(segs):
        if _ID_PLACEHOLDER.fullmatch(s) and i > 0:
            return _singularize(segs[i - 1])
    return _singularize(segs[0]) if segs else ""


def _match_resource(kind: str, resources: dict) -> tuple[str, dict] | None:
    """자원 종류를 provisioning.resources에서 fuzzy 매칭 (vocab↔vocabulary 등)."""
    for key, val in resources.items():
        k = key.lower()
        if k == kind or k in kind or kind in k or (len(k) >= 4 and kind[:4] == k[:4]):
            return key, val
    return None


def _substitute_first_id(path: str, value) -> str:
    """path의 첫 id placeholder를 실제 값으로 치환. /vocabs/{id}/words → /vocabs/5/words."""
    return _ID_PLACEHOLDER.sub(str(value), path, count=1)


def normalize_fixture(fixture: dict | str | Path) -> dict:
    """P2 fixture(예: c2-04) → 정규화 provisioning. victim(victim_marker)·attacker(marker) 자원을 뽑는다."""
    data = fixture if isinstance(fixture, dict) else json.loads(Path(fixture).read_text(encoding="utf-8"))
    res = data.get("resources", {})
    victim = next((r for r in res.values() if isinstance(r, dict) and "victim_marker" in r), None)
    attacker = next(
        (r for r in res.values() if isinstance(r, dict) and "victim_marker" not in r and ("marker" in r or "baseline_path" in r)),
        None,
    )
    resources: dict = {}
    if victim and attacker:
        kind = _resource_kind(victim.get("read_path", "")) or "resource"
        resources[kind] = {
            "attacker_id": attacker.get("id"),
            "victim_id": victim.get("id"),
            "victim_marker": victim.get("victim_marker"),
            "owner_marker": attacker.get("marker"),
        }
    return {
        "base_url": data["base_url"],
        "auth": {"mode": data.get("authentication", {}).get("mode", "none")},
        "resources": resources,
    }


def suspects_to_candidates(
    run_id: str, suspects: list[IdorSuspect], provisioning: dict
) -> list[Candidate]:
    """IDOR 의심 endpoint들 + provisioning → 검증 가능한 Candidate 목록.

    자원 종류가 provisioning에 없는 suspect(예: 'user' 자원 미제공)는 검증 불가라 건너뛴다.
    """
    base_url = provisioning["base_url"]
    auth = provisioning.get("auth", {"mode": "none"})
    resources = provisioning.get("resources", {})

    candidates: list[Candidate] = []
    for s in suspects:
        if s.id_signal != "path":  # 경로 id만 자동 치환 가능(쿼리파라미터 BOLA는 후속)
            continue
        kind = _resource_kind(s.endpoint)
        matched = _match_resource(kind, resources)
        if not matched:
            continue  # 이 종류의 seed 자원이 없어 검증 불가 — 배치가 로그로 남기면 됨
        _, rc = matched
        if rc.get("attacker_id") is None or rc.get("victim_id") is None:
            continue

        attack_params = {
            "base_url": base_url,
            "auth_mode": auth.get("mode", "none"),
            "baseline_path": _substitute_first_id(s.endpoint, rc["attacker_id"]),  # 공격자 자기 자원
            "attack_path": _substitute_first_id(s.endpoint, rc["victim_id"]),  # 피해자 자원
            "victim_marker": str(rc.get("victim_marker", "")),
        }
        if rc.get("owner_marker"):
            attack_params["owner_marker"] = str(rc["owner_marker"])
        # 인증 방식별 추가 파라미터(bearer/session)는 auth에 있으면 그대로 실어준다.
        for k in ("signup_path", "path_template", "token_key", "auth_path", "auth_username",
                  "auth_password", "app_username", "app_password"):
            if k in auth:
                attack_params[k] = str(auth[k])

        candidates.append(
            Candidate(
                id=f"cand-{uuid4().hex[:12]}",
                run_id=run_id,
                cwe="CWE-639",
                vuln_class="idor",
                endpoint=s.endpoint,
                source_symbols=[s.file] if s.file else [],
                confidence=s.score,
                attack_params=attack_params,
            )
        )
    return candidates
