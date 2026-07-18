"""suspect → verifiable Candidate 브리지 (배치 통합, VERIFIER_BATCH_INTERFACE.md 계약).

`surface.graph.find_idor_suspects`의 IdorSuspect(패턴) + P2 `vc_get_verifier_provisioning`의
`VerifierProvisioning`을 합쳐, verifier가 바로 검증할 typed `Candidate`를 만든다. 계약(문서 §2):

  - strategy=fixture_file  → `candidate_from_fixture(run_id, fixture_path)`로 baseline/attack·marker 채움
                             (+ 같은 자원 종류의 다른 suspect endpoint까지 자원 id 대입으로 확장)
  - strategy=self_signup   → P3가 확인한 signup_path/token_key + suspect endpoint(path_template)로
                             bearer candidate 생성(토큰은 verifier가 메모리에서만 다룸)
  - fixture_contract_required / contract_required → Candidate를 만들지 않고 `blocked`로 남긴다

**endpoint만 보고 공격하지 않는다**(문서 §2). provisioning 정보가 없으면 blocked + 필요한 계약을 남긴다.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel

from contracts.schemas import Candidate
from runtime.provisioning import ProvisioningStrategy, VerifierProvisioning
from surface.graph import IdorSuspect
from verifiers.access_control import candidate_from_fixture

_ID_PLACEHOLDER = re.compile(r"\{[^}]+\}|:[A-Za-z_]\w*|<[^>]+>")

# P3가 확인한 self_signup 앱별 인증 흐름(계약: self_signup은 P3가 signup/token 정보를 제공).
# provisioning은 signup_path/token_key를 담지 않으므로 P3가 여기서(또는 인자로) 준다.
_SELF_SIGNUP_HINTS: dict[str, dict[str, str]] = {
    "26s-w1-c1-05": {"signup_path": "/api/auth/signup", "token_key": "accessToken"},
}


class BlockedTarget(BaseModel):
    """검증 가능한 candidate를 못 만든 target — 필요한 provisioning 계약을 남긴다."""

    target_id: str
    strategy: str
    reason: str
    needed: str


class BridgeResult(BaseModel):
    candidates: list[Candidate] = []
    blocked: list[BlockedTarget] = []


# ── fixture 자원 정규화 + 패턴 치환(확장 커버리지용) ─────────────────────────────────


def _singularize(seg: str) -> str:
    seg = seg.strip("/").lower()
    if seg.endswith("ies"):
        return seg[:-3] + "y"
    return seg[:-1] if seg.endswith("s") else seg


def _resource_kind(path: str) -> str:
    segs = [s for s in path.split("/") if s]
    for i, s in enumerate(segs):
        if _ID_PLACEHOLDER.fullmatch(s) and i > 0:
            return _singularize(segs[i - 1])
    return _singularize(segs[0]) if segs else ""


def _match_resource(kind: str, resources: dict) -> dict | None:
    for key, val in resources.items():
        k = key.lower()
        if k == kind or k in kind or kind in k or (len(k) >= 4 and kind[:4] == k[:4]):
            return val
    return None


def _substitute_first_id(path: str, value) -> str:
    return _ID_PLACEHOLDER.sub(str(value), path, count=1)


def _to_id_template(path: str) -> str:
    """첫 path placeholder를 `{id}`로 정규화 (bearer verifier의 path_template.format(id=...)용)."""
    return _ID_PLACEHOLDER.sub("{id}", path, count=1)


def _fixture_resources(fixture: dict | str | Path) -> dict:
    """P2 fixture에서 victim(victim_marker)·attacker(marker) 자원을 {종류:{ids,markers}}로."""
    data = fixture if isinstance(fixture, dict) else json.loads(Path(fixture).read_text(encoding="utf-8"))
    res = data.get("resources", {})
    victim = next((r for r in res.values() if isinstance(r, dict) and "victim_marker" in r), None)
    attacker = next(
        (r for r in res.values() if isinstance(r, dict) and "victim_marker" not in r and ("marker" in r or "baseline_path" in r)),
        None,
    )
    if not (victim and attacker):
        return {}
    kind = _resource_kind(victim.get("read_path", "")) or "resource"
    return {
        kind: {
            "attacker_id": attacker.get("id"),
            "victim_id": victim.get("id"),
            "victim_marker": victim.get("victim_marker"),
            "owner_marker": attacker.get("marker"),
        }
    }


def _expand_fixture_suspects(run_id, suspects, provisioning, resources) -> list[Candidate]:
    """fixture 자원 id를 suspect 패턴에 대입해, fixture가 미리 안 만든 endpoint까지 candidate로."""
    out: list[Candidate] = []
    for s in suspects:
        if s.id_signal != "path":
            continue
        rc = _match_resource(_resource_kind(s.endpoint), resources)
        if not rc or rc.get("attacker_id") is None or rc.get("victim_id") is None:
            continue
        ap = {
            "base_url": provisioning.base_url,
            "auth_mode": provisioning.auth_mode,
            "baseline_path": _substitute_first_id(s.endpoint, rc["attacker_id"]),
            "attack_path": _substitute_first_id(s.endpoint, rc["victim_id"]),
            "victim_marker": str(rc.get("victim_marker", "")),
        }
        if rc.get("owner_marker"):
            ap["owner_marker"] = str(rc["owner_marker"])
        out.append(
            Candidate(
                id=f"cand-{uuid4().hex[:12]}", run_id=run_id, cwe="CWE-639", vuln_class="idor",
                endpoint=s.endpoint, source_symbols=[s.file] if s.file else [], confidence=s.score,
                attack_params=ap,
            )
        )
    return out


def _bearer_candidate(run_id, suspect, provisioning, signup_path, token_key) -> Candidate:
    n = uuid4().hex[:8]
    return Candidate(
        id=f"cand-{uuid4().hex[:12]}", run_id=run_id, cwe="CWE-639", vuln_class="idor",
        endpoint=suspect.endpoint, source_symbols=[suspect.file] if suspect.file else [],
        confidence=suspect.score,
        attack_params={
            "base_url": provisioning.base_url,
            "auth_mode": "bearer",
            "signup_path": signup_path,
            "path_template": _to_id_template(suspect.endpoint),
            "token_key": token_key,
            "victim_marker": f"vc-owner-{n}",   # verifier가 이 이름으로 피해자 계정을 만든다
            "owner_marker": f"vc-attacker-{n}",  # 공격자 계정
        },
    )


# ── 계약 진입점 ────────────────────────────────────────────────────────────────────


def build_candidates(
    run_id: str,
    provisioning: VerifierProvisioning,
    suspects: list[IdorSuspect],
    *,
    self_signup_hints: dict | None = None,
) -> BridgeResult:
    """VerifierProvisioning + suspects → 검증가능 Candidate 또는 blocked (문서 §2 계약)."""
    strat = provisioning.strategy
    tid = provisioning.target_id

    def blocked(reason: str, needed: str) -> BridgeResult:
        return BridgeResult(blocked=[BlockedTarget(target_id=tid, strategy=str(strat), reason=reason, needed=needed)])

    if strat == ProvisioningStrategy.FIXTURE_FILE:
        if not provisioning.fixture_available or not provisioning.fixture_path:
            return blocked(
                "fixture 아티팩트가 없음(stale/reset)",
                "P1 승인으로 vc_prepare_verifier_fixture(target_id, approved=True) 실행",
            )
        fixture_path = provisioning.fixture_path
        candidates: list[Candidate] = []
        try:
            candidates.append(candidate_from_fixture(run_id, fixture_path))  # 계약 기본 candidate
        except Exception as e:  # noqa: BLE001 — fixture 형식 문제는 blocked로
            return blocked(f"candidate_from_fixture 실패: {e}", "P2 fixture metadata 형식 확인")
        candidates.extend(_expand_fixture_suspects(run_id, suspects, provisioning, _fixture_resources(fixture_path)))
        # baseline/attack 경로 기준 중복 제거
        seen: set[tuple] = set()
        deduped: list[Candidate] = []
        for c in candidates:
            key = (c.attack_params.get("baseline_path"), c.attack_params.get("attack_path"))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(c)
        return BridgeResult(candidates=deduped)

    if strat == ProvisioningStrategy.SELF_SIGNUP:
        hints = self_signup_hints if (self_signup_hints and "signup_path" in self_signup_hints) else _SELF_SIGNUP_HINTS.get(tid)
        if not hints or not hints.get("signup_path"):
            return blocked(
                "self_signup인데 P3의 signup_path/token_key 계약이 없음",
                f"P3가 {tid}의 signup_path·token_key를 _SELF_SIGNUP_HINTS 또는 인자로 제공",
            )
        token_key = hints.get("token_key", "accessToken")
        cands = [
            _bearer_candidate(run_id, s, provisioning, hints["signup_path"], token_key)
            for s in suspects
            if s.id_signal == "path"
        ]
        if not cands:
            return blocked("path-id suspect가 없어 bearer candidate를 만들 수 없음", "프리필터 재확인")
        return BridgeResult(candidates=cands)

    # fixture_contract_required / contract_required
    return blocked(
        "인증/seed 방식 미확정",
        "P3가 필요한 role/resource/endpoint schema를 handoff로 제공 → P2가 fixture 구현",
    )
