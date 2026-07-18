"""suspect → verifiable Candidate 브리지 (배치 통합, VERIFIER_BATCH_INTERFACE.md 계약).

`surface.graph.find_idor_suspects`의 IdorSuspect(패턴) + P2 `vc_get_verifier_provisioning`의
`VerifierProvisioning`을 합쳐, verifier가 바로 검증할 typed `Candidate`를 만든다. 계약(문서 §2):

  - strategy=fixture_file  → `candidate_from_fixture(run_id, fixture_path)`로 baseline/attack·marker 채움
                             (+ 같은 자원 종류의 다른 suspect endpoint까지 자원 id 대입으로 확장)
                             (+ fixture에 `safe_mutation`이 있으면 write-IDOR candidate도 추가 —
                                `write_candidate_from_fixture`, idor_mode=write로 표시)
  - strategy=self_signup   → P3가 확인한 signup_path/token_key + suspect endpoint(path_template)로
                             bearer candidate 생성(토큰은 verifier가 메모리에서만 다룸)
  - fixture_contract_required / contract_required → Candidate를 만들지 않고 `blocked`로 남긴다

read-IDOR("남의 걸 봤나")와 write-IDOR("남의 걸 바꿨나")를 둘 다 만든다. write는 dispatch가
`verify_mutation`으로 라우팅한다(현재 무인증 fixture_file만 — 인증 write는 후속 계약).

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
from surface.graph import IdorSuspect, find_idor_suspects
from verifiers.access_control import candidate_from_fixture, mutation_probe_from_fixture

_ID_PLACEHOLDER = re.compile(r"\{[^}]+\}|:[A-Za-z_]\w*|<[^>]+>")

# P3가 확인한 self_signup 앱별 인증 흐름(계약: self_signup은 P3가 signup/token 정보를 제공).
# provisioning은 signup_path/token_key를 담지 않으므로 P3가 여기서(또는 인자로) 준다.
_SELF_SIGNUP_HINTS: dict[str, dict[str, str]] = {
    "26s-w1-c1-05": {"signup_path": "/api/auth/signup", "token_key": "accessToken"},
    # P2가 실제 FastAPI source와 local runtime에서 확인한 c2-01 계약. tokens/passwords는
    # 여기나 Candidate에 저장하지 않고 verifier 런타임에서만 생성한다.
    "26s-w1-c2-01": {
        "signup_path": "/api/v1/auth/signup",
        "signup_body_json": '{"email":"{email}","password":"{password}","name":"{name}"}',
        "login_path": "/api/v1/auth/login",
        "login_body_json": '{"email":"{email}","password":"{password}"}',
        "token_key": "access_token",
        "owner_setup_path": "/api/v1/workspaces",
        "owner_setup_body_json": '{"name":"{marker}"}',
        "path_template": "/api/v1/workspaces/{id}",
        "candidate_handlers": "get_detail",
    },
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
    """P2 fixture에서 victim/attacker 자원을 {종류:{ids,markers}}로.

    새 fixture는 `resources.<kind>.attacker_id/victim_id/...` 형태를 우선 사용한다.
    D1/D2 c2-04 fixture의 legacy `victim_*`/`attacker_*` 분리 형태도 계속 지원한다.
    """
    data = fixture if isinstance(fixture, dict) else json.loads(Path(fixture).read_text(encoding="utf-8"))
    res = data.get("resources", {})
    for key, val in res.items():
        if not isinstance(val, dict):
            continue
        if {"attacker_id", "victim_id", "victim_marker", "owner_marker"} <= set(val):
            return {
                str(val.get("kind") or key): {
                    "attacker_id": val["attacker_id"],
                    "victim_id": val["victim_id"],
                    "victim_marker": val["victim_marker"],
                    "owner_marker": val["owner_marker"],
                }
            }

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


def write_candidate_from_fixture(run_id: str, fixture: dict | str | Path) -> Candidate | None:
    """fixture의 `safe_mutation` → write-IDOR Candidate (없으면 None).

    read `candidate_from_fixture`의 write 짝. verifier의 `mutation_probe_from_fixture`로
    MutationProbe(안전·되돌릴 수 있는 변경만)를 얻어, P1의 `mutation_probe_from_candidate` 계약
    키로 typed `attack_params`에 담는다:
      - `extra_body`(중첩 dict)는 attack_params가 dict[str,str]이라 `extra_body_json`에 JSON으로 담는다.
      - `mutation_marker`도 candidate에 담는다(P1 계약: write tool/dispatch가 이 값을 그대로 읽음).
    `idor_mode=write`로 표시해 dispatch(`verify_candidate`)가 write oracle로 라우팅하게 한다.
    observe_path는 `mutation_probe_from_fixture`가 fixture의 `safe_mutation.observe_path`를 우선 쓴다(P2 f4b08e5).
    """
    try:
        probe = mutation_probe_from_fixture(fixture)
    except (ValueError, KeyError):
        return None  # safe_mutation 미선언 → write 후보 없음(정상)
    ap = {
        "base_url": probe.base_url,
        "observe_path": probe.observe_path,
        "mutation_method": probe.mutation_method,
        "mutation_path": probe.mutation_path,
        "mutation_marker": probe.mutation_marker,  # P1 계약: candidate에 담는다
        "marker_field": probe.marker_field,
        "extra_body_json": json.dumps(probe.extra_body, ensure_ascii=False),  # P1 계약 키명
        "idor_mode": "write",  # dispatch 라우팅용
    }
    return Candidate(
        id=f"cand-{uuid4().hex[:12]}", run_id=run_id, cwe="CWE-639", vuln_class="idor",
        endpoint=probe.mutation_path, source_symbols=[], attack_params=ap,
    )


def _bearer_candidate(run_id, suspect, provisioning, hints: dict[str, str]) -> Candidate:
    n = uuid4().hex[:8]
    # username validation에도 통과하도록 하이픈 없는 marker를 쓴다.
    victim_marker = f"vcowner{n}"
    owner_marker = f"vcattacker{n}"
    params = {
        "base_url": provisioning.base_url,
        "auth_mode": "bearer",
        "signup_path": hints["signup_path"],
        "path_template": hints.get("path_template", _to_id_template(suspect.endpoint)),
        "token_key": hints.get("token_key", "accessToken"),
        "victim_marker": victim_marker,
        "owner_marker": owner_marker,
    }
    for key in (
        "signup_body_json", "login_path", "login_body_json", "owner_setup_path",
        "owner_setup_body_json", "resource_id_key",
    ):
        if hints.get(key):
            params[key] = hints[key]
    return Candidate(
        id=f"cand-{uuid4().hex[:12]}", run_id=run_id, cwe="CWE-639", vuln_class="idor",
        endpoint=hints.get("path_template", suspect.endpoint), source_symbols=[suspect.file] if suspect.file else [],
        confidence=suspect.score,
        attack_params=params,
    )


# ── 계약 진입점 ────────────────────────────────────────────────────────────────────


def candidates_for_target(
    run_id: str,
    provisioning: VerifierProvisioning,
    source_root: str | Path,
    *,
    self_signup_hints: dict | None = None,
) -> BridgeResult:
    """target 하나 → IDOR candidates(또는 blocked). MCP map/scan tool·배치가 부를 단일 진입점.

    `find_idor_suspects(source_root)` + `build_candidates(...)`를 한 번에 묶는다. P1 tool 배선은
    `catalog.source_root_for(target_id)`와 `vc_get_verifier_provisioning(target_id)`만 넘기면 된다.
    """
    suspects = find_idor_suspects(source_root)
    return build_candidates(run_id, provisioning, suspects, self_signup_hints=self_signup_hints)


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
        # baseline/attack 경로 기준 중복 제거 (read 후보)
        seen: set[tuple] = set()
        deduped: list[Candidate] = []
        for c in candidates:
            key = (c.attack_params.get("baseline_path"), c.attack_params.get("attack_path"))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(c)
        # write-IDOR: fixture에 safe_mutation이 있으면 write 후보도 추가(read와 별개 oracle)
        write_cand = write_candidate_from_fixture(run_id, fixture_path)
        if write_cand is not None:
            deduped.append(write_cand)
        return BridgeResult(candidates=deduped)

    if strat == ProvisioningStrategy.SELF_SIGNUP:
        hints = self_signup_hints if (self_signup_hints and "signup_path" in self_signup_hints) else _SELF_SIGNUP_HINTS.get(tid)
        if not hints or not hints.get("signup_path"):
            return blocked(
                "self_signup인데 P3의 signup_path/token_key 계약이 없음",
                f"P3가 {tid}의 signup_path·token_key를 _SELF_SIGNUP_HINTS 또는 인자로 제공",
            )
        allowed_handlers = set(hints.get("candidate_handlers", "").split(",")) - {""}
        cands = [
            _bearer_candidate(run_id, s, provisioning, hints)
            for s in suspects
            if s.id_signal == "path" and (not allowed_handlers or s.handler in allowed_handlers)
        ]
        if not cands:
            return blocked("path-id suspect가 없어 bearer candidate를 만들 수 없음", "프리필터 재확인")
        return BridgeResult(candidates=cands)

    # fixture_contract_required / contract_required
    return blocked(
        "인증/seed 방식 미확정",
        "P3가 필요한 role/resource/endpoint schema를 handoff로 제공 → P2가 fixture 구현",
    )
