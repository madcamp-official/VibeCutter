"""Broken Access Control / IDOR verifier (7.3절, CWE-639). P0 — MVP의 승부처.

검증 oracle (7.3절 표): "역할 A가 만든 자원을 역할 B가 읽거나 변경했는지 DB/API 상태 비교".
즉 응답 코드 200 하나로 verified를 만들지 않는다 — 공격자로 요청했는데 응답에 피해자의
데이터가 담겨 나오는지를 baseline과 비교해서 판정한다.

11.5절 P0 / 16장: IDOR 한 종류라도 발견→재현→코드 위치→패치→재공격→정상 기능 통과.

────────────────────────────────────────────────────────────────────────────
구성 (D2에 3덩어리로 분리, D3에 재현을 auth_mode로 일반화)
────────────────────────────────────────────────────────────────────────────
  ① idor_oracle()   — 판정 로직. **대상/언어/인증 방식과 무관**하게 응답 body만 본다. 재사용.
  ② 재현(_replay_*) — HTTP 재현. 갈리는 축은 언어가 아니라 **인증 방식(auth_mode)**이다:
        - "none"         : 인증 없는 식별자-스왑 (예: 26s-w1-c2-04 WordNote — 토큰/세션 없음)
        - "session_form" : 폼 로그인 + 세션 쿠키 (예: WebGoat)
     대상별 endpoint/ID/marker는 코드에 박지 않고 candidate(=P2 fixture 메타데이터)에서 온다.
  ③ verify()        — 조립 + evidence 저장.

즉 앱이 21개여도 verifier는 언어(Spring/FastAPI/Node…)를 몰라도 되고 인증 패턴 몇 개만
지원하면 된다. 언어에 의존하는 건 route 추출(surface/routes.py)과 patch 합성
(repair/patcher.py)이지 verifier가 아니다.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from uuid import uuid4

import httpx
from pydantic import BaseModel

from contracts.schemas import Candidate
from core import evidence_store
from verifiers.types import MAX_REQUESTS_DEFAULT, VerifierOutput

PRODUCER = "vc_verify_access_control"


# --- secret redaction --------------------------------------------------------------
# evidence_store 저장계층이 이제 동일 redaction을 걸지만(P1 구멍 ② 수정), 저장 직전 이중
# 방어는 idempotent하고 무해하다. 제거 시점은 P1과 협의(Day5 하드닝 예정).
_REDACTIONS = [
    (re.compile(r"(JSESSIONID=)[^;\s\"]+"), r"\1<redacted>"),
    (re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]+"), r"\1<redacted>"),
    (re.compile(r'("?(?:password|matchingPassword)"?\s*[=:]\s*"?)[^&"\s,}]+'), r"\1<redacted>"),
]


def redact(text: str) -> str:
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


# --- ① IDOR oracle (핵심, 대상/언어/인증 무관) ----------------------------------------


def idor_oracle(baseline_body: str, attack_body: str, victim_marker: str) -> tuple[bool, str]:
    """공격 응답이 피해자 자원을 노출했는지 판정한다.

    verified 조건 (셋 다 만족):
      1. 공격 응답에 victim_marker(피해자만 가진 값)가 들어있다.
      2. baseline 응답(공격자 자기 자원)에는 그 marker가 없다 — 원래 못 보던 걸 봤다는 뜻.
      3. 두 응답이 실제로 다르다 — 서버가 요청 무시하고 같은 걸 돌려준 게 아니다.

    "200이 떴다"만으로 verified 하지 않는다(D1-P3.md 구멍 ①). 판정 근거를 응답 내용에 둔다.
    """
    marker_in_attack = victim_marker in attack_body
    marker_in_baseline = victim_marker in baseline_body
    differ = baseline_body.strip() != attack_body.strip()

    if marker_in_attack and not marker_in_baseline and differ:
        return True, (
            f"공격자 요청에 응답으로 피해자 마커 {victim_marker!r}가 노출됨"
            f" (baseline 응답에는 없음). 수평 권한 통제 부재 (CWE-639)."
        )
    if marker_in_attack and marker_in_baseline:
        return False, f"marker {victim_marker!r}가 baseline에도 있어 피해자 고유 데이터로 볼 수 없음"
    if not differ:
        return False, "공격/baseline 응답이 동일 — 서버가 요청한 자원을 반영하지 않음"
    return False, f"응답에 피해자 마커 {victim_marker!r}가 없음 — 접근이 차단된 것으로 보임"


# --- probe: 재현에 필요한 입력 --------------------------------------------------------


class IdorProbe(BaseModel):
    """IDOR 재현에 실제로 필요한 입력. 대상별 값은 candidate.signals 또는 P2 fixture에서 온다.

    auth_mode에 따라 필요한 필드가 다르다:
      - "none"         : base_url, baseline_path, attack_path, victim_marker (owner_marker 선택)
      - "session_form" : 위 + app_username/app_password/auth_path/auth_username/auth_password
    """

    base_url: str
    auth_mode: str = "session_form"  # "none" | "session_form" | "bearer" (기본은 D2 WebGoat 호환)
    # none/session_form은 baseline_path/attack_path를 직접 받고, bearer는 path_template+생성 id로 런타임에 만든다.
    baseline_path: str | None = None  # 공격자 자기 자원
    attack_path: str | None = None  # 피해자 자원
    victim_marker: str  # attack 응답에 이게 보이면 피해자 데이터
    owner_marker: str | None = None  # baseline 응답에 있어야 정상기능 OK (repair/validators.py)

    # --- session_form 전용 (none 모드면 불필요) ---
    app_username: str | None = None
    app_password: str | None = None
    auth_path: str | None = None
    auth_username: str | None = None
    auth_password: str | None = None

    # --- bearer 전용 (JWT 토큰 인증 앱, 예: c1-05 Scrum Helper) ---
    # 자체 provision: 회원가입 2명(이름=victim_marker/owner_marker) → 공격자 토큰으로 재현.
    # 토큰은 재현 중 메모리에만 있고 candidate/evidence에 저장되지 않는다(secret 위생).
    signup_path: str | None = None  # 예: /api/auth/signup ({name,email,password} → data.accessToken/data.user.id)
    path_template: str | None = None  # 예: /api/users/{id}/profile — {id}에 생성된 사용자 id를 넣는다
    token_key: str = "accessToken"  # 회원가입 응답에서 JWT를 찾을 key
    # 서로 다른 가입/로그인 DTO를 쓰는 앱을 위한 no-secret JSON 템플릿. `{email}`, `{name}`,
    # `{username}`, `{marker}`, `{password}`만 런타임에 치환하며 후보/evidence에는 비밀번호를 남기지 않는다.
    signup_body_json: str | None = None
    login_path: str | None = None
    login_body_json: str | None = None
    # 사용자 id가 아니라 별도 소유 리소스 id를 URL에 넣어야 하는 앱용 안전한 setup 단계.
    # POST 두 번(각 역할의 이름표 리소스 생성)만 허용하고, 반환 id로 GET 교차 조회한다.
    owner_setup_path: str | None = None
    owner_setup_body_json: str | None = None
    resource_id_key: str = "id"


def probe_from_candidate(candidate: Candidate) -> IdorProbe:
    """candidate에서 probe를 만든다. typed `attack_params`를 우선 쓴다.

    D1-P3.md 이견 1 / D2-P3 우회였던 `signals` "key=value" 파싱은 이제 하위호환 폴백으로만 남긴다
    (P1이 `Candidate.attack_params: dict[str,str]`를 도입, P4가 SAST에서 vuln_class를 채움 —
    D2-P4 최우선 요청). 새 후보는 attack_params로 온다.
    """
    if candidate.attack_params:
        return IdorProbe(**candidate.attack_params)

    kv: dict[str, str] = {}  # 하위호환: 예전 signals 기반 후보(WebGoat 데모 등)
    for s in candidate.signals:
        if "=" in s:
            key, _, value = s.partition("=")
            kv[key.strip()] = value.strip()
    return IdorProbe(**kv)


def _pick_resource(resources: dict, required_field: str) -> dict:
    for res in resources.values():
        if isinstance(res, dict) and required_field in res:
            return res
    raise ValueError(f"fixture resources에 '{required_field}'를 가진 자원이 없다")


def probe_from_fixture(fixture: dict | str | Path) -> IdorProbe:
    """P2 IDOR fixture 메타데이터 → IdorProbe.

    P2↔P3 계약(`.vibecutter/fixtures/<target>-idor.json`): `resources`에서 victim 자원은
    `read_path`+`victim_marker`를, attacker(baseline) 자원은 `baseline_path`+`marker`를 갖는다.
    자원 key 이름(예: victim_vocabulary)이 아니라 이 필드 이름으로 찾으므로 앱마다 이름이 달라도 된다.
    """
    data = (
        fixture
        if isinstance(fixture, dict)
        else json.loads(Path(fixture).read_text(encoding="utf-8"))
    )
    resources = data.get("resources", {})
    victim = _pick_resource(resources, "victim_marker")
    attacker = _pick_resource(resources, "baseline_path")
    auth = data.get("auth") if isinstance(data.get("auth"), dict) else data.get("authentication", {})
    return IdorProbe(
        base_url=data["base_url"],
        auth_mode=auth.get("mode", "none") if isinstance(auth, dict) else "none",
        baseline_path=attacker["baseline_path"],
        attack_path=victim["read_path"],
        victim_marker=victim["victim_marker"],
        owner_marker=attacker.get("marker"),
    )


def candidate_from_fixture(
    run_id: str, fixture: dict | str | Path, *, candidate_id: str | None = None
) -> Candidate:
    """fixture → Candidate. probe를 typed `attack_params`로 담아 verify()에 바로 넘길 수 있다.

    probe → attack_params dict → probe_from_candidate로 왕복 복원된다. vuln_class="idor"라
    verify_candidate 디스패처가 access_control로 라우팅한다.
    """
    probe = probe_from_fixture(fixture)
    attack_params = {k: str(v) for k, v in probe.model_dump().items() if v is not None}
    return Candidate(
        id=candidate_id or f"cand-{uuid4().hex[:12]}",
        run_id=run_id,
        cwe="CWE-639",
        vuln_class="idor",
        attack_params=attack_params,
    )


# --- ② HTTP 재현 (auth_mode dispatch) -------------------------------------------------


def _exchange(method: str, path: str, response: httpx.Response) -> dict:
    """요청/응답을 evidence artifact가 될 dict로."""
    return {
        "request": {"method": method, "path": path},
        "response": {"status": response.status_code, "body": response.text},
    }


def _replay_none(probe: IdorProbe) -> tuple[dict, dict]:
    """인증 없는 식별자-스왑 IDOR (예: 26s-w1-c2-04 WordNote).

    baseline = 공격자가 자기 자원(baseline_path)을, attack = 인증 없이 같은 방식으로 피해자
    자원(attack_path)을 요청. Authorization 헤더 없음 — 토큰/세션 자체가 없는 앱.
    """
    if not probe.baseline_path or not probe.attack_path:
        raise ValueError("none 재현엔 baseline_path와 attack_path가 필요하다")
    base = probe.base_url.rstrip("/")
    with httpx.Client(follow_redirects=True, timeout=10.0) as client:
        r_base = client.get(f"{base}{probe.baseline_path}")
        r_atk = client.get(f"{base}{probe.attack_path}")
    return _exchange("GET", probe.baseline_path, r_base), _exchange("GET", probe.attack_path, r_atk)


def _replay_session_form(probe: IdorProbe) -> tuple[dict, dict]:
    """폼 로그인 + 세션 쿠키 IDOR (WebGoat 흐름). 공격자로 인증 후 자기/피해자 자원 요청.

    register/login 경로는 현재 WebGoat 형태로 고정. 다른 세션형 앱으로 넓히려면 login_path 등을
    probe로 파라미터화한다(다음 라운드).
    """
    missing = [
        f
        for f in ("baseline_path", "attack_path", "app_username", "app_password",
                  "auth_path", "auth_username", "auth_password")
        if getattr(probe, f) is None
    ]
    if missing:
        raise ValueError(f"session_form 재현에 필요한 필드 누락: {missing}")

    base = probe.base_url.rstrip("/")
    with httpx.Client(follow_redirects=True, timeout=10.0) as client:
        client.post(
            f"{base}/register.mvc",
            data={
                "username": probe.app_username,
                "password": probe.app_password,
                "matchingPassword": probe.app_password,
                "agree": "agree",
            },
        )
        client.post(
            f"{base}/login", data={"username": probe.app_username, "password": probe.app_password}
        )
        client.post(
            f"{base}{probe.auth_path}",
            data={"username": probe.auth_username, "password": probe.auth_password},
        )
        r_base = client.get(f"{base}{probe.baseline_path}")
        r_atk = client.get(f"{base}{probe.attack_path}")
    return _exchange("GET", probe.baseline_path, r_base), _exchange("GET", probe.attack_path, r_atk)


def _dig(obj: object, key: str) -> object:
    """JSON 응답(중첩 dict/list)에서 key의 첫 값을 찾는다(예: data.user.id, data.accessToken)."""
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            found = _dig(v, key)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for v in obj:
            found = _dig(v, key)
            if found is not None:
                return found
    return None


def _render_body(template: str | None, values: dict[str, str], *, default: dict[str, str]) -> dict[str, str]:
    """저장된 no-secret JSON template을 역할별 일회성 값으로만 렌더한다."""
    if template is None:
        return default
    try:
        body = json.loads(template)
    except json.JSONDecodeError as exc:
        raise ValueError("bearer body template은 JSON object여야 한다") from exc
    if not isinstance(body, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in body.items()):
        raise ValueError("bearer body template은 string key/value JSON object여야 한다")
    try:
        return {key: value.format(**values) for key, value in body.items()}
    except KeyError as exc:
        raise ValueError(f"bearer body template의 허용되지 않은 placeholder: {exc.args[0]}") from exc


def _identity_values(marker: str, password: str) -> dict[str, str]:
    return {
        "marker": marker,
        "name": marker,
        "username": marker,
        "email": f"{marker}@vc.local",
        "password": password,
    }


def _replay_bearer(probe: IdorProbe) -> tuple[dict, dict]:
    """JWT bearer 인증 IDOR (예: c1-05 Scrum Helper의 GET /api/users/{id}/profile).

    자체 provision: 회원가입 2명(owner 이름=victim_marker, attacker 이름=owner_marker) → 공격자
    토큰으로 baseline(자기 프로필)·attack(피해자 프로필)을 요청. 토큰은 메모리에만 존재하고
    요청 헤더는 evidence에 기록하지 않는다(secret 위생). id는 생성 응답에서 뽑아 path_template에 채운다.
    """
    if not probe.signup_path or not probe.path_template:
        raise ValueError("bearer 재현엔 signup_path와 path_template이 필요하다")
    base = probe.base_url.rstrip("/")
    pw = "VcLocal123!"  # provision 전용 임시 비번(로컬 격리 대상, evidence 미기록)
    if probe.owner_marker is None:
        raise ValueError("bearer 재현엔 owner_marker가 필요하다")
    owner_values = _identity_values(probe.victim_marker, pw)
    attacker_values = _identity_values(probe.owner_marker, pw)
    with httpx.Client(follow_redirects=True, timeout=10.0) as client:
        # owner(피해자)와 attacker(공격자)를 회원가입. 이름을 marker로 써서 프로필에 노출되게 한다.
        owner_response = client.post(
            f"{base}{probe.signup_path}",
            json=_render_body(
                probe.signup_body_json,
                owner_values,
                default={"name": owner_values["name"], "email": owner_values["email"], "password": pw},
            ),
        )
        attacker_response = client.post(
            f"{base}{probe.signup_path}",
            json=_render_body(
                probe.signup_body_json,
                attacker_values,
                default={"name": attacker_values["name"], "email": attacker_values["email"], "password": pw},
            ),
        )
        owner = owner_response.json()
        attacker = attacker_response.json()
        owner_id = _dig(owner, "id")
        attacker_id = _dig(attacker, "id")
        owner_token = _dig(owner, probe.token_key)
        attacker_token = _dig(attacker, probe.token_key)
        if probe.login_path:
            owner_login = client.post(
                f"{base}{probe.login_path}",
                json=_render_body(
                    probe.login_body_json,
                    owner_values,
                    default={"email": owner_values["email"], "password": pw},
                ),
            ).json()
            attacker_login = client.post(
                f"{base}{probe.login_path}",
                json=_render_body(
                    probe.login_body_json,
                    attacker_values,
                    default={"email": attacker_values["email"], "password": pw},
                ),
            ).json()
            owner_token = _dig(owner_login, probe.token_key)
            attacker_token = _dig(attacker_login, probe.token_key)
        if owner_id is None or attacker_id is None or owner_token is None or attacker_token is None:
            raise ValueError("bearer provision 실패: 응답에서 id/token을 찾지 못함")

        owner_headers = {"Authorization": f"Bearer {owner_token}"}
        attacker_headers = {"Authorization": f"Bearer {attacker_token}"}  # evidence에 헤더를 담지 않는다.
        baseline_id, attack_id = attacker_id, owner_id
        if probe.owner_setup_path:
            if probe.owner_setup_body_json is None:
                raise ValueError("owner_setup_path에는 owner_setup_body_json이 필요하다")
            owner_resource = client.post(
                f"{base}{probe.owner_setup_path}",
                headers=owner_headers,
                json=_render_body(probe.owner_setup_body_json, owner_values, default={}),
            ).json()
            attacker_resource = client.post(
                f"{base}{probe.owner_setup_path}",
                headers=attacker_headers,
                json=_render_body(probe.owner_setup_body_json, attacker_values, default={}),
            ).json()
            attack_id = _dig(owner_resource, probe.resource_id_key)
            baseline_id = _dig(attacker_resource, probe.resource_id_key)
            if attack_id is None or baseline_id is None:
                raise ValueError("bearer resource setup 실패: 응답에서 resource id를 찾지 못함")

        baseline_path = probe.path_template.format(id=baseline_id)  # 공격자 자기 자원
        attack_path = probe.path_template.format(id=attack_id)  # 피해자 자원
        r_base = client.get(f"{base}{baseline_path}", headers=attacker_headers)
        r_atk = client.get(f"{base}{attack_path}", headers=attacker_headers)
    return _exchange("GET", baseline_path, r_base), _exchange("GET", attack_path, r_atk)


# auth_mode → (필요 요청 수, 재현 함수). 요청 수 상한은 10.2절 rate/impact limit 통제에 걸린다.
_REPLAY: dict[str, tuple[int, object]] = {
    "none": (2, _replay_none),
    "session_form": (5, _replay_session_form),
    "bearer": (4, _replay_bearer),  # signup×2 + baseline + attack
}


def _required_requests(probe: IdorProbe, default: int) -> int:
    """선언된 bearer login/resource setup에 맞춰 rate-limit 예산을 정확히 계산한다."""
    if probe.auth_mode != "bearer":
        return default
    return default + (2 if probe.login_path else 0) + (2 if probe.owner_setup_path else 0)


def _replay_idor(probe: IdorProbe, max_requests: int) -> tuple[dict, dict]:
    """probe.auth_mode에 맞는 재현 전략으로 (baseline, attack) 교환을 만든다.

    repair/validators.py도 이 함수를 재사용한다(패치 후 동일 시퀀스 재실행) — 이름/시그니처 유지.
    """
    entry = _REPLAY.get(probe.auth_mode)
    if entry is None:
        raise ValueError(f"지원하지 않는 auth_mode {probe.auth_mode!r} (지원: {sorted(_REPLAY)})")
    default_needed, strategy = entry
    needed = _required_requests(probe, default_needed)
    if needed > max_requests:
        raise ValueError(
            f"{probe.auth_mode} 재현에 {needed}회 필요하지만 max_requests={max_requests}로 제한됨"
        )
    return strategy(probe)  # type: ignore[operator]


# --- ③ verify() 조립 + evidence 저장 --------------------------------------------------


def verify(
    run_id: str,
    candidate: Candidate,
    *,
    max_requests: int = MAX_REQUESTS_DEFAULT,
) -> VerifierOutput:
    """IDOR 후보를 재현·판정하고, 요청/응답을 evidence로 남긴 뒤 VerifierOutput을 반환한다.

    P1의 tool 본문(vc_verify_access_control)이 이 함수를 호출하고, 반환된 evidence_ids로
    update_finding_status(finding_id, VERIFIED, evidence_ids=...)를 호출한다. policy 검사와
    상태 전이는 호출자(P1)의 몫 — 이 함수는 "보안 영향이 있는가"만 판정한다.
    """
    probe = probe_from_candidate(candidate)
    baseline, attack = _replay_idor(probe, max_requests)

    verified, reason = idor_oracle(
        baseline["response"]["body"], attack["response"]["body"], probe.victim_marker
    )

    evidence_ids: list[str] = []
    for label, exchange in (("baseline", baseline), ("attack", attack)):
        data = redact(json.dumps(exchange, ensure_ascii=False)).encode()
        obs = evidence_store.write_artifact(
            run_id, observation_type="http_exchange", producer=f"{PRODUCER}:{label}", data=data
        )
        evidence_ids.append(obs.id)

    return VerifierOutput(verified=verified, evidence_ids=evidence_ids, reason=reason)


# ══ Write-IDOR (상태변화 oracle) ══════════════════════════════════════════════════════
# 읽기 IDOR("남의 걸 봤나")를 넘어 쓰기 IDOR("남의 걸 바꿨나")를 판정한다. 7.3절 oracle의
# 진짜 의도인 "DB/API 상태 비교" — 공격 응답 200이 아니라, 피해자 자원을 독립적으로 before/after로
# 읽어 실제 상태가 바뀌었는지로 verified를 만든다.


def mutation_idor_oracle(
    before_body: str, after_body: str, mutation_marker: str
) -> tuple[bool, str]:
    """공격자의 변경이 피해자 자원에 실제로 반영됐는지 판정한다(상태 비교).

    verified 조건: 변경 marker가 before(변경 전 피해자 자원)엔 없고 after(변경 후)엔 있다 —
    공격자가 남의 자원을 실제로 바꿨다는 뜻. before에도 있으면 상태 변화가 아님.
    """
    in_before = mutation_marker in before_body
    in_after = mutation_marker in after_body
    if not in_before and in_after:
        return True, (
            f"공격자가 피해자 자원을 변경함 — 변경 marker {mutation_marker!r}가 공격 후 피해자 자원에"
            f" 나타남(변경 전엔 없음). 수평 쓰기 권한 통제 부재 (CWE-639)."
        )
    if in_before:
        return False, f"marker {mutation_marker!r}가 변경 전에도 있어 상태 변화로 볼 수 없음"
    return False, f"변경 marker {mutation_marker!r}가 피해자 자원에 반영 안 됨 — 쓰기가 차단된 듯"


class MutationProbe(BaseModel):
    """write-IDOR 재현 입력. observe_path로 피해자 자원을 before/after 읽고, mutation_*로 변경한다."""

    base_url: str
    observe_path: str  # GET으로 피해자 자원(변경 대상 필드 포함)을 읽는 경로
    mutation_method: str  # PUT/PATCH/POST/DELETE
    mutation_path: str  # 피해자 자원 변경 경로
    mutation_marker: str  # 변경 후 피해자 자원에 나타나야 하는 값
    marker_field: str = "description"  # 변경 바디에서 marker를 넣을 필드
    extra_body: dict = {}  # 변경 바디의 나머지 필수 필드(예: tags)


def mutation_probe_from_fixture(fixture: dict | str | Path) -> MutationProbe:
    """P2 fixture의 `safe_mutation`(안전·되돌릴 수 있는 변경)으로 MutationProbe를 만든다."""
    data = (
        fixture
        if isinstance(fixture, dict)
        else json.loads(Path(fixture).read_text(encoding="utf-8"))
    )
    victim = _pick_resource(data.get("resources", {}), "safe_mutation")
    sm = victim["safe_mutation"]
    observe_path = sm.get("observe_path")
    if observe_path is None:
        owner_id = data["roles"][victim.get("owner_role", "user_a")]["id"]
        observe_path = f"/vocabs/?owner_id={owner_id}"
    body = dict(sm.get("json", {}))
    marker_field = "description" if "description" in body else next(iter(body), "description")
    body.pop(marker_field, None)
    return MutationProbe(
        base_url=data["base_url"],
        observe_path=observe_path,
        mutation_method=sm["method"],
        mutation_path=sm["path"],
        mutation_marker=f"vc-write-idor-{uuid4().hex[:8]}",
        marker_field=marker_field,
        extra_body=body,
    )


def _replay_mutation_none(probe: MutationProbe, max_requests: int) -> tuple[dict, dict, dict]:
    """무인증 write-IDOR 재현: 피해자 자원 읽기(before) → 공격자 변경 → 다시 읽기(after)."""
    needed = 3
    if needed > max_requests:
        raise ValueError(f"write-IDOR 재현에 {needed}회 필요하지만 max_requests={max_requests}로 제한됨")
    base = probe.base_url.rstrip("/")
    body = {**probe.extra_body, probe.marker_field: probe.mutation_marker}
    with httpx.Client(follow_redirects=True, timeout=10.0) as client:
        r_before = client.get(f"{base}{probe.observe_path}")
        r_mut = client.request(probe.mutation_method, f"{base}{probe.mutation_path}", json=body)
        r_after = client.get(f"{base}{probe.observe_path}")
    before = _exchange("GET", probe.observe_path, r_before)
    mutation = {
        "request": {"method": probe.mutation_method, "path": probe.mutation_path},
        "response": {"status": r_mut.status_code, "body": r_mut.text},
    }
    after = _exchange("GET", probe.observe_path, r_after)
    return before, mutation, after


def verify_mutation(
    run_id: str, probe: MutationProbe, *, max_requests: int = MAX_REQUESTS_DEFAULT
) -> VerifierOutput:
    """write-IDOR을 재현·판정하고 before/mutation/after 3건을 evidence로 남긴다.

    read-IDOR verify()의 write 버전. verified는 오라클이 before↔after 상태 비교로 판정하며,
    변경은 fixture의 `safe_mutation`(되돌릴 수 있는 안전 변경)만 사용한다(파괴적 변경 금지, 10.4절).
    """
    before, mutation, after = _replay_mutation_none(probe, max_requests)
    verified, reason = mutation_idor_oracle(
        before["response"]["body"], after["response"]["body"], probe.mutation_marker
    )
    evidence_ids: list[str] = []
    for label, exchange in (("write_before", before), ("write_mutation", mutation), ("write_after", after)):
        data = redact(json.dumps(exchange, ensure_ascii=False)).encode()
        obs = evidence_store.write_artifact(
            run_id, observation_type="http_exchange", producer=f"{PRODUCER}:{label}", data=data
        )
        evidence_ids.append(obs.id)
    return VerifierOutput(verified=verified, evidence_ids=evidence_ids, reason=reason)
