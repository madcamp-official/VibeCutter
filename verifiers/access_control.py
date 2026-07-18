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
    auth_mode: str = "session_form"  # "none" | "session_form" (기본은 D2 WebGoat 호환)
    baseline_path: str  # 공격자 자기 자원
    attack_path: str  # 피해자 자원
    victim_marker: str  # attack 응답에 이게 보이면 피해자 데이터
    owner_marker: str | None = None  # baseline 응답에 있어야 정상기능 OK (repair/validators.py)

    # --- session_form 전용 (none 모드면 불필요) ---
    app_username: str | None = None
    app_password: str | None = None
    auth_path: str | None = None
    auth_username: str | None = None
    auth_password: str | None = None


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
    return IdorProbe(
        base_url=data["base_url"],
        auth_mode=data.get("authentication", {}).get("mode", "none"),
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
        for f in ("app_username", "app_password", "auth_path", "auth_username", "auth_password")
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


# auth_mode → (필요 요청 수, 재현 함수). 요청 수 상한은 10.2절 rate/impact limit 통제에 걸린다.
_REPLAY: dict[str, tuple[int, object]] = {
    "none": (2, _replay_none),
    "session_form": (5, _replay_session_form),
}


def _replay_idor(probe: IdorProbe, max_requests: int) -> tuple[dict, dict]:
    """probe.auth_mode에 맞는 재현 전략으로 (baseline, attack) 교환을 만든다.

    repair/validators.py도 이 함수를 재사용한다(패치 후 동일 시퀀스 재실행) — 이름/시그니처 유지.
    """
    entry = _REPLAY.get(probe.auth_mode)
    if entry is None:
        raise ValueError(f"지원하지 않는 auth_mode {probe.auth_mode!r} (지원: {sorted(_REPLAY)})")
    needed, strategy = entry
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
