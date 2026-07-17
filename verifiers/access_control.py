"""Broken Access Control / IDOR verifier (7.3절, CWE-639). P0 — MVP의 승부처.

검증 oracle (7.3절 표): "역할 A가 만든 자원을 역할 B가 읽거나 변경했는지 DB/API 상태 비교".
즉 응답 코드 200 하나로 verified를 만들지 않는다 — 공격자 세션으로 요청했는데 응답에
피해자의 데이터가 담겨 나오는지를 baseline과 비교해서 판정한다.

11.5절 P0: "IDOR verifier + patch loop — 한 취약점을 발견·수정·재검증".
16장: "IDOR 한 종류라도 발견→재현→코드 위치→패치→재공격→정상 기능 통과를 먼저 완성해야 한다."

Day2 완료 기준: IDOR verified 1건 이상.

구성 3덩어리:
  ① idor_oracle()       — 판정 로직 (일반적, 재사용 가능)
  ② _replay_idor()      — HTTP 재현 (지금은 WebGoat 흐름; P2 role fixture로 대체 예정)
  ③ verify()            — 조립 + evidence 저장(redaction 적용)
"""

from __future__ import annotations

import json
import re
from uuid import uuid4

import httpx
from pydantic import BaseModel

from contracts.schemas import Candidate
from core import evidence_store
from verifiers.types import MAX_REQUESTS_DEFAULT, VerifierOutput

PRODUCER = "vc_verify_access_control"


# --- ③-a) secret redaction (D1-P3.md 구멍 ② 임시 방어) --------------------------------
# evidence_store.write_artifact에 redaction이 아직 없어(P1과 소유자 협의 중), verifier가
# 저장 직전에 세션 토큰/비밀번호를 지운다. 공격자 인증 트래픽을 다루는 게 P3뿐이라 여기서
# 먼저 막는다. cowork_rule.md 4절: "secret/token은 evidence 저장 전에 제거".
_REDACTIONS = [
    (re.compile(r"(JSESSIONID=)[^;\s\"]+"), r"\1<redacted>"),
    (re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]+"), r"\1<redacted>"),
    (re.compile(r'("?(?:password|matchingPassword)"?\s*[=:]\s*"?)[^&"\s,}]+'), r"\1<redacted>"),
]


def redact(text: str) -> str:
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


# --- ① IDOR oracle (핵심, 일반적) -----------------------------------------------------


def idor_oracle(baseline_body: str, attack_body: str, victim_marker: str) -> tuple[bool, str]:
    """공격 응답이 피해자 자원을 노출했는지 판정한다.

    verified 조건 (셋 다 만족):
      1. 공격 응답에 victim_marker(피해자만 가진 값)가 들어있다.
      2. baseline 응답(공격자 자기 자원)에는 그 marker가 없다 — 원래 못 보던 걸 봤다는 뜻.
      3. 두 응답이 실제로 다르다 — 서버가 요청 무시하고 같은 걸 돌려준 게 아니다.

    marker 하나가 아니라 이 세 조건을 같이 보는 이유: "200이 떴다"만으로 verified 하면
    D1-P3.md 구멍 ①(증거 없는 승격)이 그대로 재현된다. 판정 근거를 응답 내용에 둔다.
    """
    marker_in_attack = victim_marker in attack_body
    marker_in_baseline = victim_marker in baseline_body
    differ = baseline_body.strip() != attack_body.strip()

    if marker_in_attack and not marker_in_baseline and differ:
        return True, (
            f"공격자 세션으로 요청했는데 응답에 피해자 마커 {victim_marker!r}가 노출됨"
            f" (baseline 응답에는 없음). 수평 권한 통제 부재 (CWE-639)."
        )
    if marker_in_attack and marker_in_baseline:
        return False, f"marker {victim_marker!r}가 baseline에도 있어 피해자 고유 데이터로 볼 수 없음"
    if not differ:
        return False, "공격/baseline 응답이 동일 — 서버가 요청한 자원을 반영하지 않음"
    return False, f"응답에 피해자 마커 {victim_marker!r}가 없음 — 접근이 차단된 것으로 보임"


# --- ②-준비) verifier 입력 (지금 Candidate 스키마가 못 담아 signals에서 파싱) -----------


class IdorProbe(BaseModel):
    """IDOR 재현에 실제로 필요한 입력.

    D1-P3.md 계약 이견 1: Candidate에 vuln_class/공격 파라미터 typed 필드가 없어, 당분간
    candidate.signals의 "key=value" 리스트에서 파싱한다. 스키마가 개선되면 이 우회를 제거한다.
    """

    base_url: str
    app_username: str  # WebGoat 접근용 계정 (대상 준비 영역, 임시로 verifier가 회원가입)
    app_password: str
    auth_path: str  # 공격자 역할 인증 endpoint (role fixture에 해당)
    auth_username: str
    auth_password: str
    baseline_path: str  # 공격자 자기 자원
    attack_path: str  # 피해자 자원
    victim_marker: str  # 응답에 이게 보이면 피해자 데이터


def probe_from_candidate(candidate: Candidate) -> IdorProbe:
    kv: dict[str, str] = {}
    for s in candidate.signals:
        if "=" in s:
            key, _, value = s.partition("=")
            kv[key.strip()] = value.strip()
    return IdorProbe(**kv)


# --- ② HTTP 재현 (WebGoat 흐름 — 나중에 P2 role fixture로 대체) -------------------------


def _replay_idor(probe: IdorProbe, max_requests: int) -> tuple[dict, dict]:
    """공격자로 인증한 뒤 baseline(자기 자원)과 attack(피해자 자원)을 요청한다.

    반환: (baseline_exchange, attack_exchange). 각 exchange는 {request, response} dict로,
    그대로 evidence artifact가 된다.

    필요 요청 수(회원가입/로그인/역할인증/baseline/attack = 5)가 max_requests를 넘으면
    거부한다 — 10.2절 rate/impact limit을 코드로 강제.
    """
    needed = 5
    if needed > max_requests:
        raise ValueError(f"IDOR 재현에 {needed}회 필요하지만 max_requests={max_requests}로 제한됨")

    # base_url + 절대경로를 httpx.Client(base_url=...)에 맡기면 httpx가 "/..."를 절대
    # 경로로 보고 컨텍스트 경로(/WebGoat)를 버린다. 그래서 URL을 직접 결합한다.
    base = probe.base_url.rstrip("/")
    with httpx.Client(follow_redirects=True, timeout=10.0) as client:
        # 1) WebGoat 접근 계정 회원가입 + 로그인 (대상 준비, 임시)
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

        # 2) 공격자 역할로 인증 (role fixture에 해당)
        client.post(
            f"{base}{probe.auth_path}",
            data={"username": probe.auth_username, "password": probe.auth_password},
        )

        # 3) baseline: 공격자 자기 자원
        r_base = client.get(f"{base}{probe.baseline_path}")
        baseline = {
            "request": {"method": "GET", "path": probe.baseline_path},
            "response": {"status": r_base.status_code, "body": r_base.text},
        }

        # 4) attack: 피해자 자원 (같은 세션, 남의 식별자)
        r_atk = client.get(f"{base}{probe.attack_path}")
        attack = {
            "request": {"method": "GET", "path": probe.attack_path},
            "response": {"status": r_atk.status_code, "body": r_atk.text},
        }

    return baseline, attack


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

    # 요청/응답을 evidence로 저장 — 저장 직전에 redaction (구멍 ② 방어).
    evidence_ids: list[str] = []
    for label, exchange in (("baseline", baseline), ("attack", attack)):
        data = redact(json.dumps(exchange, ensure_ascii=False)).encode()
        obs = evidence_store.write_artifact(
            run_id, observation_type="http_exchange", producer=f"{PRODUCER}:{label}", data=data
        )
        evidence_ids.append(obs.id)

    return VerifierOutput(verified=verified, evidence_ids=evidence_ids, reason=reason)
