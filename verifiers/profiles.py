"""Vulnerability profile 로더 + 안전 스키마 검증 (P3 소유).

`policies/vulnerability_profiles/*.yaml`에 담긴 "취약점 클래스별 안전 payload 템플릿"을
로드하고, **로드 시점에** 안전 불변식을 강제한다:

  - 공통: 임의 URL 입력 금지(대상은 candidate.attack_params로만), egress 차단, 대상 origin 유지.
  - XSS  : benign marker만(실행되면 window 플래그 하나만 set), 네트워크/쿠키/지속성 토큰 금지.
  - Injection: 불리언 차등 payload만(SELECT 읽기 전용), 파괴적 write/스택쿼리/UNION/time-based 금지.
  - IDOR : safe_mutation(되돌릴 수 있는 benign 변경)만, DELETE 등 파괴적 메서드 금지.

목적(7.3절, SKILL.md "절대 금지"): verifier가 임의 payload를 지어내지 않고 검증된 안전
템플릿에만 제한되도록 하는 단일 출처. 안전 위반이 있는 프로파일은 로드 자체가 실패한다
(`ProfileValidationError`) — 조용히 통과시키지 않는다.

**additive 경계**: 이 모듈은 순수 추가분이다. 기존 verifier(access_control/xss/injection)
본문은 아직 이 프로파일을 소비하지 않는다 — payload는 지금도 각 verifier 안의 상수
(`_benign_payloads`/`_PAYLOAD_PAIRS`)에서 온다. 이 프로파일은 그 상수를 그대로 옮긴
것이며(`tests/test_vulnerability_profiles.py`가 왕복 일치를 검증), verifier가 실제로 이
프로파일을 payload 출처로 소비하도록 재배선하는 것은 별도 후속 작업이다. 그 전까지 이
로더는 "verifier가 쓰는 payload가 안전 템플릿으로 표현 가능함"을 보증하는 계약 지점이다.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError

PROFILES_DIR = Path(__file__).resolve().parent.parent / "policies" / "vulnerability_profiles"

# 공통 안전 상수 — 프로파일이 이 값과 정확히 일치해야 로드된다.
_REQUIRED_URL_SOURCE = "candidate.attack_params"
_REQUIRED_EGRESS = "blocked"

# safe_mutation에 허용되지 않는(파괴적) HTTP 메서드.
_DESTRUCTIVE_METHODS = frozenset({"DELETE"})


class ProfileValidationError(ValueError):
    """프로파일 스키마 위반 또는 안전 불변식 위반. 로드 실패로 표현한다."""


# --- 스키마 모델 ----------------------------------------------------------------------


class Safety(BaseModel):
    """모든 프로파일이 공유하는 안전 제약 + 클래스별 안전 플래그."""

    model_config = ConfigDict(extra="forbid")

    # 공통(필수)
    allowed_url_source: str
    egress: str
    stay_within_target_origin: bool
    forbidden_tokens: list[str] = []

    # 클래스별(선택)
    benign_marker_only: bool | None = None
    boolean_differential_only: bool | None = None
    select_only: bool | None = None
    non_get_requires_read_query: bool | None = None
    raw_response_not_stored: bool | None = None
    safe_mutation_only: bool | None = None
    destructive_actions_forbidden: bool | None = None
    forbidden_mutations: list[str] = []


class XssMarker(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str
    effect_template: str  # 실행되면 이것만 한다. {flag} placeholder.
    flag_prefix: str


class XssPayloadTemplate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    context: str
    template: str  # {js} placeholder (js = marker.effect_template을 flag로 렌더한 값)


class InjectionPayloadPair(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    true_payload: str
    false_payload: str


class IdorReadOracle(BaseModel):
    model_config = ConfigDict(extra="forbid")
    method: str
    marker_source: str


class IdorWriteMarker(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str
    prefix: str


class IdorWriteOracle(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str
    reversible: bool
    marker: IdorWriteMarker
    allowed_methods: list[str]
    default_marker_field: str


class VulnerabilityProfile(BaseModel):
    """취약점 클래스 하나의 안전 payload 프로파일.

    공통 필드 + 클래스별 섹션(선택)을 담는다. `model_dump` 없이 pydantic 검증만으로는
    안전 불변식을 완전히 강제할 수 없어(교차 필드·payload 내용 검사), 로더의
    `_enforce_safety()`가 로드 시점에 추가 검증한다.
    """

    model_config = ConfigDict(extra="forbid")

    vuln_class: str
    cwe: str
    title: str
    description: str
    oracle: str
    safety: Safety

    # XSS
    contexts: list[str] | None = None
    marker: XssMarker | None = None
    payload_templates: list[XssPayloadTemplate] | None = None

    # Injection
    inject_locations: list[str] | None = None
    default_method: str | None = None
    min_delta: int | None = None
    payload_pairs: list[InjectionPayloadPair] | None = None

    # IDOR
    auth_modes: list[str] | None = None
    read_oracle: IdorReadOracle | None = None
    write_oracle: IdorWriteOracle | None = None


# --- 렌더 헬퍼 ------------------------------------------------------------------------


def render_xss_payloads(profile: VulnerabilityProfile, flag: str) -> list[str]:
    """XSS 프로파일 템플릿을 flag로 렌더한 실제 payload 리스트.

    `verifiers.xss._benign_payloads(flag)`와 왕복 일치해야 한다(테스트가 검증).
    """
    if profile.marker is None or profile.payload_templates is None:
        raise ProfileValidationError(f"{profile.vuln_class} 프로파일에 XSS marker/payload_templates가 없다")
    js = profile.marker.effect_template.format(flag=flag)
    return [tmpl.template.format(js=js) for tmpl in profile.payload_templates]


def injection_pairs(profile: VulnerabilityProfile) -> list[tuple[str, str]]:
    """Injection 프로파일의 (참, 거짓) payload 쌍. `verifiers.injection._PAYLOAD_PAIRS`와 일치해야 한다."""
    if profile.payload_pairs is None:
        raise ProfileValidationError(f"{profile.vuln_class} 프로파일에 payload_pairs가 없다")
    return [(p.true_payload, p.false_payload) for p in profile.payload_pairs]


# --- 안전 불변식 강제 -----------------------------------------------------------------


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise ProfileValidationError(message)


def _contains_forbidden(text: str, forbidden: list[str]) -> str | None:
    low = text.lower()
    for tok in forbidden:
        if tok.lower() in low:
            return tok
    return None


def _enforce_common_safety(profile: VulnerabilityProfile) -> None:
    s = profile.safety
    _assert(
        s.allowed_url_source == _REQUIRED_URL_SOURCE,
        f"{profile.vuln_class}: allowed_url_source는 {_REQUIRED_URL_SOURCE!r}여야 한다"
        f" (임의 URL 입력 금지) — 실제 {s.allowed_url_source!r}",
    )
    _assert(
        s.egress == _REQUIRED_EGRESS,
        f"{profile.vuln_class}: egress는 {_REQUIRED_EGRESS!r}여야 한다 (외부 host 유출 금지) —"
        f" 실제 {s.egress!r}",
    )
    _assert(
        s.stay_within_target_origin is True,
        f"{profile.vuln_class}: stay_within_target_origin은 true여야 한다",
    )


def _enforce_xss_safety(profile: VulnerabilityProfile) -> None:
    s = profile.safety
    _assert(s.benign_marker_only is True, "xss: safety.benign_marker_only는 true여야 한다")
    _assert(profile.marker is not None, "xss: marker 섹션이 필요하다")
    _assert(bool(profile.payload_templates), "xss: payload_templates가 필요하다")
    # 렌더된 payload(마커 effect 포함)에 네트워크/쿠키/지속성/임의실행 토큰이 없어야 한다.
    rendered = render_xss_payloads(profile, "__vc_probe_flag__")
    for payload in rendered:
        hit = _contains_forbidden(payload, s.forbidden_tokens)
        _assert(hit is None, f"xss: payload {payload!r}에 금지 토큰 {hit!r} (egress/exfil 위험)")


def _enforce_injection_safety(profile: VulnerabilityProfile) -> None:
    s = profile.safety
    _assert(s.boolean_differential_only is True, "injection: safety.boolean_differential_only는 true여야 한다")
    _assert(s.select_only is True, "injection: safety.select_only는 true여야 한다 (읽기 전용)")
    _assert(
        s.non_get_requires_read_query is True,
        "injection: safety.non_get_requires_read_query는 true여야 한다 (비-GET은 SELECT 보증 필요)",
    )
    _assert(bool(profile.payload_pairs), "injection: payload_pairs가 필요하다")
    for pair in profile.payload_pairs or []:
        for payload in (pair.true_payload, pair.false_payload):
            hit = _contains_forbidden(payload, s.forbidden_tokens)
            _assert(hit is None, f"injection: payload {payload!r}에 금지 토큰 {hit!r} (파괴적/위험)")
        # 참/거짓은 길이가 같고 최대 한 글자만 달라야 한다(불리언 결과만 토글 → 응답 차이가 SQL 해석의 증거).
        _assert(
            len(pair.true_payload) == len(pair.false_payload),
            f"injection: 쌍 {pair.id!r}의 참/거짓 길이가 다르다",
        )
        diff = sum(1 for a, b in zip(pair.true_payload, pair.false_payload) if a != b)
        _assert(diff <= 1, f"injection: 쌍 {pair.id!r}이 한 글자 넘게 다르다 (차등 무효)")


def _enforce_idor_safety(profile: VulnerabilityProfile) -> None:
    s = profile.safety
    _assert(s.safe_mutation_only is True, "idor: safety.safe_mutation_only는 true여야 한다")
    _assert(
        s.destructive_actions_forbidden is True,
        "idor: safety.destructive_actions_forbidden는 true여야 한다",
    )
    _assert(profile.read_oracle is not None, "idor: read_oracle 섹션이 필요하다")
    _assert(profile.write_oracle is not None, "idor: write_oracle 섹션이 필요하다")
    wo = profile.write_oracle
    assert wo is not None  # for type-checkers; _assert 위에서 이미 보장
    _assert(wo.reversible is True, "idor: write_oracle.reversible은 true여야 한다")
    _assert(bool(wo.marker.prefix), "idor: write_oracle.marker.prefix가 필요하다")
    _assert(bool(wo.allowed_methods), "idor: write_oracle.allowed_methods가 필요하다")
    for method in wo.allowed_methods:
        _assert(
            method.upper() not in _DESTRUCTIVE_METHODS,
            f"idor: write_oracle.allowed_methods에 파괴적 메서드 {method!r} 금지 (safe_mutation만)",
        )


_ENFORCERS = {
    "xss": _enforce_xss_safety,
    "injection": _enforce_injection_safety,
    "idor": _enforce_idor_safety,
}


def _enforce_safety(profile: VulnerabilityProfile) -> None:
    _enforce_common_safety(profile)
    enforcer = _ENFORCERS.get(profile.vuln_class)
    _assert(
        enforcer is not None,
        f"알 수 없는 vuln_class {profile.vuln_class!r} (지원: {sorted(_ENFORCERS)})",
    )
    assert enforcer is not None
    enforcer(profile)


# --- 공개 API -------------------------------------------------------------------------


def parse_profile(data: dict) -> VulnerabilityProfile:
    """dict → 검증된 VulnerabilityProfile. 스키마·안전 불변식을 모두 강제한다."""
    try:
        profile = VulnerabilityProfile.model_validate(data)
    except ValidationError as exc:
        raise ProfileValidationError(f"프로파일 스키마 위반: {exc}") from exc
    _enforce_safety(profile)
    return profile


def load_profile(path: Path) -> VulnerabilityProfile:
    """단일 YAML 프로파일 파일을 로드·검증한다."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ProfileValidationError(f"{path.name}: 프로파일은 YAML mapping이어야 한다")
    return parse_profile(data)


def load_all(profiles_dir: Path = PROFILES_DIR) -> dict[str, VulnerabilityProfile]:
    """profiles_dir의 모든 `*.yaml`을 로드해 `{vuln_class: profile}`로 돌려준다.

    파일명이 `<vuln_class>.yaml`과 다르거나 vuln_class가 중복되면 거부한다(계약 명확성).
    """
    if not profiles_dir.exists():
        raise ProfileValidationError(f"프로파일 디렉토리가 없다: {profiles_dir}")
    out: dict[str, VulnerabilityProfile] = {}
    for path in sorted(profiles_dir.glob("*.yaml")):
        profile = load_profile(path)
        _assert(
            path.stem == profile.vuln_class,
            f"{path.name}: 파일명 stem과 vuln_class({profile.vuln_class!r})가 다르다",
        )
        _assert(
            profile.vuln_class not in out,
            f"vuln_class {profile.vuln_class!r} 프로파일이 중복 정의됐다",
        )
        out[profile.vuln_class] = profile
    return out


def get_profile(vuln_class: str, profiles_dir: Path = PROFILES_DIR) -> VulnerabilityProfile:
    """vuln_class로 프로파일 하나를 로드한다. 없으면 ProfileValidationError."""
    profiles = load_all(profiles_dir)
    profile = profiles.get(vuln_class)
    if profile is None:
        raise ProfileValidationError(
            f"vuln_class {vuln_class!r} 프로파일이 없다 (있는 것: {sorted(profiles)})"
        )
    return profile
