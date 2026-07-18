"""XSS verifier (7.3절, CWE-79). IDOR에 이은 두 번째 oracle 축 — "실행됐나".

────────────────────────────────────────────────────────────────────────────
IDOR과의 결정적 차이 (왜 브라우저가 필요한가)
────────────────────────────────────────────────────────────────────────────
IDOR oracle은 응답 **body 문자열 비교**(피해자 marker가 보이나)라 HTTP만으로 판정했다.
XSS는 "payload가 HTML에 반사됐나"로 판정하면 **틀린다** — 서버가 `&lt;script&gt;`로
이스케이프하면 반사돼도 실행되지 않는다(안전). 그래서 XSS oracle은 **격리 브라우저에서
주입한 benign marker가 실제로 *실행*됐는지**를 관찰한다. 반사는 필요조건이지 충분조건이 아니다.

구성 (access_control.py와 동형 3덩어리):
  ① xss_oracle()     — 판정 로직(브라우저가 준 실행 신호로). 대상 독립·단위 테스트 가능.
  ② 재현(_replay_*)  — Playwright 격리 브라우저. reflected(쿼리 반사) / stored(저장 후 렌더).
  ③ verify()         — 조립 + evidence 저장(observation_type="browser_trace").

────────────────────────────────────────────────────────────────────────────
절대 안전 경계 (공격 코드를 쓰는 사람의 원칙, 10.4절)
────────────────────────────────────────────────────────────────────────────
  - **benign marker만**: payload는 `window.<flag>=1` 딱 하나만 세팅한다. 네트워크 호출·쿠키
    접근·alert·지속성 행위 없음. "실행됐다"의 증거일 뿐 실제 피해를 주지 않는다.
  - **격리 headless + ephemeral context**: 상태를 저장하지 않는 임시 브라우저.
  - **egress 차단**: 브라우저의 모든 요청을 가로채 대상 origin 밖(외부 도메인)은 abort한다.
    payload가 어떻게든 밖으로 새려 해도 못 나간다(컨테이너 밖 유출 금지).
  - **허용 base_url만**. 임의 URL 입력 금지 — candidate.attack_params로만 온다.
"""

from __future__ import annotations

import json
from urllib.parse import urlencode, urlparse
from uuid import uuid4

import httpx
from pydantic import BaseModel

from contracts.schemas import Candidate
from core import evidence_store
from verifiers.types import MAX_REQUESTS_DEFAULT, VerifierOutput

PRODUCER = "vc_verify_xss"


# --- probe: 재현에 필요한 입력 --------------------------------------------------------


class XssProbe(BaseModel):
    """XSS 재현에 필요한 입력. 대상별 값은 candidate.attack_params(=P2 fixture)에서 온다.

    context에 따라:
      - "reflected" : inject_path?<inject_param>=<payload> 를 열어 응답 자체에서 실행 확인.
      - "stored"    : inject_path에 payload를 저장(POST) → render_path를 열어 실행 확인.
    """

    base_url: str
    context: str = "reflected"          # "reflected" | "stored"
    inject_path: str                    # 주입 지점 경로
    inject_param: str                   # 주입할 파라미터/필드 이름
    inject_method: str = "GET"          # reflected는 보통 GET, stored는 POST
    render_path: str | None = None      # stored: payload가 렌더되는 경로(없으면 inject_path)
    extra_params: dict[str, str] = {}   # 함께 보내야 하는 다른 필수 필드


def xss_probe_from_candidate(candidate: Candidate) -> XssProbe:
    """candidate.attack_params → XssProbe (IDOR probe_from_candidate의 XSS 짝).

    extra_params(중첩 dict)는 attack_params가 dict[str,str]이라 `extra_params_json`에
    JSON 문자열로 담겨 오면 여기서 되푼다.
    """
    ap = dict(candidate.attack_params)
    extra = ap.pop("extra_params_json", None)
    if extra:
        ap["extra_params"] = json.loads(extra)
    return XssProbe(**ap)


# --- ① XSS oracle (핵심, 대상 독립) ---------------------------------------------------


def xss_oracle(executed: bool, raw_reflected: bool, escaped_reflected: bool) -> tuple[bool, str]:
    """브라우저가 관찰한 신호로 XSS를 판정한다. **실행됐을 때만** verified.

    "반사됐다"만으로 verified 하지 않는다(이스케이프되면 반사돼도 무해). 판정 근거는 격리
    브라우저에서 benign marker가 실제로 실행됐다는 사실(window 플래그 set)에 둔다.
    """
    if executed:
        return True, (
            "격리 브라우저에서 주입한 benign marker가 실제로 실행됨(window 플래그 set). "
            "출력 인코딩/살균 부재로 임의 스크립트 실행 가능 (XSS, CWE-79)."
        )
    if raw_reflected:
        return False, (
            "payload가 이스케이프 없이 반사됐으나 실행되진 않음(CSP 등으로 차단됐을 수 있음) — "
            "실행 근거가 없어 verified 아님."
        )
    if escaped_reflected:
        return False, "payload가 HTML 이스케이프되어 반사됨(inert) — 안전, XSS 아님."
    return False, "payload가 응답에 반사되지 않음 — 주입 지점이 아니거나 필터링됨."


# --- benign marker payload 템플릿 (실행되면 window 플래그만 set) -----------------------


def _benign_payloads(flag: str) -> list[str]:
    """실행 시 `window.<flag>=1`만 하는 무해 payload들. 컨텍스트별(태그/속성/SVG)로 몇 개."""
    js = f"window['{flag}']=1"
    return [
        f"<script>{js}</script>",           # HTML 본문에 태그 주입
        f'"><script>{js}</script>',         # 속성값 안에서 태그 탈출
        f'"><img src=x onerror="{js}">',    # 속성 탈출 + 이벤트 핸들러
        f"<img src=x onerror={js}>",         # 본문 이벤트 핸들러
        f"<svg onload={js}>",                # SVG onload
        f"'><svg onload={js}>",              # 홑따옴표 속성 탈출
    ]


# --- ② 재현 (Playwright 격리 브라우저, egress 차단) -----------------------------------


class _Attempt(BaseModel):
    payload: str
    url: str
    executed: bool
    raw_reflected: bool = False
    escaped_reflected: bool = False


def _reflection_kind(body: str, payload: str) -> tuple[bool, bool]:
    """응답/DOM에서 payload가 (그대로 반사됐나, 이스케이프돼 반사됐나)."""
    raw = payload in body
    escaped = (payload.replace("<", "&lt;").replace(">", "&gt;") in body) or ("&lt;script&gt;" in body)
    return raw, escaped


def _reflected_url(probe: XssProbe, payload: str) -> str:
    q = {**probe.extra_params, probe.inject_param: payload}
    return f"{probe.base_url.rstrip('/')}{probe.inject_path}?{urlencode(q)}"


def _egress_guard(allowed_netloc: str):
    """대상 origin 밖 요청을 abort하는 Playwright route 핸들러를 만든다."""

    def _guard(route):
        u = route.request.url
        if u.startswith(("data:", "about:", "blob:")) or urlparse(u).netloc == allowed_netloc:
            route.continue_()
        else:
            route.abort()

    return _guard


def _replay_reflected(probe: XssProbe, flag: str, max_requests: int) -> list[_Attempt]:
    """reflected XSS 재현: payload를 쿼리에 넣어 열고 실행 여부 관찰. 첫 실행에서 멈춘다."""
    from playwright.sync_api import sync_playwright

    allowed = urlparse(probe.base_url).netloc
    attempts: list[_Attempt] = []
    budget = max_requests

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context()
        context.route("**/*", _egress_guard(allowed))
        try:
            with httpx.Client(follow_redirects=True, timeout=10.0) as client:
                for payload in _benign_payloads(flag):
                    if budget <= 0:
                        break
                    budget -= 1
                    url = _reflected_url(probe, payload)
                    raw_reflected = escaped_reflected = False
                    try:
                        raw_reflected, escaped_reflected = _reflection_kind(client.get(url).text, payload)
                    except httpx.HTTPError:
                        pass
                    page = context.new_page()
                    executed = False
                    try:
                        page.goto(url, wait_until="load", timeout=10000)
                        page.wait_for_timeout(600)  # onerror/onload 실행 여유
                        executed = bool(page.evaluate(f"() => !!window['{flag}']"))
                    except Exception:  # noqa: BLE001 — 개별 payload 실패는 다음으로
                        pass
                    finally:
                        page.close()
                    attempts.append(_Attempt(payload=payload, url=url, executed=executed,
                                             raw_reflected=raw_reflected, escaped_reflected=escaped_reflected))
                    if executed:
                        break
        finally:
            browser.close()
    return attempts


def _replay_stored(probe: XssProbe, flag: str, max_requests: int) -> list[_Attempt]:
    """stored XSS 재현: payload를 저장(POST)한 뒤 render_path를 열어 실행 관찰."""
    from playwright.sync_api import sync_playwright

    render_url = f"{probe.base_url.rstrip('/')}{probe.render_path or probe.inject_path}"
    inject_url = f"{probe.base_url.rstrip('/')}{probe.inject_path}"
    allowed = urlparse(probe.base_url).netloc
    attempts: list[_Attempt] = []
    budget = max_requests

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context()
        context.route("**/*", _egress_guard(allowed))
        try:
            with httpx.Client(follow_redirects=True, timeout=10.0) as client:
                for payload in _benign_payloads(flag):
                    if budget < 2:  # 저장 + 렌더 = 2요청
                        break
                    budget -= 2
                    body = {**probe.extra_params, probe.inject_param: payload}
                    try:
                        client.request(probe.inject_method, inject_url, data=body)
                    except httpx.HTTPError:
                        continue
                    page = context.new_page()
                    executed = raw_reflected = escaped_reflected = False
                    try:
                        page.goto(render_url, wait_until="load", timeout=10000)
                        page.wait_for_timeout(600)
                        executed = bool(page.evaluate(f"() => !!window['{flag}']"))
                        raw_reflected, escaped_reflected = _reflection_kind(page.content(), payload)
                    except Exception:  # noqa: BLE001
                        pass
                    finally:
                        page.close()
                    attempts.append(_Attempt(payload=payload, url=render_url, executed=executed,
                                             raw_reflected=raw_reflected, escaped_reflected=escaped_reflected))
                    if executed:
                        break
        finally:
            browser.close()
    return attempts


_REPLAY = {"reflected": _replay_reflected, "stored": _replay_stored}


# --- ③ verify() 조립 + evidence 저장 --------------------------------------------------


def verify(
    run_id: str,
    candidate: Candidate,
    *,
    max_requests: int = MAX_REQUESTS_DEFAULT,
) -> VerifierOutput:
    """XSS 후보를 격리 브라우저로 재현·판정하고 시도를 evidence로 남긴다.

    IDOR verify()와 같은 계약: P1의 vc_verify_xss tool이 이 함수를 호출하고, 반환된
    evidence_ids로 update_finding_status(finding_id, VERIFIED, evidence_ids=...)를 부른다.
    policy 검사·상태 전이는 호출자(P1) 몫 — 이 함수는 "실행되는 XSS인가"만 판정한다.
    """
    probe = xss_probe_from_candidate(candidate)
    strategy = _REPLAY.get(probe.context)
    if strategy is None:
        raise ValueError(f"지원하지 않는 XSS context {probe.context!r} (지원: {sorted(_REPLAY)})")

    flag = f"__vc_xss_{uuid4().hex[:8]}"  # 재현마다 fresh — 이전 실행이 남긴 플래그 오판 방지
    attempts = strategy(probe, flag, max_requests)

    executed = any(a.executed for a in attempts)
    raw_reflected = any(a.raw_reflected for a in attempts)
    escaped_reflected = any(a.escaped_reflected for a in attempts)
    verified, reason = xss_oracle(executed, raw_reflected, escaped_reflected)

    evidence_ids: list[str] = []
    winner = next((a for a in attempts if a.executed), attempts[-1] if attempts else None)
    if winner is not None:
        data = json.dumps(
            {"context": probe.context, "inject_path": probe.inject_path, "param": probe.inject_param,
             "payload": winner.payload, "executed": winner.executed,
             "raw_reflected": winner.raw_reflected, "escaped_reflected": winner.escaped_reflected,
             "attempts": len(attempts)},
            ensure_ascii=False,
        ).encode()
        obs = evidence_store.write_artifact(
            run_id, observation_type="browser_trace",
            producer=f"{PRODUCER}:{'executed' if verified else 'no_exec'}", data=data,
        )
        evidence_ids.append(obs.id)

    return VerifierOutput(verified=verified, evidence_ids=evidence_ids, reason=reason)
