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
from urllib.parse import parse_qsl, urlencode, urlparse
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
    """실행 시 `window.<flag>=1`만 하는 무해 payload들. 컨텍스트(태그/속성/SVG)와 **필터 우회**(대소문자·
    슬래시 구분자·비-script 자동실행 태그)를 함께 커버해, script/img/svg를 블록리스트로 막는 앱에서도
    실행 근거를 얻는다. 전부 window 플래그만 세팅(네트워크·쿠키·지속성 없음)."""
    js = f"window['{flag}']=1"
    return [
        f"<script>{js}</script>",            # HTML 본문에 태그 주입
        f'"><script>{js}</script>',          # 속성값 안에서 태그 탈출
        f'"><img src=x onerror="{js}">',     # 속성 탈출 + 이벤트 핸들러
        f"<img src=x onerror={js}>",          # 본문 이벤트 핸들러
        f"<svg onload={js}>",                 # SVG onload
        f"'><svg onload={js}>",               # 홑따옴표 속성 탈출
        f"<details open ontoggle={js}>",      # ontoggle 자동 실행 — script/img/svg 블록리스트 우회
        f'"><details open ontoggle={js}>',    # 속성 탈출 + details ontoggle
        f"'><svg/onload={js}>",               # 슬래시 구분자 — 공백/태그 필터 우회
        f"<ScRiPt>{js}</ScRiPt>",             # 대소문자 혼합 — 대소문자 기반 필터 우회
    ]


# --- ② 재현 (Playwright 격리 브라우저, egress 차단) -----------------------------------


class _Attempt(BaseModel):
    payload: str
    url: str
    executed: bool
    raw_reflected: bool = False
    escaped_reflected: bool = False


def _reflection_kind(body: str, payload: str) -> tuple[bool, bool]:
    """응답/DOM에서 payload가 (그대로 반사됐나, 이스케이프돼 반사됐나).

    이스케이프는 명명 엔티티만이 아니라 십진/십육진 수치 엔티티, JS 유니코드 이스케이프까지 인식한다 —
    안전(escaped)과 위험(raw 반사)을 정확히 가르기 위함(oracle 근거 정확도).
    """
    raw = payload in body
    variants = (
        payload.replace("<", "&lt;").replace(">", "&gt;"),        # 명명 엔티티
        payload.replace("<", "&#60;").replace(">", "&#62;"),      # 십진 수치 엔티티
        payload.replace("<", "&#x3c;").replace(">", "&#x3e;"),    # 십육진 수치 엔티티
        payload.replace("<", "\\u003c").replace(">", "\\u003e"),  # JS 유니코드 이스케이프
    )
    escaped = any(v in body for v in variants) or ("&lt;script&gt;" in body) or ("&#60;script&#62;" in body)
    return raw, escaped


def _reflected_url(probe: XssProbe, payload: str) -> str:
    q = {**probe.extra_params, probe.inject_param: payload}
    path = probe.inject_path
    # inject_path가 이미 쿼리스트링(`?...`)을 담고 있으면(예: P2가 확정한 Angular 해시라우트
    # `/#/track-result?id=`), 새 `?`를 덧붙이면 `?id=?id=<payload>`로 겹친다(J-3 후 XSS 라이브 발견, P1).
    # 기존 쿼리를 파싱해 병합하고 주입 파라미터만 payload로 덮어써 `?id=<payload>` 한 벌로 만든다.
    if "?" in path:
        path, existing = path.split("?", 1)
        merged = dict(parse_qsl(existing, keep_blank_values=True))
        merged.update(q)  # extra_params·inject_param이 기존 placeholder 값을 덮어씀
        q = merged
    return f"{probe.base_url.rstrip('/')}{path}?{urlencode(q)}"


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


def _playwright_available() -> tuple[bool, str]:
    """chromium 격리 브라우저가 실행 가능한지 사전점검한다(브라우저를 띄우진 않는다). (가능, 사유).

    없으면 verify()가 크래시하거나 억지로 verified 처리하지 않고, 명확한 사유로 degrade하게 한다(X5).
    chromium이 없으면 XSS 실행 관찰이 불가능하므로 '검증 불가'가 정직한 결과다.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return False, "playwright 미설치 — `pip install playwright && playwright install chromium` 필요"
    try:
        import os

        with sync_playwright() as pw:
            exe = pw.chromium.executable_path
        if not exe or not os.path.exists(exe):
            return False, "chromium 브라우저 미설치 — `playwright install chromium` 필요"
    except Exception as exc:  # noqa: BLE001 — 사전점검 실패도 degrade로(크래시 금지)
        return False, f"격리 브라우저 사전점검 실패({type(exc).__name__}) — chromium 설치·권한 확인 필요"
    return True, ""


# --- ③ verify() 조립 + evidence 저장 --------------------------------------------------


def _run_isolated(fn, *args):
    """Playwright Sync API 호출을 전용 스레드에서 돌린다.

    `vc_verify_xss`는 MCP tool로서 이미 실행 중인 asyncio 이벤트 루프 안에서 sync 함수로
    호출된다(`mcp.call_tool` → FastMCP tool dispatch). Playwright Sync API는 그 안에서
    바로 부르면 "It looks like you are using Playwright Sync API inside the asyncio loop"
    로 예외를 던진다 — `_playwright_available()`이 그 예외를 넓은 except로 잡아 "chromium
    사전점검 실패"로 오인 degrade시키고, `_replay_reflected`/`_replay_stored`는 아예 호출
    전에 막혀 evidence 없이 verified=False가 나온다(2026-07-22, X7 Juice Shop 라이브 검증
    중 발견 — 실제로는 XSS가 재현되는데도 evidence_ids=[]라 Finding 전이 자체가
    MissingEvidenceError로 막힘). Playwright 공식 권장 우회대로 이벤트 루프가 없는 전용
    스레드에서 실행해 우회한다 — 판정 로직(오라클/재현)은 전혀 건드리지 않는다.
    """
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(fn, *args).result()


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

    # X5: 격리 브라우저 사전점검. 없으면 크래시·억지 verified 대신 명확한 사유로 degrade한다.
    ok, why = _run_isolated(_playwright_available)
    if not ok:
        return VerifierOutput(
            verified=False, evidence_ids=[],
            reason=(f"XSS 검증 불가 — {why}. 격리 브라우저 없이는 스크립트 실행을 관찰할 수 없어 "
                    "verified로 처리하지 않는다(안전). 브라우저 설치 후 재검증 필요."),
        )

    flag = f"__vc_xss_{uuid4().hex[:8]}"  # 재현마다 fresh — 이전 실행이 남긴 플래그 오판 방지
    attempts = _run_isolated(strategy, probe, flag, max_requests)

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


# --- positive functionality 게이트 지원 (repair.validators가 _run_isolated로 소비) --------


def render_benign(probe: XssProbe, value: str, *, timeout_ms: int = 10000) -> tuple[int, str]:
    """정상기능(positive) 게이트용: benign 평문 값을 넣고 **격리 브라우저로 클라이언트 렌더된 DOM**을
    `(status, dom_html)`으로 돌려준다.

    왜 httpx가 아니라 브라우저인가(X9 Juice Shop 라이브 발견, P1): hash-routed SPA(`#/search?q=…`)는
    URL fragment(`#` 이후)가 RFC 3986상 서버로 전송되지 않아, httpx는 SPA shell(`GET /`)만 받고
    Angular가 클라이언트에서 렌더하는 검색어는 응답에 절대 없다 → benign 값이 항상 '반영 안 됨'으로
    잡혀 positive_test가 패치 품질과 무관하게 늘 False가 됐다. attack 게이트(`_replay_reflected`)와 같은
    Playwright 경로로 실제 렌더를 관찰해 이 구조적 오판을 없앤다. payload가 아니라 benign 평문이라
    실행 검사는 없다 — 호출자(positive 오라클)가 benign 값의 DOM 반영만 본다. egress는 대상 origin 밖 차단.

    stored는 먼저 benign을 저장(server-side POST는 httpx로 충분)한 뒤 render_path를 브라우저로 연다.
    """
    from playwright.sync_api import sync_playwright

    base = probe.base_url.rstrip("/")
    if probe.context == "stored":
        try:
            with httpx.Client(follow_redirects=True, timeout=10.0) as client:
                client.request(probe.inject_method, f"{base}{probe.inject_path}",
                               data={**probe.extra_params, probe.inject_param: value})
        except httpx.HTTPError:
            pass
        url = f"{base}{probe.render_path or probe.inject_path}"
    else:  # reflected
        url = _reflected_url(probe, value)

    allowed = urlparse(probe.base_url).netloc
    status, dom = 0, ""
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        context = browser.new_context()
        context.route("**/*", _egress_guard(allowed))
        try:
            page = context.new_page()
            try:
                resp = page.goto(url, wait_until="load", timeout=timeout_ms)
                page.wait_for_timeout(600)  # 클라이언트(Angular) 렌더 여유 — attack 경로와 동일
                status = resp.status if resp is not None else 200
                dom = page.content()
            except Exception:  # noqa: BLE001 — 렌더 실패는 (0,"")로 → 오라클이 overblocking로 판정
                pass
            finally:
                page.close()
        finally:
            browser.close()
    return status, dom
