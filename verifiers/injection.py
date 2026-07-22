"""SQL Injection verifier (7.3절, CWE-89). IDOR·XSS에 이은 세 번째 oracle 축 — "쿼리를 제어했나".

────────────────────────────────────────────────────────────────────────────
oracle = 불리언 차등(boolean-based blind) — 왜 이게 안전하고 확실한가
────────────────────────────────────────────────────────────────────────────
"응답에 SQL 에러가 보이나"로 판정하면 취약하다(에러 안 나는 앱도 많고, 반사 에코와 헷갈린다).
대신 **거의 동일한 두 payload**를 보낸다:
  - 참(true) : `... OR '1'='1`  → WHERE가 항상 참이면 결과셋이 열린다(행이 다 나온다)
  - 거짓(false): `... OR '1'='2` → WHERE가 항상 거짓이면 결과셋이 닫힌다(행이 안 나온다)
두 문자열은 **딱 한 글자(1 vs 2)만 다르다**. 앱이 입력을 리터럴로 살균하면 두 응답은 같다(injection
아님). 앱이 입력을 SQL로 해석하면 참은 결과를 열고 거짓은 닫아 **응답이 확연히 달라진다** — 이
차이는 한 글자 에코로는 설명이 안 되므로 SQL 해석의 증거다. IDOR의 "실제 상태 변화"·XSS의 "실제
실행"에 대응하는, injection의 진짜 oracle(응답 200 하나로 verified 하지 않는다).

구성 (access_control.py / xss.py와 동형 3덩어리):
  ① injection_oracle() — 판정 로직(참/거짓 응답 차등으로). 대상 독립·네트워크 없이 단위 테스트 가능.
  ② 재현(_replay_injection) — httpx로 baseline/true/false 요청. 대상 origin 안에서만.
  ③ verify() — 조립 + evidence 저장(observation_type="http_exchange").

────────────────────────────────────────────────────────────────────────────
절대 안전 경계 (공격 코드를 쓰는 사람의 원칙, 10.4절 — injection은 특히 위험)
────────────────────────────────────────────────────────────────────────────
  - **불리언 tautology payload만**: WHERE 평가만 토글한다. INSERT/UPDATE/DELETE/DROP 없음,
    스택 쿼리(`;`) 없음, UNION(타 테이블 열람) 없음, time-based(지연=DoS) 없음, OS/커맨드 없음.
  - **파괴적 쿼리 차단**: `OR '1'='1`은 SELECT의 WHERE만 넓혀 '읽기'가 된다. 그러나 이 payload가
    DELETE/UPDATE의 WHERE에 들어가면 전체 행이 날아간다. 그래서 **GET(읽기 의미) 기본**만 자동
    허용하고, 비-GET은 candidate가 `read_query=true`(SELECT 기반임을 계약으로 보증)를 명시해야만
    재현한다 — 없으면 조용히 통과하지 않고 거부한다(추측으로 파괴적 요청을 보내지 않는다).
  - **fixture 경계 안에서만**: 대상은 격리 로컬 컨테이너. payload는 base_url 밖으로 나가지 않는다.
  - **evidence에 데이터 원문 미기록**: 참(`OR 1=1`)은 DB 행을 다 반환할 수 있어(개인정보/토큰 포함
    가능) 응답 body를 그대로 저장하지 않는다. 상태코드·길이·차이(delta)와 redaction된 짧은 스니펫만.
  - **허용 base_url만**. 임의 URL 입력 금지 — candidate.attack_params로만 온다.
"""

from __future__ import annotations

import difflib
import json
from uuid import uuid4

import httpx
from pydantic import BaseModel

from contracts.schemas import Candidate
from core import evidence_store
from core.redaction import redact
from verifiers.types import MAX_REQUESTS_DEFAULT, VerifierOutput

PRODUCER = "vc_verify_injection"

# 응답 길이 차이가 이 값 이상이면 "결과셋이 열렸다"로 본다. 한 글자 payload 에코(1 vs 2)로는
# 절대 못 넘는 보수적 임계 — verified precision 우선(12.4절), 오탐을 만들지 않는다.
_MIN_DELTA = 48

# 콘텐츠 발산 신호(길이-델타 보완, recall): 참/거짓 본문의 **길이가 비슷해도**(delta<임계) 구조가
# 크게 갈리면 결과셋이 열/닫힌 것 — 길이가 우연히 맞는 취약 앱을 놓치지 않는다. 아래 임계는 precision을
# 깨지 않게 극도로 보수적이다: 한 글자 에코(sim≈1.0)나 살균 앱(두 무효값이 같은 '없음' 페이지, sim≈1.0)은
# 절대 못 넘고, 실제로 rows-vs-empty처럼 본문 태반이 달라야만(sim ≤ _MAX_DIVERGENT_SIM) 발화한다.
_MAX_DIVERGENT_SIM = 0.4     # 참/거짓 유사도가 이보다 높으면 발산으로 보지 않음(닮음)
_SIM_MARGIN = 0.4           # 발산이 benign 자연 유사도 바닥보다 이만큼 아래여야 신뢰(노이즈 억제)
_SIM_MIN_BODY = 64          # 둘 다 이 길이 이상일 때만 — 짧은 본문은 유사도 비율이 불안정
_SIM_CAP = 4000             # 유사도 계산 입력 상한(SequenceMatcher O(n²) 폭주 방지)


def _ratio(a: str, b: str) -> float:
    """두 본문의 구조 유사도(0=완전 다름 ~ 1=동일). 앞 _SIM_CAP자만 본다(성능·안정)."""
    a, b = (a or "")[:_SIM_CAP], (b or "")[:_SIM_CAP]
    if not a and not b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b).ratio()


# --- probe: 재현에 필요한 입력 --------------------------------------------------------


class InjectionProbe(BaseModel):
    """SQLi 재현 입력. 대상별 값은 candidate.attack_params(=SAST/fixture)에서 온다.

    inject_location: query(GET 파라미터) | form(폼 body) | json(JSON body).
    read_query: 비-GET일 때 "이 요청은 SELECT 기반이라 불리언 payload가 파괴적이지 않다"는 계약 보증.
    """

    base_url: str
    inject_path: str                    # 주입 지점 경로 (예: /api/search, /api/auth/login)
    inject_param: str                   # 주입할 파라미터/필드 이름
    inject_method: str = "GET"          # 기본 GET(읽기). 비-GET은 read_query=true 필요
    inject_location: str = "query"      # "query" | "form" | "json" | "path"(경로 파라미터)
    baseline_value: str = "1"           # 정상 동작 확인용 benign 값
    read_query: bool = False            # 비-GET 재현 허용 게이트(SELECT 기반 보증)
    extra_params: dict[str, str] = {}   # 함께 보내야 하는 다른 필수 필드


def injection_probe_from_candidate(candidate: Candidate) -> InjectionProbe:
    """candidate.attack_params → InjectionProbe (IDOR/XSS probe_from_candidate의 injection 짝).

    extra_params(중첩 dict)는 attack_params가 dict[str,str]이라 `extra_params_json`에 JSON
    문자열로 담겨 오면 여기서 되푼다. `read_query`는 "true"/"1" 문자열도 허용한다.
    """
    ap = dict(candidate.attack_params)
    extra = ap.pop("extra_params_json", None)
    if extra:
        ap["extra_params"] = json.loads(extra)
    if "read_query" in ap and isinstance(ap["read_query"], str):
        ap["read_query"] = ap["read_query"].strip().lower() in {"true", "1", "yes"}
    return InjectionProbe(**ap)


# 참/거짓 payload 쌍 — 각 쌍은 딱 한 글자만 다르다(에코 차이 무시 가능). 전부 불리언 tautology(읽기)라
# 파괴적이지 않다. **상위 4개는 기본 예산(10=baseline 2 + 4쌍×2)에서 실제 시도되므로 컨텍스트 다양성을
# 우선**한다: 홑따옴표 문자열 / 숫자 / 괄호로 감싼 문자열 / 겹따옴표 문자열. 나머지는 더 큰 예산일 때
# 시도되는 overflow(주석 종결·괄호+겹따옴표·MySQL # 주석). WHERE가 `(col = '...')`처럼 괄호에 싸인
# 쿼리는 괄호를 닫아야 tautology가 성립 → 이 컨텍스트를 상위에 넣어 recall을 넓힌다.
_PAYLOAD_PAIRS: list[tuple[str, str]] = [
    ("' OR '1'='1", "' OR '1'='2"),            # 문자열, 홑따옴표 탈출
    ("1 OR 1=1", "1 OR 1=2"),                  # 숫자 컨텍스트
    ("') OR ('1'='1", "') OR ('1'='2"),        # 괄호로 감싼 문자열 WHERE — `(col = '...')` 닫기
    ('" OR "1"="1', '" OR "1"="2'),            # 문자열, 겹따옴표 탈출
    ("' OR '1'='1' -- ", "' OR '1'='2' -- "),  # (overflow) 문자열 + 주석으로 뒤 절 무력화
    ('") OR ("1"="1', '") OR ("1"="2'),        # (overflow) 괄호로 감싼 겹따옴표 문자열
    ("' OR '1'='1' #", "' OR '1'='2' #"),      # (overflow) MySQL # 주석
]


# --- ① injection oracle (핵심, 대상 독립, 네트워크 없음) ------------------------------


def injection_oracle(
    true_status: int, true_body: str, false_status: int, false_body: str, *,
    min_delta: int = _MIN_DELTA, baseline_variance: int = 0, baseline_status_stable: bool = True,
    baseline_similarity: float = 1.0,
) -> tuple[bool, str]:
    """참/거짓 응답 차등으로 SQLi를 판정한다. 두 payload는 한 글자만 다르므로, 유의미한 차이는
    입력이 SQL 불리언으로 해석됐다는 증거다. 살균(리터럴 처리)되면 둘은 같다 → injection 아님.

    **노이즈 바닥(baseline_variance)**: 엔드포인트 응답이 요청마다 자연히 흔들리면(타임스탬프·nonce·
    페이지네이션) 안전한 앱도 참≠거짓이 되어 오탐한다. 재현부가 benign baseline을 2회 재서 잰 자연
    변동을 여기로 넘기면, 판정 임계를 `min_delta + 2×변동`으로 올려 노이즈로 설명되는 차이는 무시한다
    (변동 0인 조용한 엔드포인트는 기존과 동일하게 동작 → 랩 true-positive 유지). baseline_status_stable
    =False(baseline 상태코드도 흔들림)면 상태코드 갈림 신호도 노이즈로 보고 신뢰하지 않는다.

    **콘텐츠 발산(baseline_similarity)**: 길이 델타는 참(모든 행)과 거짓(빈 결과)의 **byte 길이가 우연히
    비슷하면** 놓친다. 이때도 두 본문의 구조는 크게 다르다(행 목록 vs 없음 페이지). 참/거짓 유사도가
    benign 2-sample 유사도 바닥보다 크게 아래로 떨어지면 결과셋 열/닫힘으로 본다. 한 글자 에코나 살균
    앱(두 무효값이 같은 '없음' 페이지)은 유사도가 높아 절대 걸리지 않아 precision을 지킨다.
    """
    tb, fb = (true_body or ""), (false_body or "")
    delta = len(tb) - len(fb)
    threshold = min_delta + 2 * max(0, baseline_variance)  # 자연 변동 위로 min_delta만큼 여유

    # (1) 참(1=1)이 거짓(1=2)보다 노이즈 바닥을 넘어 확연히 큼 = 결과셋이 열림(불리언 blind SQLi).
    if delta >= threshold:
        return True, (
            f"참 조건(OR 1=1) 응답이 거짓 조건(OR 1=2)보다 {delta}바이트 큼(자연 변동 {baseline_variance}"
            f"바이트 초과, 임계 {threshold}) — 입력이 SQL 불리언으로 해석돼 결과셋을 제어함 (SQL Injection, CWE-89)."
        )
    # (2) 상태 코드가 5xx 경계에서 갈림 — 단 baseline 상태가 안정적일 때만(불안정하면 노이즈).
    if baseline_status_stable and (true_status < 500) != (false_status < 500):
        return True, (
            f"참/거짓 조건에서 응답 상태가 갈림(true={true_status}, false={false_status}) — "
            f"입력이 SQL 실행 경로에 영향 (SQL Injection, CWE-89)."
        )
    # (2b) 길이는 비슷해도(위 델타 미달) 참/거짓 본문이 구조적으로 크게 갈림 = 결과셋 열/닫힘.
    #      둘 다 실질 길이(_SIM_MIN_BODY)이고 상태가 안정적일 때만, benign 자연 유사도 바닥보다
    #      _SIM_MARGIN 이상 아래로 발산해야 발화 — 에코·살균은 유사도가 높아 여기 못 온다.
    if baseline_status_stable and min(len(tb), len(fb)) >= _SIM_MIN_BODY:
        sim = _ratio(tb, fb)
        if sim <= _MAX_DIVERGENT_SIM and (baseline_similarity - sim) >= _SIM_MARGIN:
            return True, (
                f"참/거짓 응답 길이는 비슷하나 본문이 구조적으로 크게 갈림(유사도 {sim:.2f} ≤ "
                f"{_MAX_DIVERGENT_SIM}, benign 자연 유사도 {baseline_similarity:.2f} 대비 "
                f"{baseline_similarity - sim:.2f} 하락) — 결과셋이 열/닫혀 SQL 불리언 제어됨 (SQL Injection, CWE-89)."
            )
    # (3) 참 ≈ 거짓 (노이즈 범위 내) → 입력이 리터럴로 처리됨(살균/파라미터화).
    if abs(delta) < threshold:
        return False, (
            f"참/거짓 조건 응답 차이({abs(delta)}바이트)가 자연 변동 바닥(임계 {threshold}바이트) 이내 — "
            f"입력이 리터럴로 처리됨(살균/파라미터화), SQL Injection 아님."
        )
    return False, "판정 신호 부족 — SQL Injection 근거 없음."


# --- ② 재현 (httpx, 대상 origin 안에서만) --------------------------------------------


class _Attempt(BaseModel):
    true_payload: str
    false_payload: str
    true_status: int
    false_status: int
    true_len: int
    false_len: int
    baseline_variance: int = 0
    verified: bool
    reason: str


def _inject_into_path(inject_path: str, param: str, value: str) -> str:
    """경로 파라미터 자리(`:param`/`{param}`/`<param>`)에 payload를 URL 인코딩해 치환한다.

    토큰이 없으면(정규화 경로) payload를 마지막 세그먼트로 덧붙인다(best-effort). 경로 주입은
    SELECT 읽기 sink에만 오므로(write는 candidate 단계에서 blocked) 불리언 payload가 파괴적이지 않다.
    """
    from urllib.parse import quote

    enc = quote(value, safe="")
    for token in (f":{param}", f"{{{param}}}", f"<{param}>"):
        if token in inject_path:
            return inject_path.replace(token, enc)
    return f"{inject_path.rstrip('/')}/{enc}"


def _send(client: httpx.Client, probe: InjectionProbe, value: str) -> tuple[int, str]:
    """주입 값 하나로 요청을 보내 (status, body)를 돌려준다. location에 맞게 주입 위치를 고른다."""
    method = probe.inject_method.upper()
    # 경로 파라미터 주입(`req.params.id`): payload를 경로 토큰에 치환. query/body와 배타적.
    if probe.inject_location == "path":
        url = f"{probe.base_url.rstrip('/')}{_inject_into_path(probe.inject_path, probe.inject_param, value)}"
        r = client.request(method, url, params=(probe.extra_params or None))
        return r.status_code, r.text
    url = f"{probe.base_url.rstrip('/')}{probe.inject_path}"
    payload = {**probe.extra_params, probe.inject_param: value}
    if method == "GET":
        r = client.get(url, params=payload)
    elif probe.inject_location == "json":
        r = client.request(method, url, json=payload)
    else:  # form
        r = client.request(method, url, data=payload)
    return r.status_code, r.text


def _replay_injection(probe: InjectionProbe, max_requests: int) -> list[_Attempt]:
    """baseline **2회**(자연 변동 측정) + 쌍마다 (참, 거짓) 2회. 첫 verified에서 멈춘다. max_requests 상한.

    baseline을 두 번 보내 응답 길이가 요청마다 얼마나 흔들리는지(자연 변동)와 상태코드 안정성을 재고,
    그 노이즈 바닥을 oracle에 넘겨 오탐을 막는다(타임스탬프·nonce·페이지네이션 대응).
    """
    if probe.inject_method.upper() != "GET" and not probe.read_query:
        # 비-GET에 불리언 payload를 보내면 DELETE/UPDATE의 WHERE를 넓힐 위험 → 계약 보증 없이는 거부.
        raise NotImplementedError(
            "비-GET injection 재현은 read_query=true(SELECT 기반 보증)가 있어야 한다 — "
            "불리언 payload가 파괴적 쿼리에 들어가는 것을 막는다(추측 금지)."
        )

    attempts: list[_Attempt] = []
    budget = max_requests
    baseline_variance = 0
    baseline_status_stable = True
    baseline_similarity = 1.0
    with httpx.Client(follow_redirects=True, timeout=10.0) as client:
        # baseline(benign) 2회: 엔드포인트의 자연 변동(응답 길이·상태·구조) 측정 = 노이즈 바닥.
        samples: list[tuple[int, str]] = []
        while len(samples) < 2 and budget > 0:
            budget -= 1
            try:
                samples.append(_send(client, probe, probe.baseline_value))
            except httpx.HTTPError:
                samples.append((0, ""))
        if len(samples) == 2:
            baseline_variance = abs(len(samples[0][1]) - len(samples[1][1]))
            baseline_status_stable = samples[0][0] == samples[1][0]
            baseline_similarity = _ratio(samples[0][1], samples[1][1])  # 발산 신호의 노이즈 바닥
        for true_pl, false_pl in _PAYLOAD_PAIRS:
            if budget < 2:  # 참 + 거짓 = 2요청
                break
            budget -= 2
            try:
                t_status, t_body = _send(client, probe, true_pl)
                f_status, f_body = _send(client, probe, false_pl)
            except httpx.HTTPError:
                continue
            verified, reason = injection_oracle(
                t_status, t_body, f_status, f_body,
                baseline_variance=baseline_variance, baseline_status_stable=baseline_status_stable,
                baseline_similarity=baseline_similarity,
            )
            attempts.append(_Attempt(
                true_payload=true_pl, false_payload=false_pl,
                true_status=t_status, false_status=f_status,
                true_len=len(t_body or ""), false_len=len(f_body or ""),
                baseline_variance=baseline_variance, verified=verified, reason=reason,
            ))
            if verified:
                break
    return attempts


# --- ③ verify() 조립 + evidence 저장 --------------------------------------------------


def verify(
    run_id: str,
    candidate: Candidate,
    *,
    max_requests: int = MAX_REQUESTS_DEFAULT,
) -> VerifierOutput:
    """SQLi 후보를 불리언 차등으로 재현·판정하고 시도를 evidence로 남긴다.

    IDOR/XSS verify()와 같은 계약: P1의 vc_verify_injection tool이 이 함수를 호출하고, 반환된
    evidence_ids로 update_finding_status(finding_id, VERIFIED, evidence_ids=...)를 부른다.
    policy 검사·상태 전이는 호출자(P1) 몫 — 이 함수는 "쿼리를 제어하는 injection인가"만 판정한다.
    """
    probe = injection_probe_from_candidate(candidate)
    attempts = _replay_injection(probe, max_requests)

    verified = any(a.verified for a in attempts)
    winner = next((a for a in attempts if a.verified), attempts[-1] if attempts else None)
    reason = winner.reason if winner is not None else "재현 시도가 없었다 — 요청 예산 부족 또는 대상 무응답."

    evidence_ids: list[str] = []
    if winner is not None:
        # 데이터 원문은 저장하지 않는다(참 조건이 DB 행을 다 반환할 수 있음). 상태·길이·차이만 + redaction 스니펫.
        data = json.dumps(
            {
                "inject_path": probe.inject_path, "param": probe.inject_param, "method": probe.inject_method,
                "true_payload": winner.true_payload, "false_payload": winner.false_payload,
                "true_status": winner.true_status, "false_status": winner.false_status,
                "true_len": winner.true_len, "false_len": winner.false_len,
                "delta": winner.true_len - winner.false_len,
                "baseline_variance": winner.baseline_variance,
                "verified": winner.verified, "reason": redact(winner.reason), "attempts": len(attempts),
            },
            ensure_ascii=False,
        ).encode()
        obs = evidence_store.write_artifact(
            run_id, observation_type="http_exchange",
            producer=f"{PRODUCER}:{'boolean_diff' if verified else 'no_diff'}", data=data,
        )
        evidence_ids.append(obs.id)

    return VerifierOutput(verified=verified, evidence_ids=evidence_ids, reason=reason)


# 네트워크 없이 oracle 자가 점검: `python -m verifiers.injection`
if __name__ == "__main__":
    ok = 0
    # 취약: 참이 거짓보다 훨씬 큼(결과셋 열림)
    v, _ = injection_oracle(200, "row" * 200, 200, "")
    ok += v is True
    # 취약: 상태 갈림(거짓만 500)
    v, _ = injection_oracle(200, "x", 500, "error")
    ok += v is True
    # 안전(살균): 참≈거짓
    v, _ = injection_oracle(200, "same body here", 200, "same body here!")
    ok += v is False
    # 안전: 둘 다 빈 결과
    v, _ = injection_oracle(200, "", 200, "")
    ok += v is False
    # 하드닝: 참-거짓 차이 100(옛 임계 48이면 오탐)이지만 자연 변동 100이면 노이즈로 억제 → False
    v, _ = injection_oracle(200, "a" * 100, 200, "", baseline_variance=100)
    ok += v is False
    # 대조: 같은 100 차이라도 변동 0(조용한 엔드포인트)이면 그대로 탐지 → True (랩 TP 유지)
    v, _ = injection_oracle(200, "a" * 100, 200, "", baseline_variance=0)
    ok += v is True
    # 콘텐츠 발산: 길이는 거의 같지만(델타<임계) 본문 구조가 크게 갈림 = 결과셋 열/닫힘 → True
    v, _ = injection_oracle(200, "ROW " * 40, 200, "no results found. " * 9, baseline_similarity=1.0)
    ok += v is True
    # 발산 precision: 두 무효값이 같은 '없음' 페이지(한 글자만 다름, 유사도 높음) → 미탐 → False
    v, _ = injection_oracle(200, "no results for '1'='1" * 8, 200, "no results for '1'='2" * 8)
    ok += v is False
    print(f"injection_oracle self-check: {ok}/8 {'PASS' if ok == 8 else 'FAIL'}")
