"""Attack gate / Positive functionality gate 실행기 (7.6절). Day3 — closed-loop의 마지막 관문.

P1의 judge(core/judge.py)가 호출하는 실행기. 6개 게이트 중 P3가 실물을 제공하는 것:
- Attack gate: 기존 재현 시퀀스가 더 이상 보안 영향을 만들지 않음 (verifier 재사용)
- Positive functionality gate: 정상 권한 사용자의 원래 기능이 패치 후에도 성공함

나머지 4개(Build/Regression/Static/Scope)는 P1 배선 + P2 test runner / P4 Semgrep.

────────────────────────────────────────────────────────────────────────────
왜 이 두 게이트를 한 곳에서, 한 번의 재현으로 뽑나
────────────────────────────────────────────────────────────────────────────
IDOR 재현 한 번(`access_control._replay_idor`)이 두 개의 응답을 만든다:
  - baseline : 공격자가 *자기* 자원을 요청한 응답 (정상 기능에 해당)
  - attack   : 공격자가 *피해자* 자원을 요청한 응답 (공격에 해당)

패치 후 이 시퀀스를 다시 돌리면 두 게이트를 동시에 판정할 수 있다:
  - Attack gate           : attack 응답에 피해자 데이터가 더는 없어야 통과
  - Positive funct. gate  : baseline 응답이 여전히 2xx이고 주인 데이터가 남아 있어야 통과

이 조합이 기획서 3.2절이 경고한 **overblocking 패치**를 잡는다 — "모든 접근을 막아버리는"
패치는 attack gate는 통과하지만(공격 차단됨) positive gate에서 실패한다(주인도 자기 걸 못 봄).
보안 oracle만 봤다면 그 나쁜 패치가 FIXED로 승격됐을 것이다.

────────────────────────────────────────────────────────────────────────────
judge와의 관계 (의존 방향)
────────────────────────────────────────────────────────────────────────────
core/judge.py가 verifier를 import해 쓰듯(judge → verifiers), judge는 이 모듈도 import해 쓴다
(judge → repair.validators). 이 모듈은 core/judge.py를 import하지 않는다 — 그래서 judge의
나머지 게이트가 완성되기 전에도 **단독 실행**이 된다(`python -m repair.validators`로 self-check).

이 모듈은 `Finding.verification_state`를 직접 바꾸지 않는다. verify()가 그랬듯 "게이트를
통과했는가"만 판정하고 evidence를 남긴다. 최종 `fixed` 승격은 judge가 6게이트를 전부 모아
`update_finding_status()`(evidence 실존 검사 포함)로만 한다.
"""

from __future__ import annotations

import json

from pydantic import BaseModel

from contracts.schemas import Candidate
from core import evidence_store

# 재현 로직은 verifier 것을 그대로 재사용한다(DRY). `_replay_idor`는 P3 패키지 내부 재사용이라
# 밑줄 이름이지만 의도적으로 가져다 쓴다 — 공격 시퀀스가 재현과 재검증에서 동일해야
# "같은 공격을 다시 했는데 이제 실패한다"가 성립하기 때문이다.
from verifiers.access_control import (
    _replay_idor,
    idor_oracle,
    probe_from_candidate,
)
from verifiers.types import MAX_REQUESTS_DEFAULT

PRODUCER = "vc_validate_patch"


class GateOutcome(BaseModel):
    """게이트 하나의 판정 결과.

    `passed`가 bool 판정(judge의 `Validation.attack`/`positive_test` 필드에 그대로 들어간다),
    `evidence_ids`는 판정 근거로 실제 저장된 Observation id들(재현/승격과 동일한 evidence 규율).
    """

    gate: str  # "attack" | "positive_functionality"
    passed: bool
    reason: str
    evidence_ids: list[str] = []


class SecurityValidation(BaseModel):
    """P3 소유 두 게이트의 결과 묶음.

    **최종 verdict(FIXED/RETRY/HUMAN_REVIEW)는 여기서 내지 않는다** — build/regression/static/
    scope까지 6게이트를 전부 모아 판정하는 건 judge의 몫이다. 이 모델은 그중 2칸만 채운다.
    """

    attack: GateOutcome
    positive_functionality: GateOutcome

    @property
    def both_passed(self) -> bool:
        """P3가 책임지는 두 게이트가 모두 통과했는지. (FIXED 여부가 아니라 P3 몫만.)"""
        return self.attack.passed and self.positive_functionality.passed


# ── ① 순수 oracle (네트워크 X, 단위 테스트 가능) ─────────────────────────────────────


def attack_gate_oracle(baseline_body: str, attack_body: str, victim_marker: str) -> tuple[bool, str]:
    """재공격 게이트: 패치 후 IDOR이 더 이상 재현되지 않으면 통과(True).

    판정 근거를 verifier와 완전히 일치시키기 위해 `idor_oracle`을 그대로 뒤집어 쓴다 —
    verify()가 "verified=True(뚫림)"를 만든 바로 그 규칙이 이제 "False(못 뚫음)"를 내야
    게이트 통과다. 별도 규칙을 쓰면 "verify는 뚫렸다는데 gate는 막혔다다"는 모순이 생길 수 있다.
    """
    still_vulnerable, why = idor_oracle(baseline_body, attack_body, victim_marker)
    if still_vulnerable:
        return False, f"패치 후에도 공격이 그대로 재현됨 — {why}"
    return True, f"동일 공격을 재실행했으나 재현 실패 — 피해자 자원이 더는 노출되지 않음 ({why})"


def positive_gate_oracle(
    baseline_status: int, baseline_body: str, owner_marker: str | None
) -> tuple[bool, str]:
    """정상기능 게이트: 정상 사용자가 패치 후에도 자기 자원을 정상 조회하면 통과(True).

    baseline 요청 = 공격자(=일반 사용자)가 *자기* 자원을 요청한 것. 이건 원래부터 허용돼야 하는
    정상 기능이다. overblocking 패치("전부 막기")는 이 요청까지 죽이므로 여기서 걸린다.

    - status가 2xx가 아니면        → 실패 (정상 기능이 깨짐)
    - owner_marker가 주어졌는데 응답에서 사라졌으면 → 실패 (2xx지만 빈 응답/데이터 증발)
    - owner_marker가 없으면        → status만으로 판정 (약한 통과, 아래 확장 주석 참고)
    """
    if not 200 <= baseline_status < 300:
        return False, (
            f"정상 사용자의 자기 자원 요청이 실패(status={baseline_status}) — "
            f"패치가 정상 기능까지 막은 overblocking으로 의심됨"
        )
    if owner_marker and owner_marker not in baseline_body:
        return False, (
            f"응답은 2xx지만 주인의 데이터 {owner_marker!r}가 사라짐 — "
            f"패치가 정상 기능을 손상시킴(빈 응답/데이터 누락)"
        )
    return True, "정상 사용자는 패치 후에도 자기 자원을 정상적으로 조회함"


# ── ② + ③ 재현 + 조립 + evidence ────────────────────────────────────────────────────


def validate_patch(
    run_id: str,
    candidate: Candidate,
    *,
    max_requests: int = MAX_REQUESTS_DEFAULT,
) -> SecurityValidation:
    """패치된 대상에 동일 공격 시퀀스를 재실행해 재공격·정상기능 게이트를 함께 판정한다.

    호출 전제: patcher가 patch를 worktree에 적용하고 그 인스턴스가 떠 있어야 한다. 이 함수는
    candidate.signals의 base_url이 가리키는 대상을 그대로 찌른다 — closed-loop에서 호출자가
    base_url을 "패치된 인스턴스"로 바꿔 candidate를 넘기면 된다(로직은 대상 위치에 무관).

    P1의 judge.check_positive_functionality/check_attack가 이 함수를 한 번 호출하고
    `.positive_functionality.passed` / `.attack.passed`를 각 게이트 bool로 읽으면 된다 —
    게이트마다 따로 재현하지 말 것(요청 수 2배, 10.2절 rate limit 낭비).
    """
    probe = probe_from_candidate(candidate)
    baseline, attack = _replay_idor(probe, max_requests)

    # 패치 후 재공격 교환 2건을 evidence로 저장. verify()가 재현 근거를 남기듯, 재검증도
    # 근거를 남겨야 FIXED 판정이 evidence 기반이 된다. redaction/해시는 write_artifact가 건다.
    evidence_ids: list[str] = []
    for label, exchange in (("post_patch_baseline", baseline), ("post_patch_attack", attack)):
        data = json.dumps(exchange, ensure_ascii=False).encode()
        obs = evidence_store.write_artifact(
            run_id, observation_type="http_exchange", producer=f"{PRODUCER}:{label}", data=data
        )
        evidence_ids.append(obs.id)

    attack_passed, attack_reason = attack_gate_oracle(
        baseline["response"]["body"], attack["response"]["body"], probe.victim_marker
    )
    positive_passed, positive_reason = positive_gate_oracle(
        baseline["response"]["status"], baseline["response"]["body"], probe.owner_marker
    )

    return SecurityValidation(
        attack=GateOutcome(
            gate="attack",
            passed=attack_passed,
            reason=attack_reason,
            evidence_ids=evidence_ids,
        ),
        positive_functionality=GateOutcome(
            gate="positive_functionality",
            passed=positive_passed,
            reason=positive_reason,
            evidence_ids=evidence_ids,
        ),
    )


# 확장 여지(다음 라운드): 지금 정상기능 게이트는 baseline(공격자의 자기 자원)만 확인한다.
# 더 엄격히 하려면 피해자 역할로도 재인증해 "피해자도 자기 자원을 여전히 본다"를 확인해야
# 한다("owner-scoped" 패치가 특정 사용자만 통과시키는 실수를 잡기 위함). P2 role fixture로
# 두 번째 인증이 붙으면 추가한다. 지금은 단일 세션 재현으로 MVP를 만족한다.


if __name__ == "__main__":
    # judge/네트워크 없이 순수 oracle만 self-check — "단독 실행 가능"의 증거.
    # (실제 대상 재현은 live 인스턴스가 필요하므로 여기서는 판정 로직만 검증한다.)
    cases = [
        # (라벨, baseline_body, attack_body, victim_marker, expect_attack_pass)
        ("취약(패치 전): 공격 응답에 피해자 노출", "me=Tom", "victim=Buffalo Bill", "Buffalo Bill", False),
        ("차단(좋은 패치): 공격이 막힘", "me=Tom", "Access Denied", "Buffalo Bill", True),
    ]
    print("== attack_gate_oracle ==")
    for label, base, atk, marker, expect in cases:
        passed, reason = attack_gate_oracle(base, atk, marker)
        ok = "OK" if passed == expect else "FAIL"
        print(f"  [{ok}] {label}: passed={passed} — {reason}")

    print("== positive_gate_oracle ==")
    pos_cases = [
        ("정상: 주인이 자기 데이터 봄", 200, "me=Tom", "Tom", True),
        ("overblock: 주인도 403", 403, "Forbidden", "Tom", False),
        ("overblock: 2xx지만 데이터 증발", 200, "{}", "Tom", False),
    ]
    for label, status, body, owner, expect in pos_cases:
        passed, reason = positive_gate_oracle(status, body, owner)
        ok = "OK" if passed == expect else "FAIL"
        print(f"  [{ok}] {label}: passed={passed} — {reason}")
