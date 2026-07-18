"""Day2 섹션 5(공통 계약 이견 정리) 회귀 테스트.

세 변경 모두 P3/P4가 이미 쓰고 있는 코드를 깨뜨리지 않는지가 핵심이라, "기존 필드는
여전히 동작한다"는 것과 "새 제약/필드가 실제로 강제/저장된다"는 것을 같이 확인한다.
"""

from __future__ import annotations

import unittest
from uuid import uuid4

from pydantic import ValidationError

from contracts.schemas import Candidate, Finding, Observation, ObservationType
from core.evidence_store import get, save, write_artifact


class ObservationTypeTests(unittest.TestCase):
    def test_known_values_are_accepted(self) -> None:
        for value in (
            "http_exchange",
            "db_diff",
            "browser_trace",
            "log",
            "route_map",
            "role_map",
        ):
            obs = Observation(
                id=f"obs-{uuid4().hex[:12]}",
                run_id="run-x",
                type=value,
                artifact_uri="file:///x",
                hash="0" * 64,
                producer="test",
            )
            self.assertEqual(obs.type, ObservationType(value))

    def test_unknown_value_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            Observation(
                id="obs-x",
                run_id="run-x",
                type="not_a_real_type",
                artifact_uri="file:///x",
                hash="0" * 64,
                producer="test",
            )

    def test_write_artifact_still_accepts_the_plain_string_p3_already_uses(self) -> None:
        """verifiers/access_control.py가 observation_type="http_exchange"로 호출하는 패턴."""
        run_id = f"run-{uuid4().hex[:12]}"
        obs = write_artifact(
            run_id, observation_type="http_exchange", producer="test", data=b"x"
        )
        self.assertEqual(obs.type, ObservationType.HTTP_EXCHANGE)


class CandidateTypedFieldsAreAdditiveTests(unittest.TestCase):
    def test_signals_only_candidate_still_works_without_new_fields(self) -> None:
        """P3/P4가 지금 쓰는 생성 패턴(signals만 채움)이 그대로 동작해야 한다."""
        candidate = Candidate(
            id=f"cand-{uuid4().hex[:12]}",
            run_id="run-x",
            cwe="CWE-89",
            signals=["focus:injection", "severity:HIGH"],
        )
        self.assertEqual(candidate.vuln_class, None)
        self.assertEqual(candidate.attack_params, {})
        save(candidate)
        self.assertEqual(get(Candidate, candidate.id).signals, candidate.signals)

    def test_new_typed_fields_round_trip(self) -> None:
        candidate = Candidate(
            id=f"cand-{uuid4().hex[:12]}",
            run_id="run-x",
            vuln_class="idor",
            attack_params={"method": "GET", "victim_id": "42"},
        )
        save(candidate)
        reloaded = get(Candidate, candidate.id)
        self.assertEqual(reloaded.vuln_class, "idor")
        self.assertEqual(reloaded.attack_params, {"method": "GET", "victim_id": "42"})


class FindingAffectedRolesTests(unittest.TestCase):
    def test_affected_roles_is_a_list_and_round_trips(self) -> None:
        finding = Finding(
            id=f"finding-{uuid4().hex[:12]}",
            run_id="run-x",
            title="t",
            affected_roles=["USER_A", "USER_B"],
        )
        save(finding)
        reloaded = get(Finding, finding.id)
        self.assertEqual(reloaded.affected_roles, ["USER_A", "USER_B"])

    def test_affected_role_singular_field_no_longer_exists(self) -> None:
        # 모델에 extra="forbid" 설정이 없어 미지 필드는 에러 없이 조용히 무시된다 —
        # affected_role="USER_A"를 넘겨도 저장되지 않는다는 것으로 "더 이상 존재하지
        # 않는 필드"임을 확인한다(다른 오탈자 필드와 구분이 안 되는 건 알려진 한계).
        finding = Finding(id="finding-x", run_id="run-x", title="t", affected_role="USER_A")
        self.assertFalse(hasattr(finding, "affected_role"))
        self.assertNotIn("affected_role", finding.model_dump())
        self.assertEqual(finding.affected_roles, [])


if __name__ == "__main__":
    unittest.main()
