"""verifiers/access_control.py 헤르메틱 단위 테스트 (P3 남은 일 #4).

네트워크/실앱 없이 access_control verifier의 코어 로직을 고정한다:
  - idor_oracle: 200만으로는 verified 아님 — 마커 유출 + baseline과의 차이로만 판정.
  - mutation_idor_oracle: before→after 실제 상태변화로만 verified.
  - _identity_values: nonce로 계정 식별자만 유니크하게, marker는 순수 유지(재프로비저닝 충돌 방지).
  - auth_mode 분기(none/session_form/bearer)와 rate-limit 예산(_required_requests).
  - probe/candidate/fixture 계약, _render_body/_dig 헬퍼, redact.

HTTP는 httpx.Client mock으로 대체한다(기존 test_bearer_resource_replay.py 방식).
대상 모듈(access_control.py)은 수정하지 않는다.
"""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from contracts.schemas import Candidate, Observation
from core.evidence_store import get
from verifiers import access_control as ac
from verifiers.access_control import (
    IdorProbe,
    MutationProbe,
    _dig,
    _identity_values,
    _pick_resource,
    _render_body,
    _replay_idor,
    _replay_none,
    _replay_session_form,
    _required_requests,
    candidate_from_fixture,
    idor_oracle,
    mutation_idor_oracle,
    mutation_probe_from_candidate,
    mutation_probe_from_fixture,
    probe_from_candidate,
    probe_from_fixture,
    redact,
    verify,
)


# --- httpx.Client mock 헬퍼 ------------------------------------------------------------


class _Response:
    def __init__(self, status: int, body: object) -> None:
        self.status_code = status
        if isinstance(body, str):
            self.text = body
            self._payload: object = body
        else:
            self.text = json.dumps(body)
            self._payload = body

    def json(self) -> object:
        return self._payload


class _RecordingClient:
    """테스트별로 응답 규칙을 주입할 수 있는 httpx.Client 대역.

    서브클래스가 클래스 변수로 `route(method, url, **kw) -> _Response`를 정의한다.
    호출 로그는 인스턴스가 아니라 클래스 변수 `calls`에 남겨 patch 밖에서 검사한다.
    """

    calls: list[tuple]

    def __init__(self, **_kwargs) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def get(self, url, *, headers=None):
        type(self).calls.append(("GET", url, headers))
        return type(self).respond("GET", url, headers=headers)

    def post(self, url, *, data=None, json=None, headers=None):
        type(self).calls.append(("POST", url, {"data": data, "json": json, "headers": headers}))
        return type(self).respond("POST", url, data=data, json=json, headers=headers)

    def request(self, method, url, *, json=None, headers=None):
        type(self).calls.append((method, url, {"json": json, "headers": headers}))
        return type(self).respond(method, url, json=json, headers=headers)


# --- ① idor_oracle: 200만으로는 verified 아님 ------------------------------------------


class IdorOracleTests(unittest.TestCase):
    def test_marker_leaked_only_in_attack_and_bodies_differ_is_verified(self) -> None:
        verified, reason = idor_oracle(
            baseline_body='{"name":"attacker"}',
            attack_body='{"name":"VICTIM-SECRET"}',
            victim_marker="VICTIM-SECRET",
        )
        self.assertTrue(verified)
        self.assertIn("CWE-639", reason)

    def test_marker_in_both_is_not_unique_victim_data(self) -> None:
        verified, reason = idor_oracle(
            baseline_body="shared VICTIM-SECRET here",
            attack_body="also VICTIM-SECRET there",
            victim_marker="VICTIM-SECRET",
        )
        self.assertFalse(verified)
        self.assertIn("baseline", reason)

    def test_identical_bodies_not_verified_even_if_200(self) -> None:
        # 핵심: 응답이 동일하면(서버가 요청 자원을 반영 안 함) 200이라도 verified 아님.
        body = '{"ok":true}'
        verified, reason = idor_oracle(body, body, victim_marker="VICTIM-SECRET")
        self.assertFalse(verified)
        self.assertIn("동일", reason)

    def test_marker_absent_means_access_blocked(self) -> None:
        verified, reason = idor_oracle(
            baseline_body='{"name":"attacker"}',
            attack_body='{"error":"forbidden"}',
            victim_marker="VICTIM-SECRET",
        )
        self.assertFalse(verified)
        self.assertIn("차단", reason)

    def test_whitespace_only_difference_counts_as_same(self) -> None:
        # strip 후 동일하면 서버가 자원을 반영하지 않은 것 — verified 아님.
        verified, _ = idor_oracle("  same  ", "same\n", victim_marker="m")
        self.assertFalse(verified)


class MutationOracleTests(unittest.TestCase):
    def test_marker_appears_after_but_not_before_is_verified(self) -> None:
        verified, reason = mutation_idor_oracle(
            before_body='{"description":"orig"}',
            after_body='{"description":"vc-write-idor-abcd1234"}',
            mutation_marker="vc-write-idor-abcd1234",
        )
        self.assertTrue(verified)
        self.assertIn("CWE-639", reason)

    def test_marker_already_present_before_is_not_state_change(self) -> None:
        verified, reason = mutation_idor_oracle(
            before_body="MARK already",
            after_body="MARK still",
            mutation_marker="MARK",
        )
        self.assertFalse(verified)
        self.assertIn("변경 전에도", reason)

    def test_marker_never_appears_means_write_blocked(self) -> None:
        verified, reason = mutation_idor_oracle(
            before_body="orig",
            after_body="orig",
            mutation_marker="MARK",
        )
        self.assertFalse(verified)
        self.assertIn("반영 안 됨", reason)


# --- ② bearer nonce 재프로비저닝 ------------------------------------------------------


class IdentityValuesTests(unittest.TestCase):
    def test_nonce_makes_account_identifiers_unique_but_marker_pure(self) -> None:
        v = _identity_values("owner", "pw", nonce="aaaa")
        self.assertEqual(v["marker"], "owner")  # marker는 순수 유지 → needle 매칭 그대로
        self.assertEqual(v["name"], "owner-aaaa")
        self.assertEqual(v["username"], "owner-aaaa")
        self.assertEqual(v["email"], "owner-aaaa@vc.local")
        self.assertEqual(v["password"], "pw")
        # 계정 식별자엔 marker가 substring으로 남아 idor_oracle/positive_gate needle 유지.
        self.assertIn("owner", v["name"])
        self.assertIn("owner", v["email"])

    def test_different_nonces_avoid_reprovision_collision(self) -> None:
        # attack/positive 게이트가 같은 인스턴스에 재가입해도 식별자가 달라 409 안 남.
        a = _identity_values("owner", "pw", nonce="aaaa")
        b = _identity_values("owner", "pw", nonce="bbbb")
        self.assertNotEqual(a["name"], b["name"])
        self.assertNotEqual(a["email"], b["email"])
        self.assertEqual(a["marker"], b["marker"])  # 그래도 marker는 동일하게 순수

    def test_without_nonce_identifier_equals_marker(self) -> None:
        v = _identity_values("owner", "pw")
        self.assertEqual(v["name"], "owner")
        self.assertEqual(v["email"], "owner@vc.local")


# --- ③ auth_mode 분기 재현 ------------------------------------------------------------


class ReplayNoneTests(unittest.TestCase):
    def test_none_mode_sends_two_unauthenticated_gets(self) -> None:
        class Client(_RecordingClient):
            calls = []

            @staticmethod
            def respond(method, url, **kw):
                if url.endswith("/mine"):
                    return _Response(200, {"name": "attacker"})
                return _Response(200, {"name": "VICTIM"})

        probe = IdorProbe(
            base_url="http://127.0.0.1:9",
            auth_mode="none",
            baseline_path="/notes/mine",
            attack_path="/notes/victim",
            victim_marker="VICTIM",
        )
        with patch("verifiers.access_control.httpx.Client", Client):
            baseline, attack = _replay_none(probe)
        self.assertEqual(len(Client.calls), 2)
        # 인증 헤더 없이 GET 두 번 (토큰/세션 없는 앱).
        self.assertTrue(all(c[0] == "GET" and c[2] is None for c in Client.calls))
        self.assertEqual(baseline["request"]["path"], "/notes/mine")
        self.assertEqual(attack["request"]["path"], "/notes/victim")
        self.assertIn("VICTIM", attack["response"]["body"])

    def test_none_mode_requires_both_paths(self) -> None:
        probe = IdorProbe(base_url="http://x", auth_mode="none", victim_marker="m")
        with self.assertRaises(ValueError):
            _replay_none(probe)


class ReplaySessionFormTests(unittest.TestCase):
    def test_session_form_registers_logs_in_then_reads_both(self) -> None:
        class Client(_RecordingClient):
            calls = []

            @staticmethod
            def respond(method, url, **kw):
                if url.endswith("/mine"):
                    return _Response(200, {"name": "attacker"})
                if url.endswith("/victim"):
                    return _Response(200, {"name": "VICTIM"})
                return _Response(200, {"ok": True})

        probe = IdorProbe(
            base_url="http://127.0.0.1:9",
            auth_mode="session_form",
            baseline_path="/data/mine",
            attack_path="/data/victim",
            victim_marker="VICTIM",
            app_username="atk",
            app_password="pw",
            auth_path="/authn",
            auth_username="atk",
            auth_password="pw",
        )
        with patch("verifiers.access_control.httpx.Client", Client):
            baseline, attack = _replay_session_form(probe)
        methods = [c[0] for c in Client.calls]
        self.assertEqual(methods.count("POST"), 3)  # register + login + auth_path
        self.assertEqual(methods.count("GET"), 2)   # baseline + attack
        self.assertEqual(baseline["request"]["path"], "/data/mine")
        self.assertEqual(attack["request"]["path"], "/data/victim")

    def test_session_form_missing_fields_raises(self) -> None:
        probe = IdorProbe(base_url="http://x", auth_mode="session_form", victim_marker="m")
        with self.assertRaises(ValueError) as ctx:
            _replay_session_form(probe)
        self.assertIn("session_form", str(ctx.exception))


class ReplayBearerTests(unittest.TestCase):
    """bearer: 자체 provision(회원가입 2명) 후 공격자 토큰으로 baseline/attack 요청."""

    def _make_client(self):
        class Client(_RecordingClient):
            calls = []

            @staticmethod
            def respond(method, url, **kw):
                if url.endswith("/signup"):
                    body = json.dumps(kw.get("json") or {})
                    # 이름/이메일에 어떤 marker가 들었는지로 owner/attacker 구분.
                    if "victimM" in body:
                        return _Response(201, {"id": 1, "accessToken": "tok-owner"})
                    return _Response(201, {"id": 2, "accessToken": "tok-attacker"})
                # GET /api/users/{id}/profile
                if url.endswith("/1/profile"):
                    return _Response(200, {"name": "victimM"})   # 피해자 프로필
                return _Response(200, {"name": "attackerM"})     # 공격자 자기 프로필

        return Client

    def test_bearer_uses_attacker_token_for_both_reads_and_swaps_ids(self) -> None:
        Client = self._make_client()
        probe = IdorProbe(
            base_url="http://127.0.0.1:9",
            auth_mode="bearer",
            signup_path="/api/auth/signup",
            path_template="/api/users/{id}/profile",
            victim_marker="victimM",
            owner_marker="attackerM",
        )
        with patch("verifiers.access_control.httpx.Client", Client):
            baseline, attack = _replay_idor(probe, max_requests=10)
        self.assertEqual(len(Client.calls), 4)  # signup×2 + baseline + attack
        # baseline = 공격자 자기 자원(id=2), attack = 피해자 자원(id=1).
        self.assertEqual(baseline["request"]["path"], "/api/users/2/profile")
        self.assertEqual(attack["request"]["path"], "/api/users/1/profile")
        # 두 GET 모두 공격자 토큰(Bearer tok-attacker)을 사용.
        gets = [c for c in Client.calls if c[0] == "GET"]
        self.assertTrue(all(g[2] == {"Authorization": "Bearer tok-attacker"} for g in gets))

    def test_bearer_provision_uses_nonce_unique_emails_marker_preserved(self) -> None:
        # 두 번 재현해도 signup email이 매번 달라(재프로비저닝 409 방지) 그러나 marker는 substring 유지.
        Client = self._make_client()
        probe = IdorProbe(
            base_url="http://127.0.0.1:9",
            auth_mode="bearer",
            signup_path="/api/auth/signup",
            path_template="/api/users/{id}/profile",
            victim_marker="victimM",
            owner_marker="attackerM",
        )
        emails: list[str] = []
        for _ in range(2):
            Client.calls = []
            with patch("verifiers.access_control.httpx.Client", Client):
                _replay_idor(probe, max_requests=10)
            for method, url, payload in Client.calls:
                if method == "POST" and url.endswith("/signup"):
                    emails.append(payload["json"]["email"])
        # 4개 signup email 모두 유일(각 역할 × 2회 재현), 각자 marker를 substring으로 포함.
        self.assertEqual(len(set(emails)), 4)
        self.assertTrue(any("victimM" in e for e in emails))
        self.assertTrue(any("attackerM" in e for e in emails))

    def test_bearer_requires_signup_and_template(self) -> None:
        probe = IdorProbe(base_url="http://x", auth_mode="bearer", victim_marker="m", owner_marker="o")
        with self.assertRaises(ValueError):
            ac._replay_bearer(probe)

    def test_bearer_requires_owner_marker(self) -> None:
        probe = IdorProbe(
            base_url="http://x", auth_mode="bearer", victim_marker="m",
            signup_path="/s", path_template="/u/{id}",
        )
        with self.assertRaises(ValueError):
            ac._replay_bearer(probe)


class ReplayDispatchTests(unittest.TestCase):
    def test_unknown_auth_mode_raises(self) -> None:
        probe = IdorProbe(base_url="http://x", auth_mode="carrier-pigeon", victim_marker="m")
        with self.assertRaises(ValueError) as ctx:
            _replay_idor(probe, max_requests=10)
        self.assertIn("carrier-pigeon", str(ctx.exception))

    def test_budget_exceeded_raises_before_any_request(self) -> None:
        probe = IdorProbe(
            base_url="http://x", auth_mode="none",
            baseline_path="/a", attack_path="/b", victim_marker="m",
        )
        with self.assertRaises(ValueError):
            _replay_idor(probe, max_requests=1)  # none needs 2


class RequiredRequestsTests(unittest.TestCase):
    def test_non_bearer_uses_default(self) -> None:
        probe = IdorProbe(base_url="http://x", auth_mode="none", victim_marker="m")
        self.assertEqual(_required_requests(probe, 2), 2)

    def test_bearer_login_adds_two(self) -> None:
        probe = IdorProbe(base_url="http://x", auth_mode="bearer", victim_marker="m",
                          signup_path="/s", path_template="/u/{id}", login_path="/l")
        self.assertEqual(_required_requests(probe, 4), 6)

    def test_bearer_owner_setup_adds_two(self) -> None:
        probe = IdorProbe(base_url="http://x", auth_mode="bearer", victim_marker="m",
                          signup_path="/s", path_template="/u/{id}", owner_setup_path="/w")
        self.assertEqual(_required_requests(probe, 4), 6)

    def test_bearer_login_and_setup_add_four(self) -> None:
        probe = IdorProbe(base_url="http://x", auth_mode="bearer", victim_marker="m",
                          signup_path="/s", path_template="/u/{id}",
                          login_path="/l", owner_setup_path="/w")
        self.assertEqual(_required_requests(probe, 4), 8)


# --- ④ probe/candidate/fixture 계약 ---------------------------------------------------


class ProbeContractTests(unittest.TestCase):
    def test_probe_from_candidate_prefers_attack_params(self) -> None:
        c = Candidate(id="c", run_id="r", vuln_class="idor", attack_params={
            "base_url": "http://x", "auth_mode": "none",
            "baseline_path": "/a", "attack_path": "/b", "victim_marker": "V",
        })
        p = probe_from_candidate(c)
        self.assertEqual(p.auth_mode, "none")
        self.assertEqual(p.victim_marker, "V")

    def test_probe_from_candidate_falls_back_to_signals_kv(self) -> None:
        # 하위호환: attack_params가 비면 signals "key=value"를 파싱.
        c = Candidate(id="c", run_id="r", vuln_class="idor", signals=[
            "base_url=http://x", "auth_mode=none",
            "baseline_path=/a", "attack_path=/b", "victim_marker=V",
        ])
        p = probe_from_candidate(c)
        self.assertEqual(p.base_url, "http://x")
        self.assertEqual(p.attack_path, "/b")

    def test_probe_from_fixture_maps_resources_by_field_name(self) -> None:
        fixture = {
            "base_url": "http://127.0.0.1:9",
            "auth": {"mode": "none"},
            "resources": {
                "victim_vocab": {"read_path": "/vocabs/2", "victim_marker": "VICTIM"},
                "attacker_vocab": {"baseline_path": "/vocabs/1", "marker": "OWNER"},
            },
        }
        p = probe_from_fixture(fixture)
        self.assertEqual(p.auth_mode, "none")
        self.assertEqual(p.attack_path, "/vocabs/2")
        self.assertEqual(p.baseline_path, "/vocabs/1")
        self.assertEqual(p.victim_marker, "VICTIM")
        self.assertEqual(p.owner_marker, "OWNER")

    def test_candidate_from_fixture_roundtrips_to_attack_params(self) -> None:
        fixture = {
            "base_url": "http://127.0.0.1:9",
            "resources": {
                "v": {"read_path": "/vocabs/2", "victim_marker": "VICTIM"},
                "a": {"baseline_path": "/vocabs/1", "marker": "OWNER"},
            },
        }
        cand = candidate_from_fixture("run-1", fixture, candidate_id="cand-1")
        self.assertEqual(cand.vuln_class, "idor")
        self.assertEqual(cand.cwe, "CWE-639")
        # attack_params로 왕복 복원돼야 한다.
        p = probe_from_candidate(cand)
        self.assertEqual(p.victim_marker, "VICTIM")
        self.assertEqual(p.attack_path, "/vocabs/2")

    def test_pick_resource_raises_when_field_absent(self) -> None:
        with self.assertRaises(ValueError):
            _pick_resource({"x": {"foo": 1}}, "victim_marker")


class MutationProbeContractTests(unittest.TestCase):
    def test_mutation_probe_from_candidate_decodes_extra_body_json(self) -> None:
        c = Candidate(id="c", run_id="r", vuln_class="idor", attack_params={
            "base_url": "http://x", "observe_path": "/v/1",
            "mutation_method": "PUT", "mutation_path": "/v/1",
            "mutation_marker": "MARK", "extra_body_json": json.dumps({"tags": ["a"]}),
        })
        p = mutation_probe_from_candidate(c)
        self.assertEqual(p.mutation_method, "PUT")
        self.assertEqual(p.extra_body, {"tags": ["a"]})
        self.assertEqual(p.marker_field, "description")  # 기본값

    def test_mutation_probe_from_fixture_generates_marker_and_extracts_body(self) -> None:
        fixture = {
            "base_url": "http://x",
            "resources": {
                "v": {"safe_mutation": {
                    "method": "PUT", "path": "/vocabs/2",
                    "observe_path": "/vocabs/2",
                    "json": {"description": "x", "tags": ["t"]},
                }},
            },
        }
        p = mutation_probe_from_fixture(fixture)
        self.assertEqual(p.mutation_method, "PUT")
        self.assertEqual(p.observe_path, "/vocabs/2")
        self.assertEqual(p.marker_field, "description")
        self.assertEqual(p.extra_body, {"tags": ["t"]})  # marker_field 제거된 나머지
        self.assertTrue(p.mutation_marker.startswith("vc-write-idor-"))


# --- ⑤ 헬퍼: _render_body / _dig / redact ---------------------------------------------


class RenderBodyTests(unittest.TestCase):
    def test_none_template_returns_default(self) -> None:
        self.assertEqual(_render_body(None, {}, default={"a": "b"}), {"a": "b"})

    def test_placeholders_substituted_from_values(self) -> None:
        out = _render_body('{"email":"{email}","name":"{name}"}',
                           {"email": "e@x", "name": "n"}, default={})
        self.assertEqual(out, {"email": "e@x", "name": "n"})

    def test_invalid_json_raises(self) -> None:
        with self.assertRaises(ValueError):
            _render_body("not-json", {}, default={})

    def test_non_string_values_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _render_body('{"n": 5}', {}, default={})

    def test_disallowed_placeholder_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _render_body('{"x":"{oops}"}', {"email": "e"}, default={})


class DigTests(unittest.TestCase):
    def test_finds_nested_key(self) -> None:
        self.assertEqual(_dig({"data": {"user": {"id": 7}}}, "id"), 7)

    def test_finds_through_list(self) -> None:
        self.assertEqual(_dig({"items": [{"accessToken": "tok"}]}, "accessToken"), "tok")

    def test_missing_key_returns_none(self) -> None:
        self.assertIsNone(_dig({"a": 1}, "nope"))


class RedactTests(unittest.TestCase):
    def test_redacts_session_bearer_and_password(self) -> None:
        raw = 'JSESSIONID=abc123; Authorization: Bearer eyJ.tok.en "password":"hunter2"'
        out = redact(raw)
        self.assertNotIn("abc123", out)
        self.assertNotIn("eyJ.tok.en", out)
        self.assertNotIn("hunter2", out)
        self.assertIn("<redacted>", out)


# --- ⑥ verify() 조립 (evidence 저장, 200만으로는 verified 아님) ------------------------


class VerifyAssemblyTests(unittest.TestCase):
    def _candidate(self) -> Candidate:
        return Candidate(id="c", run_id="run-verify", vuln_class="idor", cwe="CWE-639", attack_params={
            "base_url": "http://127.0.0.1:9", "auth_mode": "none",
            "baseline_path": "/notes/mine", "attack_path": "/notes/victim",
            "victim_marker": "VICTIM-LEAK",
        })

    def test_marker_leak_verified_and_evidence_persisted(self) -> None:
        class Client(_RecordingClient):
            calls = []

            @staticmethod
            def respond(method, url, **kw):
                if url.endswith("/mine"):
                    return _Response(200, {"name": "attacker"})
                return _Response(200, {"name": "VICTIM-LEAK"})

        with patch("verifiers.access_control.httpx.Client", Client):
            out = verify("run-verify", self._candidate())
        self.assertTrue(out.verified)
        self.assertEqual(len(out.evidence_ids), 2)
        # evidence_ids는 실제 evidence_store에 기록된 Observation이어야 한다.
        for eid in out.evidence_ids:
            self.assertIsNotNone(get(Observation, eid))

    def test_two_hundred_with_identical_bodies_is_not_verified(self) -> None:
        # 핵심 회귀: 공격 응답이 200이어도 baseline과 동일하면 verified 아님.
        class Client(_RecordingClient):
            calls = []

            @staticmethod
            def respond(method, url, **kw):
                return _Response(200, {"name": "attacker"})  # 두 요청 동일 응답

        with patch("verifiers.access_control.httpx.Client", Client):
            out = verify("run-verify", self._candidate())
        self.assertFalse(out.verified)
        self.assertEqual(len(out.evidence_ids), 2)  # 실패해도 evidence는 남긴다


if __name__ == "__main__":
    unittest.main()
