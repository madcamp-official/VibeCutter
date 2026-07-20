"""worker Run으로 materialize된 Candidate를 verifier가 '그대로' 처리하는지 확인 (D5-P2.md P3 요청).

P1의 `test_orchestrator`는 materialize가 필드를 보존하는지(attack_params 복제·lineage)를 보고,
여기서는 그 materialize된 candidate가 **P3 verifier 경로(dispatch 라우팅 + probe 파싱)에서 원본과
동일하게 소비되는지**를 확인한다. 즉 worker 경계가 verify 처리에 아무 영향을 주지 않음을 못박는다.
네트워크 없이 돈다(dispatch/probe는 순수).
"""

import unittest
from uuid import uuid4

from contracts.schemas import Candidate, Run, RunState
from core.orchestrator import materialize_worker_run
from mcp_server.driver import _verify_tool_for
from verifiers import injection, xss
from verifiers.dispatch import class_of


def _scan_run() -> Run:
    return Run(id=f"run-{uuid4().hex[:12]}", target_id="26s-w1-c2-04", status=RunState.CANDIDATE_SCAN)


def _cand(vuln_class: str, cwe: str, attack_params: dict) -> Candidate:
    return Candidate(id=f"cand-{uuid4().hex[:12]}", run_id="scan-run",
                     cwe=cwe, vuln_class=vuln_class, attack_params=attack_params)


_IDOR = _cand("idor", "CWE-639", {
    "base_url": "http://127.0.0.1:14017", "auth_mode": "none",
    "baseline_path": "/vocabs/1", "attack_path": "/vocabs/2", "victim_marker": "vcvictim1",
})
_XSS = _cand("xss", "CWE-79", {
    "base_url": "http://127.0.0.1:14018", "context": "reflected",
    "inject_path": "/search", "inject_param": "q", "inject_method": "GET",
})
_INJ = _cand("injection", "CWE-89", {
    "base_url": "http://127.0.0.1:14017", "inject_path": "/login/", "inject_param": "username",
    "inject_method": "POST", "inject_location": "json", "read_query": "true",
})


class WorkerCandidateVerifyTests(unittest.TestCase):
    def _materialize(self, scan_candidate: Candidate) -> Candidate:
        scan_run = _scan_run()
        scan_candidate = scan_candidate.model_copy(update={"run_id": scan_run.id})
        _, worker_candidate = materialize_worker_run(scan_run, scan_candidate)
        # 계약: 새 candidate/run id, lineage 보존, attack_params/vuln_class 그대로
        self.assertNotEqual(worker_candidate.id, scan_candidate.id)
        self.assertEqual(worker_candidate.origin_candidate_id, scan_candidate.id)
        self.assertEqual(worker_candidate.attack_params, scan_candidate.attack_params)
        self.assertEqual(worker_candidate.vuln_class, scan_candidate.vuln_class)
        return worker_candidate

    def test_idor_materialized_routes_identically(self):
        wc = self._materialize(_IDOR)
        self.assertEqual(class_of(wc), "idor")
        self.assertEqual(_verify_tool_for(wc), "vc_verify_access_control")

    def test_xss_materialized_routes_and_parses_identically(self):
        wc = self._materialize(_XSS)
        self.assertEqual(class_of(wc), "xss")
        self.assertEqual(_verify_tool_for(wc), "vc_verify_xss")
        # probe 파싱이 원본과 동일해야 한다(worker 경계가 재현 입력을 바꾸지 않음)
        p_scan = xss.xss_probe_from_candidate(_XSS)
        p_worker = xss.xss_probe_from_candidate(wc)
        self.assertEqual((p_worker.inject_path, p_worker.inject_param, p_worker.context),
                         (p_scan.inject_path, p_scan.inject_param, p_scan.context))

    def test_injection_materialized_routes_and_parses_identically(self):
        wc = self._materialize(_INJ)
        self.assertEqual(class_of(wc), "injection")
        self.assertEqual(_verify_tool_for(wc), "vc_verify_injection")
        p_scan = injection.injection_probe_from_candidate(_INJ)
        p_worker = injection.injection_probe_from_candidate(wc)
        self.assertEqual((p_worker.inject_path, p_worker.inject_param, p_worker.inject_method, p_worker.read_query),
                         (p_scan.inject_path, p_scan.inject_param, p_scan.inject_method, p_scan.read_query))

    def test_write_idor_materialized_routes_to_mutation_tool(self):
        write_idor = _cand("idor", "CWE-639", {
            "base_url": "http://127.0.0.1:14017", "idor_mode": "write",
            "observe_path": "/vocabs/2", "mutation_method": "PUT", "mutation_path": "/vocabs/2",
            "mutation_marker": "vcmut1",
        })
        wc = self._materialize(write_idor)
        self.assertEqual(_verify_tool_for(wc), "vc_verify_mutation_access_control")


if __name__ == "__main__":
    unittest.main()
