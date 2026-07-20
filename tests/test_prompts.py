"""MCP Prompt(6.5절) 등록 테스트: `audit_local_target` + 단계별 4종.

Prompt는 파이프라인을 실행하는 코드가 아니라 Host에게 주는 안내 텍스트이므로, 여기서는
"등록돼 있고, 인자를 반영하고, 승인/재시도 상한/kill switch 규칙을 언급하며, 실제
등록된 tool 이름만 참조하는지"만 확인한다. 실제 안전 강제는 각 tool
(vc_apply_patch/vc_generate_patch/vc_pause)이 별도로 테스트한다.
"""

from __future__ import annotations

import asyncio
import re
import unittest


def _get_prompt(name: str, args: dict[str, str]):
    from mcp_server.server import mcp

    return asyncio.run(mcp.get_prompt(name, args))


def _text(result) -> str:
    return " ".join(m.content.text for m in result.messages)


# 프롬프트가 참조해도 되는 실제 등록된 tool(구현되지 않은 tool 안내 금지 규칙 검사용).
_UNIMPLEMENTED_TOOLS = ("vc_map_routes", "vc_map_roles", "vc_index_code", "vc_browser_crawl")


class AuditLocalTargetPromptTests(unittest.TestCase):
    def _get(self, target_id: str):
        return _get_prompt("audit_local_target", {"target_id": target_id})

    def test_registered_and_lists_key_tools(self) -> None:
        result = self._get("26s-w1-c2-04")
        text = " ".join(m.content.text for m in result.messages)

        self.assertIn("26s-w1-c2-04", text)
        for tool_name in (
            "vc_scan_access_control",
            "vc_materialize_worker_run",
            "vc_verify_access_control",
            "vc_apply_patch",
            "vc_generate_patch",
            "vc_pause",
        ):
            self.assertIn(tool_name, text)

    def test_explains_worker_run_per_candidate(self) -> None:
        result = self._get("some-target")
        text = " ".join(m.content.text for m in result.messages)
        # candidate-per-worker-Run 계약(D5-P2.md): scan Run은 부모, 후보마다 worker Run.
        self.assertIn("worker Run", text)
        self.assertIn("순차", text)

    def test_mentions_approval_and_retry_cap(self) -> None:
        result = self._get("some-target")
        text = " ".join(m.content.text for m in result.messages)

        self.assertIn("승인", text)
        self.assertIn("3", text)  # 재시도 상한 3회 언급


class StagePromptTests(unittest.TestCase):
    """6.5절 표의 단계별 프롬프트 4종: verify_candidate/repair/retest/triage."""

    def test_verify_candidate_registered_and_reflects_args(self) -> None:
        text = _text(_get_prompt("verify_candidate", {"scan_run_id": "scan-1", "candidate_id": "cand-9"}))
        self.assertIn("scan-1", text)
        self.assertIn("cand-9", text)
        # 후보 하나를 worker Run으로 materialize한 뒤 vuln_class별 verify tool을 고른다.
        self.assertIn("vc_materialize_worker_run", text)
        for verify_tool in (
            "vc_verify_access_control",
            "vc_verify_mutation_access_control",
            "vc_verify_injection",
            "vc_verify_xss",
        ):
            self.assertIn(verify_tool, text)
        self.assertIn("순차", text)  # 고정 포트 → 순차 처리 규칙

    def test_repair_verified_finding_mentions_approval_and_retry_cap(self) -> None:
        text = _text(_get_prompt("repair_verified_finding", {"finding_id": "find-7"}))
        self.assertIn("find-7", text)
        self.assertIn("vc_localize_root_cause", text)
        self.assertIn("vc_generate_patch", text)
        self.assertIn("vc_apply_patch", text)
        self.assertIn("승인", text)  # diff 승인 게이트
        self.assertIn("3", text)  # 재시도 상한

    def test_retest_patch_lists_all_three_validation_tools(self) -> None:
        text = _text(_get_prompt("retest_patch", {"patch_id": "patch-2"}))
        self.assertIn("patch-2", text)
        for tool in ("vc_build_and_test", "vc_replay_attack", "vc_validate_regression"):
            self.assertIn(tool, text)

    def test_triage_report_uses_report_tool_and_evidence_first(self) -> None:
        text = _text(_get_prompt("triage_report", {"run_id": "run-5"}))
        self.assertIn("run-5", text)
        self.assertIn("vc_generate_report", text)
        # evidence-first: 검증 안 된 candidate를 확정 취약점으로 올리지 않는다.
        self.assertIn("evidence", text.lower())

    def test_no_prompt_references_unimplemented_tools(self) -> None:
        # "존재하지 않는 tool 안내 금지" 규칙 — 모든 프롬프트 텍스트에서 미구현 tool 미참조.
        prompts = {
            "audit_local_target": {"target_id": "t"},
            "verify_candidate": {"scan_run_id": "s", "candidate_id": "c"},
            "repair_verified_finding": {"finding_id": "f"},
            "retest_patch": {"patch_id": "p"},
            "triage_report": {"run_id": "r"},
        }
        for name, args in prompts.items():
            text = _text(_get_prompt(name, args))
            for tool in _UNIMPLEMENTED_TOOLS:
                # audit_local_target은 이 tool들을 "부르지 않는다"고 명시적으로 언급하므로 예외.
                if name == "audit_local_target":
                    continue
                self.assertNotIn(tool, text, f"{name} references unimplemented {tool}")

    def test_all_referenced_vc_tools_are_registered(self) -> None:
        # 각 프롬프트가 언급하는 vc_* 이름이 전부 실제 등록된 tool인지 확인한다.
        from mcp_server.server import mcp

        registered = {t.name for t in asyncio.run(mcp.list_tools())}
        prompts = {
            "verify_candidate": {"scan_run_id": "s", "candidate_id": "c"},
            "repair_verified_finding": {"finding_id": "f"},
            "retest_patch": {"patch_id": "p"},
            "triage_report": {"run_id": "r"},
        }
        for name, args in prompts.items():
            text = _text(_get_prompt(name, args))
            for tool in set(re.findall(r"\bvc_[a-z_]+", text)):
                # `vc_verify_*` 같은 와일드카드 표기(취약점군별 verify tool 묶음)는 실제
                # tool명이 아니라 안내용 glob이므로 제외한다(끝이 `_`).
                if tool.endswith("_"):
                    continue
                self.assertIn(tool, registered, f"{name} references unregistered {tool}")


if __name__ == "__main__":
    unittest.main()
