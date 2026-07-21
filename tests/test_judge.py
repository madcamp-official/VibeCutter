from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

from contracts.schemas import Candidate, Finding, Patch, Run, RunState, Validation, VerificationResult
from core.evidence_store import save
from core.judge import (
    ScopeViolationError,
    assert_diff_within_worktree,
    check_attack,
    check_build,
    check_positive_functionality,
    check_regression,
    check_scope,
    check_static,
    compute_verdict,
    diff_touched_files,
)


def _finding_with_candidate(run_id: str) -> tuple[Finding, Candidate]:
    candidate = Candidate(id=f"cand-{uuid4().hex[:12]}", run_id=run_id, cwe="CWE-639")
    save(candidate)
    finding = Finding(
        id=f"finding-{uuid4().hex[:12]}", run_id=run_id, candidate_id=candidate.id, title="t"
    )
    save(finding)
    return finding, candidate


class CheckAttackTests(unittest.TestCase):
    """Day2 범위: Attack gate만 실제로 동작해야 한다."""

    def test_passes_when_verifier_reports_no_longer_verified(self) -> None:
        run_id = f"run-{uuid4().hex[:12]}"
        finding, _ = _finding_with_candidate(run_id)

        def fake_verifier(run_id, candidate, *, max_requests=10):
            return VerificationResult(verified=False, evidence_ids=[], reason="patched")

        self.assertTrue(
            check_attack(run_id, finding.id, verifier=fake_verifier)
        )

    def test_fails_when_attack_still_succeeds(self) -> None:
        run_id = f"run-{uuid4().hex[:12]}"
        finding, _ = _finding_with_candidate(run_id)

        def fake_verifier(run_id, candidate, *, max_requests=10):
            return VerificationResult(verified=True, evidence_ids=["obs-x"], reason="still broken")

        self.assertFalse(
            check_attack(run_id, finding.id, verifier=fake_verifier)
        )

    def test_rejects_unknown_finding(self) -> None:
        with self.assertRaises(ValueError):
            check_attack("run-x", "finding-does-not-exist")

    def test_rejects_finding_without_candidate(self) -> None:
        run_id = f"run-{uuid4().hex[:12]}"
        finding = Finding(id=f"finding-{uuid4().hex[:12]}", run_id=run_id, title="no candidate")
        save(finding)
        with self.assertRaises(ValueError):
            check_attack(run_id, finding.id)


def _run_and_patch_with_worktree(worktree: Path) -> tuple[Run, Patch]:
    run = Run(id=f"run-{uuid4().hex[:12]}", target_id="fake-target", status=RunState.VALIDATING)
    save(run)
    p = Patch(id=f"patch-{uuid4().hex[:12]}", finding_id="finding-x", run_id=run.id, diff="d")
    save(p)
    return run, p


def _fake_service_with_worktree(worktree: Path, source_root: Path | None = None) -> MagicMock:
    fake_service = MagicMock()
    fake_service.catalog.worktree_manager_for.return_value.path_for.return_value = worktree
    fake_service.catalog.run_source_root_for.return_value = source_root or worktree
    return fake_service


class CheckBuildTests(unittest.TestCase):
    def test_returns_true_when_worktree_build_passes(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            worktree = Path(td) / "repo"
            source_root = worktree / "backend"
            source_root.mkdir(parents=True)
            run, p = _run_and_patch_with_worktree(worktree)

            fake_manifest = MagicMock()
            fake_manifest.docker_isolation = None
            fake_manifest.model_copy.return_value = fake_manifest
            fake_service = _fake_service_with_worktree(worktree, source_root)
            fake_service.catalog.get.return_value = MagicMock(manifest=fake_manifest)

            fake_lifecycle_instance = MagicMock()
            fake_lifecycle_instance.build.return_value = MagicMock(status="passed")
            fake_lifecycle_cls = MagicMock(return_value=fake_lifecycle_instance)

            with (
                patch("core.judge._service", return_value=fake_service),
                patch("runtime.lifecycle.LifecycleManager", fake_lifecycle_cls),
            ):
                self.assertTrue(check_build(run.id, p.id))
            fake_lifecycle_cls.assert_called_once_with(fake_manifest, source_root)
            fake_manifest.model_copy.assert_called_once_with(update={"source_dir": "."})

    def test_returns_false_when_worktree_build_fails(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            worktree = Path(td) / "repo"
            source_root = worktree / "backend"
            source_root.mkdir(parents=True)
            run, p = _run_and_patch_with_worktree(worktree)

            fake_manifest = MagicMock()
            fake_manifest.docker_isolation = None
            fake_manifest.model_copy.return_value = fake_manifest
            fake_service = _fake_service_with_worktree(worktree, source_root)
            fake_service.catalog.get.return_value = MagicMock(manifest=fake_manifest)

            fake_lifecycle_instance = MagicMock()
            fake_lifecycle_instance.build.return_value = MagicMock(status="failed")

            with (
                patch("core.judge._service", return_value=fake_service),
                patch("runtime.lifecycle.LifecycleManager", return_value=fake_lifecycle_instance),
            ):
                self.assertFalse(check_build(run.id, p.id))

    def test_running_local_returns_none_without_attempting_build(self) -> None:
        """W-3/§3A-5: 이미 떠 있는 사용자 서비스는 patched worktree를 build/restart 못 한다.

        `None`은 "실행 안 함"이지 "실패"가 아니다 — `False`로 두면 RETRY가 되고 `True`로
        두면 못 돌린 게이트를 통과로 위조하는 것이라 둘 다 틀렸다. `compute_verdict`는 게이트가
        하나라도 `None`이면 verdict를 내지 않으므로, running_local target은 이 게이트가 절대
        채워지지 않아 FIXED가 구조적으로 불가능해진다(추가 방어 불필요, `ComputeVerdictTests`가
        일반 케이스를 이미 고정).
        """
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            worktree = Path(td) / "repo"
            worktree.mkdir(parents=True)
            run, p = _run_and_patch_with_worktree(worktree)

            fake_manifest = MagicMock()
            fake_manifest.kind = "running_local"
            fake_service = _fake_service_with_worktree(worktree)
            fake_service.catalog.get.return_value = MagicMock(manifest=fake_manifest)

            fake_lifecycle_cls = MagicMock()
            with (
                patch("core.judge._service", return_value=fake_service),
                patch("runtime.lifecycle.LifecycleManager", fake_lifecycle_cls),
            ):
                self.assertIsNone(check_build(run.id, p.id))
            # None은 "build를 시도했는데 확인 못 함"이 아니라 "애초에 시도하지 않음"이어야 한다.
            fake_lifecycle_cls.assert_not_called()
            fake_service.catalog.run_overlay_for.assert_not_called()

    def test_missing_worktree_raises(self) -> None:
        run = Run(id=f"run-{uuid4().hex[:12]}", target_id="fake-target", status=RunState.PATCH_APPLIED)
        save(run)
        p = Patch(id=f"patch-{uuid4().hex[:12]}", finding_id="finding-x", run_id=run.id, diff="d")
        save(p)
        fake_service = _fake_service_with_worktree(Path("/nonexistent-worktree-path"))
        with patch("core.judge._service", return_value=fake_service):
            with self.assertRaises(FileNotFoundError):
                check_build(run.id, p.id)

    def test_compose_target_builds_via_run_scoped_overlay(self) -> None:
        """docker_isolation이 설정된 target은 P2 run_overlay_for()를 build context로 써야 한다 —
        직접 LifecycleManager를 worktree에 대고 돌리면 checked-in Compose의 build context가
        여전히 원본 source clone을 가리켜 patched 코드를 검증하지 못한다(D3-P2.md가 이 문제를
        풀려고 만든 run-scoped overlay). build 성공 뒤에는 원본을 stop하고 overlay를
        start+health까지 확인해야 한다 — 안 그러면 attack/positive 게이트가 여전히 원본
        인스턴스를 재공격한다(repoint)."""
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            worktree = Path(td)
            run, p = _run_and_patch_with_worktree(worktree)

            fake_manifest = MagicMock()
            fake_manifest.docker_isolation = MagicMock()  # Compose-based target
            fake_service = _fake_service_with_worktree(worktree)
            fake_service.catalog.get.return_value = MagicMock(manifest=fake_manifest)

            fake_overlay = MagicMock()
            fake_overlay.execute.return_value = MagicMock(status="passed")
            fake_overlay.check_health.return_value = MagicMock(status="ready")
            fake_service.catalog.run_overlay_for.return_value = fake_overlay

            fake_lifecycle_instance = MagicMock()
            fake_lifecycle_cls = MagicMock(return_value=fake_lifecycle_instance)

            with (
                patch("core.judge._service", return_value=fake_service),
                patch("runtime.lifecycle.LifecycleManager", fake_lifecycle_cls),
            ):
                self.assertTrue(check_build(run.id, p.id))

            fake_service.catalog.run_overlay_for.assert_called_once_with(run.target_id, run.id)
            fake_overlay.prepare.assert_called_once_with()
            fake_overlay.execute.assert_any_call("build")
            fake_overlay.execute.assert_any_call("start")
            # 원본 인스턴스가 patched overlay start보다 먼저 내려가야 같은 포트를 넘겨받는다.
            fake_lifecycle_cls.assert_called_once_with(fake_manifest, fake_service.catalog.repository_root)
            fake_lifecycle_instance.stop.assert_called_once_with()
            fake_overlay.check_health.assert_called_once_with()

    def test_compose_target_build_failure_fails_gate(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            worktree = Path(td)
            run, p = _run_and_patch_with_worktree(worktree)

            fake_manifest = MagicMock()
            fake_manifest.docker_isolation = MagicMock()
            fake_service = _fake_service_with_worktree(worktree)
            fake_service.catalog.get.return_value = MagicMock(manifest=fake_manifest)

            fake_overlay = MagicMock()
            fake_overlay.execute.return_value = MagicMock(status="failed")
            fake_service.catalog.run_overlay_for.return_value = fake_overlay

            with patch("core.judge._service", return_value=fake_service):
                self.assertFalse(check_build(run.id, p.id))
            # build 자체가 실패하면 원본을 내리거나 overlay를 띄우려 시도하면 안 된다.
            fake_overlay.execute.assert_called_once_with("build")

    def test_compose_target_build_passes_but_patched_start_fails_gate(self) -> None:
        """build는 통과했지만 patched overlay가 뜨지 않으면(포트 경합, 크래시 등) build
        게이트 자체를 실패로 처리한다 — 그래야 attack/positive 게이트가 죽어있는 patched
        인스턴스나 여전히 원본을 조용히 재공격하는 대신 명확히 멈춘다."""
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            worktree = Path(td)
            run, p = _run_and_patch_with_worktree(worktree)

            fake_manifest = MagicMock()
            fake_manifest.docker_isolation = MagicMock()
            fake_service = _fake_service_with_worktree(worktree)
            fake_service.catalog.get.return_value = MagicMock(manifest=fake_manifest)

            fake_overlay = MagicMock()
            fake_overlay.execute.side_effect = lambda command_id: MagicMock(
                status="passed" if command_id == "build" else "failed"
            )
            fake_service.catalog.run_overlay_for.return_value = fake_overlay

            with (
                patch("core.judge._service", return_value=fake_service),
                patch("runtime.lifecycle.LifecycleManager", return_value=MagicMock()),
            ):
                self.assertFalse(check_build(run.id, p.id))

    def test_compose_target_build_passes_but_patched_health_fails_gate(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            worktree = Path(td)
            run, p = _run_and_patch_with_worktree(worktree)

            fake_manifest = MagicMock()
            fake_manifest.docker_isolation = MagicMock()
            fake_service = _fake_service_with_worktree(worktree)
            fake_service.catalog.get.return_value = MagicMock(manifest=fake_manifest)

            fake_overlay = MagicMock()
            fake_overlay.execute.return_value = MagicMock(status="passed")
            fake_overlay.check_health.return_value = MagicMock(status="not_ready")
            fake_service.catalog.run_overlay_for.return_value = fake_overlay

            with (
                patch("core.judge._service", return_value=fake_service),
                patch("runtime.lifecycle.LifecycleManager", return_value=MagicMock()),
            ):
                self.assertFalse(check_build(run.id, p.id))


class CheckRegressionTests(unittest.TestCase):
    def test_delegates_to_run_scoped_test_runner_passed_property(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            worktree = Path(td)
            run, p = _run_and_patch_with_worktree(worktree)
            fake_service = _fake_service_with_worktree(worktree)
            fake_manifest = MagicMock()
            fake_manifest.docker_isolation = None
            fake_service.catalog.get.return_value = MagicMock(manifest=fake_manifest)
            fake_service.catalog.test_runner_for.return_value.run.return_value = MagicMock(passed=True)

            with patch("core.judge._service", return_value=fake_service):
                self.assertTrue(check_regression(run.id, p.id))
            fake_service.catalog.test_runner_for.return_value.run.assert_called_once_with(run.id)

    def test_not_configured_test_suite_does_not_pass(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            worktree = Path(td)
            run, p = _run_and_patch_with_worktree(worktree)
            fake_service = _fake_service_with_worktree(worktree)
            fake_manifest = MagicMock()
            fake_manifest.docker_isolation = None
            fake_service.catalog.get.return_value = MagicMock(manifest=fake_manifest)
            fake_service.catalog.test_runner_for.return_value.run.return_value = MagicMock(passed=False)

            with patch("core.judge._service", return_value=fake_service):
                self.assertFalse(check_regression(run.id, p.id))

    def test_compose_target_regression_runs_via_run_scoped_overlay(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            worktree = Path(td)
            run, p = _run_and_patch_with_worktree(worktree)
            fake_service = _fake_service_with_worktree(worktree)
            fake_manifest = MagicMock()
            fake_manifest.docker_isolation = MagicMock()
            fake_manifest.test_suites = [MagicMock(command_id="backend_regression")]
            fake_service.catalog.get.return_value = MagicMock(manifest=fake_manifest)
            fake_overlay = MagicMock()
            fake_overlay.execute.return_value = MagicMock(status="passed")
            fake_service.catalog.run_overlay_for.return_value = fake_overlay

            with patch("core.judge._service", return_value=fake_service):
                self.assertTrue(check_regression(run.id, p.id))

            fake_service.catalog.run_overlay_for.assert_called_once_with(run.target_id, run.id)
            fake_overlay.prepare.assert_called_once_with()
            fake_overlay.execute.assert_called_once_with("backend_regression")

    def test_compose_target_without_test_suite_does_not_pass_regression(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            worktree = Path(td)
            run, p = _run_and_patch_with_worktree(worktree)
            fake_service = _fake_service_with_worktree(worktree)
            fake_manifest = MagicMock()
            fake_manifest.docker_isolation = MagicMock()
            fake_manifest.test_suites = []
            fake_service.catalog.get.return_value = MagicMock(manifest=fake_manifest)

            with patch("core.judge._service", return_value=fake_service):
                self.assertFalse(check_regression(run.id, p.id))


class CheckStaticTests(unittest.TestCase):
    def _candidate(self, run_id: str, severity: str) -> Candidate:
        return Candidate(
            id=f"cand-{uuid4().hex[:12]}",
            run_id=run_id,
            source_symbols=[f"src/{uuid4().hex[:6]}.py:1"],
            confidence=0.7,
            signals=[f"severity:{severity}"],
        )

    def test_passes_when_patched_has_no_more_high_severity_than_baseline(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            worktree = Path(td)
            run, p = _run_and_patch_with_worktree(worktree)
            fake_service = _fake_service_with_worktree(worktree)
            fake_service.catalog.source_root_for.return_value = Path(__file__).resolve().parent

            baseline = [self._candidate(run.id, "ERROR")]
            patched: list[Candidate] = []  # patch removed the finding

            with (
                patch("core.judge._service", return_value=fake_service),
                patch("core.judge.run_semgrep", side_effect=[baseline, patched]),
            ):
                self.assertTrue(check_static(run.id, p.id))

    def test_fails_when_patched_introduces_new_high_severity(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            worktree = Path(td)
            run, p = _run_and_patch_with_worktree(worktree)
            fake_service = _fake_service_with_worktree(worktree)
            fake_service.catalog.source_root_for.return_value = Path(__file__).resolve().parent

            baseline: list[Candidate] = []
            patched = [self._candidate(run.id, "ERROR")]

            with (
                patch("core.judge._service", return_value=fake_service),
                patch("core.judge.run_semgrep", side_effect=[baseline, patched]),
            ):
                self.assertFalse(check_static(run.id, p.id))


class ComputeVerdictTests(unittest.TestCase):
    def test_none_while_any_gate_is_unset(self) -> None:
        v = Validation(id="v-1", run_id="run-x", patch_id="patch-x", build=True)
        self.assertIsNone(compute_verdict(v))

    def test_fixed_when_all_gates_pass(self) -> None:
        v = Validation(
            id="v-1", run_id="run-x", patch_id="patch-x",
            build=True, attack=True, positive_test=True, regression=True, static=True, scope=True,
        )
        self.assertEqual(compute_verdict(v), "FIXED")

    def test_retry_when_any_gate_fails(self) -> None:
        v = Validation(
            id="v-1", run_id="run-x", patch_id="patch-x",
            build=True, attack=True, positive_test=True, regression=False, static=True, scope=True,
        )
        self.assertEqual(compute_verdict(v), "RETRY")


class DiffTouchedFilesTests(unittest.TestCase):
    def test_extracts_paths_from_plus_plus_plus_headers(self) -> None:
        diff = (
            "--- a/src/Foo.java\n+++ b/src/Foo.java\n@@ -1,1 +1,1 @@\n-x\n+y\n"
            "--- a/src/Bar.java\n+++ b/src/Bar.java\n@@ -1,1 +1,1 @@\n-x\n+y\n"
        )
        self.assertEqual(diff_touched_files(diff), ["src/Foo.java", "src/Bar.java"])

    def test_empty_diff_yields_no_files(self) -> None:
        self.assertEqual(diff_touched_files(""), [])


class AssertDiffWithinWorktreeTests(unittest.TestCase):
    """10.1절 절대 원칙: worktree 밖 경로는 무조건 거부."""

    def test_passes_for_paths_inside_worktree(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            worktree = Path(td)
            diff = "--- a/src/Foo.java\n+++ b/src/Foo.java\n@@ -1,1 +1,1 @@\n-x\n+y\n"
            assert_diff_within_worktree(diff, worktree)  # 예외 없이 통과

    def test_rejects_path_traversal_outside_worktree(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            worktree = Path(td) / "worktree"
            worktree.mkdir()
            diff = "--- a/../../etc/passwd\n+++ b/../../etc/passwd\n@@ -1,1 +1,1 @@\n-x\n+y\n"
            with self.assertRaises(ScopeViolationError):
                assert_diff_within_worktree(diff, worktree)


class CheckScopeTests(unittest.TestCase):
    """check_scope: vc_apply_patch의 사전 강제와 짝을 이루는 사후 검증(Day3 구현)."""

    def _run_and_patch(self, diff: str) -> tuple[Run, Patch]:
        run = Run(id=f"run-{uuid4().hex[:12]}", target_id="fake-target", status=RunState.VALIDATING)
        save(run)
        p = Patch(id=f"patch-{uuid4().hex[:12]}", finding_id="finding-x", run_id=run.id, diff=diff)
        save(p)
        return run, p

    def test_passes_when_all_files_inside_worktree(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            worktree = Path(td)
            run, p = self._run_and_patch(
                "--- a/src/Foo.java\n+++ b/src/Foo.java\n@@ -1,1 +1,1 @@\n-x\n+y\n"
            )
            fake_service = MagicMock()
            fake_service.catalog.worktree_manager_for.return_value.path_for.return_value = worktree
            fake_service.catalog.run_source_root_for.return_value = worktree
            with patch("core.judge._service", return_value=fake_service):
                self.assertTrue(check_scope(run.id, p.id))

    def test_fails_when_diff_escapes_worktree(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            worktree = Path(td) / "worktree"
            worktree.mkdir()
            run, p = self._run_and_patch(
                "--- a/../../etc/passwd\n+++ b/../../etc/passwd\n@@ -1,1 +1,1 @@\n-x\n+y\n"
            )
            fake_service = MagicMock()
            fake_service.catalog.worktree_manager_for.return_value.path_for.return_value = worktree
            fake_service.catalog.run_source_root_for.return_value = worktree
            with patch("core.judge._service", return_value=fake_service):
                self.assertFalse(check_scope(run.id, p.id))

    def test_unknown_patch_raises(self) -> None:
        with self.assertRaises(ValueError):
            check_scope("run-x", "patch-does-not-exist")


class CheckPositiveFunctionalityDelegatesToP3ValidatorsTests(unittest.TestCase):
    """P3 handoff(Plan B, D3-P3.md): check_positive_functionality는 이제 실제로 구현된
    `repair.validators.validate_patch()`에 top-level import로 위임한다(D3에 P3가 계약대로
    맞춰 구현 완료). `core.judge`가 `from repair.validators import validate_patch`로 이름을
    직접 바인딩해서 patch 대상은 origin(`repair.validators.validate_patch`)이 아니라
    `core.judge.validate_patch`여야 한다.
    """

    def test_delegates_to_repair_validators_validate_patch(self) -> None:
        with patch("core.judge.validate_patch", return_value=True) as mock_fn:
            self.assertTrue(check_positive_functionality("run-x", "patch-x"))
        mock_fn.assert_called_once_with("run-x", "patch-x")

    def test_propagates_false_from_validate_patch(self) -> None:
        with patch("core.judge.validate_patch", return_value=False):
            self.assertFalse(check_positive_functionality("run-x", "patch-x"))

    def test_unknown_patch_id_raises_value_error(self) -> None:
        # repair.validators.validate_patch가 이제 실제로 존재한다 — 존재하지 않는 patch_id는
        # (mock 없이) 그 실제 구현이 ValueError로 거부한다.
        with self.assertRaises(ValueError):
            check_positive_functionality("run-x", "patch-does-not-exist")


if __name__ == "__main__":
    unittest.main()
