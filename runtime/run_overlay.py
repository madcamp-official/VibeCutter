"""Run-scoped Compose overlays that build an isolated target worktree.

The checked-in manifest and Compose file remain the approved static contract.
For a patch run, this module emits an ignored Compose document whose only
semantic source change is that build contexts inside the target source clone
point at its detached worktree.  Dockerfile and P2 runtime asset paths are
resolved to trusted absolute repository paths so relocating the generated file
does not change their meaning.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import shutil
import subprocess

import yaml

from .compose_isolation import ComposeIsolationInspector, ComposeIsolationReport
from .lifecycle import CommandResult, LifecycleManager
from .manifest import TargetManifest


def _resolve_from(base: Path, value: str, repository_root: Path, *, label: str) -> Path:
    path = Path(value)
    resolved = path.resolve() if path.is_absolute() else (base / path).resolve()
    if resolved != repository_root and repository_root not in resolved.parents:
        raise ValueError(f"{label} escapes repository root")
    return resolved


def _is_within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


@dataclass(frozen=True)
class RunComposeOverlay:
    """Trusted target/run projection of a checked-in Docker Compose runtime."""

    manifest: TargetManifest
    repository_root: Path
    source_repository: Path
    worktree_path: Path
    run_id: str
    # Built-in manifests resolve compose paths from VibeCutter's repository.
    # User-approved manifests resolve them from their approved source repo while
    # keeping generated artifacts under the VibeCutter run root.
    project_root: Path | None = None

    @property
    def output_path(self) -> Path:
        return (
            self.repository_root.resolve()
            / ".vibecutter"
            / "run-overlays"
            / self.manifest.id
            / self.run_id
            / "compose.yaml"
        )

    @property
    def project_name(self) -> str:
        """Deterministic Docker Compose project name for this target/run overlay."""
        return f"vc-{sha256(f'{self.manifest.id}:{self.run_id}'.encode()).hexdigest()[:16]}"

    def prepare(self) -> Path:
        """Generate and statically validate a worktree-only Compose projection."""
        source_repository = self.source_repository.resolve()
        worktree_path = self.worktree_path.resolve()
        repository_root = self.repository_root.resolve()
        expected_root = repository_root / ".vibecutter" / "worktrees" / self.manifest.id
        if not _is_within(worktree_path, expected_root):
            raise ValueError("worktree path is outside the target run artifact root")
        if not worktree_path.is_dir() or not _is_git_worktree(worktree_path):
            raise ValueError("run source path is not a Git worktree")
        if not source_repository.is_dir():
            raise FileNotFoundError(f"target source repository does not exist: {source_repository}")
        if self.manifest.docker_isolation is None:
            raise ValueError("run-scoped Compose requires docker_isolation metadata")

        project_root = (self.project_root or repository_root).resolve()
        original_path = _resolve_from(
            project_root,
            self.manifest.docker_isolation.compose_file,
            project_root,
            label="checked-in compose file",
        )
        document = yaml.safe_load(original_path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            raise ValueError("checked-in compose document must be a mapping")
        generated = _rewrite_document(
            deepcopy(document),
            compose_directory=original_path.parent,
            repository_root=project_root,
            source_repository=source_repository,
            worktree_path=worktree_path,
        )
        generated["name"] = self.project_name
        output_path = self.output_path
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(yaml.safe_dump(generated, allow_unicode=True, sort_keys=False), encoding="utf-8")
        report = self.inspect()
        if not report.compliant:
            raise ValueError(f"generated compose violates isolation: {report.issues}")
        return output_path

    def inspect(self) -> ComposeIsolationReport:
        return ComposeIsolationInspector(
            self.manifest, self.repository_root, compose_path=self.output_path
        ).inspect()

    def remove_artifact(self) -> None:
        """Remove this generated run artifact after its Compose project is down."""
        artifact_dir = self.output_path.parent.resolve()
        expected = (
            self.repository_root.resolve()
            / ".vibecutter"
            / "run-overlays"
            / self.manifest.id
            / self.run_id
        ).resolve()
        if artifact_dir != expected:
            raise ValueError("run overlay artifact path is outside its target/run root")
        if artifact_dir.is_dir():
            shutil.rmtree(artifact_dir)

    def execute(self, command_id: str) -> CommandResult:
        """Run a checked-in lifecycle command against the generated Compose file only."""
        if not self.output_path.is_file():
            raise FileNotFoundError("run-scoped compose has not been prepared")
        try:
            command = self.manifest.commands[command_id]
        except KeyError as exc:
            raise KeyError(f"command_id is not registered for {self.manifest.id}: {command_id}") from exc
        argv = _replace_compose_file_arg(command.argv, self.manifest.docker_isolation.compose_file, self.output_path)
        commands = self.manifest.commands.copy()
        commands[command_id] = command.model_copy(update={"argv": argv, "working_dir": "."})
        projected = self.manifest.model_copy(update={"commands": commands})
        return LifecycleManager(projected, self.repository_root).execute(command_id)

    def check_health(self):
        return LifecycleManager(self.manifest, self.repository_root).check_health()


def _is_git_worktree(path: Path) -> bool:
    result = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        check=False,
        shell=False,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def _rewrite_document(
    document: dict,
    *,
    compose_directory: Path,
    repository_root: Path,
    source_repository: Path,
    worktree_path: Path,
) -> dict:
    services = document.get("services")
    if not isinstance(services, dict):
        raise ValueError("compose document must declare services")
    for name, service in services.items():
        if not isinstance(service, dict):
            raise ValueError(f"compose service {name!r} must be a mapping")
        build = service.get("build")
        if isinstance(build, str):
            service["build"] = {"context": _rewrite_source_path(build, compose_directory, repository_root, source_repository, worktree_path)}
        elif isinstance(build, dict):
            context = build.get("context", ".")
            if not isinstance(context, str):
                raise ValueError(f"compose service {name!r} build context must be a path")
            original_context = _resolve_from(
                compose_directory, context, repository_root, label="compose build context"
            )
            build["context"] = str(_map_source_path(original_context, source_repository, worktree_path))
            dockerfile = build.get("dockerfile")
            if isinstance(dockerfile, str):
                build["dockerfile"] = str(
                    _resolve_from(original_context, dockerfile, repository_root, label="compose Dockerfile")
                )
        _rewrite_volume_paths(service, compose_directory, repository_root)
        _rewrite_env_file_paths(service, compose_directory, repository_root)
    return document


def _rewrite_source_path(
    value: str,
    compose_directory: Path,
    repository_root: Path,
    source_repository: Path,
    worktree_path: Path,
) -> str:
    original = _resolve_from(compose_directory, value, repository_root, label="compose build context")
    return str(_map_source_path(original, source_repository, worktree_path))


def _map_source_path(original: Path, source_repository: Path, worktree_path: Path) -> Path:
    if _is_within(original, source_repository):
        return (worktree_path / original.relative_to(source_repository)).resolve()
    return original


def _rewrite_volume_paths(service: dict, compose_directory: Path, repository_root: Path) -> None:
    volumes = service.get("volumes")
    if not isinstance(volumes, list):
        return
    rewritten: list[object] = []
    for volume in volumes:
        if not isinstance(volume, str):
            rewritten.append(volume)
            continue
        parts = volume.rsplit(":", 2)
        host = parts[0]
        if not host.startswith((".", "/")):
            rewritten.append(volume)
            continue
        resolved = _resolve_from(compose_directory, host, repository_root, label="compose bind mount")
        rewritten.append(":".join([str(resolved), *parts[1:]]))
    service["volumes"] = rewritten


def _rewrite_env_file_paths(service: dict, compose_directory: Path, repository_root: Path) -> None:
    value = service.get("env_file")
    if isinstance(value, str):
        service["env_file"] = str(_resolve_from(compose_directory, value, repository_root, label="compose env_file"))
    elif isinstance(value, list):
        service["env_file"] = [
            str(_resolve_from(compose_directory, item, repository_root, label="compose env_file"))
            if isinstance(item, str)
            else item
            for item in value
        ]


def _replace_compose_file_arg(argv: list[str], configured_path: str, generated_path: Path) -> list[str]:
    rewritten = list(argv)
    for index, value in enumerate(rewritten[:-1]):
        if value in {"-f", "--file"} and rewritten[index + 1] == configured_path:
            rewritten[index + 1] = str(generated_path)
            return rewritten
    raise ValueError("manifest command does not reference its configured compose file")
