"""Repo → manifest 초안 스캐폴딩 (REMAINING_PLAN.md 5절 U1).

`vc_register_local_target(manifest, source_path, ...)`은 manifest를 이미 조립된 상태로
요구한다. 비전문 사용자는 build/start/stop/reset argv·healthcheck·test_suites 값을 모르므로
"사용자가 manifest를 쓴다"는 요구 자체가 온보딩의 벽이 된다.

이 모듈은 `docker-compose.yml`/`package.json`/`pom.xml`/`requirements.txt` 등 레포에 이미
있는 파일을 읽어 `TargetManifest` 스키마를 만족하는 **초안** dict와, 각 값을 어느 파일에서
뽑았는지 근거(`evidence`)를 만든다. **아무것도 등록·실행하지 않는다** — 초안은
`vc_register_local_target(manifest, source_path, confirmed=False)`의 미리보기로 넘어가
사람이 승인해야 다음 단계로 간다(TEAM_CONTRACT 안전 불변식 2, `confirmed=True` 게이트는
그대로 유지).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from runtime.manifest import AdapterKind

_COMPOSE_FILENAMES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")

# 주 서비스를 고를 때 걸러낼 인프라 이미지(DB/캐시/큐 등) 힌트. 완벽할 필요는 없다 —
# 못 걸러도 최악의 경우 "확인해서 고치라"는 warning이 붙을 뿐, 안전 게이트는 그대로다.
_INFRA_IMAGE_HINTS = (
    "postgres", "mysql", "mariadb", "mongo", "redis", "memcached",
    "rabbitmq", "elasticsearch", "adminer", "pgadmin", "minio",
)
_SERVICE_NAME_HINTS = ("web", "app", "api", "server", "backend")


class ScaffoldResult(BaseModel):
    """`vc_register_local_target`에 그대로 넘길 수 있는 draft manifest + 근거.

    `manifest`가 `None`이면 확신 있는 초안을 만들지 못했다는 뜻이다(무엇을 못 찾았는지는
    `warnings`에 쉬운 말로 담는다) — 틀릴 바에는 만들지 않는다.
    """

    source_path: str
    detected: bool
    detected_stack: str
    manifest: dict[str, Any] | None = None
    evidence: dict[str, str] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


def scaffold_manifest(source_path: Path) -> ScaffoldResult:
    if not source_path.is_dir():
        return ScaffoldResult(
            source_path=str(source_path),
            detected=False,
            detected_stack="unknown",
            warnings=[f"source_path가 디렉터리가 아닙니다: {source_path}"],
        )

    compose_path = _find_compose_file(source_path)
    if compose_path is not None:
        return _scaffold_from_compose(source_path, compose_path)
    return _scaffold_single_service(source_path)


# --- 공통 헬퍼 -----------------------------------------------------------------------


def _find_compose_file(source_path: Path) -> Path | None:
    for name in _COMPOSE_FILENAMES:
        candidate = source_path / name
        if candidate.is_file():
            return candidate
    return None


def _slugify(name: str) -> str:
    """`TargetId` 패턴(`^[a-z0-9][a-z0-9-]{1,62}$`)을 만족하는 id로 변환."""
    slug = re.sub(r"[^a-z0-9-]+", "-", name.strip().lower()).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)
    if not slug or not slug[0].isalnum():
        slug = f"local-{slug}".strip("-") if slug else "local-project"
    return slug[:63]


def _detect_adapter_from_dir(directory: Path) -> tuple[AdapterKind, str]:
    """단일 디렉터리 안의 마커 파일로 adapter label을 고른다.

    4종 adapter는 전부 같은 `ManifestCommandAdapter`로 실행되므로(`adapters/registry.py`)
    이건 실행 방식이 아니라 사람이 읽는 라벨 선택이다 — 확신이 없으면 generic-docker로
    떨어뜨려도 안전하다(U2).
    """
    if (directory / "package.json").is_file():
        return AdapterKind.NODE, str(directory / "package.json")
    if any((directory / name).is_file() for name in ("pom.xml", "build.gradle", "build.gradle.kts")):
        marker = next(name for name in ("pom.xml", "build.gradle", "build.gradle.kts") if (directory / name).is_file())
        return AdapterKind.SPRING_BOOT, str(directory / marker)
    if any((directory / name).is_file() for name in ("requirements.txt", "pyproject.toml")):
        marker = "requirements.txt" if (directory / "requirements.txt").is_file() else "pyproject.toml"
        return AdapterKind.FASTAPI, str(directory / marker)
    return AdapterKind.GENERIC_DOCKER, "package.json/pom.xml/requirements.txt 중 아무것도 못 찾음"


# --- docker-compose 경로 (주 경로, U1 완료 판정 기준) -----------------------------------


def _looks_like_infra_service(name: str, service: dict) -> bool:
    image = str(service.get("image", "")).lower()
    haystack = f"{name.lower()} {image}"
    return any(hint in haystack for hint in _INFRA_IMAGE_HINTS)


def _pick_primary_service(services: dict[str, Any]) -> tuple[str, dict] | None:
    candidates = {
        name: svc for name, svc in services.items()
        if isinstance(svc, dict) and not _looks_like_infra_service(name, svc)
    }
    if not candidates:
        return None
    # 로컬 소스에서 빌드하는(=우리 앱일 가능성이 높은) 서비스를 이미지만 pull하는
    # 서비스보다 우선한다.
    built = {name: svc for name, svc in candidates.items() if "build" in svc}
    pool = built or candidates
    for hint in _SERVICE_NAME_HINTS:
        for name, svc in pool.items():
            if hint in name.lower():
                return name, svc
    first_name = next(iter(pool))
    return first_name, pool[first_name]


def _parse_port_mapping(raw: Any) -> tuple[int, int] | None:
    """docker-compose `ports` 항목 하나에서 (host_port, container_port)를 뽑는다.

    환경변수 치환(`${PORT}:3000`)이나 호스트 바인딩 없는 컨테이너 전용 포트는 정적으로
    풀 수 없으므로 `None`을 반환한다 — 틀리게 추측하지 않는다.
    """
    if isinstance(raw, dict):
        published = raw.get("published")
        target = raw.get("target")
        try:
            if published is not None and target is not None:
                return int(published), int(target)
        except (TypeError, ValueError):
            return None
        return None
    if isinstance(raw, str):
        if "$" in raw:
            return None
        parts = raw.split(":")
        try:
            if len(parts) == 2:
                return int(parts[0]), int(parts[1])
            if len(parts) == 3:
                return int(parts[1]), int(parts[2])
        except ValueError:
            return None
    return None


def _resolve_build_context(compose_path: Path, service: dict) -> Path:
    build_spec = service.get("build")
    if isinstance(build_spec, dict) and build_spec.get("context"):
        return (compose_path.parent / str(build_spec["context"])).resolve()
    if isinstance(build_spec, str):
        return (compose_path.parent / build_spec).resolve()
    return compose_path.parent


def _detect_test_command(
    build_context: Path, rel_compose: str, service_name: str
) -> tuple[dict[str, Any], dict[str, Any], str] | None:
    """가능하면 `docker compose run --rm <service> <test>` 형태의 test 후보를 만든다."""
    package_json = build_context / "package.json"
    if package_json.is_file():
        try:
            pkg = json.loads(package_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if "test" in pkg.get("scripts", {}):
            spec = {
                "argv": ["docker", "compose", "-f", rel_compose, "run", "--rm", service_name, "npm", "test"],
                "timeout_seconds": 600,
            }
            suite = {"name": "unit", "command_id": "test"}
            return spec, suite, f"{package_json}: scripts.test 발견"
        return None

    requirements = build_context / "requirements.txt"
    has_pytest_dep = requirements.is_file() and "pytest" in requirements.read_text(encoding="utf-8", errors="ignore")
    if has_pytest_dep or (build_context / "tests").is_dir():
        spec = {
            "argv": ["docker", "compose", "-f", rel_compose, "run", "--rm", service_name, "pytest"],
            "timeout_seconds": 600,
        }
        suite = {"name": "unit", "command_id": "test"}
        evidence = f"{requirements if has_pytest_dep else build_context / 'tests'} 발견"
        return spec, suite, evidence
    return None


def _scaffold_from_compose(source_path: Path, compose_path: Path) -> ScaffoldResult:
    rel_compose = str(compose_path.relative_to(source_path))

    try:
        data = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        return ScaffoldResult(
            source_path=str(source_path),
            detected=False,
            detected_stack="docker-compose (parse failed)",
            warnings=[f"{rel_compose}를 읽지 못했습니다: {exc}"],
        )

    services = (data or {}).get("services") if isinstance(data, dict) else None
    if not isinstance(services, dict) or not services:
        return ScaffoldResult(
            source_path=str(source_path),
            detected=False,
            detected_stack="docker-compose (no services)",
            warnings=[f"{rel_compose}에 services가 없습니다."],
        )

    picked = _pick_primary_service(services)
    if picked is None:
        return ScaffoldResult(
            source_path=str(source_path),
            detected=False,
            detected_stack="docker-compose",
            warnings=[
                f"{rel_compose}의 서비스가 모두 DB/캐시처럼 보여 주 서비스를 고르지 못했습니다 — "
                f"직접 manifest를 작성하거나 문의하세요."
            ],
        )
    service_name, service = picked

    evidence: dict[str, str] = {
        "adapter/service": f"{rel_compose}: services.{service_name} 를 주 서비스로 선택",
    }
    warnings: list[str] = []

    port_pair = None
    for raw_port in service.get("ports") or []:
        port_pair = _parse_port_mapping(raw_port)
        if port_pair is not None:
            break
    if port_pair is None:
        host_port = 18080
        warnings.append(
            f"{rel_compose}의 services.{service_name}.ports에서 고정 호스트 포트를 찾지 못해 "
            f"{host_port}을 임시로 사용했습니다 — 실제 포트로 확인 후 고치세요."
        )
    else:
        host_port, _container_port = port_pair
        evidence["base_url"] = f"{rel_compose}: services.{service_name}.ports → host port {host_port}"

    build_context = _resolve_build_context(compose_path, service)
    adapter, adapter_evidence = _detect_adapter_from_dir(build_context)
    evidence["adapter"] = adapter_evidence

    target_id = _slugify(source_path.name)
    evidence["id"] = f"소스 디렉터리 이름({source_path.name})에서 생성"

    manifest: dict[str, Any] = {
        "manifest_version": 1,
        "kind": "compose_project",
        "id": target_id,
        "display_name": source_path.name,
        "adapter": adapter.value,
        "source_dir": ".",
        "base_url": f"http://127.0.0.1:{host_port}",
        "commands": {
            "build": {"argv": ["docker", "compose", "-f", rel_compose, "build"], "timeout_seconds": 900},
            "start": {"argv": ["docker", "compose", "-f", rel_compose, "up", "-d"], "timeout_seconds": 180},
            "stop": {"argv": ["docker", "compose", "-f", rel_compose, "down"], "timeout_seconds": 180},
            "reset": {"argv": ["docker", "compose", "-f", rel_compose, "down", "--volumes"], "timeout_seconds": 180},
        },
        "healthcheck": {"path": "/health", "expected_status": 200, "timeout_seconds": 20},
        "reset": {"command_id": "reset"},
    }
    evidence["commands.build/start/stop/reset"] = f"{rel_compose} 기반 표준 docker compose 명령"

    test_hit = _detect_test_command(build_context, rel_compose, service_name)
    if test_hit is not None:
        spec, suite, test_evidence = test_hit
        manifest["commands"]["test"] = spec
        manifest["test_suites"] = [suite]
        evidence["commands.test"] = test_evidence

    warnings.append("healthcheck.path는 기본값(/health)입니다 — 앱에 실제로 있는 경로인지 확인하세요.")
    warnings.append("reset은 볼륨만 삭제합니다(down --volumes) — 이어서 start가 다시 필요할 수 있습니다.")
    warnings.append("docker network 격리(docker_isolation)는 자동 설정하지 않았습니다 — 필요하면 직접 추가하세요.")

    return ScaffoldResult(
        source_path=str(source_path),
        detected=True,
        detected_stack=f"docker-compose ({adapter.value})",
        manifest=manifest,
        evidence=evidence,
        warnings=warnings,
    )


# --- docker-compose가 없는 단일 서비스 fallback ------------------------------------------


def _scaffold_single_service(source_path: Path) -> ScaffoldResult:
    adapter, adapter_evidence = _detect_adapter_from_dir(source_path)
    if adapter is AdapterKind.GENERIC_DOCKER:
        return ScaffoldResult(
            source_path=str(source_path),
            detected=False,
            detected_stack="unknown",
            warnings=[
                "docker-compose.yml / package.json / pom.xml / requirements.txt 중 아무것도 "
                "찾지 못했습니다 — manifest를 직접 작성하거나, 앱을 실행할 수 있다면 "
                "'generic-docker' adapter로 수동 등록하세요.",
            ],
        )

    evidence: dict[str, str] = {
        "adapter": adapter_evidence,
        "id": f"소스 디렉터리 이름({source_path.name})에서 생성",
    }
    warnings: list[str] = [
        "docker-compose 없이 감지했습니다 — build/start/포트는 추정값이니 실행 전 반드시 확인하세요.",
        "reset 명령은 자동 감지할 수 없어 자리표시자(echo)를 넣었습니다 — 실제 DB/상태 초기화 명령으로 바꾸세요.",
        "healthcheck.path는 기본값(/health)입니다 — 앱에 실제로 있는 경로인지 확인하세요.",
    ]

    if adapter is AdapterKind.NODE:
        build_argv = ["npm", "install"]
        start_argv = ["npm", "start"]
        port = 3000
        package_json = source_path / "package.json"
        try:
            pkg = json.loads(package_json.read_text(encoding="utf-8"))
            if "start" in pkg.get("scripts", {}):
                evidence["commands.start"] = f"package.json: scripts.start = {pkg['scripts']['start']!r}"
            else:
                warnings.append("package.json에 scripts.start가 없어 'npm start'를 그대로 가정했습니다.")
        except (OSError, json.JSONDecodeError) as exc:
            warnings.append(f"package.json을 읽지 못했습니다: {exc}")
        evidence["base_url"] = "package.json에 포트 정보가 없어 node 기본 포트 3000을 가정"
    elif adapter is AdapterKind.FASTAPI:
        build_argv = ["pip", "install", "-r", "requirements.txt"]
        start_argv = ["uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8000"]
        port = 8000
        evidence["base_url"] = "requirements.txt 발견 — FastAPI 기본 포트 8000을 가정"
        warnings.append(
            "start 명령은 'uvicorn main:app' 관례를 가정했습니다 — 실제 앱 진입점(module:app)으로 확인하세요."
        )
    else:  # SPRING_BOOT
        build_argv = ["mvn", "-B", "package", "-DskipTests"]
        start_argv = ["mvn", "spring-boot:run"]
        port = 8080
        evidence["base_url"] = "pom.xml/build.gradle 발견 — Spring Boot 기본 포트 8080을 가정"

    target_id = _slugify(source_path.name)

    # kind="running_local": 범용 stop 방법을 안전하게 추정할 수 없어(프로세스를 잘못
    # kill하면 다른 작업을 죽일 위험) stop을 필수로 요구하지 않는다(runtime/manifest.py의
    # referenced_commands_must_exist가 running_local에는 stop을 요구하지 않는 이유와 동일).
    manifest: dict[str, Any] = {
        "manifest_version": 1,
        "kind": "running_local",
        "id": target_id,
        "display_name": source_path.name,
        "adapter": adapter.value,
        "source_dir": ".",
        "base_url": f"http://127.0.0.1:{port}",
        "commands": {
            "build": {"argv": build_argv, "timeout_seconds": 900},
            "start": {"argv": start_argv, "timeout_seconds": 180},
            "reset": {"argv": ["echo", "manual-reset-required"], "timeout_seconds": 30},
        },
        "healthcheck": {"path": "/health", "expected_status": 200, "timeout_seconds": 20},
        "reset": {"command_id": "reset"},
    }

    return ScaffoldResult(
        source_path=str(source_path),
        detected=True,
        detected_stack=f"{adapter.value} (docker-compose 없음)",
        manifest=manifest,
        evidence=evidence,
        warnings=warnings,
    )
