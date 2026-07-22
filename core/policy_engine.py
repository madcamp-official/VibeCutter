"""Policy engine v1: target allowlist + command_id/typed-args 검증.

"등록된 target_id와 manifest에서 허용된 범위만 사용한다. 임의 URL/IP/shell 문자열을 공통
도구 입력으로 받지 않는다. 명령은 command_id + typed arguments로 제한한다"
(cowork_rule.md 4절 공통 안전 규칙)를 코드로 강제한다.

거부는 항상 `PolicyViolation` 예외로 표현한다. 이 모듈 자체는 로깅하지 않는다 — 호출자
(MCP tool 배선, Day2~)가 이 예외를 잡아 audit log(item 10)에 남긴다.

target 허용 목록은 **두 출처**를 가진다(TEAM_CONTRACT 3.2):
  ① `policies/scope.yaml` — 팀이 체크인한 built-in demo target(기존 20개).
  ② 사용자 로컬 승인 레지스트리(`runtime.registry.LocalRegistry`, P2 소유) — 사용자가
     자기 프로젝트를 명시 승인해 자기 머신에 기록한 것.

②가 이번 스프린트의 방향 전환이다. **allowlist라는 안전 원칙은 유지하고 소유자만 옮긴다** —
"우리 저장소에 커밋됐다"가 아니라 "사용자가 그 내용을 보고 승인했다"가 승인의 근거가 된다.
loopback 강제는 이 모듈이 아니라 `runtime.manifest.TargetManifest`의 스키마 검증기가
구조적으로 하므로, 출처가 늘어도 "localhost 외에는 공격 불가"는 그대로다.

실행 가능한 command_id는 `policies/commands.yaml`이 정의한다. 이 모듈은 정책을 읽고
강제하기만 한다 — 정책 값 자체를 코드에 하드코딩하지 않는다.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Protocol, runtime_checkable
from urllib.parse import urlparse

import yaml

_POLICIES_DIR = Path(__file__).resolve().parent.parent / "policies"
_DEFAULT_SCOPE_PATH = _POLICIES_DIR / "scope.yaml"
_DEFAULT_COMMANDS_PATH = _POLICIES_DIR / "commands.yaml"

_ARG_TYPES: dict[str, type] = {"str": str, "int": int, "float": float, "bool": bool}


class PolicyViolation(PermissionError):
    """target allowlist 또는 command policy를 위반했을 때 발생한다."""


def _load_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    # Policies are versioned UTF-8 YAML and include Korean documentation.
    # Relying on Windows' active code page (often cp949) makes the policy gate
    # fail before it can decide allow/deny, despite valid checked-in files.
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def load_scope(path: Path = _DEFAULT_SCOPE_PATH) -> dict[str, dict]:
    """`policies/scope.yaml`의 targets 맵. `{target_id: {allowed_hosts: [...], ...}}`."""
    return _load_yaml(path).get("targets") or {}


def load_commands(path: Path = _DEFAULT_COMMANDS_PATH) -> dict[str, dict]:
    """`policies/commands.yaml`의 commands 맵. `{command_id: {args: {name: type}}}`."""
    return _load_yaml(path).get("commands") or {}


# --- 사용자 로컬 승인 레지스트리 (P2 소유 `runtime.registry`) ---------------------------
#
# P1은 아래 두 Protocol에만 의존한다. P2의 구현 클래스를 직접 import 하지 않으므로
# 레지스트리가 아직 없는 상태(브랜치 병합 전)에서도 이 모듈과 테스트가 정상 동작한다.


@runtime_checkable
class _ApprovedTargetLike(Protocol):
    """`runtime.registry.ApprovedTarget`이 만족해야 하는 최소 형태 (TEAM_CONTRACT 3.1)."""

    target_id: str
    allowed_hosts: list[str]


@runtime_checkable
class _RegistryLike(Protocol):
    def get(self, target_id: str) -> Optional[_ApprovedTargetLike]: ...


_REGISTRY_UNSET = object()
_registry_cache: object = _REGISTRY_UNSET


def _default_registry() -> Optional[_RegistryLike]:
    """`runtime.registry.LocalRegistry`를 지연 로드한다. 없으면 None.

    P2가 아직 레지스트리를 main에 올리지 않았거나, 사용자가 자기 프로젝트를 하나도
    등록하지 않은 환경에서도 built-in demo target 경로는 그대로 돌아야 한다 —
    c1-05 gold가 fallback이라 이게 깨지면 안 된다(TEAM_CONTRACT 0절).
    """
    global _registry_cache
    if _registry_cache is _REGISTRY_UNSET:
        try:
            from runtime.registry import LocalRegistry  # type: ignore[import-not-found]

            _registry_cache = LocalRegistry.load()
        except Exception:
            # ImportError(미구현) / 손상된 레지스트리 파일 모두 여기로 온다. 정책 게이트가
            # 판단 자체를 못 하고 죽는 것보다, built-in만으로 판정하고 계속하는 편이 낫다.
            _registry_cache = None
    return _registry_cache  # type: ignore[return-value]


def reset_registry_cache() -> None:
    """테스트/재등록 후 지연 로드 캐시를 비운다."""
    global _registry_cache
    _registry_cache = _REGISTRY_UNSET


def _registry_entry(target_id: str, registry: Optional[_RegistryLike]) -> Optional[dict]:
    """레지스트리의 승인 기록을 scope.yaml 엔트리와 같은 모양의 dict로 바꾼다.

    두 출처가 같은 형태를 내야 `require_host_allowed`가 출처를 몰라도 된다.
    """
    if registry is None:
        return None
    approved = registry.get(target_id)
    if approved is None:
        return None
    base_url = getattr(approved, "base_url", None)
    # scope.yaml의 built-in 엔트리는 항상 `port`를 명시하고(정적 검토된 값), P2
    # `_require_authorized`(runtime/target_service.py)가 그 port를 manifest.base_url의
    # 실제 port와 대조해 이중 확인한다. 이 정규화가 `port`를 안 채우면(2026-07-22, U4
    # 라이브 발견 — 로컬 target 등록 경로가 실행된 적이 없어 아무도 못 봄) 로컬 레지스트리로
    # 승인된 target은 이 대조에서 항상 `configured_port=None`이 돼 스캔조차 못 한다 —
    # base_url에서 port를 뽑아 built-in과 같은 모양으로 맞춘다.
    port = urlparse(base_url).port if base_url else None
    return {
        "allowed_hosts": list(approved.allowed_hosts),
        "source": "user_registry",
        "base_url": base_url,
        "port": port,
    }


# --- target 허용 판정 (이중 출처) ------------------------------------------------------


def is_target_allowed(
    target_id: str,
    *,
    path: Path = _DEFAULT_SCOPE_PATH,
    registry: Optional[_RegistryLike] = None,
) -> bool:
    if target_id in load_scope(path):
        return True
    reg = registry if registry is not None else _default_registry()
    return _registry_entry(target_id, reg) is not None


def require_target_allowed(
    target_id: str,
    *,
    path: Path = _DEFAULT_SCOPE_PATH,
    registry: Optional[_RegistryLike] = None,
) -> dict:
    """등록되지 않은 target_id는 무조건 거부한다 (DoD: 미등록 target_id 전부 거부).

    built-in demo(`policies/scope.yaml`) → 사용자 로컬 승인 레지스트리 순으로 조회한다.
    **built-in을 먼저 보는 순서가 중요하다** — 사용자가 실수로 같은 target_id를 등록해도
    팀이 체크인한 데모 target의 정의가 이긴다.
    """
    scope = load_scope(path)
    if target_id in scope:
        return scope[target_id]

    reg = registry if registry is not None else _default_registry()
    entry = _registry_entry(target_id, reg)
    if entry is not None:
        return entry

    raise PolicyViolation(
        f"target_id={target_id!r}는 승인되지 않았습니다 "
        f"(policies/scope.yaml의 built-in target도, 로컬 승인 레지스트리에도 없음). "
        f"자기 프로젝트라면 vc_register_local_target으로 먼저 승인하세요."
    )


def _extract_host(url_or_host: str) -> str:
    if "://" in url_or_host:
        return urlparse(url_or_host).hostname or url_or_host
    if url_or_host.startswith("[") or url_or_host.count(":") > 1:
        # bare "host:port" 형태만 지원한다(기획서 전체가 127.0.0.1만 다룸). IPv6는
        # 콜론이 여러 개라 naive split(":")[0]으로는 조용히 잘못 파싱된다 — 지원하지
        # 않는 형태는 조용히 틀리게 처리하는 대신 명확히 거부한다.
        raise PolicyViolation(f"IPv6로 보이는 host는 아직 지원하지 않습니다: {url_or_host!r}")
    return url_or_host.split(":")[0]


def require_host_allowed(
    target_id: str,
    url_or_host: str,
    *,
    path: Path = _DEFAULT_SCOPE_PATH,
    registry: Optional[_RegistryLike] = None,
) -> None:
    """target의 allowed_hosts 밖의 URL/IP는 전부 거부한다. 임의 네트워크 목적지 구성을 막는 게이트.

    출처(built-in / 사용자 레지스트리)를 구분하지 않는다 — `require_target_allowed`가 두
    출처를 같은 모양의 엔트리로 정규화해 주기 때문이다.
    """
    entry = require_target_allowed(target_id, path=path, registry=registry)
    allowed_hosts = entry.get("allowed_hosts") or []
    host = _extract_host(url_or_host)
    if host not in allowed_hosts:
        raise PolicyViolation(
            f"host={host!r} (target_id={target_id!r})는 allowed_hosts={allowed_hosts}에 없습니다"
        )


def require_valid_command(
    command_id: str, args: dict, *, path: Path = _DEFAULT_COMMANDS_PATH
) -> None:
    """command_id + typed args만 허용한다. shell 문자열을 직접 받지 않는다 (6.7절/10.2절).

    - command_id가 policies/commands.yaml에 없으면 거부.
    - args에 정의되지 않은 키가 있으면 거부.
    - 정의된 키가 빠졌거나 타입이 안 맞으면 거부.
    """
    commands = load_commands(path)
    if command_id not in commands:
        raise PolicyViolation(
            f"command_id={command_id!r}는 policies/commands.yaml에 등록되지 않았습니다"
        )

    schema: dict[str, str] = commands[command_id].get("args") or {}
    unknown = set(args) - set(schema)
    if unknown:
        raise PolicyViolation(f"command_id={command_id!r}: 정의되지 않은 인자 {unknown}")

    for name, type_name in schema.items():
        if name not in args:
            raise PolicyViolation(f"command_id={command_id!r}: 필수 인자 {name!r} 누락")
        expected_type = _ARG_TYPES.get(type_name)
        if expected_type is None:
            raise PolicyViolation(
                f"command_id={command_id!r}: 알 수 없는 타입 {type_name!r} (인자 {name!r})"
            )
        if not isinstance(args[name], expected_type):
            raise PolicyViolation(
                f"command_id={command_id!r}: 인자 {name!r}는 {type_name} 타입이어야 합니다"
                f" (받은 값: {args[name]!r})"
            )
