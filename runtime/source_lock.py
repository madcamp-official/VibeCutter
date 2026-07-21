"""Checked-in source identity contract for P2-managed target clones.

기본 규칙은 "target_id 하나당 madcamp-official 조직의 동명 저장소"다. 캠프 코퍼스 20개는
이 규칙으로 repository를 **유추**할 수 있어 오타·바꿔치기가 구조적으로 불가능하다.

여기에 `external_allowlist`(선택)를 더한다. 승인된 외부 벤치마크 저장소(OWASP Juice Shop
등)를 소스까지 vendor해야 하기 때문이다 — image-only 동적 target으로 두면 `source_dir`이
실제 파일 트리를 못 가리켜서 static·scope 게이트와 LLM 패치 합성이 전부 bypass된다.

**allowlist는 안전 원칙의 예외가 아니라 같은 원칙의 확장이다**: 여기 적히지 않은 URL은
여전히 거부되고, 이 파일은 체크인되어 팀 리뷰를 거친다. allowlist 필드가 없으면 동작은
기존과 100% 동일하다(하위호환).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

import yaml


_TARGET_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY_PREFIX = "https://github.com/madcamp-official/"
# allowlist에 적을 수 있는 형태. https + .git 만 허용해 file://, git://, ssh:// 로
# 로컬 경로나 인증 우회 원격을 끼워 넣지 못하게 한다.
_EXTERNAL_REPOSITORY = re.compile(r"^https://[A-Za-z0-9.\-]+/[A-Za-z0-9._\-/]+\.git$")


@dataclass(frozen=True)
class SourceRevision:
    target_id: str
    repository: str
    revision: str


class SourceLock:
    """Validated target ID -> canonical repository/exact commit mapping."""

    def __init__(self, entries: dict[str, SourceRevision]) -> None:
        self._entries = dict(entries)

    @classmethod
    def load(
        cls,
        path: Path,
        *,
        expected_target_ids: set[str] | None = None,
    ) -> "SourceLock":
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict) or not set(document) <= {
            "lock_version",
            "targets",
            "external_allowlist",
        } or not {"lock_version", "targets"} <= set(document):
            raise ValueError(
                "source lock must contain lock_version and targets"
                " (external_allowlist optional)"
            )
        if document.get("lock_version") != 1:
            raise ValueError("source lock must declare lock_version: 1")
        targets = document.get("targets")
        if not isinstance(targets, dict) or not targets:
            raise ValueError("source lock must declare at least one target")
        external = cls._load_external_allowlist(document.get("external_allowlist"))

        entries: dict[str, SourceRevision] = {}
        for target_id, value in targets.items():
            if not isinstance(target_id, str) or not _TARGET_ID.fullmatch(target_id):
                raise ValueError(f"invalid source lock target ID: {target_id!r}")
            if not isinstance(value, dict) or set(value) != {"repository", "revision"}:
                raise ValueError(
                    f"source lock entry {target_id!r} must contain only repository and revision"
                )
            repository = value.get("repository")
            revision = value.get("revision")
            expected_repository = f"{_REPOSITORY_PREFIX}{target_id}.git"
            # 캠프 코퍼스는 target_id에서 저장소를 유추할 수 있어야 하고, 그 밖의 저장소는
            # external_allowlist에 **정확히 일치**하는 항목이 있을 때만 허용한다(부분일치·
            # 접두사 매칭 금지 — 비슷한 이름의 다른 저장소가 통과하면 안 된다).
            if repository != expected_repository and repository not in external:
                raise ValueError(
                    f"source lock repository for {target_id} must be {expected_repository!r}"
                    f" or listed in external_allowlist"
                )
            if not isinstance(revision, str) or not _REVISION.fullmatch(revision):
                raise ValueError(
                    f"source lock revision for {target_id} must be 40 lowercase hex"
                )
            entries[target_id] = SourceRevision(
                target_id=target_id,
                repository=repository,
                revision=revision,
            )

        if expected_target_ids is not None and set(entries) != expected_target_ids:
            missing = sorted(expected_target_ids - set(entries))
            extra = sorted(set(entries) - expected_target_ids)
            raise ValueError(
                f"source lock must cover target manifests exactly; missing={missing}, extra={extra}"
            )
        return cls(entries)

    @staticmethod
    def _load_external_allowlist(value: object) -> frozenset[str]:
        """승인된 외부 저장소 URL 집합. 필드가 없으면 빈 집합(기존 동작 그대로).

        형태를 좁게 검증한다 — `https://…/….git` 만 허용해서 `file://`(로컬 경로 주입),
        `git://`·`ssh://`(인증 우회), 자격증명이 박힌 URL(`https://user:pw@…`)이 들어오지
        못하게 한다. 이 파일은 체크인되어 리뷰를 거치지만, 리뷰가 놓쳐도 걸리도록 둔다.
        """
        if value is None:
            return frozenset()
        if not isinstance(value, list) or not value:
            raise ValueError("external_allowlist must be a non-empty list when present")
        allowed: set[str] = set()
        for item in value:
            if not isinstance(item, str) or not _EXTERNAL_REPOSITORY.fullmatch(item):
                raise ValueError(
                    f"external_allowlist entry must be an https .git URL: {item!r}"
                )
            allowed.add(item)
        return frozenset(allowed)

    def get(self, target_id: str) -> SourceRevision:
        try:
            return self._entries[target_id]
        except KeyError as exc:
            raise KeyError(
                f"target_id is not registered in source lock: {target_id}"
            ) from exc

    @property
    def target_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._entries))
