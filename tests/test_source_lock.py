from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from runtime.source_lock import SourceLock


class _LockFixture(unittest.TestCase):
    """두 스위트가 공유하는 헬퍼만 담는다 (테스트 없음 — 상속해도 중복 실행되지 않는다)."""

    def _write(self, document: dict) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "source-lock.yaml"
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
        return path

    @staticmethod
    def _document(*target_ids: str) -> dict:
        return {
            "lock_version": 1,
            "targets": {
                target_id: {
                    "repository": f"https://github.com/madcamp-official/{target_id}.git",
                    "revision": "a" * 40,
                }
                for target_id in target_ids
            },
        }


class SourceLockTests(_LockFixture):
    def test_loads_canonical_exact_target_revisions(self) -> None:
        lock = SourceLock.load(
            self._write(self._document("demo-api", "other-api")),
            expected_target_ids={"demo-api", "other-api"},
        )
        self.assertEqual(lock.target_ids, ("demo-api", "other-api"))
        self.assertEqual(lock.get("demo-api").revision, "a" * 40)

    def test_rejects_unknown_fields_and_noncanonical_revision(self) -> None:
        document = self._document("demo-api")
        document["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "lock_version and targets"):
            SourceLock.load(self._write(document))

        document = self._document("demo-api")
        document["targets"]["demo-api"]["revision"] = "A" * 40
        with self.assertRaisesRegex(ValueError, "40 lowercase hex"):
            SourceLock.load(self._write(document))

    def test_rejects_repository_that_does_not_match_target_id(self) -> None:
        document = self._document("demo-api")
        document["targets"]["demo-api"]["repository"] = (
            "https://github.com/madcamp-official/other-api.git"
        )
        with self.assertRaisesRegex(ValueError, "must be"):
            SourceLock.load(self._write(document))

    def test_rejects_missing_or_extra_manifest_coverage(self) -> None:
        path = self._write(self._document("demo-api", "extra-api"))
        with self.assertRaisesRegex(
            ValueError, "missing=.*other-api.*extra=.*extra-api"
        ):
            SourceLock.load(path, expected_target_ids={"demo-api", "other-api"})

    def test_unknown_target_lookup_is_rejected(self) -> None:
        lock = SourceLock.load(self._write(self._document("demo-api")))
        with self.assertRaisesRegex(KeyError, "not registered"):
            lock.get("other-api")


class ExternalAllowlistTests(_LockFixture):
    """승인된 외부 벤치마크 저장소(Juice Shop 등)를 lock에 담기 위한 확장.

    소스를 vendor해야 `source_dir`이 실제 파일 트리를 가리키고, 그래야 static·scope 게이트와
    LLM 패치 합성이 동작한다(image-only 동적 target으로 두면 전부 bypass된다).
    """

    JUICE_SHOP = "https://github.com/juice-shop/juice-shop.git"

    def _with_external(self, *, allowlist: list | None, repository: str) -> dict:
        document = self._document("demo-api")
        document["targets"]["juice-shop"] = {
            "repository": repository,
            "revision": "b" * 40,
        }
        if allowlist is not None:
            document["external_allowlist"] = allowlist
        return document

    def test_allowlisted_external_repository_is_accepted(self) -> None:
        lock = SourceLock.load(
            self._write(self._with_external(
                allowlist=[self.JUICE_SHOP], repository=self.JUICE_SHOP
            ))
        )
        self.assertEqual(lock.get("juice-shop").repository, self.JUICE_SHOP)
        # 캠프 코퍼스 규칙은 그대로 공존한다.
        self.assertEqual(
            lock.get("demo-api").repository,
            "https://github.com/madcamp-official/demo-api.git",
        )

    def test_external_repository_without_allowlist_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "external_allowlist"):
            SourceLock.load(
                self._write(self._with_external(allowlist=None, repository=self.JUICE_SHOP))
            )

    def test_repository_not_in_allowlist_is_rejected(self) -> None:
        """allowlist에 있는 것과 다른 저장소는 통과하지 못한다(정확 일치만)."""
        with self.assertRaisesRegex(ValueError, "external_allowlist"):
            SourceLock.load(
                self._write(self._with_external(
                    allowlist=[self.JUICE_SHOP],
                    repository="https://github.com/attacker/juice-shop.git",
                ))
            )

    def test_allowlist_rejects_non_https_schemes(self) -> None:
        """file://·git://·ssh://로 로컬 경로 주입이나 인증 우회를 막는다."""
        for bad in (
            "file:///tmp/evil.git",
            "git://github.com/juice-shop/juice-shop.git",
            "ssh://git@github.com/juice-shop/juice-shop.git",
            "https://user:pw@github.com/juice-shop/juice-shop.git",
            "https://github.com/juice-shop/juice-shop",  # .git 없음
        ):
            with self.subTest(url=bad):
                with self.assertRaisesRegex(ValueError, "https .git URL"):
                    SourceLock.load(
                        self._write(self._with_external(
                            allowlist=[bad], repository=self.JUICE_SHOP
                        ))
                    )

    def test_empty_allowlist_is_rejected(self) -> None:
        """빈 리스트는 의도가 불분명하다 — 필드를 빼거나 항목을 넣어야 한다."""
        with self.assertRaisesRegex(ValueError, "non-empty list"):
            SourceLock.load(
                self._write(self._with_external(allowlist=[], repository=self.JUICE_SHOP))
            )

    def test_absent_allowlist_keeps_legacy_behaviour(self) -> None:
        """필드가 없으면 기존 동작 100% 동일(하위호환)."""
        lock = SourceLock.load(
            self._write(self._document("demo-api", "other-api")),
            expected_target_ids={"demo-api", "other-api"},
        )
        self.assertEqual(lock.target_ids, ("demo-api", "other-api"))


if __name__ == "__main__":
    unittest.main()
