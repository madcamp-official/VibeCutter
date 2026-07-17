"""Target app inventory 로더/검증기 (P4 소유).

`datasets/inventory.yaml`를 읽어 (1) 계약 위반을 잡고 (2) 3군 커버리지를
집계하고 (3) P2/P1이 쓸 Target-호환 stub을 만든다.

inventory 는 **분류된 카탈로그**일 뿐, 어떤 앱을 쓸지 고르지 않는다. 앱이 실제로
빌드·기동되는지는 P2 가 전 레포에 health check 를 돌려 판정한다(그래서 status/priority
같은 선별 필드는 두지 않는다).

계약 근거: cowork_rule.md 3·5절, docs/handoffs/D1-P1.md
  - app `id` 는 contracts.schemas.Target.id 와 동일한 문자열이어야 한다.
  - inventory 의 focus 는 반드시 {idor, xss, injection} 의 부분집합.

CLI:
    python -m datasets.inventory              # 요약 표 출력
    python -m datasets.inventory --targets    # Target stub JSON 출력
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml

INVENTORY_PATH = Path(__file__).with_name("inventory.yaml")

# 고정 어휘 (inventory.yaml 헤더와 동일해야 함).
FOCUS_GROUPS = {"idor", "xss", "injection"}
VALID_ADAPTERS = {"node", "fastapi", "spring", "generic_docker"}


class InventoryError(ValueError):
    """inventory.yaml 이 공통 계약을 위반했을 때."""


@dataclass(frozen=True)
class AppEntry:
    id: str
    name: str
    repo_url: str
    stack: str
    adapter: str
    focus: tuple[str, ...]
    expected_vulns: tuple[str, ...]
    verify: bool
    notes: str = ""

    @classmethod
    def from_dict(cls, raw: dict) -> "AppEntry":
        missing = {"id", "name", "repo_url", "stack", "adapter", "focus"} - raw.keys()
        if missing:
            raise InventoryError(f"app {raw.get('id', '<no-id>')}: 필수 필드 누락 {sorted(missing)}")
        return cls(
            id=raw["id"],
            name=raw["name"],
            repo_url=raw["repo_url"],
            stack=raw["stack"],
            adapter=raw["adapter"],
            focus=tuple(raw["focus"]),
            expected_vulns=tuple(raw.get("expected_vulns", [])),
            verify=bool(raw.get("verify", False)),
            notes=(raw.get("notes") or "").strip(),
        )

    def to_target_stub(self) -> dict:
        """contracts.schemas.Target 로 채워질 필드의 초안(나머지는 P2가 채움).

        manifest_hash/source_commit/allowed_hosts 는 P2 manifest 확정 시 결정되므로
        여기서는 id·adapter 만 계약값으로 넘긴다.
        """
        return {"id": self.id, "adapter": self.adapter}


@dataclass
class Inventory:
    apps: list[AppEntry] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path = INVENTORY_PATH) -> "Inventory":
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        raw_apps = data.get("apps") or []
        apps = [AppEntry.from_dict(a) for a in raw_apps]
        inv = cls(apps=apps)
        inv.validate()
        return inv

    def validate(self) -> None:
        seen: set[str] = set()
        for app in self.apps:
            if app.id in seen:
                raise InventoryError(f"중복 id: {app.id} (Target.id 는 유일해야 함)")
            seen.add(app.id)
            if app.id != app.id.lower() or " " in app.id or "_" in app.id:
                raise InventoryError(f"{app.id}: id 는 소문자 kebab-case 여야 함")
            if app.adapter not in VALID_ADAPTERS:
                raise InventoryError(f"{app.id}: adapter '{app.adapter}' 는 {VALID_ADAPTERS} 중 하나여야 함")
            bad_focus = set(app.focus) - FOCUS_GROUPS
            if bad_focus:
                raise InventoryError(f"{app.id}: focus {sorted(bad_focus)} 는 {FOCUS_GROUPS} 부분집합이 아님")
            if not app.focus:
                raise InventoryError(f"{app.id}: focus 가 비어 있음 (3군 중 최소 1개)")

    def coverage(self, apps: list[AppEntry] | None = None) -> dict[str, list[str]]:
        """3군별로 그 취약점을 노리는 앱 id 목록."""
        apps = self.apps if apps is None else apps
        cov: dict[str, list[str]] = {g: [] for g in sorted(FOCUS_GROUPS)}
        for app in apps:
            for g in app.focus:
                cov[g].append(app.id)
        return cov


def _print_summary(inv: Inventory, apps: list[AppEntry]) -> None:
    by_adapter: dict[str, int] = {}
    for a in apps:
        by_adapter[a.adapter] = by_adapter.get(a.adapter, 0) + 1

    print(f"총 {len(apps)}개 앱\n")
    print(f"{'id':<34}{'adapter':<16}{'focus':<24}{'verify'}")
    print("-" * 82)
    for a in sorted(apps, key=lambda x: x.id):
        flag = "⚠ verify" if a.verify else ""
        print(f"{a.id:<34}{a.adapter:<16}{','.join(a.focus):<24}{flag}")

    print("\nadapter 분포:", ", ".join(f"{k}={v}" for k, v in sorted(by_adapter.items())))
    cov = inv.coverage(apps)
    print("3군 커버리지:")
    for g, ids in cov.items():
        print(f"  {g:<10} {len(ids)}개")


def main() -> None:
    parser = argparse.ArgumentParser(description="Target app inventory 로더/검증기")
    parser.add_argument("--targets", action="store_true", help="Target stub JSON 출력")
    args = parser.parse_args()

    inv = Inventory.load()

    if args.targets:
        print(json.dumps([a.to_target_stub() for a in inv.apps], ensure_ascii=False, indent=2))
        return

    _print_summary(inv, inv.apps)


if __name__ == "__main__":
    main()
