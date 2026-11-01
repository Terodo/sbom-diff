from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from sbom_diff.model import Component, Sbom


@dataclass(frozen=True, slots=True)
class ComponentChange:
    key: str
    name: str
    old_versions: tuple[str, ...]
    new_versions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DiffResult:
    added: tuple[Component, ...]
    removed: tuple[Component, ...]
    changed: tuple[ComponentChange, ...]

    def __bool__(self) -> bool:
        return bool(self.added or self.removed or self.changed)


def _group(sbom: Sbom) -> dict[str, list[Component]]:
    groups: dict[str, list[Component]] = defaultdict(list)
    for c in sbom.components:
        groups[c.key].append(c)
    return groups


def _versions(components: list[Component]) -> tuple[str, ...]:
    return tuple(sorted({c.version or "" for c in components}))


def diff(old: Sbom, new: Sbom) -> DiffResult:
    """Compare components of two SBOMs.

    Components are matched by `Component.key`, so a version bump is `changed`,
    not removed + added. A package present in several versions is compared as a set.
    """
    a, b = _group(old), _group(new)
    added = [c for k in sorted(b.keys() - a.keys()) for c in b[k]]
    removed = [c for k in sorted(a.keys() - b.keys()) for c in a[k]]
    changed = [
        ComponentChange(k, a[k][0].name, _versions(a[k]), _versions(b[k]))
        for k in sorted(a.keys() & b.keys())
        if _versions(a[k]) != _versions(b[k])
    ]
    return DiffResult(tuple(added), tuple(removed), tuple(changed))
