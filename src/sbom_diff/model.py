"""Format-independent SBOM model."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class Component:
    name: str
    version: str | None = None
    purl: str | None = None
    group: str | None = None

    @property
    def key(self) -> str:
        """Identity of a component across versions.

        Uses the purl without version and qualifiers; falls back to group/name.
        """
        if self.purl:
            base = self.purl.split("#", 1)[0].split("?", 1)[0]
            return base.rsplit("@", 1)[0] if "@" in base else base
        return f"{self.group}/{self.name}" if self.group else self.name


@dataclass(frozen=True, slots=True)
class Sbom:
    format: str
    components: tuple[Component, ...] = field(default_factory=tuple)
