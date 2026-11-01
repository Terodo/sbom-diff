from __future__ import annotations

from typing import Any

from sbom_diff.model import Component, Sbom


def parse(data: dict[str, Any]) -> Sbom:
    """Parse CycloneDX JSON. The subject (`metadata.component`) is skipped."""
    components: list[Component] = []

    def walk(items: list[dict[str, Any]]) -> None:
        for item in items:
            components.append(
                Component(
                    name=item["name"],
                    version=item.get("version"),
                    purl=item.get("purl"),
                    group=item.get("group"),
                )
            )
            walk(item.get("components", []))

    walk(data.get("components", []))
    return Sbom(format="CycloneDX", components=tuple(components))
