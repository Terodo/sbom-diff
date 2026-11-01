from __future__ import annotations

import dataclasses
import json

from sbom_diff.diff import DiffResult
from sbom_diff.model import Component


def _label(c: Component) -> str:
    return f"{c.name}@{c.version}" if c.version else c.name


def _versions(v: tuple[str, ...]) -> str:
    return ", ".join(x or "(none)" for x in v)


def to_text(result: DiffResult) -> str:
    if not result:
        return "No differences."
    lines = [f"+ {_label(c)}" for c in result.added]
    lines += [f"- {_label(c)}" for c in result.removed]
    lines += [
        f"~ {c.name}: {_versions(c.old_versions)} -> {_versions(c.new_versions)}"
        for c in result.changed
    ]
    return "\n".join(lines)


def to_markdown(result: DiffResult) -> str:
    if not result:
        return "No differences."
    out: list[str] = []
    if result.added:
        out += ["### Added", *(f"- `{_label(c)}`" for c in result.added), ""]
    if result.removed:
        out += ["### Removed", *(f"- `{_label(c)}`" for c in result.removed), ""]
    if result.changed:
        out += [
            "### Changed",
            "| Component | Old | New |",
            "|---|---|---|",
            *(
                f"| `{c.name}` | {_versions(c.old_versions)} "
                f"| {_versions(c.new_versions)} |"
                for c in result.changed
            ),
            "",
        ]
    return "\n".join(out).rstrip()


def to_json(result: DiffResult) -> str:
    return json.dumps(dataclasses.asdict(result), indent=2)
