from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sbom_diff.model import Sbom
from sbom_diff.parsers import cyclonedx, spdx


class SbomParseError(ValueError):
    """Input is not a supported SBOM."""


def loads(data: dict[str, Any]) -> Sbom:
    """Parse an already decoded SBOM document, autodetecting the format."""
    if data.get("bomFormat") == "CycloneDX":
        return cyclonedx.parse(data)
    if str(data.get("spdxVersion", "")).startswith("SPDX-2"):
        return spdx.parse(data)
    raise SbomParseError("unsupported SBOM: expected CycloneDX JSON or SPDX 2.x JSON")


def load(path: str | Path) -> Sbom:
    """Read an SBOM file (JSON), autodetecting the format."""
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise SbomParseError(f"{path}: invalid JSON: {e}") from e
    if not isinstance(data, dict):
        raise SbomParseError(f"{path}: expected a JSON object")
    try:
        return loads(data)
    except (KeyError, TypeError) as e:
        raise SbomParseError(f"{path}: malformed SBOM ({e!r})") from e
    except SbomParseError as e:
        raise SbomParseError(f"{path}: {e}") from e
