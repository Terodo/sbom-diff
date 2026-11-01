from __future__ import annotations

from typing import Any

from sbom_diff.model import Component, Sbom

_DOCUMENT_ID = "SPDXRef-DOCUMENT"


def _described_ids(data: dict[str, Any]) -> set[str]:
    ids = set(data.get("documentDescribes", []))
    for rel in data.get("relationships", []):
        if (
            rel.get("relationshipType") == "DESCRIBES"
            and rel.get("spdxElementId") == _DOCUMENT_ID
        ):
            ids.add(rel["relatedSpdxElement"])
    return ids


def parse(data: dict[str, Any]) -> Sbom:
    """Parse an SPDX 2.x JSON document. Packages the document describes are skipped."""
    described = _described_ids(data)
    components: list[Component] = []
    for pkg in data.get("packages", []):
        if pkg.get("SPDXID") in described:
            continue
        purl = next(
            (
                ref["referenceLocator"]
                for ref in pkg.get("externalRefs", [])
                if ref.get("referenceType") == "purl"
            ),
            None,
        )
        components.append(
            Component(name=pkg["name"], version=pkg.get("versionInfo"), purl=purl)
        )
    return Sbom(format="SPDX", components=tuple(components))
