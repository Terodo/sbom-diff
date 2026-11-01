import json

import pytest

from sbom_diff import SbomParseError, diff, load, loads
from sbom_diff.cli import main


def cdx(*comps):
    return {
        "bomFormat": "CycloneDX",
        "metadata": {"component": {"name": "app"}},
        "components": [
            {"name": n, "version": v, "purl": f"pkg:pypi/{n}@{v}"} for n, v in comps
        ],
    }


def spdx(*comps):
    return {
        "spdxVersion": "SPDX-2.3",
        "documentDescribes": ["SPDXRef-root"],
        "packages": [{"SPDXID": "SPDXRef-root", "name": "app"}]
        + [
            {
                "SPDXID": f"SPDXRef-{n}",
                "name": n,
                "versionInfo": v,
                "externalRefs": [
                    {"referenceType": "purl", "referenceLocator": f"pkg:pypi/{n}@{v}"}
                ],
            }
            for n, v in comps
        ],
    }


def test_added_removed_changed():
    result = diff(
        loads(cdx(("a", "1"), ("b", "1"), ("c", "1"))),
        loads(cdx(("a", "1"), ("b", "2"), ("d", "1"))),
    )
    assert [c.name for c in result.added] == ["d"]
    assert [c.name for c in result.removed] == ["c"]
    assert [(c.name, c.old_versions, c.new_versions) for c in result.changed] == [
        ("b", ("1",), ("2",))
    ]


def test_cross_format_identical():
    assert not diff(loads(cdx(("a", "1"))), loads(spdx(("a", "1"))))


def test_nested_cyclonedx():
    doc = cdx(("a", "1"))
    doc["components"][0]["components"] = [{"name": "n", "version": "1"}]
    assert {c.name for c in loads(doc).components} == {"a", "n"}


def test_unsupported():
    with pytest.raises(SbomParseError):
        loads({"foo": 1})


def test_cli(tmp_path, capsys):
    old, new = tmp_path / "o.json", tmp_path / "n.json"
    old.write_text(json.dumps(cdx(("a", "1"))))
    new.write_text(json.dumps(cdx(("a", "2"))))
    assert main([str(old), str(new)]) == 1
    assert "~ a: 1 -> 2" in capsys.readouterr().out
    assert main([str(old), str(old)]) == 0
    assert main([str(old), str(tmp_path / "missing.json")]) == 2
    assert load(old).format == "CycloneDX"
