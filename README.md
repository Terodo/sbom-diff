# sbom-diff

Python library (plus thin CLI) to compare SBOMs. Supports CycloneDX JSON and SPDX 2.x JSON; format is autodetected.

```python
from sbom_diff import diff, load

result = diff(load("old.cdx.json"), load("new.spdx.json"))
result.added, result.removed, result.changed
```

```sh
sbom-diff old.json new.json --format markdown   # text | markdown | json
```

Exit code: 0 identical, 1 differences, 2 error.

Components are matched by purl (without version/qualifiers), falling back to `group/name`.
