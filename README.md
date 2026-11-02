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

## Verifying releases

Release artifacts are built by the reusable workflow
[`build.yml`](.github/workflows/build.yml) and carry two GitHub attestations
(SLSA build provenance and a CycloneDX SBOM), plus the PyPI publish attestation.

```sh
pip download --no-deps --index-url https://test.pypi.org/simple/ sbom-diff -d dl
cd dl

# Verify build provenance against the expected builder workflow
gh attestation verify ./*.whl --repo Terodo/sbom-diff \
  --signer-workflow Terodo/sbom-diff/.github/workflows/build.yml

# Inspect the in-toto statements
gh attestation verify ./*.whl --repo Terodo/sbom-diff --format json \
  | jq '.[].verificationResult.statement'
gh attestation verify ./*.whl --repo Terodo/sbom-diff --format json \
  --predicate-type https://cyclonedx.org/bom | jq '.[].verificationResult.statement.predicate'

# Raw PEP 740 publish attestation
curl -s https://test.pypi.org/integrity/sbom-diff/<version>/<file>.whl/provenance | jq
```
