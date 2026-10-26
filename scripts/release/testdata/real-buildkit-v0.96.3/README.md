# Real BuildKit attestation of a published image (self-test fixture)

Captured anonymously from ghcr.io on 2026-10-23 (RC-FIX-3575-1), image
`ghcr.io/keyorixhq/keyorix-k8s-sync:0.96.3` (release v0.96.3, commit b9ef496):

| file | origin |
|---|---|
| `index.json` | the image index, verbatim (`sha256:bbdf72b5201db2c710c29bf62e9fe97e65519dae43b9a339601546f974d55404`) |
| `attestation-manifest.json` | the attestation manifest referenced by the index, verbatim (`sha256:862b7c3fa8f976eede22e72fbab7574fbd2262ab468df3d97222101fb526f494`). Layers: `https://spdx.dev/Document` and `https://slsa.dev/provenance/v1` |
| `provenance.blob.json` | the SLSA layer blob, verbatim (`sha256:75ca1aea6d23d9123609466e00dfad85e15be5311df9b30e10a315c947b5647b`) |
| `sbom.blob.trimmed.json` | the SPDX layer blob (`sha256:545eac42f314e153f360661f272b1215b641de7ef5470caf5eecb5fc78d72fcf`, 630 KB) with `files`, `packages`, `relationships`, `hasExtractedLicensingInfos` cut to their first 1-3 elements. All keys and nesting are unchanged; the digest therefore differs from the real layer digest |

`verify-release.sh --self-test` uses the manifest verbatim (the layer lookup is asserted against the
real layer digests) and, to serve a consistent registry, derives per-platform manifests from it by replacing
only the layer digests/sizes (the trimmed SBOM has another digest) and the `subject`.

Every one of the six v0.96.3 images (all platforms) has this layer layout, and so does keyorix-k8s-sync
0.87.0 through 0.89.0 (older tags carry no attestation manifest). `https://spdx.dev/Spdx` occurs in none of them.
