# Verifying a Keyorix release

Use this before you install or upgrade, and again whenever you mirror a release into
your own registry. It answers four questions with tools you control: is this the
release Keyorix published, was it built by Keyorix's release pipeline from the tagged
commit, does it carry the SBOMs and attestations it should, and did it pass the
vulnerability gate before it was tagged.

Everything here needs **read access only**. No registry login, no GitHub token, nothing
is installed or modified on the system being checked.

## What a release contains

| Artifact | Where | Signed / attested by |
|----------|-------|----------------------|
| 14 binaries: `keyorix`, `keyorix-server`, `keyorix-migrate` (linux and darwin, amd64 and arm64) and `keyorix-server-airgap` (linux only) | GitHub Release | listed in `checksums.txt`; SLSA provenance (GitHub attestation) names all 14 |
| 15 CycloneDX SBOMs (`<binary>_sbom.cdx.json`, plus one shared `keyorix-server_frontend_sbom.cdx.json`) | GitHub Release | listed in `checksums.txt` |
| `checksums.txt`, `checksums.txt.sig`, `checksums.txt.pem` | GitHub Release | cosign keyless signature by `release.yml` at the tag |
| 6 container images: `keyorix-server`, `keyorix-server` (`<version>-airgap` tag), `keyorix-k8s-sync`, `keyorix-operator`, `keyorix-mcp`, `keyorix-web` | `ghcr.io/keyorixhq/<name>` tagged `<version>` (no `v`) and `sha-<7 chars>` | cosign keyless signature by `docker-publish.yml` at the tag; BuildKit SPDX SBOM and provenance attestations inside the image index; GitHub SLSA attestation |
| 3 Helm charts: `keyorix`, `keyorix-k8s-sync`, `keyorix-operator` | `oci://ghcr.io/keyorixhq/charts/<name>`, version and appVersion both `<version>` | cosign keyless signature by `release.yml` at the tag |

Images are pushed by digest first, scanned (Trivy, HIGH and CRITICAL, fixed
vulnerabilities only, every published platform), attested and signed, and only then
tagged. **A version tag that exists on an image therefore means the scan gate passed.**
A missing tag means the pipeline stopped before tagging.

"Keyless" means there is no long-lived signing key. The certificate names the GitHub
Actions workflow that signed, for example
`https://github.com/keyorixhq/keyorix/.github/workflows/release.yml@refs/tags/v0.96.3`,
issued by `https://token.actions.githubusercontent.com`, and the signature is recorded
in the public Sigstore transparency log (Rekor).

## One command

```sh
scripts/release/verify-release.sh v0.96.3
```

The script is in the repository (and can be downloaded on its own from the tag). It
needs `curl`, `jq` and `sha256sum` (or `shasum`); `cosign`, `openssl` and `gh` make more
checks possible. It prints one line per check and a verdict:

```
PASS  release.checksums.binaries    all 14 binaries match checksums.txt
FAIL  image.web.tag                 ghcr.io/keyorixhq/keyorix-web:0.96.3 not found (HTTP 404) - ...
SKIP  release.signature.cosign      cosign not installed ...
```

| Exit code | Meaning |
|-----------|---------|
| 0 | every check passed |
| 1 | at least one check **FAILED**: do not deploy until each FAIL is explained |
| 2 | no failure, but some checks **could not run** (a tool or the network was missing). This is not a pass; install the tool or run the printed command elsewhere |
| 3 | usage error or a required tool is missing |

Useful options: `--registry HOST/PATH` (your mirror), `--assets-dir DIR` (release files
you already downloaded), `--skip-binaries` (skip the ~540 MB of binaries; SBOMs are still
checked), `--offline` (never call api.github.com), `--cosign-args "..."` (extra cosign
flags). `scripts/release/verify-release.sh --help` lists all of them.

## The same checks by hand

Set the version once:

```sh
TAG=v0.96.3; VER=${TAG#v}
ID=https://github.com/keyorixhq/keyorix/.github/workflows
ISS=https://token.actions.githubusercontent.com
```

**1. Release files match the signed checksums.**

```sh
gh release download "$TAG" -R keyorixhq/keyorix        # or download from the Releases page
cosign verify-blob \
  --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity "$ID/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer "$ISS" checksums.txt
sha256sum -c checksums.txt        # macOS: shasum -a 256 -c checksums.txt
```

`checksums.txt` must list exactly 29 files (14 binaries, 15 SBOMs).

**2. Binary provenance (which workflow run built it, from which commit).**

```sh
gh attestation verify keyorix-server_linux_amd64 --repo keyorixhq/keyorix
```

**3. SBOMs.** Each is a CycloneDX JSON document:

```sh
jq '{format: .bomFormat, version: .specVersion, components: (.components | length)}' \
  keyorix-server_linux_amd64_sbom.cdx.json
```

**4. Images: tag, signature, SBOM, provenance.** Repeat for `keyorix-server` (also with
the tag `$VER-airgap`), `keyorix-k8s-sync`, `keyorix-operator`, `keyorix-mcp`,
`keyorix-web`:

```sh
IMG=ghcr.io/keyorixhq/keyorix-server
DIGEST=$(docker buildx imagetools inspect "$IMG:$VER" --format '{{.Manifest.Digest}}')
cosign verify \
  --certificate-identity "$ID/docker-publish.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer "$ISS" "$IMG@$DIGEST"
gh attestation verify "oci://$IMG@$DIGEST" --repo keyorixhq/keyorix
docker buildx imagetools inspect "$IMG:$VER" --format '{{ json .SBOM }}' | jq '.[] | .SPDX.packages | length'
docker buildx imagetools inspect "$IMG:$VER" --format '{{ json .Provenance }}' | jq 'keys'
```

Always verify the **digest**, then deploy that digest (or a tag you have confirmed
resolves to it).

**5. Helm charts.**

```sh
for c in keyorix keyorix-k8s-sync keyorix-operator; do
  helm show chart "oci://ghcr.io/keyorixhq/charts/$c" --version "$VER" | grep -E '^(name|version|appVersion):'
  cosign verify --certificate-identity "$ID/release.yml@refs/tags/$TAG" \
    --certificate-oidc-issuer "$ISS" "ghcr.io/keyorixhq/charts/$c:$VER"
done
```

`version` and `appVersion` must both equal `$VER`.

## What a failure means

| Check | A FAIL means | What to do |
|-------|--------------|-----------|
| `release.assets` | a file is missing, or an extra file is attached that `checksums.txt` does not cover | Do not install from this release. Report it; a missing file usually means the release job failed part-way |
| `release.checksums.*` | a downloaded file differs from the signed list | Re-download once over a trusted network. If it still differs, treat the file as tampered and do not run it |
| `release.signature.cosign` | the signature is not from Keyorix's release workflow at this tag, or the transparency-log entry is missing | Do not trust `checksums.txt`, so do not trust any file. Report it |
| `release.signature.cert` / `.offline` | the certificate names another workflow or tag, or `checksums.txt` was edited after signing | Same as above. These two run without cosign and without network |
| `release.sbom` | an SBOM is missing, empty or not CycloneDX | The release is incomplete for compliance use; report it |
| `release.provenance`, `image.*.slsa` | GitHub has no provenance for the file, or it names a different workflow, tag or digest | The artifact was not produced by the release pipeline, or the attestation step was skipped. Report it |
| `ci.*-run` | the release or image workflow did not finish successfully, or a scan, sign, tag or publish step did not succeed | Do not use artifacts from an unfinished pipeline |
| `image.*.tag` | the version tag does not exist | The image was never published, or the pipeline stopped at the vulnerability scan or signing step before tagging. Wait for a fixed release |
| `image.*.shatag` | the `sha-<7>` tag is missing or points to another digest than the version tag | The tags were assembled inconsistently; report it |
| `image.*.platforms` | the index lacks a platform (the full server, air-gapped server and web images are `linux/amd64` + `linux/arm64`) | You would get the wrong or no image on that CPU; report it |
| `image.*.sbom`, `image.*.buildkit-provenance` | the image index has no SPDX SBOM or provenance attestation for some platform | The image was built without attestations; report it |
| `image.*.signature`, `chart.*.signature` | no valid signature from `docker-publish.yml` / `release.yml` at this tag for that digest | Do not deploy that digest. If you mirrored the image, check that the signature was copied too (see below) |
| `chart.*.version` | the chart's name, version or appVersion is not the release | Do not install that chart |

A **SKIP** is never a pass. Each SKIP line says what could not run and prints the exact
command to run somewhere that can.

## Air-gapped or mirrored registries

Nothing needs the public internet except fetching the release once. The idea: verify on
a connected host, copy the verified artifacts **together with their signatures** into
your registry, then re-run the check against the mirror from inside the isolated network.

**On a connected host**

```sh
TAG=v0.96.3; VER=${TAG#v}; MIRROR=registry.internal.example:5000/keyorix
mkdir release && cd release
gh release download "$TAG" -R keyorixhq/keyorix
../scripts/release/verify-release.sh "$TAG" --assets-dir "$PWD"    # full check against ghcr.io first
```

Copy images and charts by digest, with their signatures and attestations. `cosign copy`
copies an image together with its cosign signature and attestations; `crane copy` and
`skopeo copy --all` copy the multi-arch index (and its BuildKit attestation manifests)
but **not** the `sha256-<digest>.sig` signature tag, so copy that one as well:

```sh
for img in keyorix-server keyorix-k8s-sync keyorix-operator keyorix-mcp keyorix-web; do
  cosign copy "ghcr.io/keyorixhq/$img:$VER" "$MIRROR/$img:$VER"
done
cosign copy "ghcr.io/keyorixhq/keyorix-server:$VER-airgap" "$MIRROR/keyorix-server:$VER-airgap"
for c in keyorix keyorix-k8s-sync keyorix-operator; do
  helm pull "oci://ghcr.io/keyorixhq/charts/$c" --version "$VER"
  helm push "$c-$VER.tgz" "oci://$MIRROR/charts"
  cosign copy "ghcr.io/keyorixhq/charts/$c:$VER" "$MIRROR/charts/$c:$VER"
done
```

Also carry across: the `release/` directory (all 32 files) and, for offline signature
verification, a Sigstore trust root (next section). Mirrored copies keep the original
digests, so the signatures and the GitHub attestations (which are keyed by digest) still
apply to them.

**Inside the isolated network**

```sh
scripts/release/verify-release.sh "$TAG" \
  --registry "$MIRROR" --assets-dir ./release --offline \
  --cosign-args "<offline options below>"
```

`--registry` points images and charts at the mirror (add `--plain-http` for an http-only
mirror; `REGISTRY_USER` / `REGISTRY_PASSWORD` if it needs read credentials). With
`--offline` the checks that need api.github.com (workflow-run evidence, GitHub SLSA
attestations, the `sha-<7>` tag unless you also pass `--commit <sha>`) are reported as
SKIP, so the verdict is INCOMPLETE (exit 2) unless you add `--allow-skip`. Do that only
if you accept that those checks ran on the connected host.

**Signature checks without the internet.** cosign normally fetches the Sigstore trust
root over the network and looks the signature up in Rekor. Offline you have two options,
strongest first:

1. Initialise cosign from a trust root you transferred and verify using the transparency
   entry embedded in the signature (`cosign initialize --mirror <url> --root <root.json>`
   once, then `--cosign-args "--offline"`). Image signatures carry that embedded entry;
   `checksums.txt.sig` does not (see below).
2. If the embedded entry is not available, `--cosign-args "--insecure-ignore-tlog=true"`
   still checks the certificate chain and identity but **not** that the signature was
   publicly logged. Record that you did this.

Two checks never need cosign, the network or a trust root, and run even on the most
restricted host: `release.signature.cert` (the certificate names the right workflow and
tag) and `release.signature.offline` (the signature matches the certificate's key over
`checksums.txt`). They do not prove the certificate chains to Sigstore, which is why they
are reported as partial; use them together with option 1 or 2, not instead of them.

Offline flags vary between cosign versions. Confirm the combination you intend to use
against a known-good tag in your environment before you rely on it for a release you have
not seen before.

## Limits of this check

- It proves provenance and integrity, not safety. It does not scan for vulnerabilities
  (the pipeline's Trivy gate does, and the script checks that the gate ran and passed).
- Evidence that comes from GitHub (workflow runs, attestations) is only as trustworthy
  as GitHub; the cosign and openssl checks do not depend on it.
- The script knows the expected file and image lists for the current release layout. If
  a release legitimately adds an artifact, the script reports it as `unexpected` until it
  is updated; that is deliberate, because an attachment not covered by `checksums.txt`
  is exactly what an attacker would add.
