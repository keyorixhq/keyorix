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

## Tools

| Tool | Version | Needed for |
|------|---------|-----------|
| `curl`, `jq`, `sha256sum` (macOS: `shasum`) | any | the script itself, checksums |
| **`cosign`** | **>= 3** (3.0.6 was used for the v0.96.3 images and charts) | image and chart signatures (steps 4 and 5); also verifies `checksums.txt` (step 1) |
| `openssl` | any recent | the two partial signature checks that need no network |
| `gh` (logged in) | any recent | `gh attestation verify` (step 2, step 4); the script SKIPs without it |
| `oras` | >= 1.2 | copying images and charts into a mirror **with their signatures** (see the mirror section) |
| `docker buildx` | any recent | `imagetools inspect` (step 4) |

**Why cosign >= 3.** The release pipeline signs with two different cosign versions:

| Signed object | Signed by | Where the signature lives | Verifiable with |
|---------------|-----------|---------------------------|-----------------|
| `checksums.txt` (`.sig` + `.pem` assets) | cosign **2.5.2**, pinned in `release.yml` (cosign 3.1 changed the `sign-blob` flags) | two release assets | cosign 2.x **and** 3.x |
| 6 images, 3 Helm charts | cosign **3.x** (the `sigstore/cosign-installer` default; 3.0.6 for v0.96.3) | an **OCI referrer** next to the image (new Sigstore bundle format), not a `sha256-<digest>.sig` tag | **cosign >= 3 only** |

cosign 2.x looks for the old `.sig` tag, finds none and prints `Error: no signatures found`
for a perfectly good image. That message from cosign 2.x says nothing about the release.
`verify-release.sh` detects the cosign version: with cosign < 3 it still verifies
`checksums.txt`, but reports the nine image and chart signature checks as **SKIP**
("cosign ... is too old to see referrer signatures ... install cosign >= 3"), never as FAIL,
and exits 2.

## One command

```sh
scripts/release/verify-release.sh v0.96.3
```

The script is in the repository (and can be downloaded on its own from the tag). It
needs `curl`, `jq` and `sha256sum` (or `shasum`); `cosign` (>= 3), `openssl` and `gh` make
more checks possible. It prints one line per check and a verdict:

```
PASS  release.checksums.binaries    all 14 binaries match checksums.txt
FAIL  image.web.tag                 ghcr.io/keyorixhq/keyorix-web:0.96.3 not found (HTTP 404) - ...
SKIP  release.signature.cosign      cosign not installed ...
```

| Exit code | Meaning |
|-----------|---------|
| 0 | every check passed |
| 1 | at least one check **FAILED**: do not deploy until each FAIL is explained |
| 2 | no failure, but some checks **could not run** (a tool, a tool version or the network was missing, or the GitHub API rate limit was reached). This is not a pass; install the tool or run the printed command elsewhere |
| 3 | usage error or a required tool is missing |

Useful options: `--registry HOST/PATH` (your mirror), `--assets-dir DIR` (release files
you already downloaded), `--skip-binaries` (skip the ~540 MB of binaries; SBOMs are still
checked), `--offline` (never call api.github.com), `--cosign-args "..."` (extra cosign
flags). `scripts/release/verify-release.sh --help` lists all of them.

The GitHub API allows 60 anonymous requests per hour per IP address and one full run uses
about 12. When the limit is reached the affected checks are reported as SKIP ("GitHub API
rate limit reached"), not FAIL; set `GITHUB_TOKEN` (any token, no scopes) or wait, and
re-run.

## The same checks by hand

Check first that you have **cosign >= 3** (`cosign version`); see [Tools](#tools). Set the
version once:

```sh
TAG=v0.96.3; VER=${TAG#v}
ID=https://github.com/keyorixhq/keyorix/.github/workflows
ISS=https://token.actions.githubusercontent.com
```

**1. Release files match the signed checksums.**

```sh
gh release download "$TAG" -R keyorixhq/keyorix        # or download from the Releases page
# cosign >= 3 (cosign 2.x also verifies this one file; it cannot see the image signatures of steps 4 and 5)
cosign verify-blob \
  --certificate checksums.txt.pem --signature checksums.txt.sig \
  --certificate-identity "$ID/release.yml@refs/tags/$TAG" \
  --certificate-oidc-issuer "$ISS" checksums.txt
sha256sum -c checksums.txt        # macOS: shasum -a 256 -c checksums.txt
```

`checksums.txt` must list exactly 29 files (14 binaries, 15 SBOMs). This command needs
network access to the Sigstore services (trust root and transparency log); see the
air-gapped section for what you can do without.

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
# cosign >= 3 is required: the signature is an OCI referrer; cosign 2.x answers "no signatures found"
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
# cosign >= 3 is required here as well (referrer signature)
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
| `image.*.signature`, `chart.*.signature` | no valid signature from `docker-publish.yml` / `release.yml` at this tag for that digest | Do not deploy that digest. If you mirrored the image, check that the signature was copied too (`cosign copy` and `crane copy` do **not** copy it; use `oras cp -r`, see below). With cosign < 3 these checks are SKIPped, not FAILed (see [Tools](#tools)) |
| `chart.*.version` | the chart's name, version or appVersion is not the release | Do not install that chart |

A **SKIP** is never a pass. Each SKIP line says what could not run and prints the exact
command to run somewhere that can.

## Air-gapped or mirrored registries

The idea: verify on a connected host, copy the verified artifacts **together with their
signatures** into your registry, then check the mirror from inside the isolated network.
Read the limits first; they decide what "verified" can mean inside.

**What works without the internet today, and what does not**

| Works with no network | Does not work with no network today |
|-----------------------|-------------------------------------|
| `release.checksums.*` (every file against `checksums.txt`), `release.assets`, `release.sbom` | **Verifying the signature of `checksums.txt` with cosign.** Neither `--offline` nor `--insecure-ignore-tlog=true` makes this work (details below) |
| `release.signature.cert` (PARTIAL: the certificate *claims* the right workflow and tag) and `release.signature.offline` (the signature matches the certificate's key over `checksums.txt`, checked with `openssl`). Neither proves who signed | Anything that calls api.github.com: workflow-run evidence, GitHub SLSA attestations, binary provenance (SKIPped with `--offline`) |
| On a mirror: `image.*.tag`, `.platforms`, `.sbom`, `.buildkit-provenance`, `chart.*.version` (registry content only) | cosign verification of image and chart signatures: it needs a Sigstore trust root; this guide has **not** tested a transferred-trust-root flow, so treat it as unavailable |

`release.signature.cert` and `.offline` are reported as PARTIAL, consistency only. **Without
cosign they prove nothing about who signed.** They show what the certificate *claims* (the
workflow and the issuer) and that the signature matches the certificate's own key. Anyone can
make a self-signed certificate that claims the release workflow and sign forged files with
it, and both checks pass. Only cosign checks that the certificate chains to Sigstore's Fulcio
and that the signature was publicly logged. For that reason the script never lets a SKIPped
cosign signature check count as verified: `--allow-skip` does not cover it, and the exit
code stays 2 (INCOMPLETE).

**`--insecure-ignore-tlog` does not verify `checksums.txt` offline.** The signature in
`checksums.txt.sig` was made with a Fulcio certificate that is valid for only ten minutes.
Verifying it later needs proof that it was made while the certificate was valid, which is
a signed timestamp from the Rekor transparency log. `checksums.txt.sig` and `.pem` do not
carry that proof, so cosign must either ask Rekor (network) or fail: with
`--insecure-ignore-tlog=true` and a complete local trust root the result is
`expected a signed timestamp to verify an expired certificate`. Without a local trust root
cosign also tries to download one and fails earlier. `--offline` is deprecated in cosign 3
and does not help either. Tested on v0.96.3 with cosign 2.5.2 and 3.0.6 in an empty
network namespace: every variant fails.

**Fully offline verification of `checksums.txt` needs a Sigstore bundle**
(`checksums.txt.bundle`: signature, certificate and the Rekor entry in one file). The
release pipeline does not publish one yet (tracked as RC-ARTIFACTS-1 gap 1). Until it
does, the strongest offline statement is: *I verified the full cosign signature on a
connected host, and the files here match the `checksums.txt` that run verified*. The two
partial checks add nothing to that on their own. Do the connected-host run (below), keep its output, and compare the
digests it prints with the ones the isolated run prints.

**On a connected host**

```sh
TAG=v0.96.3; VER=${TAG#v}; MIRROR=registry.internal.example:5000/keyorix
SRC=ghcr.io/keyorixhq
mkdir release && cd release
gh release download "$TAG" -R keyorixhq/keyorix
../scripts/release/verify-release.sh "$TAG" --assets-dir "$PWD" | tee ../verify-connected.txt   # needs cosign >= 3
COMMIT=$(gh api "repos/keyorixhq/keyorix/commits/$TAG" --jq .sha); SHA7=${COMMIT:0:7}         # the commit the tag points to
```

**Copy images and charts with a referrer-aware tool.** The cosign 3 signature and the
GitHub SLSA attestation of an image are OCI *referrers*: separate manifests that point at
the image digest. A copy must carry them, and it must keep the digest (the signature is
over the digest). Tested on v0.96.3, with the results on a local `registry:2`:

| Copy method | Digest kept | Signature (referrer) copied | `cosign verify` on the copy |
|-------------|-------------|-----------------------------|------------------------------|
| `oras cp -r` (oras 1.2.3) | yes | **yes** | **OK** (images, multi-arch image, chart) |
| `cosign copy` (3.0.6) | yes | **no** | `no signatures found` |
| `crane copy` (0.20.6) | yes | **no** | `no signatures found` |
| `helm pull` + `helm push` (charts) | **no** (new digest) | no | cannot apply: the digest is different |

`skopeo copy --all` was not tested; do not use a tool for mirroring until `cosign verify`
passes on its output. The guide previously said `cosign copy` copies signatures and that
mirrored copies keep their digests; both are wrong for these releases.

Use `oras cp -r` (`-r` copies the referrers). One command copies the version tag **and**
the `sha-<7>` tag, so `verify-release.sh --commit` can check both:

```sh
for img in keyorix-server keyorix-k8s-sync keyorix-operator keyorix-mcp keyorix-web; do
  oras cp -r "$SRC/$img:$VER" "$MIRROR/$img:$VER,sha-$SHA7"
done
oras cp -r "$SRC/keyorix-server:$VER-airgap" "$MIRROR/keyorix-server:$VER-airgap,sha-$SHA7-airgap"
for c in keyorix keyorix-k8s-sync keyorix-operator; do
  oras cp -r "$SRC/charts/$c:$VER" "$MIRROR/charts/$c:$VER"
done
```

Add `--to-plain-http` for a mirror that speaks http, and `oras login "${MIRROR%%/*}"` first
if it needs credentials. The mirror must accept OCI artifacts with referrers; the local
`registry:2` used for the test (no OCI 1.1 referrers API) works. After copying, `oras
discover "$MIRROR/keyorix-k8s-sync:$VER"` must list a `application/vnd.dev.sigstore.bundle`
referrer, and `crane digest "$MIRROR/keyorix-k8s-sync:$VER"` must equal the digest printed by
the connected-host run. A chart is copied unchanged, so `helm pull` / `helm install` from
the mirror give exactly the signed chart.

**No network path between the two sides.** Copy to files, carry them across, copy into the
mirror (tested the same way: digests equal, `cosign verify` OK on the result):

```sh
# connected host
oras cp -r "$SRC/keyorix-k8s-sync:$VER" --to-oci-layout "layouts/keyorix-k8s-sync:$VER"    # one layout directory per artifact
oras cp -r "$SRC/charts/keyorix:$VER"   --to-oci-layout "layouts/chart-keyorix:$VER"
# isolated side, after carrying layouts/, release/ and verify-connected.txt across
oras cp -r --from-oci-layout "layouts/keyorix-k8s-sync:$VER" "$MIRROR/keyorix-k8s-sync:$VER,sha-$SHA7"
oras cp -r --from-oci-layout "layouts/chart-keyorix:$VER"    "$MIRROR/charts/keyorix:$VER"
```

Repeat for the other images (use a separate layout directory for the `-airgap` image).

**Inside the isolated network**

```sh
scripts/release/verify-release.sh "$TAG" \
  --registry "$MIRROR" --assets-dir ./release --offline --no-cosign \
  --commit "<the 40-character $COMMIT of the connected host; the source.commit line of verify-connected.txt>"
```

`--no-cosign` is deliberate: without network cosign fails on the trust root, and the
script would print a FAIL that says nothing about the release. With it, the signature
checks are SKIPped and the verdict is INCOMPLETE (exit 2), also with `--allow-skip`. That
exit 2 is expected here: the signatures were verified on the connected host, not inside.
Do not treat exit 0 as required, and do not script around the 2. `--registry` points images and charts
at the mirror (`--plain-http` for an http-only mirror; `REGISTRY_USER` /
`REGISTRY_PASSWORD` if it needs read credentials). `--commit` makes the `sha-<7>` tag check
run; **without `--commit`, that check is a SKIP**, which is the alternative if you did not
copy the `sha-<7>` tags. Offline, `source.commit` is a SKIP either way: with `--commit` it
says ASSERTED, because nothing inside can check the value you typed. On a connected host
the script compares `--commit` with the commit the tag points to and FAILs on a mismatch.

What this proves inside: the files match `checksums.txt`, the mirror holds the tags,
platforms and BuildKit SBOM/provenance attestations, and (compare the `image.*.tag` and
`chart.*.version` digests with `verify-connected.txt`) the mirrored digests are the ones
whose signatures you verified on the connected host. Trust in `checksums.txt` itself comes
**only** from the connected-host cosign run: compare `sha256sum checksums.txt` on both sides.
The `release.signature.cert` and `.offline` PASS lines inside do not prove who signed (a
self-signed certificate passes them). What it does not prove inside: who signed, the
Sigstore chain and the transparency-log entry, until `checksums.txt.bundle` is published.

Offline flags vary between cosign versions. Whatever you choose, confirm it against a
known-good tag in your environment before relying on it for a release you have not seen.

## Limits of this check

- It proves provenance and integrity, not safety. It does not scan for vulnerabilities
  (the pipeline's Trivy gate does, and the script checks that the gate ran and passed).
- Evidence that comes from GitHub (workflow runs, attestations) is only as trustworthy
  as GitHub; the cosign checks do not depend on it. The openssl checks do not depend on
  GitHub either, but they do not prove who signed (see above).
- The script knows the expected file and image lists for the current release layout. If
  a release legitimately adds an artifact, the script reports it as `unexpected` until it
  is updated; that is deliberate, because an attachment not covered by `checksums.txt`
  is exactly what an attacker would add.
