# Releasing Keyorix

Releases are automated: pushing a `vX.Y.Z` git tag is the only manual step. The
tag fires three workflows that publish everything a user consumes.

## Cut a release

1. Make sure `main` is green and `CHANGELOG.md` has an entry for the new version.
2. (If the chart changed) bump `version`/`appVersion` in
   `deploy/helm/keyorix/Chart.yaml`.
3. Tag and push:

   ```sh
   git checkout main && git pull
   git tag v0.3.0
   git push origin v0.3.0
   ```

That's it. Watch the runs under the repo's **Actions** tab.

## What the tag publishes

| Workflow | Trigger | Output |
|----------|---------|--------|
| `release.yml` → `build-and-release` | `v*` tag | CLI + server binaries for linux/darwin × amd64/arm64 (`keyorix_<os>_<arch>`, `keyorix-server_<os>_<arch>`), one CycloneDX SBOM per binary (`<binary_asset_name>_sbom.cdx.json`, 8 total) plus one shared, production-scope frontend SBOM (`keyorix-server_frontend_sbom.cdx.json`, linked from all four server SBOMs — ADR-073), `checksums.txt` covering all 17 files, and `checksums.txt.sig`/`.pem` (cosign keyless signature). All attached to the GitHub Release. |
| `release.yml` → `publish-chart` | `v*` tag | Helm chart pushed to `oci://ghcr.io/keyorixhq/charts` (chart + app version = the tag without the `v`). |
| `docker-publish.yml` | `v*` tag (and `main`) | `ghcr.io/keyorixhq/keyorix-server` image tagged with the semver version. |
| `docker-publish.yml` | `v*` tag (and `main`) | `ghcr.io/keyorixhq/keyorix-web` image tagged with the same semver version — same workflow run, same tag (ADR-070). |

The asset names produced by `make release` are exactly what `install.sh`
downloads — keep `make release`, `install.sh`, and any image references in sync.

## After the release — verify it's consumable

```sh
# CLI installer (latest)
curl -fsSL https://raw.githubusercontent.com/keyorixhq/keyorix/main/install.sh | sh
keyorix --version          # → the new version

# Helm chart from the OCI registry
helm show chart oci://ghcr.io/keyorixhq/charts/keyorix --version 0.3.0
```

## Versioning

Semantic Versioning. New user-facing features → minor; fixes → patch; breaking
changes → major. The CLI/server embed the version via `-ldflags` at build time
(`make release VERSION=<tag>`), so `keyorix --version` reports the tag.
