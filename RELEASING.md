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
| `release.yml` → `build-and-release` | `v*` tag | CLI + server binaries for linux/darwin × amd64/arm64 (`keyorix_<os>_<arch>`, `keyorix-server_<os>_<arch>`) + `checksums.txt`, attached to the GitHub Release. |
| `release.yml` → `publish-chart` | `v*` tag | Helm chart pushed to `oci://ghcr.io/keyorixhq/charts` (chart + app version = the tag without the `v`). |
| `docker-publish.yml` | `v*` tag (and `main`) | `ghcr.io/keyorixhq/keyorix-server` image tagged with the semver version. |

The asset names produced by `make release` are exactly what `install.sh`
downloads — keep `make release`, `install.sh`, and any image references in sync.

> The **web** image (`ghcr.io/keyorixhq/keyorix-web`) is published from the
> separate `keyorix-web` repository; tag it there too for a matching version.

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
