### Security
- **Image and dependency bumps for the nightly trivy gate.** `golang.org/x/net` is now v0.62.0 in the root module, `operator/` and `migrate/` (CVE-2026-78661, HIGH, `x/net/html` denial of service), which clears the finding in the server, airgap and operator images. The web image's `apk add --upgrade` floors gain `brotli-libs>=1.2.1-r0` (CVE-2026-111497, CRITICAL), `curl` and `libcurl>=8.23.0-r0` (CVE-2026-92392) and `musl-utils>=1.2.6-r3` (CVE-2026-107891), and the floor list is now sorted by package. The nightly `docker-publish` trivy gate, which has failed on main since 2026-11-02, is expected to pass after this merges; that is confirmed only by the next nightly run.

### Testing
- **Web image floors are checked in PR CI.** `deploy/web_dockerfile_floors_test.go` fails a malformed (unquoted, exact-pinned or release-less) or unsorted floor in `web/Dockerfile`'s `apk add --upgrade` line, instead of the nightly trivy gate finding it a day later.
