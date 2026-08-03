# ADR-070: Frontend monorepo consolidation (`keyorix-web` → `web/`)

## Status

Accepted.

## Context

`keyorix-web` (the dashboard) has shipped as a separate repository since its
creation. That split assumed the frontend would develop on its own cadence,
independently reviewable and releasable from the backend. It hasn't.

**Cadence.** Over the last 90 days, `keyorix-web` had commits on 33 distinct
calendar days (407 commits total). Every one of those 33 days — 33 of 33,
100% — also had at least one `keyorix` backend commit (1,359 commits total
across 56 active backend days in the same window). There is no day where the
frontend moved and the backend didn't. The independent-cadence assumption the
split was built on does not hold and, on the evidence of the last 90 days,
never has in any way that shows up in the commit record.

**Defects the split has shipped**, each verified directly against the current
state of both repos before writing it down here:

- **The pinned web image cannot resolve.** `docker-compose.yml` pins
  `ghcr.io/keyorixhq/keyorix-web:v0.88.0` (line 56), matching the backend's
  `keyorix-server:v0.88.0` pin (line 26) on the assumption that the two track
  the same version. They don't. `keyorix-web`'s only tag, ever, is `v0.2.0`
  (`git tag -l`), and its `docker-publish.yml` triggers on `push: tags:
  ['v*']` and derives the published image tag via
  `type=semver,pattern={{version}}` from that same pushed tag — there is no
  mechanism, today, by which a `v0.88.0` image could exist. Anyone who runs
  `docker compose up` against the pinned versions gets an image pull failure.
- **Released server binaries do not embed the dashboard.** `Makefile`'s
  `release` target (line 90) cross-compiles `keyorix`/`keyorix-server` for
  four platforms directly via `go build ./server` — it has no dependency on
  `build-ui`, so `server/webui/dist/` still holds whatever was last committed
  (the tracked placeholder `index.html`) at the moment `release` runs.
  `.github/workflows/release.yml`, which invokes `make release` on every
  `vX.Y.Z` tag push, has no pnpm/Node.js setup step anywhere in the file —
  there is no code path in the released-binary pipeline that could produce a
  dashboard-embedding build even if `release` did depend on `build-ui`. Every
  published `keyorix-server_*` release binary to date embeds the placeholder
  page (which candidly says so: "This build does not bundle the web
  dashboard"), not the real UI.
- **What `build-ui` does produce is not reproducible from a tag.**
  `KEYORIX_WEB_DIR ?= ../keyorix-web` (`Makefile` line 46) makes the one
  local path that *does* build the dashboard a function of whatever commit
  happens to be checked out in an unversioned sibling directory on the
  machine running `make build-ui` — not a function of the `keyorix` tag or
  commit being built. `release`'s own cross-compile flags
  (`-trimpath`, and `LDFLAGS` embedding only version/commit/trust-key
  metadata, no build timestamp) show a deliberate intent that the same input
  commit always produces the same output bytes. `KEYORIX_WEB_DIR` breaks that
  for the one artifact (the embedded dashboard) that most needs it, since the
  air-gap "single binary" deployment model this repo targets depends on the
  binary being exactly reproducible from source.

**The CRA/DORA rationale.** ADR-067 (release lifecycle, LTS designation and
support periods — accepted, not yet merged to `main` as of this writing)
defines a **designated release** as a single tagged artifact bundle: a
Declaration of Conformity, a signed ADR-064 update bundle, an SBOM, and a VEX
document, all attached to one `vX.Y.Z` tag, carrying a declared multi-year
security-support commitment. `keyorix-web` has its own, independent tag and
release lifecycle — one tag (`v0.2.0`) ever cut, its own `docker-publish.yml`
(cosign-signs the image keylessly, matching the backend's own signing
pattern) and its own `sbom.yml` (CycloneDX, gated on push-to-main or a GitHub
Release being published — the latter never happens, since nothing in
`keyorix-web` cuts GitHub Releases). None of that is wrong on its own terms,
but it is **entirely decoupled** from the backend's `v*`-tag-triggered
`release.yml`. A backend designated release, however carefully signed and
SBOM'd, cannot today — even in principle — produce a correspondingly
versioned, equally-covered dashboard artifact, because the two artifact
streams share no tag, no commit, and no release event. The support-period
promise ADR-067 makes about "the product" silently does not cover half of
what `docker-compose.yml` says the product is.

## Decision

Import `keyorix-web` into `keyorix` as a subdirectory at `web/`, via
`git subtree`, preserving history (subject to the DCO constraint recorded in
Phase 2 of the accompanying working notes — full history is not mergeable
as-is under this repo's DCO gate without an admin override, since none of
`keyorix-web`'s 421 commits carry a `Signed-off-by:` trailer and the DCO
check validates every individual commit in a PR's range, not a squashed
diff; that trade-off is decided separately, not by this ADR).

One repository. One `v*` tag triggers both the server release and the web
image build. One CI pipeline gates both. This is the only decision that
actually closes the three defects above: it makes "the same tag builds both"
true by construction instead of by convention two people have to remember to
keep in sync across two repos.

## Explicit non-decision

The SDK repositories (`keyorix-go`, `keyorix-node`, `keyorix-python`,
`keyorix-java`) and `keyorix-landing` are **not in scope** for this ADR and
are not folded into this monorepo by this decision. They have a genuinely
different release cadence (each versioned and published independently to its
own package registry — npm, PyPI, Maven, Go modules — on its own schedule,
decoupled from `keyorix` server releases by design, per each SDK's own
versioning story), unlike the dashboard, which has shipped in lockstep with
backend changes as its only real pattern. Any future consolidation instinct
should treat that difference as the actual test, not as a reason to sweep
these in as an afterthought.

## Consequences

- `web/.github/workflows/*` (six files: `ci.yml`, `codeql.yml`,
  `dependency-review.yml`, `docker-publish.yml`, `sbom.yml`,
  `sonarcloud.yml`) land at a path GitHub Actions never reads. Each must be
  folded into a root workflow, promoted to its own path-filtered root
  workflow, or dropped as redundant — decided file-by-file in the
  implementation phase, not blanket.
- Two SonarCloud projects (one per repo today) now describe one repository.
  They must be reconciled — monorepo multi-module configuration, or retiring
  one project — before `web/`'s Sonar config can be trusted; this ADR does
  not pre-decide which.
- `codeql.yml` gates Go today. It must gain the JavaScript/TypeScript
  language, or `web/`'s application code ships with no static analysis
  coverage at all going forward.
- `docker-compose.yml` and `deploy/helm/keyorix/values.yaml`'s version pins
  need to move to tracking one tag for both images — the direct fix for the
  first defect above.
- `make release` needs to depend on `build-ui` — the direct fix for the
  second defect above.
