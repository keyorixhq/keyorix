# ADR-073: Release SBOM coverage for the embedded frontend

## Status

Accepted. Phase 0 (verification) and Phase 1 (this ADR, through three rounds
of review) complete. Phase 2 (implementation) proceeds against this record.

## Context

**Scope, stated early because it makes the problem tractable and prevents a
future "fix" to something that isn't broken:** this ADR is about exactly one
distribution channel — `make release`'s cross-compiled binary tarballs, the
air-gapped single-binary deployment path. It is **not** about container
images. Verified directly, not assumed:

- `server/Dockerfile` builds `keyorix-server`'s container image via a plain
  `go build ./server`, with no `populate-webui-dist` step anywhere in its
  build — it embeds only the committed placeholder `index.html`. This is
  correct, by design: `docker-compose.yml` pairs an API-only `keyorix-server`
  container with a **separate** `keyorix-web` image (nginx-based, its own
  `docker-publish.yml` job, its own BuildKit `provenance: mode=max` /
  `sbom: true` attestation). Containerized deployments already have two
  inventories for two images, and that split is unaffected by anything below.
- Only `make release`'s binaries (and `make build-ui`) run
  `populate-webui-dist` before compiling, which is what makes the gap real
  for that one path and only that path.

Someone reading this ADR later and reaching for the container image's SBOM
pipeline to "fix" is solving a problem that does not exist there — the
container split already gives that path independent, correct coverage.

**When the gap opened, and why neither change that opened it was wrong.**
Two independently correct decisions interact into a gap:

- ADR-070 merged the frontend into this repo and made `server/webui/embed.go`
  (`//go:embed all:dist`) bake the real dashboard build into the
  `keyorix-server` binary via `make release: populate-webui-dist`. Before
  this merge, the release binary shipped a placeholder page, and a
  Go-only SBOM was an accurate description of what it contained.
- PR #1298 (merged today, a clean reimplementation of the `chore/dev-guidance`
  branch that sat unmerged for a month — see PROCESS.md) added
  `cyclonedx-gomod app` SBOM generation to `make release`, which reads the Go
  module graph exactly and correctly.

Both changes are correct in isolation. `cyclonedx-gomod` was never going to
see a `pnpm-lock.yaml` — that isn't a defect in the tool, it operates on the
Go module graph by design. The frontend merge made that graph an incomplete
description of the binary's actual contents. The gap opened at the
intersection, not in either change.

## Problem

CRA Annex I Part II expects an SBOM to describe the product as placed on the
market. `keyorix-server_sbom.cdx.json` currently describes only the Go module
graph, while the binary it's attached to also contains a full React SPA and
everything that went into building it. A customer running `grype` or
`govulncheck` against the release SBOM today gets a clean result for
components that are physically shipped in the binary — the SBOM
under-reports, which is the more dangerous direction of the two possible
errors here (the other being over-reporting, addressed below).

## The devDependency trap

A naive frontend SBOM is not simply "the missing half" — it actively
over-reports if generated carelessly. Verified via `pnpm list --json`
(exact counts, not estimated):

- **Production dependencies: 125**
- **Full tree (prod + dev): 478** — a 3.8x inflation if reported naively
- Confirmed concretely present in the full tree and absent from production:
  `eslint`, `vite`, `playwright`, `@playwright/test` — none of which ship in
  the built bundle, all of which would generate CVE findings a scanner has no
  business raising against this artifact.

Both directions are real inaccuracies. Under-reporting (today's state) hides
real exposure; over-reporting (a naive full-tree scan) manufactures fake
exposure and teaches whoever reads the SBOM to distrust it. Production-only
resolution is required, not a nice-to-have.

## Production-only mechanism — three options tested against real tool output

**Tooling choice first, since it constrains what "production-only" can even
mean:** `@cyclonedx/cyclonedx-npm` v6.0.0 fails outright against this project
(exit 254) — it shells out to `npm ls --json --long --all`, which cannot
interpret pnpm's `.pnpm` symlink store. `@cyclonedx/cdxgen` v12.8.2, run with
**no `--type` flag** (autodetection), correctly parses `pnpm-lock.yaml` for
full transitive resolution: 478 components, an exact match to the independent
`pnpm list` count. Forcing `--type npm` silently drops to a shallow,
package.json-direct-dependencies-only scan (47 components) with no error —
see "The `--type npm` trap" below.

cdxgen's own scope inference is not usable for the prod/dev split: its
`--required-only` flag returned 35 components, including `eslint` and three
eslint plugins — none of which are production dependencies. This is not a
minor calibration issue; it fails on the exact packages the devDependency
trap section above calls out. Three alternatives were built and tested
against the real files, not decided on documentation:

**1. Clean prod install, then scan.** `pnpm install --prod --frozen-lockfile`
into a scratch tree (confirmed: exactly 125 packages resolved, `127` entries
physically in `node_modules/.pnpm`), then ran cdxgen against that tree.
**Result: 478 components** — identical to the full-tree scan. cdxgen resolves
from `pnpm-lock.yaml`'s complete graph regardless of what's actually
installed on disk; it does not consult `node_modules` as ground truth. This
option does not work with this tool, full stop — not a matter of preference.

**2. Post-hoc filter.** Full 478-component SBOM filtered against
`pnpm list --prod --depth Infinity --json`'s package set (matched on
group+name+version, not name alone — scoped packages like `@radix-ui/*`
report `group`/`name` as separate JSON fields, and a naive name-only match
silently drops 73 of 125 production packages). Correctly matched: **exactly
125 kept, 353 dropped, 0 production packages unmatched.** Still schema-valid
after filtering. One real wrinkle, not cosmetic: filtering the `components`
array alone leaves the `dependencies` graph broken — 471 dangling
`dependsOn` references to removed components. Schema validation doesn't
catch this (dependency-graph referential integrity isn't schema-enforced),
but a consumer walking the graph would hit dead ends constantly. **Phase 2
must prune the `dependencies` array alongside `components`** — remove
dependency nodes for dropped components and strip dangling `dependsOn`
entries from the nodes that remain.

**3. Emit all 478, mark dev components `scope: excluded`.** Built this
exactly (125 `required`, 353 `excluded`) and tested it against `grype`
v0.116.1 rather than trusting documentation about scanner behavior. The real
dependency tree currently has zero known vulnerabilities at these exact
versions (confirmed the vulnerability DB itself was valid and current before
trusting that zero-match result), so it couldn't demonstrate scope handling
either way. Built a minimal synthetic BOM instead: one component,
`lodash@4.17.15` (known-vulnerable), marked `scope: excluded`. **grype
flagged it anyway — 6 GHSA advisories, full matches, scope field completely
ignored.** This is decisive, not a matter of principle: shipping `scope:
excluded` components reproduces the exact false-positive problem this ADR
exists to avoid, against a scanner in the same sentence as the ones named in
the Problem section.

**Decision: option 2, post-hoc filter.** Option 1 is disqualified by
tool behavior, not preference. Option 3 is disqualified by direct
measurement against a real scanner. Between the two live candidates the
choice was never really open once 1 failed — filtering is what's left. On
release-path robustness specifically: filtering fails loudly (a
count-mismatch check — see Phase 2 requirements — throws immediately if the
prod-set and cdxgen's output disagree on package identity, exactly the class
of bug the group/name mismatch above would have caused if shipped
unverified) rather than silently producing a wrong-but-plausible count.

## Honest limit: production-only is an approximation, not ground truth

Tree-shaking means not every one of the 125 production dependencies
necessarily reaches Vite's actual output bundle — some may be imported only
in code paths that get eliminated. The exact answer would come from
analyzing Vite's build output (e.g. a bundle-content report correlated back
to package boundaries) rather than the dependency tree. This was considered
and rejected for Phase 2: no existing tooling in this project's stack
produces that mapping today, and building it is a disproportionate lift for
this ADR's scope. **Reopening trigger:** if Vite or an ecosystem tool ships a
reliable bundle-to-package attribution report, revisit — production-only
dependency-tree resolution is the defensible approximation until then, not
the permanent answer.

## Four binaries, one Go SBOM — measured, then eliminated rather than documented

`make release` cross-compiles four `keyorix-server_*` binaries
(`linux_amd64`, `linux_arm64`, `darwin_amd64`, `darwin_arm64`) but generated
exactly one `keyorix-server_sbom.cdx.json` under PR #1298, via a single
`cyclonedx-gomod app` invocation with no `GOOS`/`GOARCH` override. Whether
that one SBOM is accurate for the other three binaries was checked directly:
ran `cyclonedx-gomod app -main server` under all four GOOS/GOARCH
combinations in the release matrix and diffed the component lists.

- **`linux/amd64` vs `linux/arm64`: identical.** 124 components each.
- **`darwin/amd64` vs `darwin/arm64`: identical.** 125 components each.
- **Linux vs Darwin: differ by 5 packages.** Linux-only:
  `github.com/prometheus/procfs`, `github.com/tklauser/numcpus`
  (procfs/CPU-count libraries, Linux-specific by nature). Darwin-only:
  `github.com/ebitengine/purego`, `github.com/mattn/go-isatty`,
  `github.com/ncruces/go-strftime` (darwin-side of a platform-conditional
  dependency, likely the CGO-free SQLite driver's per-OS implementation).
  Directionally mixed — the shared SBOM both omits 3 real Darwin
  dependencies and includes 2 that don't apply to Darwin builds at all.

**This does not require a macOS runner, and that was verified rather than
assumed** — the load-bearing question for whether per-platform generation is
even affordable in CI. `cyclonedx-gomod app` performs static, build-constraint-
aware module-graph resolution (the same mechanism `go build`'s own
cross-compilation uses), not execution on the target OS. Confirmed
concretely: generated the `darwin/arm64` SBOM two ways — natively on this
macOS host, and separately from inside a `golang:1.26.5` **Linux** container
(`docker run --platform linux/amd64`, matching `release.yml`'s
`ubuntu-latest` runner) with `GOOS=darwin GOARCH=arm64` set. **Identical
result: 125 components, exact match, from a host that has never run macOS.**
`release.yml` can generate all four server SBOMs — including both Darwin
ones — on its existing `ubuntu-latest` runner, no new runner class needed.

**CI cost, measured rather than guessed** (per-invocation timing, warm
module cache — the same cache state the `release` job already has after its
8 `go build` cross-compiles run earlier in the same job): three consecutive
`cyclonedx-gomod app` invocations timed at 6.04s, 5.77s, 5.48s. Going from 2
invocations (1 server + 1 CLI) to 8 (4 + 4) adds 6 invocations, roughly
**+36 seconds** to the release job. Recorded here as the actual number, not
an estimate, given the release pipeline's existing ~10% failure rate — this
is a small, known addition, not a blind trade of reliability for accuracy.

**Decision: eliminate the gap, don't document it.** Generate one Go SBOM per
binary — 8 total, not 2 — rather than recording "off by ~4% for two of four
binaries" as an accepted limitation. The measurement above is what
motivated the change; it is not a limitation this ADR ships with.

## Shape: merge into one file, or ship separate — tested, not decided on
preference

The instinct going in was to merge: the release tarball's `keyorix-server`
binary is one artifact, and a customer pointing a scanner at it should get
one inventory rather than needing to remember to check a second file. But
the container-image finding above (server and web already split into two
images with two independent SBOM stories) argues the opposite: mirroring
that existing split is consistent, and a merge tool might not actually
produce something coherent enough to justify breaking that consistency.
Tested `cyclonedx-cli merge` v0.33.1 both ways against the real files
(`keyorix-server_sbom.cdx.json`, 125 Go components; the filtered 125-component
JS SBOM):

- **Plain `merge`** (no flags): kept the first input file's `metadata.component`
  (`github.com/keyorixhq/keyorix`, the real Go module) as the nominal root —
  looks coherent at a glance. It isn't: the JS SBOM's own root component
  (`keyorix-web`, `type: application`) got dumped into the flat `components`
  array as if it were an ordinary dependency of the server, and the
  dependency graph confirms it's structurally orphaned — the real root's
  `dependsOn` lists 47 entries that do **not** include the JS tree; `keyorix-web`
  sits as a second, disconnected subtree with its own 15 `dependsOn` entries.
  Two roots, not one, with a cosmetic single-root header papering over it.
- **`--hierarchical --name keyorix-server --version vX.Y.Z`**: produces a
  clean tree with no orphans, but the root is a **synthetic wrapper** —
  `keyorix-server@vX.Y.Z` with no purl, not a real, independently verifiable
  package identity, just a label supplied via CLI flags. The actual Go module
  component (`github.com/keyorixhq/keyorix`) becomes a *nested child* of this
  invented root rather than being the root itself.

Neither mode produces "one binary, one inventory" — the actual binary's own
identity (the Go module component cyclonedx-gomod already generates
correctly) never ends up as the tree's root component in either mode.
**Decision: ship separate files, not merged** — real artifacts with real
identities, matching the container path's existing precedent, neither
requiring a merge step whose output would need its own disclaimer. This
finding stands unchanged by the per-binary reversal below; it settles "merge
or separate," not "how many files."

**`externalReferences` with `type: bom` closes the disconnection gap without
reviving merging.** Added an `externalReferences` entry (`type: bom`,
pointing at the frontend SBOM's filename, with a SHA-256 `hashes` entry — see
"Link integrity" below for why the hash is not optional) to a Go SBOM's
`metadata.component`, and tested the result two ways, hash included:

- **Schema validation**: the linked file, hash present, validates cleanly as
  CycloneDX 1.6 (checked against the official schema with `ajv-cli`, same
  method as every other validation in this ADR).
- **grype**: ran grype against the linked file, hash present. It processes
  without error and returns the same single match (`GO-2026-5932`,
  `golang.org/x/crypto` — a real, pre-existing finding, unrelated to this
  change) as the unlinked file — confirmed by running grype against both and
  diffing. The link adds zero new scan surface, which is exactly the
  expected/correct behavior: `externalReferences` is metadata about the
  document, not a scannable component.

**Adopted, and this is the clearest justification for the mechanism**: one
shared frontend SBOM, referenced from all four server Go SBOMs (see below),
no duplication. A consumer who downloads any one of the four
`keyorix-server_*` binaries and opens its SBOM is one field away from the
frontend inventory, without four copies of the same file.

**Link integrity: the `hashes` field is required, not decorative.** Every
other artifact adjacent to these SBOMs in the release is integrity-protected
— `checksums.txt` covers the binaries and the SBOMs themselves, cosign signs
the release. A `type: bom` reference with a bare `url` and no hash would be
the one unauthenticated pointer in the whole artifact set: a consumer
following it has no way to confirm the file they retrieved is the one this
ADR's tooling actually generated, rather than a substituted or stale one
sitting at the same filename. Verified this doesn't cost anything: the
schema-validation and grype checks above were run against the
hash-bearing version specifically, not a bare-`url` version — both pass
identically with the hash present, so there was no fallback case to record.

## Frontend SBOM stays one file — the embedded content doesn't vary by platform

The per-binary reversal above applies to the **Go** SBOMs, which genuinely
differ by `GOOS`. The frontend SBOM does not get the same treatment, and
that's a structural fact about the build, not a separate judgment call:
`populate-webui-dist` (Makefile) runs **once** per `make release` invocation
— `pnpm build` produces one `web/dist/`, copied once into
`server/webui/dist/` — and all four `GOOS`/`GOARCH` server builds embed that
same, already-built `dist/` via `go:embed`. There is no per-platform
frontend build step to diverge in the first place. One frontend SBOM
describing that one build output is exact, not an approximation like the
Go-SBOM-per-binary question was before today's fix.

**Filename** — interface, not an implementation detail, since it appears in
`checksums.txt` and as a release asset name: **`keyorix-server_frontend_sbom.cdx.json`.**
Considered and rejected: `keyorix-web_sbom.cdx.json` — this release matrix
ships no `keyorix-web` binary (that name belongs to the separate container
image, per the Context section's scope boundary); naming the file after a
binary that doesn't exist in this artifact set would misdirect anyone
scanning `checksums.txt`. Considered and rejected:
`keyorix-server-dashboard_sbom.cdx.json` — more explicit about content, but
breaks the existing `{binary}_sbom.cdx.json` pattern's prefix matching.
`keyorix-server_frontend_sbom.cdx.json` keeps the `keyorix-server_` prefix
(a companion inventory for that binary family, not a new artifact) and
sorts immediately adjacent to the four `keyorix-server_{os}_{arch}_sbom.cdx.json`
files in an alphabetically sorted `checksums.txt` or release asset list.

**Linked from all four**, not just one: each of
`keyorix-server_linux_amd64_sbom.cdx.json`,
`keyorix-server_linux_arm64_sbom.cdx.json`,
`keyorix-server_darwin_amd64_sbom.cdx.json`, and
`keyorix-server_darwin_arm64_sbom.cdx.json` carries the same
`externalReferences` (`type: bom`) entry pointing at
`keyorix-server_frontend_sbom.cdx.json`, hash included. Four referents, one
shared artifact, no duplication — the scenario the mechanism was built for.

**Build-order constraint, binding on Phase 2**: the frontend SBOM must be
generated, and its SHA-256 computed, **before** any of the four server Go
SBOMs are generated. Getting this backwards — generating the server SBOMs
first, or hashing the frontend file before it's in its final form — produces
a reference that validates cleanly (schema validation has no way to know the
hash is wrong or stale) while pointing at a hash that doesn't match the
actual shipped file, which is worse than no hash at all: it looks verified
and isn't. Phase 2's `release`/`sbom` Makefile targets must sequence
frontend-SBOM-generation-and-hashing strictly before the four
`cyclonedx-gomod app -main server` invocations. Phase 2's own verification
must assert this by recomputing the SHA-256 of the shipped
`keyorix-server_frontend_sbom.cdx.json` and comparing it against the hash
embedded in each of the four server SBOMs' `externalReferences` — asserting
the `hashes` field is merely *present* would pass a build-order bug
silently; asserting the values *match* would not.

## The `--type npm` trap must be documented at the call site

`cdxgen --type npm` against this pnpm project doesn't error — it silently
returns 47 components (package.json's direct dependencies only) instead of
478, with no warning that anything went wrong. This is exactly the kind of
mistake that happens while editing the Makefile, not while reading this ADR.
Phase 2 must add a comment directly next to the generation command, following
the existing convention (`cyclonedx-gomod`'s and cosign's pins both carry
explanatory comments in place already) — the ADR record alone does not help
someone mid-edit six months from now.

## Tooling pin

`@cyclonedx/cdxgen` pinned to **v12.8.2** (the version tested throughout this
ADR's verification), following the exact pattern already established for
`cyclonedx-gomod@v1.10.0` in `release.yml`, NOSONAR comment style included.

## The CLI SBOM is deliberately unchanged

Verified via `go list -deps .` against the CLI's root package (authoritative
— the actual Go build graph, not grep-inferred): `server/webui` does not
appear anywhere in it. The CLI binary does not embed the dashboard or any
other build output with its own dependency tree. It does embed one other
`go:embed` (`internal/i18n`'s `locales/*.json`), but that's authored JSON
data with no separate lockfile or dependency tree — not an SBOM gap. The
CLI's existing Go-only SBOM is already an accurate description of what it
contains. Changing it would be introducing the same class of error this ADR
exists to fix, in the opposite direction — over-reporting components that
were never shipped.

## This ADR also retroactively covers the Go SBOM decision

PR #1298 titled its work "per-binary CycloneDX SBOMs," but shipped
per-module: one `keyorix_sbom.cdx.json` for all four CLI binaries and one
`keyorix-server_sbom.cdx.json` for all four server binaries, not eight files.
That naming was aspirational, not yet accurate — true only in the narrow
sense that each binary *family* (CLI, server) got its own file, not each
binary. It landed today without an ADR of its own; rather than leave a hole
in the record where that original decision should be, this ADR covers the
release SBOM story as a whole. With the per-binary reversal above, the
"per-binary" name PR #1298 chose **becomes accurate rather than
aspirational** — eight Go SBOM files for eight binaries, matching what the
name always claimed.

## `make sbom` gets the same per-binary shape

Today, before this ADR, `make sbom` (the standalone, no-full-release target
for ad-hoc audits) and `make release` generate the Go SBOMs via identical
`cyclonedx-gomod` invocations — verified directly in the Makefile, lines
123-124 (`release`) match lines 135-136 (`sbom`) exactly. That parity is
worth preserving deliberately, not by accident: `sbom`'s own comment states
its purpose is "Feed to govulncheck/grype to answer 'are we affected by
CVE-X?' — the core CRA Article 14 question." That question applies exactly
as much to someone running `make sbom` for an ad-hoc audit as it does to a
tagged release. If the two targets diverged, an auditor running `make sbom`
would get a smaller or less accurate artifact set with no signal that
anything was missing — precisely the "silently missing SBOM is worse than a
broken build" failure mode this whole effort exists to avoid. **Decision:
`make sbom` generates the same eight per-binary Go SBOMs plus the one linked
frontend SBOM, keeping the two targets in the parity they already have.**

## Decision summary

1. Generate a frontend SBOM from `web/` via `cdxgen` v12.8.2, **no `--type`
   flag** (autodetection — forcing `npm` silently breaks pnpm resolution).
2. Filter to production scope by matching cdxgen's output against
   `pnpm list --prod --depth Infinity --json` on group+name+version, pruning
   both `components` and `dependencies` (removing dangling `dependsOn`
   entries) — not relying on cdxgen's own scope inference or the CycloneDX
   `scope` field for exclusion.
3. Generate **one Go SBOM per binary — 8 total**, not one per binary family —
   named `<binary_asset_name>_sbom.cdx.json` (e.g.
   `keyorix-server_darwin_arm64_sbom.cdx.json`), by running
   `cyclonedx-gomod app` once per `GOOS`/`GOARCH` in the release matrix.
   Verified this needs no macOS runner (Linux-container-generated and
   native-macOS-generated `darwin/arm64` SBOMs are byte-identical in
   component set) and costs roughly +36 seconds of CI time (measured, not
   estimated) over today's 2-invocation baseline.
4. Generate **one frontend SBOM**, not one per server binary — the embedded
   `dist/` is structurally identical across all four server builds
   (`populate-webui-dist` runs once per release). Ship as a **separate
   file**, named `keyorix-server_frontend_sbom.cdx.json` — `cyclonedx-cli
   merge` does not produce a coherent single-root result in either tested
   mode. Link it from **all four** server Go SBOMs via an
   `externalReferences` (`type: bom`) entry **with a SHA-256 `hashes`
   entry** (an unauthenticated pointer would be the one unverifiable
   artifact in a release where everything else is checksum- and
   cosign-covered), tested to validate as CycloneDX 1.6 and to add zero
   scan surface for grype with the hash present.
5. **Build order is binding**: the frontend SBOM must be generated and
   hashed *before* the four server Go SBOMs, so the embedded hash describes
   the real, final file rather than a stale or absent one. Phase 2's
   verification must recompute the frontend SBOM's SHA-256 and assert it
   matches the hash embedded in all four server SBOMs — not merely that the
   `hashes` field is populated, which would pass a build-order bug silently.
6. The CLI SBOMs are unchanged in content, deliberately, because they're
   already accurate — only their count changes (1 → 4, matching the 4 CLI
   binaries), not what they describe.
7. Comment the `--type npm` trap directly at the Makefile call site.
8. `make sbom` generates the same 8 Go SBOMs + 1 linked frontend SBOM as
   `make release`, preserving the parity the two targets already have.

## Consequences

- `make release`'s binary tarballs get accurate SBOM coverage matching what
  they actually contain, closing the CRA Annex I Part II gap for the
  air-gapped distribution path — the only path that was ever actually wrong.
- Container image SBOM coverage (both `keyorix-server` and `keyorix-web`) is
  explicitly out of scope and explicitly not broken — recorded here so it
  isn't "fixed" again later by someone who didn't re-derive this.
- The cross-BOM link is integrity-protected like everything else in the
  release, not a bare pointer: each of the four server SBOMs' `bom`-type
  `externalReferences` entry carries the frontend SBOM's SHA-256, and the
  Makefile sequencing (frontend generated and hashed first) plus Phase 2's
  hash-matches-actual-file verification are what make that hash trustworthy
  rather than merely present.
- **`dist/` carries 9 SBOM files after this ADR, not 2** (today's state) or
  the 10 a naive one-file-per-artifact reading might suggest: 8 Go SBOMs (one
  per CLI/server binary, each platform-exact) + 1 shared frontend SBOM
  (linked from all 4 server ones, since the embedded content genuinely is
  single-sourced). Stated plainly because it's a real, visible cost —
  `checksums.txt` roughly quadruples in SBOM-related lines. **Accuracy wins
  this trade deliberately, not by default**: this product is positioned on
  regulatory depth (CRA Article 14/Annex I Part II, the Problem section's
  entire premise), and a smaller artifact set that's measurably wrong for
  half the release matrix (the Darwin binaries, before today) is a worse
  position than a larger one that's exact for all of it. File count is a
  legibility cost; a scanner producing a false-clean result for a real
  binary is a trust cost, and this ADR has already established (Problem,
  devDependency trap) that trust cost is the one to avoid.
- Production-only frontend dependency resolution is a defensible
  approximation (tree-shaking means some of the 125 may not reach the actual
  bundle), not an exact accounting — recorded explicitly rather than implied,
  with Vite bundle-to-package attribution as the specific, named reopening
  trigger if it ever becomes available. This is now the **only** unresolved
  approximation in this ADR — the one-SBOM-four-binaries gap that motivated
  the per-binary reversal above is eliminated, not merely documented.
- Release job time increases by roughly 36 seconds (measured: three
  `cyclonedx-gomod app` invocations at 6.04s/5.77s/5.48s with a warm module
  cache, times 6 additional invocations), against an existing ~10% release
  pipeline failure rate — recorded as the actual number so this trade was
  made with the cost known, not assumed negligible.
- `cdxgen` v12.8.2 becomes a new pinned build-time dependency, following the
  existing `cyclonedx-gomod` pinning convention exactly.
- `make sbom` and `make release` stay in the parity they already had for the
  Go SBOMs — both generate the same 8+1 SBOM set, so an ad-hoc audit via
  `make sbom` never silently produces a smaller or less accurate artifact
  set than a real release.
- The CLI's SBOM *content* does not change — recorded as a deliberate
  decision, not an oversight, so a future contributor doesn't add frontend
  components to it "for consistency." Only its file count changes (1 → 4),
  matching the CLI's own four cross-compiled binaries.
- PR #1298's "per-binary CycloneDX SBOMs" description, aspirational at
  merge time (it was actually per-module), is accurate as of this ADR.
