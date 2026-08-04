# ADR-072: SDK consolidation into `keyorix-sdks`

## Status

Accepted.

## Context

Four separately-versioned client SDK repositories exist:
`github.com/keyorixhq/keyorix-go`, `keyorix-node`, `keyorix-python`, and
`keyorix-java`. Combined they are small — 1,344 lines of SDK source (the
actual client library files: `keyorix.go`, `keyorix.js`+`keyorix.d.ts`,
`keyorix.py`, and the seven files under `keyorix-java/src/main/java/com/keyorix/`),
or 2,221 lines counting their test suites and `examples/petstore/` demo apps
too — verified via `git ls-files | grep -E '\.(go|js|py|java|ts)$' | xargs wc -l`
per repo, not assumed.

All four currently declare version `0.2.1` in their manifests
(`package.json`, `pyproject.toml`, `pom.xml`; Go modules carry no in-repo
version field, only the git tag). They were **not**, however, all released
the same day: `keyorix-go`'s `v0.2.1` tag lands 2026-05-07, while
`keyorix-node`, `keyorix-python`, and `keyorix-java`'s land together on
2026-06-03, a month later. Nor does `main` currently match the `v0.2.1` tag
in any of the four — each has since taken untagged commits past it (go,
node, and python one apiece; java twenty-eight, mostly Dependabot bumps and
CI hardening). The four are nominally versioned in lockstep, but the git
history shows that lockstep has already started to drift unmanaged — one of
the problems this ADR's versioning decision (below) addresses directly.

## Problem

**The licensing defect is sharper than "one AGPL repo, three unlicensed
ones."** `keyorix-go` ships an actual `LICENSE` file (AGPL-3.0, verified by
its header text) and its README states `AGPL-3.0 — see [LICENSE](LICENSE)`.
`keyorix-node`, `keyorix-python`, and `keyorix-java` have no `LICENSE` file —
but all three **already claim AGPL-3.0** everywhere else a consumer would
look: each README has a `## License` section stating `AGPL-3.0`, and each
manifest declares it too (`package.json`'s `"license": "AGPL-3.0"`,
`pyproject.toml`'s `license = {text = "AGPL-3.0"}` plus a matching PyPI
trove classifier, `pom.xml`'s `<licenses><license><name>GNU Affero General
Public License v3.0</name>`). So the defect for these three is not "no
license stated, defaulting to all-rights-reserved ambiguity" — it is AGPL-3.0
claimed everywhere a registry, a license scanner, or a human reads it,
without the one file that would make that claim complete and enforceable.
Practically, this means **all four** SDKs already present as AGPL-3.0 to
anyone evaluating them, not just `keyorix-go`.

That matters because an AGPL client library triggers copyleft the moment
it's linked into a customer's proprietary application — enterprise legal
blocks the one artifact whose entire purpose is adoption. This is the
primary driver for this work, not repo tidiness.

## Decision

Consolidate all four into a single `keyorix-sdks` repository, licensed
**Apache-2.0** for all SDK code. This follows established industry
precedent for exactly this shape — a restrictively-licensed server paired
with a permissively-licensed client so adoption isn't blocked by the
server's own license: HashiCorp Vault (BSL server, MPL-2.0 API client) and
MongoDB (SSPL server, Apache-2.0 drivers) both do this.

### Scope of the licensing change

Every AGPL declaration found during Problem-section verification must stop
declaring it — this is the explicit checklist Phase 3 executes against,
rather than relying on a single grep to catch everything:

- `keyorix-go/LICENSE` — delete. The consolidated repo's root Apache-2.0
  `LICENSE` is authoritative; two conflicting `LICENSE` files in one repo is
  worse than the original problem.
- `package.json`'s `"license"` field → `Apache-2.0` (node).
- `pyproject.toml`'s `license` field **and** the AGPL PyPI trove classifier
  (`"License :: OSI Approved :: GNU Affero General Public License v3"`) —
  two separate strings in two separate places in the same file; a naive
  edit of one leaves the other intact and still AGPL-declared (python).
- `pom.xml`'s `<licenses>` block (java).
- The `## License` section in all four READMEs.
- **Verification gate**: after Phase 3, `git grep -in "AGPL\|Affero\|agpl-3.0"`
  across the whole `keyorix-sdks` tree must return zero hits. Any hit is a
  failure, not a note for later.

## Relicensing authority

Verified via `git shortlog -sne --all` in each of the four repos: every
human-authored commit is by Andrei Beshkov `<andrey.beshkov@gmail.com>` —
go: 5, node: 5, python: 8, java: 20. The only other committer anywhere is
`dependabot[bot]` (10 commits, `keyorix-java` only); verified these touch
only `pom.xml` and two CI workflow files
(`.github/workflows/dependency-check.yml`, `.github/workflows/sonar.yml`)
across their entire history — never SDK source. Sole authorship of every
line of copyrightable code is therefore held by one person, and unilateral
relicensing (the Apache-2.0 decision above) is permitted.

**The incorporation gap.** Each repo's creation date, verified via
`gh repo view --json createdAt`: `keyorix-go` 2026-04-20, `keyorix-python`
2026-04-20, `keyorix-node` 2026-04-24, `keyorix-java` 2026-04-25. All four
predate Keyorix SL's incorporation in June 2026. Copyright in this code
therefore vested in Andrei Beshkov personally at the moment of creation,
not in the company — a fact of authorship law, not a choice available to
this ADR. The Apache-2.0 `LICENSE` this ADR mandates for `keyorix-sdks`
asserts Keyorix SL's copyright; that assertion requires a written IP
assignment from the founder to the company covering this pre-incorporation
work, which does not yet exist. The same gap applies to the `keyorix`
server repository itself, and to any other repo created before June
2026 — it is not SDK-specific. Recorded here as an open dependency this
consolidation surfaces, not as something this ADR or Phase 2/3 resolves.

## Prior AGPL grant is irrevocable

Relicensing is forward-looking only. Anyone who obtained an SDK release
under AGPL-3.0 retains that license grant for the versions they received —
Apache-2.0 governs this repository's future distributions, not past ones.

This is not theoretical. `keyorixhq/keyorix-go` has been public since
2026-04-20 and currently has 1 fork, recorded 2026-07-24 (verified via
`gh repo view` / `gh api repos/syntax-syndicate/keyorix-go`). That context
matters and is recorded precisely rather than left as a bare number:
`syntax-syndicate` is a GitHub **Organization** account (verified via
`gh api users/syntax-syndicate`) operating a bulk repository-mirroring
operation of 6,446 public repositories. A sample of its 30
most-recently-updated repos (verified via `gh api users/syntax-syndicate/repos`)
are all forks, all carry 0 stars, and span licenses from MIT to Apache-2.0
to GPL-3.0 to none-detected — forking indiscriminately regardless of
license, not selectively. The `keyorix-go` fork itself has 0 stars and 0
forks of its own, and its `pushed_at` timestamp predates its own
`created_at` — meaning zero activity of any kind since the mechanical fork
operation itself; it is an untouched mirror snapshot, not a repo anyone is
building against.

**One fork recorded 2026-07-24 by an account operating a bulk
repository-mirroring organization (~6,400 repositories, no stars across
any of them). No evidence of adoption or downstream use.** The AGPL-3.0
grant was technically exercised — the fork operation itself is a form of
distribution/reproduction under the license — but "exercised" should not
be read as "adopted": nothing here indicates a human evaluated, is using,
or depends on this code.

The Go import path break (below) is stated accordingly: not "no known
adopters" (a diligence reviewer who checks the fork count themselves would
find that claim false), but exposure this low and this well-characterized
is functionally the same as none for the purpose of deciding whether to
break the import path now. The break is still correct and still cheapest
to make now rather than later.

## Why not fold into the `keyorix` repo

- **License divergence.** AGPL-3.0 server code and Apache-2.0 SDK code in
  one tree is a confusing story for a customer's license auditor to
  untangle, even with directory-scoped `LICENSE` files.
- **Version divergence.** The server is at `v0.88.0`; the SDKs are at
  `v0.2.x` and versioned against the API contract, not the server release —
  the two cannot share a tag namespace without one of them lying about what
  its version number means.
- **Clone weight.** A consumer who wants a ~300-line client library
  shouldn't have to clone the entire server monorepo to get it.

## Why not keep them separate

No independent release cadence exists between the four today — they are
already versioned and released together (mostly; see the drift noted in
Context). Four repos enforcing a coordination discipline that a single repo
gives for free is unjustified overhead.

## Versioning

One `vX.Y.Z` tag drives all four languages' releases together. The Go
module additionally requires its own `go/vX.Y.Z`-prefixed tag (Go's module
proxy resolves versions for a module living in a subdirectory this way);
that prefixed tag is pushed alongside the top-level one on every release,
not as a separate decision point.

SDK versions track the **API contract**, not the server's release version —
a version number describes what surface of the Keyorix HTTP API the SDKs
implement, independent of which server version happens to be running. A
compatibility matrix (which SDK versions work against which server
versions) is required before GA; it does not exist yet and is not created
by this ADR.

**The first release of the consolidated repository is `v0.3.0`**, with the
companion Go tag `go/v0.3.0`. Rationale: the Go import path change above is
breaking, and under pre-1.0 semver a breaking change increments the minor
version — `v0.2.1` is also already taken four times over, once per source
repo's own divergent history (see Context). The four repos' divergent
`v0.2.1` states converge at this single `v0.3.0` tag; no `v0.2.x` tag is
created in `keyorix-sdks` itself.

## Go import path break

`github.com/keyorixhq/keyorix-go` becomes
`github.com/keyorixhq/keyorix-sdks/go`. This is a breaking change for any
existing Go import, accepted deliberately **now** — with exposure as low as
it will ever be (one fork, by a bulk-mirroring account, zero activity since
creation — see "Prior AGPL grant is irrevocable" above for the full
characterization; no evidence of `keyorix-go` being imported as a
dependency anywhere) — because the cost of this exact break only grows with
every downstream consumer who'd otherwise need to update an import path
later.

## Package naming and namespace strategy

- **npm: `@keyorixhq/sdk`, scoped, never bare.** A scope is an org-owned
  namespace: future packages are pre-owned rather than separate name races,
  consumers get a mechanically checkable invariant that anything outside
  the scope is not ours, and it enables per-scope registry pinning
  (`@keyorixhq:registry=`) — the documented mitigation for
  dependency-confusion attacks against organizations running internal
  registries, which are our target buyers. Verified 2026-08-04: neither the
  bare name `keyorix` nor `@keyorixhq/sdk` exist on the registry (`npm view`
  → HTTP 404 for both), and no package exists under the `@keyorixhq` scope
  at all (`npm search "@keyorixhq"` → no matches) — the scope itself is
  unclaimed, not just this one name within it.
- **PyPI: `keyorix`.** PyPI has no namespace/scope mechanism — the package
  name itself is the only protection, so defensive registration of
  variants matters more here than anywhere else. Verified 2026-08-04:
  `keyorix` returns HTTP 404 from `pypi.org/pypi/keyorix/json` —
  unregistered.
- **Maven Central: `com.keyorix`, domain-verified, no extra action.** The
  Sonatype OSSRH domain-verification status itself is an account fact
  asserted here, not independently checkable via a public API. What is
  independently verified, 2026-08-04, via Maven Central's search API
  (`search.maven.org/solrsearch/select?q=g:com.keyorix`): zero published
  artifacts under this groupId — nobody has squatted it.
- **Go: `github.com/keyorixhq/keyorix-sdks/go`.** The import path is an
  org-owned GitHub URL; there is nothing separate to squat.

**The underlying principle**: Go and Maven carry namespace ownership at the
ecosystem level (a GitHub org URL; a domain-verified groupId); npm requires
opting into a scope to get the equivalent; PyPI provides no namespace
mechanism at all. Defensive effort should scale inversely with how much
protection the ecosystem already builds in — heaviest on PyPI, lightest on
Go and Maven.

**Publishing will use OIDC trusted publishing, not long-lived registry
tokens.** Verified 2026-08-04 (github.blog changelog, 2026-07-08 and
2026-07-31 posts): npm restricted 2FA-bypass granular access tokens from
account-changing operations (creating tokens, changing maintainers,
managing org membership) effective 2026-07-31, and has a stated target of
January 2027 to also remove those tokens' direct-publish capability,
reducing their surface to "stage a publish, a maintainer approves with
2FA" — with OIDC trusted publishing explicitly recommended as the
migration path. Token-based CI publishing is therefore a dead end to build
toward. This repo's eventual publish workflow — itself out of scope for
this ADR and for Phase 2/3 below — should be designed for OIDC from the
start rather than retrofitted later.

## Follow-on decision, recorded but not taken here

`server/http/handlers/openapi.yaml` defines 126 paths (verified:
`grep -cE "^  /" openapi.yaml`). The Go SDK currently calls exactly 4 of
them — `/auth/login`, `/health`, `/api/v1/projects`, `/api/v1/secrets`
(verified: every `baseURL`/`serverURL`-prefixed URL construction in
`keyorix.go`, cross-checked against `openapi.yaml`'s path list). Generating
SDK clients directly from the OpenAPI spec is the intended direction to
close that gap, and will get its own ADR — this coverage number is recorded
here only as the baseline that follow-on ADR will need to measure progress
against.

## Blocked-on

Any publish workflow (npm, PyPI, Maven) for this repo is blocked on
defensive registration of the names decided in "Package naming and
namespace strategy" above — npm scope `@keyorixhq` (and bare `keyorix`),
and PyPI `keyorix` — see the existing BACKLOG.md entry ("Defensive
package-name registration (supply-chain)"), which documents that these
names are currently unregistered and unclaimed. Publishing this repo's
packages before that registration exists would be publishing into
squattable name space.

## Consequences

- One repository, one license (Apache-2.0, with an explicit scrub checklist
  and a zero-hits verification gate), one version scheme (`v0.3.0` first) —
  the AGPL-declared-without-backing inconsistency and the unmanaged version
  drift documented in Context and Problem both go away by construction.
- `github.com/keyorixhq/keyorix-go` import consumers — at least one, the
  existing fork — face a one-time, deliberately-accepted breaking path
  change; users of prior AGPL-licensed releases keep the license they were
  granted.
- A written founder-to-company IP assignment covering all pre-June-2026
  repos (this SDK work and the `keyorix` server repo alike) is now an
  explicit, recorded open dependency — not resolved by this ADR, but no
  longer silently assumed away either.
- Package names are decided (`@keyorixhq/sdk` npm, `keyorix` PyPI,
  `com.keyorix` Maven, `keyorix-sdks/go` Go), verified unregistered/
  unsquatted across all four registries, and publishing is designed for
  OIDC trusted publishing from the start rather than long-lived tokens —
  but publishing itself is blocked until the defensive registrations land;
  this ADR does not perform or schedule that registration, only records
  the dependency.
- OpenAPI-driven code generation and a server/SDK compatibility matrix are
  both real, near-term follow-on decisions — explicitly not made here, with
  the coverage baseline (4/126 paths) recorded so the next ADR has a
  starting point rather than a fresh guess.
- **Imported SDK history is present in the object graph but not fully
  path-traversable via `git log`.** All 48 source commits (go: 5, node: 5,
  python: 8, java: 30 — of which 10 are Dependabot bumps; go, node, and
  python have none) are reachable, verified via `git merge-base
  --is-ancestor <original-v0.1.0-commit> HEAD` for each language. `git
  subtree add` preserves imported commits at their original
  root-relative paths, so `git log -- go/keyorix.go` (the default,
  path-limited form) does not show the pre-import commits that actually
  touched that file — confirmed empirically: it returns 0–1 entries
  rather than the true 5. **`git blame` is not affected by this** —
  verified directly, not assumed: blaming a line added by a later
  pre-import commit (`go/keyorix.go`'s `authBearer` constant, added
  2026-07-27, well after the v0.1.0 import boundary) correctly
  attributes it to that exact commit, not the import merge. `blame`
  walks the full parent graph regardless of the history simplification
  `git log <path>` applies by default; only the latter is limited.
  Reaching the same information via `log` requires the original
  pre-import paths (`git log --all -- keyorix.go`) or direct SHAs. This
  was accepted rather than corrected: the affected code is 1,344 lines
  across four repos with 5–30 commits each, and it is slated for
  replacement by generated clients. The four source repositories are
  **archived rather than deleted** specifically so the browsable
  per-file history remains available regardless of any of the above.

  The technique that would have avoided this: `git filter-repo
  --to-subdirectory-filter <lang>` on each throwaway clone, run *before*
  `git subtree add` rather than relying on subtree's own path handling.
  It rewrites every commit's tree to already live under `<lang>/`
  retroactively, so once merged, `git log -- <lang>/<file>` walks a
  path that was consistent for that file's entire history — instead of
  only reaching pre-import commits through `git blame` or a full-repo
  search by original filename. Not done here because the need wasn't
  recognized until after the import; noted so it isn't rediscovered the
  hard way next time.
