# Library-surface fuzzing: tool survey (Stage 0, LS0)

**Date:** 2026-11-20  
**Branch:** docs/ls0-library-fuzzing-survey  
**Pilot library:** `github.com/digitorus/pkcs7` v0.0.0-20261104125046-a476de3098e4  
**Web access during survey:** YES (GitHub API, pkg.go.dev, cURL)  
**Unverified facts:** None material — all license, activity, and release data fetched live.

---

## Context

The goal of this initiative is a **repeatable pipeline** (library in → ranked API
inventory + generated fuzz targets + oracles + run plan → report out) for fuzzing
a third-party library's full exported surface, not just the functions Keyorix
calls.  This document is Stage 0: tool survey.  Stage 1 is building the pipeline;
no code is written here.

### Why pkcs7 as pilot

- Security-relevant: CMS/PKCS#7 signatures, certificate trust, padding-oracle
  surface.
- **Maintainer turnaround confirmed fast:** GitHub API shows PR #23 (BER parsing
  memory exhaustion, 2026-09-14) and PR #25 (CBC padding validation, 2026-11-04)
  were both opened and merged same-day.  Three of the last four PRs are
  security-relevant fixes.
- Repo is small and self-contained (22 functions in one package — see §Existing
  coverage below), making it a tractable pilot.
- The existing work already covers `pkcs7.Parse` with three separate harnesses
  (bounded-work, grammar-driven bounded-work, time-travel differential), so the
  gap is well-defined: Verify*, Decrypt*, and the signing surface.

### Existing pkcs7 fuzz coverage in this repo

Three registered targets (all in `internal/libconformance`):

| Target | Covers | Oracle |
|--------|--------|--------|
| `FuzzDigitorusPKCS7BoundedWork` | `Parse` | time + alloc bounded-work |
| `FuzzDERPKCS7BoundedWork` | `Parse` (grammar-driven DER) | bounded-work |
| `FuzzPKCS7TimeTravelOracle` | `Parse` | time-travel differential vs older version |

**Uncovered (27 exported symbols):** `Verify`, `VerifyWithChain`,
`VerifyWithChainAtTime`, `VerifyWithOpts`, `Decrypt`, `DecryptUsingPSK`,
`Encrypt`, `EncryptUsingPSK`, `NewSignedData`, `(*SignedData).AddSigner`,
`(*SignedData).AddSignerChain`, `(*SignedData).Finish`, and ten other
`*SignedData` methods.  `DegenerateCertificate` and
`GetDigestOIDForSignatureAlgorithm` are low-priority utility functions.

---

## Internal tooling (confirmed usable as-is)

The following internal tools exist in this repo and need no Stage 1 rebuild.
They are confirmed here as the foundation for each category below.

| Tool | Location | What it does | Confirmed |
|------|----------|-------------|-----------|
| `resguard` | `internal/fuzzutil/resguard/` | Bounded memory + time guard (`fuzzutil.Guard`); wraps `testing.T.Fatalf`; used by all three existing pkcs7 harnesses | YES |
| `boundedwork.go` | `internal/fuzzutil/boundedwork/boundedwork.go` | CPU/clock primitives for bounded-work assertions | YES |
| `libconformance` harness style | `internal/libconformance/` | Differential harness pattern with known-class allowlist; `EXPECTED-DIFFERENCE.md` and `differential_expected_difference_test.go` define the template | YES |
| `bwgen` | `scripts/fuzzing/bwgen/` | Type-scanner that emits bounded-work and round-trip targets for exported funcs matching simple shapes (A/B/U); pkcs7 is already in `sweep-pkgs.txt`; uses `golang.org/x/tools/go/packages` + `go/types` | YES |
| `reachgen` | `scripts/fuzzing/reachgen/` | Offline call-graph tool that ranks third-party exported funcs Keyorix calls on untrusted input; produces RANKED-TOP40.md; uses `go/packages` + intra-procedural taint | YES |
| `autofuzzgen` | `scripts/fuzzing/autofuzzgen/` | SAST-guided skeleton emitter; two modes: CodeQL taint-guided (preferred) and AST signature-scan (fallback); emits `.txt` skeletons, never auto-merges | YES |
| `sinkmap` | `scripts/fuzzing/sinkmap/` | Offline sink-classification tool (exec/sql/net/fs/deserialize/crypto-compare); ranks uncovered sinks by reachability; AST-only | YES |
| `invariant-map` | `scripts/fuzzing/invariant-map/` | Maps INV-* invariants to their guards; identifies coverage gaps | YES |
| `fuzz-harness` runner | `keyorixhq/fuzz-harness` (external private repo) | Shared `fuzz-runner.sh` + per-project `fuzz.conf`; this repo's `scripts/fuzzing/targets.d/` is the source of truth for targets; design doc at `docs/fuzzing/continuous-rig.md` | YES (external only, no local checkout) |

**Notes on names from the task brief:**
- `internal/boundedworksweep` — not a Go package; the concept maps to `bwgen`
  (`scripts/fuzzing/bwgen/`) and the `boundedwork.go` file in `internal/fuzzutil/`.
- the dependency-matrix directory under scripts/fuzzing (named "depmatrix" in the task) — no such directory found at survey time.  The closest match is
  `reachgen`'s RANKED-TOP40.md output (call-site-weighted dependency matrix).
  If this is a planned artifact, it needs a TODO-ISSUE.
- `Corobix fuzz-runner.sh` — the actual tool is `keyorixhq/fuzz-harness`
  (`fuzz-runner.sh`), not a "corobix-private" path.  Confirmed from
  `scripts/fuzzing/README.md`.  "Corobix" appears to be the name for the broader
  AI-guided fuzzing system concept, not a repository or script.

---

## Category 1 — API inventory / exported-surface extraction

**Goal:** enumerate every exported function and method in `github.com/digitorus/pkcs7`
so Stage 1 can rank and assign an oracle family to each one.

### Tools surveyed

#### `golang.org/x/tools/go/packages` (+ `go/types`)
- **What it does:** Loads a package (even from module cache without network) with
  full type information; iterates `pkg.TypesInfo.Defs` or `pkg.Types.Scope().Names()`
  to get every exported symbol with full signature.
- **License:** BSD-3-Clause (part of Go standard toolchain extras)
- **Version in go.mod:** v0.52.0 (confirmed in this repo)
- **Last release:** Tracks the Go toolchain; v0.52.0 corresponds to Go 1.27, current
  as of 2026-11-20
- **Verdict:** The correct low-level foundation.  `bwgen` and `reachgen` are both built
  on this.  For Stage 1, do not use it directly — use `bwgen -root` mode instead, which
  already wraps it correctly.
- **Limitation:** Returns only package-level funcs for auto-emission (methods reported
  but not emitted by bwgen due to constructor-synthesis constraint); a custom
  `go/types` walk for methods is needed as a supplement.

#### `go/ast`
- **What it does:** Syntactic AST walk; cheaper than full type-loading.  Used by
  `autofuzzgen`'s `-root` mode, `sinkmap`, and `invariant-map`.
- **License:** BSD-3-Clause (stdlib)
- **Verdict:** Suitable for shape-matching (is this function signature fuzable?) but
  not for type-resolution (what are the receiver types of method X?).  Supplement to
  go/packages for surface extraction; go/packages is strictly more powerful.

#### `go/ssa` (golang.org/x/tools/go/ssa)
- **What it does:** Static single-assignment IR for call-graph construction;
  deeper than go/packages alone.  Used by `govulncheck`.
- **License:** BSD-3-Clause
- **Verdict:** Overkill for surface extraction alone; appropriate for reachability
  analysis (already done by `reachgen`).  Not needed for Stage 1 inventory.

#### `gopls` queries
- **What it does:** LSP server; `gopls symbols` can list all exported symbols in a
  package.  Requires a running server; not scriptable offline.
- **Verdict:** Wrong tool for this.  `go/packages` + `go/types` is strictly more
  automatable and already in-repo.

#### `golang.org/x/exp/apidiff` / `gorelease`
- **What it does:** `apidiff` computes the diff of exported APIs between two package
  versions.  `gorelease` (golang.org/x/exp/cmd/gorelease) checks semantic-versioning
  compliance by running apidiff.  Both are BSD-3-Clause; golang/exp GitHub shows last
  update 2026-11-09.
- **Verdict:** Useful for Stage 1 to detect *new* functions added between pkcs7 versions
  (time-travel comparison) but not for initial surface enumeration.  Nice-to-have for the
  time-travel differential phase; not needed for the inventory step.

#### `go doc -all`
- **What it does:** Prints all exported symbols including methods; available offline
  from module cache.  Used in this survey (`go doc -all github.com/digitorus/pkcs7`)
  to produce the 27-symbol inventory above.
- **Verdict:** Cheap, human-readable quick-check.  Not machine-parseable without
  post-processing.  Use for a sanity check only.

### Recommendation for Stage 1 (Category 1)

**Use `bwgen` (`scripts/fuzzing/bwgen/`) in `-root github.com/digitorus/pkcs7`
mode** as the primary surface scanner.  It already has pkcs7 in `sweep-pkgs.txt`,
emits bounded-work/round-trip skeletons for functions matching the A/B/U shapes,
and reports methods explicitly.  Supplement with a `go/types` walk (20–30 lines of
glue mirroring bwgen's existing `classifyInput` logic) to generate method-target
leads for `(*PKCS7).Verify*`, `(*PKCS7).Decrypt*`, and `(*SignedData).*`.  No
external tool is needed; this is the "write glue, reuse foundation" minimum.

---

## Category 2 — Fuzz target generation from function signatures

**Goal:** given the inventory from Category 1, generate skeleton harnesses with
appropriate oracle families automatically.

### Tools surveyed

#### `thepudds/fzgen`
- **What it does:** Introspects Go packages via go/types to emit `func FuzzXxx` wrappers
  that call every function in a chain, wrapping inputs in `fuzz.NewConsumer(data)` using
  `dvyukov/go-fuzz-corpus`'s structured consumer.
- **License:** Apache-2.0
- **Last commit:** 2024-01-26 (confirmed GitHub API)
- **Stars:** 116
- **Verdict:** Largely idle since early 2024.  It predates native Go fuzzing (pre-1.18
  style) and the wrapper it emits does not match the `func Fuzz*(*testing.F)` signature
  needed for `go test -fuzz`.  Requires upstream update to be usable here.  **Drop.**

#### `google/oss-fuzz-gen`
- **What it does:** LLM-based fuzz-target generator; analyses C/C++/Python/Go projects
  and uses LLM code generation to produce harnesses.  Integrates with OSS-Fuzz's CI
  infrastructure.
- **License:** Apache-2.0
- **Stars:** 1,451 (updated 2026-11-19)
- **Go support status:** Experimental / partial.  The Go generator emits native fuzzing
  targets but requires Python 3.11+, an LLM API key, and OSS-Fuzz's Docker
  infrastructure.
- **Verdict:** Heavy dependency chain (Python + LLM API + Docker) for what is a
  code-generation step we already have internally.  The LLM step adds value for complex
  method targets — but `autofuzzgen` already does the same lead-generation with a
  CodeQL taint query as the signal (more reliable than LLM hallucination for
  security-critical harnesses).  Useful reference for oracle families but not for direct
  Stage 1 use.  **Decline for Stage 1; revisit if autofuzzgen's skeleton quality is too
  sparse for the signing surface.**

#### `AdaLogics/go-fuzz-headers`
- **What it does:** Structured byte consumer for native Go fuzzing (`*fuzz.Consumer`
  type); provides `FillGoFuzzConsumer`-style methods for filling struct fields,
  choosing from slices, etc.  Heavily used in CNCF project harnesses.
- **License:** Apache-2.0
- **Stars:** 110 (updated 2026-11-13)
- **Last commit:** 2026-11-13
- **Verdict:** Useful for constructing realistic inputs to complex method targets
  (e.g., feeding a certificate chain to `VerifyWithChain`).  Not a skeleton
  *generator* — it is a library used inside a harness.  Appropriate for the
  Verify/Decrypt surface where inputs require a valid `*x509.Certificate` or
  `crypto.PrivateKey`.  **Include as a dependency for Stage 2 method targets.**

#### `flyingmutant/rapid`
- **What it does:** Property-based testing library for Go.  Generates complex typed
  values via composable generators (`rapid.Make`); integrates with native testing.T
  via `rapid.Check`.  Can plug into `testing.F` as an oracle layer on top of raw
  bytes.
- **License:** MPL-2.0
- **Stars:** 926 (updated 2026-11-20)
- **Verdict:** Excellent for correctness oracles on the signing/round-trip surface
  (Sign → Verify: `rapid.Check` can explore the space of valid cert chains and
  signing options more systematically than raw bytes).  MPL-2.0 means source files
  that use it are MPL-licensed — acceptable for test-only files.  **Include for
  Stage 2 property-oracle targets on the signing surface.**

#### `leanovate/gopter`
- **What it does:** Haskell QuickCheck-style property-based testing; more elaborate
  API than rapid (Prop, Gen combinators).
- **License:** MIT
- **Stars:** 638 (updated 2026-11-19)
- **Verdict:** More complex API for the same functional niche as rapid.  rapid's
  shrinking is better for security-bug counterexamples.  **Prefer rapid over gopter.**

### Internal tools already covering this category

`autofuzzgen` and `bwgen` together cover this category for simple shapes.  The only
gap is method-target generation, which needs a custom `go/types` walk (described in
Category 1 recommendation).

### Recommendation for Stage 1 (Category 2)

**Primary generator:** `bwgen` for functions matching the A/B/U shapes (Parse,
Encrypt, EncryptUsingPSK, NewSignedData).  For methods, write 30–50 lines of
`go/types` glue following `bwgen`'s `classifyInput` pattern.  No new external
tool.

**For Stage 2 (complex targets):** Add `go-fuzz-headers` for structured inputs to
Verify* and Decrypt* (need realistic cert chains), and `rapid` for a correctness
oracle on the Sign→Verify round-trip.

**Drop:** `fzgen` (stale, wrong signature style), `oss-fuzz-gen` (heavy deps, LLM
  reliability concern for security harnesses), `gopter` (redundant with rapid).

---

## Category 3 — Risk ranking of functions

**Goal:** determine which unexplored pkcs7 functions to fuzz first.

### Tools surveyed

#### `reachgen` (internal)
- **What it does:** Ranks third-party funcs by untrusted-provenance call sites from
  Keyorix callers; the RANKED-TOP40.md snapshot shows 496 distinct third-party funcs
  called, with an intra-procedural taint pass labelling `request-body`,
  `config`, `backend-response`, `static`.
- **Verdict:** The correct primary ranking signal for Keyorix-reachable functions.
  Limitation: intra-procedural only; under-counts cross-function reachability.
  For the full exported surface of pkcs7 (not just what Keyorix calls), it cannot
  rank the signing/encrypt surface at all — none of those are called by Keyorix.

#### `govulncheck` (golang.org/x/vuln)
- **What it does:** Checks a module's dependencies against the Go vulnerability
  database (vuln.go.dev); uses go/ssa call-graph analysis to report only reachable
  vulns.
- **License:** BSD-3-Clause
- **In go.mod:** Indirect dependency via golang.org/x/tools; confirmed in module cache.
  `go install golang.org/x/vuln/cmd/govulncheck@latest` needed to run as a binary.
- **Last release:** Maintained by the Go security team; tracks Go releases.
- **Verdict:** Best pre-screen: if any pkcs7 function is in the vuln DB, it moves to
  the top of the queue regardless of other ranking signals.  Run once, not
  continuously.  **Use as a pre-screen step in Stage 1.**

#### `fzipp/gocyclo`
- **What it does:** Computes cyclomatic complexity (McCabe's CC) per function; output
  is a ranked list by complexity.  Works on any Go source tree offline.
- **License:** BSD-3-Clause
- **Stars:** 1,618 (updated 2026-11-19)
- **Last release:** Actively maintained.
- **Verdict:** A useful secondary signal for functions with high branching complexity
  (a proxy for parser/state-machine depth).  Limitation: CC is a code-shape metric,
  not a taint/reachability metric.  `pkcs7.Parse`, `(*PKCS7).Verify*`, and CBC
  padding logic are all likely high-CC; confirms the intuitive ranking but rarely
  surprises.  **Use as a tiebreaker in Stage 1, 10-minute effort.**

#### CodeQL `FuzzHarnessTargets.ql`
- **What it does:** Full taint query over Keyorix's own code, classifying sinks as
  parser/authz/crypto/format.  Already versioned in
  `.github/codeql/manual-queries/FuzzHarnessTargets.ql`.
- **Verdict:** The highest-signal ranking tool for functions Keyorix calls.  For the
  full pkcs7 surface (functions Keyorix does NOT call), CodeQL still applies if the
  pilot expands to running it over pkcs7's own codebase, but that is a larger setup
  step.  **Use for Keyorix-reachable subset; skip for the unexplored surface in
  Stage 1.**

#### `sinkmap` (internal)
- **What it does:** Classifies dangerous sinks in Keyorix's own code (exec/sql/net/
  fs/deserialize/crypto-compare); ranks uncovered sinks.
- **Verdict:** Keyorix-centric, not library-surface-centric.  Useful for integrating
  library findings back into the Keyorix risk model; not the primary ranker for a
  library full-surface scan.

#### Semgrep Go sink queries
- **What it does:** Semgrep rules can be written to find allocation-sized-by-input,
  slice-index-with-variable, `unsafe`, `reflect`, `encoding/asn1` calls within a Go
  package.  Repo already has `.semgrep/keyorix-rules.yml`.
- **Verdict:** Useful for a custom "which pkcs7 internal paths handle
  attacker-influenced sizes or use unsafe?" scan.  Requires writing 2–3 targeted rules.
  Lower precision than CodeQL taint; higher precision than gocyclo.  Stage 2 work,
  not Stage 1.

### Recommendation for Stage 1 (Category 3)

**Ranking order for the 27 uncovered pkcs7 functions:**

1. **`reachgen` output first:** Keyorix already calls `Parse` → `(*PKCS7).Verify`
   transitively via `internal/notary`.  Any function reachable from
   `notary.VerifyReceipt` is Tier 1.
2. **`govulncheck` pre-screen:** Any function involved in a known CVE goes to top.
3. **CBC/padding/crypto sub-surface (`Decrypt`, `DecryptUsingPSK`, CBC internals):**
   Rank high due to recent PR #25 (CBC padding fix, 2026-11-04) — this is a
   class that keeps producing fixes.
4. **Verification surface (`Verify*`):** Rank high for signature-bypass potential.
5. **Signing surface (`NewSignedData`, `AddSigner*`, `Finish`):** Rank medium; the
   dangerous direction is accept (verify), not emit (sign).
6. **`gocyclo`** as tiebreaker within tiers.

---

## Category 4 — Oracle quality / differential references

**Goal:** identify what to compare against to catch incorrect behavior, not just
crashes; validate that oracle assertions are meaningful (mutation-kill check).

### Differential references

#### `openssl cms` (OpenSSL 3.5.7)
- **What it does:** `openssl cms -verify / -decrypt / -sign` commands implement the
  CMS/PKCS#7 standard independently.  Available on this host: OpenSSL 3.5.7 installed
  at `/usr/bin/openssl`.
- **Verdict:** The strongest differential reference available — independent
  implementation, battle-tested, authoritative on the standard.  An input pkcs7
  accepts that openssl cms rejects (or vice versa) is a meaningful signal.
  **Limitation:** openssl cms operates on files/pipes; harness needs a small
  `exec.Cmd` wrapper.  Subprocess latency (~10ms/call) caps throughput; appropriate
  for seed-corpus regression checks and a nightly differential run, not
  high-frequency fuzzing.  **Use as the primary differential reference.**

#### `mozilla-services/pkcs7`
- **What it does:** Mozilla's fork of the same pkcs7 implementation; BSD/MIT-licensed.
  73 GitHub stars; last update 2026-07-21; NOT archived.
- **Verdict:** A secondary reference for divergence checking.  The time-travel pattern
  (`timetravel_pkcs7_fuzz_test.go`) already works against an older version of
  digitorus/pkcs7 — the same pattern applies against mozilla-services/pkcs7, built as
  a separate subprocess driver.  Limitation: same Go lineage as digitorus/pkcs7
  (both forked mozilla); they share historical bugs, so divergence is a weaker signal
  than openssl cms.  **Use as a secondary reference; do not replace openssl cms.**

#### `smallstep/pkcs7`
- **What it does:** Smallstep's fork.  27 stars; last update 2026-10-19; NOT archived.
  Apache-2.0.
- **Verdict:** More current than mozilla-services/pkcs7 (updated Oct 2026 vs Jul 2026).
  Same cross-fork limitation.  **Use if mozilla-services diverges too often (fewer
  expected-difference allowlist entries) in a 3-way differential.**

### Oracle / mutation tooling

#### `go test -fuzz -coverprofile` (native)
- **What it does:** Go's native fuzzer already tracks coverage per corpus entry; `-
  coverprofile` can be used to measure post-wall reach.  `harness-acceptance.sh` in
  this repo already implements the coverage-delta gate.
- **Verdict:** Use as-is.  No external tool needed.

#### `go-gremlins/gremlins`
- **What it does:** Mutation tester for Go; runs the test suite against mutated
  versions of a source file (flips operators, constants, etc.) and reports which
  mutations survive ("escaped").  Apache-2.0.  472 stars.  Last commit 2026-03-30.
- **Verdict:** The right tool to verify that oracle assertions actually fire on
  planted defects.  CLAUDE.md requires a red/green proof for security-related
  harnesses; gremlins can automate this at scale (mutate the pkcs7 source, confirm
  the fuzz corpus kills the mutation).  **Use for oracle validation in Stage 2.**

#### `zimmski/go-mutesting`
- **What it does:** An earlier Go mutation tester; MIT.  679 stars.  Last commit
  2021-06-10 — stale.
- **Verdict:** Drop in favour of gremlins.  **Drop.**

#### `pgregory.net/rapid` (also relevant here)
- **What it does (oracle angle):** rapid's shrinking produces minimal counterexamples,
  making it easier to understand and confirm a mutation-kill failure.
- **Verdict:** Useful complement to gremlins: gremlins tells you a mutation escaped,
  rapid finds the smallest input that witnesses the escape.  **Stage 2 tool.**

### Recommendation for Stage 1 (Category 4)

**Primary differential reference:** `openssl cms` subprocess driver (same pattern
as `timetravel_pkcs7_fuzz_test.go` but cross-implementation rather than
cross-version).  Write a one-time `cmd/pkcs7-openssl-driver` subprocess wrapper
that reads DER bytes on stdin, runs `openssl cms -verify -noverify`, and returns
`accept|reject|error:class`.  Plug into the libconformance time-travel harness
shape.

**Secondary references:** `mozilla-services/pkcs7` and `smallstep/pkcs7` as
subprocess drivers for a 3-way differential on `Verify`.

**Oracle mutation validation:** `go-gremlins/gremlins` to validate that
harnesses actually fire on planted pkcs7 defects before they are promoted to
continuous rig targets.  `zimmski/go-mutesting` is too stale; drop.

**Coverage gate:** `harness-acceptance.sh` already in-repo; apply to all new
Stage 2 targets.

---

## Summary table

| Category | Recommended (Stage 1) | Why | License | Active? |
|----------|-----------------------|-----|---------|---------|
| **API inventory** | `bwgen -root` + `go/types` method walk | Already in repo; pkcs7 in sweep-pkgs.txt | BSD-3-Clause | Yes |
| **Target generation** | `bwgen` for A/B/U shapes; `go/types` glue for methods | Minimum-glue approach; avoids stale fzgen, heavy oss-fuzz-gen | BSD-3-Clause | Yes |
| **Risk ranking** | `reachgen` → `govulncheck` → CBC/Verify priority → `gocyclo` as tiebreaker | Multi-signal, offline-first | BSD-3-Clause | Yes |
| **Oracle / differential** | `openssl cms` subprocess + `mozilla-services/pkcs7` secondary; `gremlins` for mutation-kill | Cross-impl is strongest signal; gremlins for oracle validation | Various | Yes |

**For Stage 2 (complex targets):** add `go-fuzz-headers` for structured cert inputs,
`rapid` for property oracles on the signing surface.

---

## Per-tool quick-reference

| Tool | Location | License | Last release/commit | Verdict |
|------|----------|---------|---------------------|---------|
| `bwgen` | scripts/fuzzing/bwgen/ | (internal) | active, in-repo | **RECOMMEND** |
| `reachgen` | scripts/fuzzing/reachgen/ | (internal) | active, in-repo | **RECOMMEND** |
| `autofuzzgen` | scripts/fuzzing/autofuzzgen/ | (internal) | active, in-repo | Use for CodeQL-guided leads |
| `sinkmap` | scripts/fuzzing/sinkmap/ | (internal) | active, in-repo | Use for Keyorix-side gap analysis |
| `golang.org/x/tools/go/packages` | go.mod v0.52.0 | BSD-3-Clause | Go 1.27 era, current | Foundation; use via bwgen |
| `golang.org/x/tools/go/ssa` | go.mod v0.52.0 | BSD-3-Clause | current | Overkill for inventory; skip |
| `golang.org/x/exp/apidiff` | not in go.mod | BSD-3-Clause | 2026-11-09 | Stage 2 nice-to-have (version diff) |
| `thepudds/fzgen` | not in go.mod | Apache-2.0 | 2024-01-26 (stale) | **Drop** |
| `google/oss-fuzz-gen` | not in go.mod | Apache-2.0 | 2026-11-19 | Heavy deps; skip Stage 1 |
| `AdaLogics/go-fuzz-headers` | not in go.mod | Apache-2.0 | 2026-11-13 | Add for Stage 2 method targets |
| `flyingmutant/rapid` | not in go.mod | MPL-2.0 | 2026-11-20 | Add for Stage 2 property oracles |
| `leanovate/gopter` | not in go.mod | MIT | 2026-11-19 | Redundant with rapid; skip |
| `govulncheck` | golang.org/x/vuln | BSD-3-Clause | Go security team, current | Pre-screen; run once |
| `fzipp/gocyclo` | not in go.mod | BSD-3-Clause | 2026-11-19 | Tiebreaker for risk ranking |
| CodeQL FuzzHarnessTargets.ql | .github/codeql/manual-queries/ | (internal) | active, in-repo | Use for Keyorix-reachable subset |
| `go-gremlins/gremlins` | not in go.mod | Apache-2.0 | 2026-03-30 | Oracle mutation-kill validation |
| `zimmski/go-mutesting` | not in go.mod | MIT | 2021-06-10 (stale) | **Drop** |
| `openssl cms` | /usr/bin/openssl (host) | OpenSSL | 3.5.7, 2026-06-09 | **Primary differential reference** |
| `mozilla-services/pkcs7` | not in repo | MIT | 2026-07-21 | Secondary differential reference |
| `smallstep/pkcs7` | not in repo | Apache-2.0 | 2026-10-19 | Tertiary differential reference |

---

## Appendix A — pkcs7 exported surface (from `go doc -all`)

27 exported symbols total; 3 currently covered by existing harnesses (all `Parse`).

```
Parse(data []byte) (*PKCS7, error)                          ← COVERED (3 harnesses)
Encrypt(content []byte, recipients []*x509.Certificate)
EncryptUsingPSK(content []byte, key []byte)
DegenerateCertificate(cert []byte)
GetDigestOIDForSignatureAlgorithm(digestAlg)
(*PKCS7).Decrypt(cert *x509.Certificate, pkey crypto.PrivateKey)
(*PKCS7).DecryptUsingPSK(key []byte)
(*PKCS7).GetOnlySigner()
(*PKCS7).UnmarshalSignedAttribute(attributeType, out)
(*PKCS7).Verify()
(*PKCS7).VerifyWithChain(truststore *x509.CertPool)
(*PKCS7).VerifyWithChainAtTime(truststore *x509.CertPool, t time.Time)
(*PKCS7).VerifyWithOpts(opts x509.VerifyOptions)
NewSignedData(data []byte) (*SignedData, error)
(*SignedData).AddCertificate(cert *x509.Certificate)
(*SignedData).AddSigner(ee, keyOrSigner, config)
(*SignedData).AddSignerChain(ee, keyOrSigner, parents, config)
(*SignedData).Detach()
(*SignedData).Finish() ([]byte, error)
(*SignedData).GetSignedData()
(*SignedData).RemoveAuthenticatedAttributes()
(*SignedData).RemoveUnauthenticatedAttributes()
(*SignedData).SetContentType(contentType)
(*SignedData).SetDigestAlgorithm(d)
(*SignedData).SetEncryptionAlgorithm(d)
(*SignedData).SignWithoutAttr(ee, keyOrSigner, config)
(*MessageDigestMismatchError).Error()
```

---

## Appendix B — pkcs7 maintainer turnaround time

Verified from GitHub API (2026-11-20):

| PR | Merged | Topic |
|----|--------|-------|
| #23 | 2026-09-14 (same day as opened) | BER parsing memory exhaustion (security) |
| #25 | 2026-11-04 (same day as opened) | CBC padding validation + malformed-ciphertext panics (security) |
| #24 | 2026-11-04 | RSASSA-PSS signer info support |
| #22 | 2026-08-21 | Mozilla upstream ancestry reconciliation |

Three of the last four merged PRs are security-relevant fixes merged same-day.
The maintainer hypothesis in the task brief is confirmed.

---

## Appendix C — stage plan sketch (not Stage 0 scope, for reference)

```
Stage 1  Build pipeline
  - Run bwgen -root github.com/digitorus/pkcs7 → generates A/B/U shape targets
  - Write go/types method walker (30–50 lines, mirrors bwgen.classifyInput)
    → emits method-target leads for Verify*, Decrypt*, SignedData
  - Run govulncheck against pinned version → pre-screen
  - Run reachgen + gocyclo → ranked list
  - For each skeleton: fill oracle, red-proof (must fire when CBC removed / 
    verify path weakened), promote to targets.d/

Stage 2  Complex targets + differential oracle
  - Add go-fuzz-headers + rapid as test deps
  - Write openssl-cms subprocess driver (Verify differential)
  - Add mozilla-services/pkcs7 and smallstep/pkcs7 drivers (3-way)
  - Run gremlins on each promoted target → confirm oracle kills mutations

Stage 3  Continuous-rig integration
  - Add targets.d/*.conf for each promoted target
  - Register in BUDGET.tsv
  - Point fuzz-harness runner at new targets
```
