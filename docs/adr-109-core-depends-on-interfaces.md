# ADR-109: `internal/core` depends on interfaces, not on connectors and backends

**Status:** Accepted (Andrei, 2026-09-23). It gets a repo ADR number when committed to `docs/`. Implementation is sequenced after the CLI/server split.
**Companion ADR:** `ADR-108 (`docs/adr-108-cli-server-split.md`)` (thin CLI, `keyorix-server admin`, `/system` proxy removal). Neither ADR is a prerequisite for the other. Both are sequenced in (Keyorix planning notes, claude/2026-09-23-refactor-program-plan-cli-server-split.md), where this one is Phase 7, after the split.
**Evidence:** (Keyorix planning notes, claude/2026-09-23-coverage-map-leaf-package-ab-results.md); the coupling section of (Keyorix planning notes, claude/2026-09-22-ssdlc-fuzzing-report-gap-analysis.md).

## Context (measured 2026-09-23)

`internal/core` imports every integration directly. Each one is used in only a handful of core files:

| Integration | Core files importing it | Coverage map of the package alone |
|---|---|---|
| `internal/connect` (Vault, AWS SM, Azure KV, GCP SM) | 2 (connect.go, service.go) | 116,182 B |
| `internal/rotation` (Postgres/MySQL/Azure rotation) | 2 (rotation_executor.go, service.go) | 122,926 B |
| `internal/dynamic` (dynamic-secret backends incl. Kubernetes) | 2 (dynamic_secrets.go, service.go) | 122,932 B |
| `internal/encryption` (KMS SDKs) | 4 | 131,838 B |
| `internal/notary`, `internal/saml`, `internal/delivery`, `internal/license`, `internal/trust` | 1–3 each | 6–30 KB each |

Consequences today:
- **Fuzzing:** core's coverage map is about 480 KB. The same kind of target in a leaf package has 5–34 KB of map, runs 18–40× more inputs per second (indicative), and doesn't stall in minimization.
  - #2001 moved 13 pure targets out of core (`internal/core/rules`, `internal/libconformance`).
  - About 10 targets exercise real core behaviour (OIDC/SSO verification, the PAT lifecycle, operation sequences) and still pay the full cost.
- **Server binary:** 97 MB, including 99 cloud-SDK packages. Every server build ships every SDK, including air-gapped installs that use none of them.
- **Vulnerabilities and SBOM:** govulncheck and CRA SBOMs list every SDK for every deployment. A CVE in an unused cloud SDK becomes an "affected" line in a customer's scanner.

Already done:
- **D0 (#2004, merged):** `internal/config` no longer imports `internal/connect`, and `i18n.Initialize` takes a narrow interface. config dropped from 123,619 to 22,632 B and i18n from 123,734 to 14,250 B; a guard test (`TestI18nAndConfigStayLight`) keeps it that way.
- **Leaf packages (#2001, merged).**

The CLI/server split removes the SDKs from the *client*. This ADR is about the *server* and core itself.

## Decision (proposed)

1. **Core depends only on small interfaces** for what it actually calls. There is one interface per integration, defined in core (or `internal/core/ports`) and modelled on the existing `storage.Storage` seam:
   - `ConnectorResolver`
   - `RotationExecutor`
   - `DynamicBackendFactory`
   - the encryption/KMS provider
   - `TimestampNotary`
   - `SAMLServiceProvider`
2. **The implementations are wired in `main`** (`server/main.go`) and passed to `NewKeyorixCore` as options.
   - A nil implementation means the feature is unavailable. The error says so clearly and **never fails open**.
   - At startup, the server checks that every feature enabled in its config has an implementation wired. A missing one stops boot, which is the ADR-082 fail-closed shape.
3. **Lean builds:** build tags group the implementations (for example `nocloud` drops the AWS/Azure/GCP connectors and KMS SDKs), which gives a supported air-gapped or lean server build rather than a fork.
4. **Guards, added with each step:**
   - a dependency test that fails if `internal/core` (production files) imports an integration package again;
   - a wiring test that the default server registers all implementations;
   - for lean builds, a test that each build tag set actually builds and that enabling a feature whose implementation was compiled out fails at startup;
   - an SBOM/dependency-count diff per build in CI.

## Order of work (one PR per step, each measured with the runner's map-size table)

1. `notary` and `saml`, the smallest (few call sites), to prove the pattern.
2. `rotation`.
3. `dynamic`.
4. `connect`, the largest surface.
5. The encryption/KMS provider. This is the most security-sensitive, so it gets an adversarial review.
6. Build tags, the lean/air-gapped build in CI, and the SBOM diff.
7. Move the remaining core fuzz targets that core's lighter map now allows, carrying their corpus with them.

## Consequences

- **Fuzzing:** core's map should fall well below 480 KB, which speeds up every remaining core, HTTP and fault-ops target. Every step is measured; nothing is assumed.
- **Air-gapped positioning:** a lean server build with a short SBOM becomes a packaging decision instead of a fork.
- **Cost:** it touches `NewKeyorixCore` and every test helper that builds a core. Doing it *after* the CLI split avoids also rewiring the old CLI (45 files import core), which the split deletes.
- **Risk:** a feature silently missing because its wiring was left out. The startup check and the wiring test make that fail at boot instead.

## Definition of done

- `go list -deps ./internal/core` (production) contains no cloud SDK and no integration package.
- A lean build exists in CI with a published SBOM diff.
- Core's coverage map and the server's binary size are reported before and after in the program plan's measurement point M4.

## Decisions on the open questions (Andrei, 2026-09-23)

1. **A lean build is a supported edition, not a price tier (yet).**
   - It ships as its own artifact, for example "Keyorix Air-Gapped Edition": no AWS/Azure/GCP code, and its own published SBOM.
   - Same price as the full build.
   - Pricing is decided after customer discovery. "Does a cloud-free build with a short SBOM matter to you?" goes into the discovery question list for the 10 customer conversations.
2. **Build-tag granularity: per integration underneath, named profiles on top.**
   - Tags per integration: `noaws`, `noazure`, `nogcp`, `novault`, `nok8s`.
   - Officially supported profiles: **full** and **air-gapped** (no cloud connectors) only. They are defined in the Makefile/goreleaser, and CI builds, tests and publishes an SBOM for each.
   - Other tag combinations compile but are not supported, which keeps the test matrix at two profiles.

## M4 measurements

Measured on `main` before any ADR-109 step, on this checkout's commit at the time of Step 0.
Methodology: `scripts/fuzzing/mapsize_of_bin.sh` (a repo-local reproduction of the rig's
`mapsize_of_bin`, validated against this ADR's own stated baseline before being trusted — see
that script's header comment), `go build -trimpath` for `GOOS=linux GOARCH=amd64`, and
`go list -deps ./internal/core` (production files only).

| Metric | Baseline (Step 0) | Step 1 (notary + saml) | Step 2 (+ rotation) | Step 3 (+ dynamic) | Step 4 (+ connect) |
|---|---|---|---|---|---|
| `internal/core` coverage map (`FuzzCoreOperationSequence`) | 486,874 B (~475 KiB) — matches this ADR's Context-section figure of "about 480 KB" | 485,107 B (~473.7 KiB); **−1,767 B (−0.36%)** | 485,109 B (~473.7 KiB); flat vs. step 1 (+2 B, noise) | 485,115 B (~473.7 KiB); flat vs. step 2 (+6 B, noise) | 485,114 B (~473.7 KiB); flat vs. step 3 (−1 B, noise) |
| `keyorix-server` binary, `linux/amd64`, `-trimpath` | 100,937,259 B (~96.3 MiB) | 100,989,425 B (~96.3 MiB); flat (build noise, +0.05%) | 100,989,278 B (~96.3 MiB); flat vs. step 1 (−147 B, noise) | 100,994,799 B (~96.3 MiB); flat vs. step 2 (+5,521 B, noise) | 100,989,091 B (~96.3 MiB); flat vs. step 3 (−5,708 B, noise) |
| `go list -deps ./internal/core` total | 872 packages | 859 packages; **−13** | 853 packages; **−6** | 753 packages; **−100** | 746 packages; **−7** |
| ...of which cloud SDK packages (aws/azure/gcp/vault) | 131 (64 `aws-sdk-go-v2`, 33 `azure-sdk-for-go`, 34 `cloud.google.com/go`, 0 `hashicorp/vault/api` — Connect's Vault backend has no official SDK dependency today) | 131, unchanged — notary and saml carry no cloud SDK | 128; **−3** — `internal/rotation`'s `awsiam.go`/`azure.go`/`gcpsa.go` each pull one cloud SDK into core's graph today, gone once rotation is behind `ports` | 128, unchanged — see note below | 121 (58 `aws-sdk-go-v2`, 32 `azure-sdk-for-go`, 31 `cloud.google.com/go`, 0 `hashicorp/vault/api`); **−7** — the first step where the *total* package drop (7) equals the cloud-SDK drop (7) exactly: `internal/connect`'s own non-SDK code (manager, ref-matching, the four connector constructors' non-SDK glue) added nothing to core's graph beyond what `connect`+`connecttypes` already contributed pre-step-4, so every package this step actually removed was an AWS/Azure/GCP SDK leaf |
| ...of which the 6 ADR-109 integration packages | `connect` (+ `connecttypes`, which stays), `rotation`, `dynamic`, `encryption`, `notary`, `saml` — all present, tracked exactly by `internal/core/dependency_guard_test.go`'s `coreIntegrationDeps` allowlist | `connect` (+ `connecttypes`), `rotation`, `dynamic`, `encryption` — notary and saml removed from the allowlist and confirmed absent from `go list -deps` | `connect` (+ `connecttypes`), `dynamic`, `encryption` — rotation removed too, confirmed absent | `connect` (+ `connecttypes`), `encryption` — dynamic removed too, confirmed absent | `encryption` only — connect removed too, confirmed absent; `connecttypes` (the carve-out, no SDK dependency) still appears in `go list -deps`, now reached only via `encryption` → `internal/config` → `internal/connect/connecttypes` (not tracked by the allowlist — see its own doc comment) rather than via `internal/connect` itself, which no longer appears at all |

Step 0 itself does not change any of these numbers — it adds `internal/core/ports` (the target
interface shapes, unwired) and the two dependency-guard tests (`internal/core`'s allowlist,
`internal/core/ports`'s own must-stay-free guard) without moving any existing import.

**Step 1** swaps `internal/core`'s direct use of `internal/notary` (`checkpointNotary
notary.Notary`, and the free function `notary.VerifyReceipt`) and `internal/saml`
(`SSOProvider.SAML SAMLAuthn`, whose `ParseResponse` returned `*saml.AssertionInfo`) for
`ports.TimestampNotary` + the new `ports.VerifyReceiptFunc`, and `ports.SAMLServiceProvider` +
`ports.SAMLAssertion`, respectively. `internal/notary.Receipt` and `internal/saml.AssertionInfo`
become type aliases of their `ports` equivalents, so `*notary.RFC3161` and `*saml.Provider`
satisfy the new interfaces directly with no adapter, and every existing caller/test that
constructed or matched on the old concrete types keeps compiling unchanged. Both are wired from
one new call site, `server/main.go`'s `DefaultIntegrations` (replacing two previously-separate,
non-adjacent inline blocks) — the single wiring point later steps (rotation, dynamic, connect)
extend, and the CLI/server split's server-mode core builder calls once these two integrations
matter there too. `checkpointAnchorVerify` is wired by the same setter as its trust roots
(`SetCheckpointAnchorRoots(roots, verify)`), since the two are only ever meaningful together;
`CheckpointAnchorVerifiable()` now requires both, and a call with an anchor recorded but no
verifier wired fails closed exactly as a missing trust root already did.

The coverage-map and binary-size deltas are both small, and that is expected, not a shortfall:
notary and saml are two of the smallest integrations (context table: "6–30 KB each" in isolation,
versus 116–132 KB each for connect/rotation/dynamic/encryption), and `server/main.go` still wires
the real `internal/notary`/`internal/saml` implementations for a full-featured server — a build
still includes them, so the server binary is unaffected until the lean/air-gapped build (step 6)
actually drops them via build tags. What step 1 proves is the *pattern* and the *dependency-count*
guarantee: `internal/core`'s production import graph dropped by exactly the 13 packages
notary+saml (and their third-party deps: `digitorus/pkcs7`, `digitorus/timestamp`,
`crewjam/saml`, `goxmldsig`, `mattermost/xml-roundtrip-validator`, transitively) pulled in, caught
exactly by `dependency_guard_test.go`'s exact-match allowlist shrink.

**Step 2** swaps `internal/core`'s direct use of `internal/rotation` for
`ports.RotationExecutorResolver` (`rotationManager`, `SetRotationManager`) and
`ports.RotationPartialError` (the `errors.As` check in `rotateOneSecret`/`RotateSecretOnDemand`).
Unlike step 1, `internal/rotation.Executor` and `internal/rotation.GeneratingExecutor` are
themselves *interfaces*, not structs — Go allows aliasing an interface type exactly like a struct
(`type Executor = ports.RotationExecutor`), so `*rotation.Manager`'s existing `Get`/`Names`
methods (whose signatures name `Executor`, not `ports.RotationExecutor`) satisfy
`ports.RotationExecutorResolver` after the alias with no changes to `Manager` itself, and every
concrete executor (Postgres/MySQL/Mongo/Redis/AWS-IAM/GCP-SA/Azure-App) keeps satisfying both
names identically. `internal/core/rotation_executor.go`'s own `exec.(rotation.GeneratingExecutor)`
type assertion becomes `exec.(ports.GeneratingRotationExecutor)` directly — a type assertion
targets any interface with a compatible method set, so this needed no alias, just a qualifier
swap. `PartialRotationError` is a struct with two methods (`Error`/`Unwrap`), so — same as step
1's `NotaryReceipt`/`SAMLAssertion` — it aliases the other way: `ports.RotationPartialError` is
the canonical declaration (methods included, since a type alias cannot carry methods of its own),
and `internal/rotation.PartialRotationError` becomes a bare alias of it; every `&PartialRotationError{...}`
literal already in `awsiam.go`/`azure.go`/`gcpsa.go` keeps compiling unchanged. All of
`internal/core`'s existing rotation tests (`rotation_executor_test.go`,
`rotation_executor_deps_test.go`, `rotation_executor_registry_exhaustiveness_test.go`,
`rotation_orchestrator_lock_test.go`, `rotation_dryrun_test.go`) needed zero edits — none of them
construct a bare `rotation.Executor`/`rotation.PartialRotationError` value in a way an alias
doesn't cover transparently. Rotation-executor wiring (previously a large standalone block deep in
`server/main.go`, well after the notary/SSO wiring) moves into `DefaultIntegrations` as
`wireBackendRotation`, the third component alongside `wireCheckpointNotary`/`wireHumanSSO`.

The map and binary deltas are flat again, for the same reason as step 1: `server/main.go` still
wires the real backend executors for a full server. The dependency count, however, moves by more
than step 1's non-cloud packages did — rotation is the first integration in this ADR whose direct
core-facing package itself has zero cloud SDK code (`rotation.go` only pulls in `fmt`/`regexp`/
`strings`) but whose SIBLING files in the same package (`awsiam.go`, `azure.go`, `gcpsa.go`) do,
one cloud SDK each — so `internal/core`'s cloud-SDK dependency count drops for the first time in
this ADR (131 → 128), ahead of the two steps (connect, encryption) expected to move it the most.

**Step 3** swaps `internal/core`'s direct use of `internal/dynamic` for `ports.DynamicBackendFactory`
(`dynamicEngineFactory`, `SetDynamicEngineFactory`), `ports.DynamicBackendEngine`
(`cleanupOrphanedRole`'s `engine` parameter), and `ports.SanitizeErrorMessage`/`ports.RedactSensitive`
(the free-function error-redaction helpers `RevokeLease` calls before logging a backend error).
`internal/dynamic.CredentialEngine` and `internal/dynamic.Credential` are themselves aliased to
their `ports` equivalents (an interface and a struct respectively — the same two shapes step 1/2
already covered), so every backend engine's `Issue`/`Revoke`/`Renew` implementation satisfies
`ports.DynamicBackendEngine` with no adapter. `ports.DynamicBackendEngine` gained one method,
`RevokeInvalidatesCredential`, that Step 0's original draft had missed relative to
`internal/dynamic.CredentialEngine`'s actual current shape — found by cross-checking the two side
by side before aliasing, not by a build failure (a missing interface method doesn't fail to build
until something tries to satisfy the narrower interface; it would have surfaced as a silent
capability gap instead). `ports.DynamicBackendFactory` itself is a plain function type, not an
interface with an `Engine` method — Step 0's original draft used an interface, but the shape
`internal/core.dynamicEngineFactory` actually holds (and always held) is a bare closure
(`func(string) (dynamic.CredentialEngine, error)`), the same pattern `ports.VerifyReceiptFunc`
already established in step 1; revised here rather than adapted around, since nothing was wired
against the original interface shape yet. `SanitizeErrorMessage`/`RedactSensitive`'s
implementation moves to `ports` outright (not just aliased) since it is a small, pure,
stdlib-only text filter (`regexp`/`strings`, no third-party or cloud dependency) that `internal/core`
calls directly — `internal/dynamic`'s own `redact.go` becomes a two-line re-export so its existing
callers (`server/http/handlers/dynamic_secrets.go`, `internal/dynamic`'s own
`log_redaction_guard_test.go`, which recognizes the call by method name only, not by package
qualifier) keep working unchanged.

Unlike steps 1/2, `internal/core.dynamicEngine`'s pre-ADR-109 behavior fell back to calling
`dynamic.New` directly whenever no factory was wired (`SetDynamicEngineFactory` is test-only in
today's codebase — no production caller had ever used it) — so removing the fallback is a real,
intentional behavior change, not just an import swap: a `*KeyorixCore` built without going through
`server/main.go`'s `DefaultIntegrations` now fails closed with "dynamic secrets are unavailable: no
engine factory configured" instead of silently working. `wireDynamicSecrets` (`DefaultIntegrations`'s
fourth component) always wires the real `dynamic.New`-backed factory unconditionally — there is no
top-level "dynamic secrets enabled" config flag to gate it on (each `DynamicSecretConfig` opts a
project into a specific backend individually) — mirroring the removed fallback's own
unconditional behavior exactly. A new test, `TestDynamicSecrets_NoFactoryConfigured_FailsClosed`,
pins the fail-closed behavior directly (ADR-109's "never fails open" is now machine-checked, not
just asserted). This changed behavior surfaced immediately in existing tests: four handler-package
test helpers (`server/http/handlers/handlers_s8_test.go`'s `freshCoreS8`,
`handlers_s11_test.go`'s `freshCoreS11`, `handlers_s12_test.go`'s `freshCoreS12WithAdmin`) built a
bare `*KeyorixCore` directly and relied on the old implicit fallback reaching a real (if
unreachable-in-tests) backend; each now wires the same factory `wireDynamicSecrets` uses,
explicitly, at the helper level.

The dependency-count drop here is far larger than steps 1/2's — 100 packages, not roughly a
dozen — because `internal/dynamic`'s MongoDB, Redis, and Kubernetes backends each pull in a large
driver dependency tree of their own (`go.mongodb.org/mongo-driver`, `go-redis`, and especially
`k8s.io/client-go` — client-go alone is one of the largest dependency trees in the Go ecosystem),
none of which any other integration `internal/core` still imports shares. The cloud-SDK-specific
count, by contrast, stayed flat (128 → 128): `internal/dynamic`'s AWS-STS/Azure/GCP backends draw
on the same underlying SDK packages `internal/connect` and `internal/encryption` (not yet
decoupled) already pull into core's graph, so removing dynamic's own copies of those references
doesn't shrink the *distinct*-package count — the cloud-SDK number will move only once connect and
encryption themselves move behind `ports`. Steps 4–5 each report a new column here as they land.

**Step 4** swaps `internal/core`'s direct use of `internal/connect` for `ports.ConnectorResolver`
(`connectManager`, `SetConnectManager`) and `ports.RefHasDotSegment`/`ports.RefWithinPrefix` (the
traversal-guard/prefix-match helpers `refMatches` calls for ADR-045 per-reference RBAC).
`internal/connect.Connector` becomes a type alias of `ports.Connector` — the same struct/interface
aliasing pattern steps 1–3 already established, here applied to an interface with three methods
(`Name`/`Type`/`GetSecret`) rather than the struct aliases steps 1 and 3 used — so every existing
connector implementation (`awssm.go`, `azurekv.go`, `gcpsm.go`, `vault.go`) satisfies
`ports.ConnectorResolver`'s element type with no adapter, and `*connect.Manager`'s existing
`Get`/`Names` methods (whose signatures name `Connector`, not `ports.Connector`) satisfy
`ports.ConnectorResolver` directly after the alias, mirroring `internal/rotation.Executor`'s own
alias of `ports.RotationExecutor` (step 2) rather than `RotationPartialError`'s struct-aliased-the-
other-way shape (steps 1/3) — the choice depends on which side already declares the canonical
shape, not on a fixed convention. `ports.RefHasDotSegment`/`ports.RefWithinPrefix` move to `ports`
outright (not just aliased), same as step 3's `SanitizeErrorMessage`/`RedactSensitive` — small,
pure, stdlib-only text/path logic — with `internal/connect/connect.go`'s own
`RefHasDotSegment`/`RefWithinPrefix`/`refWithinPrefix` becoming two-line re-exports so existing
callers (`prefixAllowed`, and this package's own tests, which call the unexported
`refWithinPrefix` directly by name) keep working unchanged.

Unlike steps 1–3, connect's wiring was not already isolated behind its own `wireXxx` helper before
this step — the ~120-line connector-construction switch, ownership resolution, and boot-time drift
check lived inline inside `initializeCoreService`, running *after* `DefaultIntegrations`'s call
site rather than through it. This step extracts that block verbatim into `wireConnect`
(`server/main.go`), called from `DefaultIntegrations` alongside `wireCheckpointNotary`/
`wireHumanSSO`/`wireBackendRotation`/`wireDynamicSecrets` — the "later step only has one wiring
call site to extend" `DefaultIntegrations` doc comment (steps 1–3) is now true in practice, not
just in the comment. `wireConnect` still calls `log.Fatalf` for the same boot-time
misconfigurations the original inline block already treated as fatal (ADR-082: an unrecognized
connector type, a `gcp-secret-manager` connector missing `project_id`, an ownership-resolution
failure, or a manager/ownership key-set mismatch) — an intentional divergence from
`wireCheckpointNotary`'s `error`-returning shape, since `DefaultIntegrations` propagating an error
here would only convert an already-fatal `log.Fatalf` into a different fatal exit path, with no
behavior change to preserve. `wireConnect` depends on `coreService.Storage()` (for
`resolveConnectorOwnership`/`warnConnectConfigDrift`), which `core.NewKeyorixCore(store)` sets well
before `DefaultIntegrations` is ever called — folding this wiring into `DefaultIntegrations` moves
it earlier in boot (before notification-channel wiring, previously after) with no dependency on
anything wired in between.

This is the step the ADR's own "Order of work" called "the largest surface" (four connector
backends: AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, Vault), and it is also the
first step where the *dependency-count* drop (7) exactly equals the *cloud-SDK* drop (7) — see the
table cell above for why: `internal/connect`'s own code contributed nothing to core's graph beyond
what `dynamic`/`encryption` already pulled in from the same cloud SDKs, so every package this step
actually removed was an SDK leaf, not glue code. The map-size and binary-size deltas stay flat for
the same reason steps 1–3's did: `server/main.go` still wires the real `internal/connect`
implementation unconditionally when `connect.enabled` is configured, so a full server build is
unaffected until the lean/air-gapped build (step 6) drops it via build tags.
