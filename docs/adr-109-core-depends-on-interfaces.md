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

| Metric | Baseline (Step 0) |
|---|---|
| `internal/core` coverage map (`FuzzCoreOperationSequence`) | 486,874 B (~475 KiB) — matches this ADR's Context-section figure of "about 480 KB" |
| `keyorix-server` binary, `linux/amd64`, `-trimpath` | 100,937,259 B (~96.3 MiB) |
| `go list -deps ./internal/core` total | 872 packages |
| ...of which cloud SDK packages (aws/azure/gcp/vault) | 131 (64 `aws-sdk-go-v2`, 33 `azure-sdk-for-go`, 34 `cloud.google.com/go`, 0 `hashicorp/vault/api` — Connect's Vault backend has no official SDK dependency today) |
| ...of which the 6 ADR-109 integration packages | `connect` (+ `connecttypes`, which stays), `rotation`, `dynamic`, `encryption`, `notary`, `saml` — all present, tracked exactly by `internal/core/dependency_guard_test.go`'s `coreIntegrationDeps` allowlist |

Step 0 itself does not change any of these numbers — it adds `internal/core/ports` (the target
interface shapes, unwired) and the two dependency-guard tests (`internal/core`'s allowlist,
`internal/core/ports`'s own must-stay-free guard) without moving any existing import. Steps 1–5
each report a new row here as they land.
