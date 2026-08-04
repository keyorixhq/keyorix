# ADR-069: Testing strategy — tiers, coverage methodology, and the no-exclusion rule

## Status

Accepted. Supersedes the ad-hoc package-exclusion practice introduced in `b81829b4`
and `7ccb7dda` (2026-04-27). Provides the test-gate obligations referenced by
[ADR-067](adr-067-release-lifecycle-support-policy.md) and constrains the
supported-combination policy in [ADR-068](adr-068-feature-flags.md).

## Context

The suite is large: 1,285 test files, 16,382 test functions, 11 fuzz harnesses, 22
benchmarks, backed by CodeQL, Semgrep, gosec, Trivy, OSV, govulncheck, gitleaks, a
ZAP/Nuclei DAST rig, and SBOM generation. By breadth of tooling this is a strong
position.

Two structural defects undermine it.

### 1. CI does not run 2,920 tests, and the coverage gate excludes them

The `build-and-test` job filters six packages out of `go list ./...`:

| Package | Test files | Tests | Legitimate? |
|---|---|---|---|
| `internal/core` | 294 | 2,318 | No |
| `server/http` | 88 | 383 | No |
| `server/middleware` | 22 | 156 | No |
| `internal/storage/remote` | 4 | 43 | No |
| `internal/cli` | 5 | 20 | No |
| `server/proto/pb` | 0 | 0 | Yes — generated |

This is the domain core and the entire HTTP and middleware layer: authentication,
authorisation, RBAC enforcement, and request handling. In a secrets manager that is
the code where a defect is a vulnerability rather than a bug.

The exclusions were introduced on 2026-04-27 because of **two** failing tests —
`TestAuthentication` (hardcoded tokens removed by a security fix) and
`TestListSecretsWithSharingInfo` (mock mismatch). Both pass today. The exclusion
outlived its cause by three months, and the excluded code kept changing without test
feedback: see #1223, repairing an `internal/core` suite broken by `IsProjectMember`,
the SSRF guard, and SAML `IsActive` changes.

The consequence reaches past engineering. `COVERAGE_FLOOR` is 80%, but it is computed
over a package set that omits the domain core. ADR-067 commits us to compliance
evidence packs, and the product's positioning rests on auditable rigour. A coverage
figure quoted in an evidence pack or a security questionnaire that silently excludes
the security-critical packages is not a defensible claim — and `ci.yml` is public, so
the exclusion is discoverable by anyone who reads it.

### 2. There are no test tiers

Only four build tags appear across 1,285 test files, all platform guards
(`darwin`, `linux`). Nothing separates unit from integration from end-to-end. `make
test` is `go test -race ./...`. The suite is one undifferentiated pool.

This is why a single misbehaving package can destroy the whole signal, and it is what
made wholesale exclusion look like the only available remedy. Measured directly:
`server/http` does not fail — it **hangs**, exceeding a 900s timeout, with dozens of
`database/sql.(*DB).connectionOpener` goroutines blocked in `select` for one to six
minutes. Tests open `sql.DB` handles and never close them. CI's `-timeout 600s` means
that package alone would exhaust the job budget even without the hang.

By contrast `server/middleware` passes cleanly in 4.7 seconds and can be restored
immediately.

## Decision

### 1. No package may be excluded from CI

Generated code (`server/proto/pb`) is the only permitted exclusion, and it is
justified inline. Excluding a package because tests in it fail is prohibited.

**When a test fails and cannot be fixed immediately**, the remedy is to quarantine the
*individual test*, never the package:

```go
func TestSomething(t *testing.T) {
    t.Skip("QUARANTINE: #1234 — mock mismatch after SSRF guard. Expires 2026-09-01.")
```

Every quarantine carries an issue reference and an expiry date. A `preflight` check
fails the build on any quarantine past its expiry. Quarantine is visible, bounded, and
attributable; package exclusion is none of those, which is precisely why one survived
three months unnoticed.

### 2. Test tiers, enforced by build tag

| Tier | Build tag | Contents | Budget | Runs on |
|---|---|---|---|---|
| Unit | *(none)* | Pure logic. No DB, no network, no filesystem. | **< 60s** | Every commit |
| Integration | `integration` | Real SQLite and PostgreSQL, real handlers, real middleware chain | < 10 min | Every PR |
| E2E | `e2e` | Full stack in containers, including the operator | < 20 min | Merge to main, and release |
| Fuzz | `gofuzz` | 11 harnesses | Continuous | Scheduled |

Budgets are enforced, not advisory. A tier that exceeds its budget fails the build,
which forces the cost to be addressed while it is still small rather than resolved by
exclusion once it is large.

**The pyramid is deliberately middle-heavy.** The canonical shape — a broad unit base
tapering sharply — is wrong for this product. Keyorix's risk is concentrated in the
interaction between authorisation, storage, and cryptography: AAD binding against
stored rows, RBAC evaluated across the HTTP boundary, audit-chain integrity under
concurrent writes. None of that is reachable by unit tests over pure functions. We
optimise for the integration tier and accept that it is larger than convention
suggests.

### 3. Risk-based coverage, reported as two numbers

A single global percentage optimises for whatever is cheapest to cover, which is never
the dangerous code. Coverage is therefore tiered:

| Set | Packages | Floor | Additional gate |
|---|---|---|---|
| **Critical** | auth, RBAC, crypto, audit hash chain, AAD binding, licence validation, fail-closed paths | **95% line and branch** | Mutation testing |
| **Standard** | everything else | 80% line | — |

Both numbers are reported separately and never blended. A blended figure conceals
exactly the signal that matters.

Mutation testing (`gremlins` or `go-mutesting`) runs on the critical set only. It is
too slow for the whole tree, and the critical set is where it answers the question
line coverage cannot: whether 95% coverage means 95% of behaviour is asserted, or
merely that 95% of lines were executed by tests that would pass regardless.

### 4. Mandatory test types

Already in place and remaining mandatory: unit, integration, fuzzing, SAST (CodeQL,
Semgrep, gosec), DAST (ZAP, Nuclei), SCA (Trivy, OSV, govulncheck), secret scanning,
licence scanning, SBOM generation.

Three additions, in priority order:

**a. Upgrade and migration tests.** ADR-067 promises direct LTS-to-LTS upgrades and
additive-only migrations within a maintained line. That promise currently has no test.
Required: restore a database captured at the previous designated release, migrate it
forward, and assert both schema and data integrity. Until this exists, the strongest
commitment in the support policy is unverified — and it is the commitment most likely
to be tested first by a real customer, on their production data, in an enclave we
cannot reach.

**b. Mutation testing on the critical set.** See §3.

**c. Air-gap bundle verification tests.** ADR-064's format, signature verification,
digest pinning, and anti-downgrade logic, exercised end to end — including negative
cases: tampered manifest, tampered component, unknown `key_id`, downgrade attempt,
and decompression-bomb guard.

**Explicitly not adopted yet.** Chaos engineering — premature before production
deployments exist. Performance gates — baseline and track, but do not gate; there is
no production workload to calibrate against, and a gate calibrated against a guess
produces false failures that teach the team to bypass gates.

### 5. Contract tests across the SDKs

Four SDKs (Go, Python, Node, Java) version in lockstep. Lockstep versioning is a
promise of behavioural equivalence, and nothing currently verifies it. A shared
contract suite run against each SDK is required before the next lockstep bump.

## Consequences

**Positive.** The coverage number becomes a claim that survives audit. Tiering means a
single leaked resource degrades one tier rather than the entire signal. The
quarantine rule keeps the fast path available under deadline pressure without letting
it become invisible, which is the actual failure mode this ADR exists to prevent.

**Negative.** Restoring the excluded packages will lower the reported coverage
figure, possibly well below 80%. That is the point: the current number is not real,
and a lower true number is more useful than a higher false one. The floor is
re-baselined from measurement once the packages are back, then ratcheted upward — it
is never lowered to accommodate a regression.

CI wall-clock time will rise. Tiering keeps the per-commit path fast; the cost lands
on the PR and merge paths, which is where it belongs.

## Implementation sequence

Ordered so that each step is independently verifiable and none is blocked on the one
after it.

1. **Re-enable `server/middleware`** — passes in 4.7s, no work required. *(This change.)*
2. **Fix the `server/http` connection-pool leak**, then re-enable. Tests open `sql.DB`
   handles without closing them; the fix is `t.Cleanup` on every handle. Worth
   checking whether the production handlers share the defect — this sits adjacent to
   the queued concurrent-`AutoMigrate` investigation.
3. **Run `internal/core`, `internal/cli`, `internal/storage/remote`**; fix what fails,
   quarantine per §1 what cannot be fixed immediately, re-enable all three.
4. **Re-baseline `COVERAGE_FLOOR`** from the true measurement. Only after steps 1–3;
   re-baselining earlier would lock in a number computed over the wrong package set.
5. **Introduce build-tag tiers** and split the CI job accordingly.
6. **Split critical-set coverage reporting**, then add mutation testing.
7. **Upgrade/migration test harness** — required before the first designated release
   under ADR-067, not before v1.0.

## Follow-ups

- Quarantine-expiry check in the `preflight` job
- Remove the `-timeout 600s` assumption once tiers exist; each tier gets its own
  budget
- SDK contract suite before the next lockstep version bump
