# Package invariants index

Every core package has an `INVARIANTS.md` next to its code: the rules a change there must
keep, each linked to the automated check that enforces it, or marked `UNGUARDED` with a
follow-up issue (label `unguarded-invariant`). **Read the relevant file(s) before changing
code in any of these packages.** See the root `CLAUDE.md`'s "Spec first, independent tests,
package invariants" convention for when this is required.

These are not invented — every entry traces to an ADR, an existing test/fuzzer/static guard,
`docs/security-closures.d/`, `docs/adr-conformance-enforced.tsv`, or a documented review
finding. If you discover or add an invariant while working in a package, add it to that
package's file in the same PR; if a change would have to break one, stop and ask rather than
silently removing it.

| Package | File | Invariants | Guarded | UNGUARDED |
|---|---|---|---|---|
| `internal/core` | [internal/core/INVARIANTS.md](../internal/core/INVARIANTS.md) | 153 | 153 | 0 |
| `internal/storage` | [internal/storage/INVARIANTS.md](../internal/storage/INVARIANTS.md) | 44 | 41 | 3 |
| `internal/storage/store` | [internal/storage/store/INVARIANTS.md](../internal/storage/store/INVARIANTS.md) | 75 | 75 | 0 |
| `internal/encryption` | [internal/encryption/INVARIANTS.md](../internal/encryption/INVARIANTS.md) | 44 | 44 | 0 |
| `internal/auditverify` | [internal/auditverify/INVARIANTS.md](../internal/auditverify/INVARIANTS.md) | 21 | 21 | 0 |
| `server/middleware` | [server/middleware/INVARIANTS.md](../server/middleware/INVARIANTS.md) | 37 | 37 | 0 |
| `server/http` (+ `handlers`) | [server/http/INVARIANTS.md](../server/http/INVARIANTS.md) | 40 | 39 | 1 |
| `server/grpc` (+ `interceptors`) | [server/grpc/INVARIANTS.md](../server/grpc/INVARIANTS.md) | 20 | 20 | 0 |
| `server/grpc/services` | [server/grpc/services/INVARIANTS.md](../server/grpc/services/INVARIANTS.md) | 10 | 10 | 0 |
| `cli` | [cli/INVARIANTS.md](../cli/INVARIANTS.md) | 19 | 19 | 0 |
| `web/src` | [web/src/INVARIANTS.md](../web/src/INVARIANTS.md) | 11 | 11 | 0 |
| `internal/solewriter` | [internal/solewriter/INVARIANTS.md](../internal/solewriter/INVARIANTS.md) | 17 | 17 | 0 |
| `internal/pqwrap` | [internal/pqwrap/INVARIANTS.md](../internal/pqwrap/INVARIANTS.md) | 9 | 8 | 1 |
| `internal/serverguard` | [internal/serverguard/INVARIANTS.md](../internal/serverguard/INVARIANTS.md) | 2 | 2 | 0 |
| `server/admin` | [server/admin/INVARIANTS.md](../server/admin/INVARIANTS.md) | 4 | 4 | 0 |
| `internal/faultstorage` | [internal/faultstorage/INVARIANTS.md](../internal/faultstorage/INVARIANTS.md) | 3 | 3 | 0 |
| `internal/secretenv` | [internal/secretenv/INVARIANTS.md](../internal/secretenv/INVARIANTS.md) | 1 | 1 | 0 |
| `internal/fuzzutil/grammar` | [internal/fuzzutil/grammar/INVARIANTS.md](../internal/fuzzutil/grammar/INVARIANTS.md) | 1 | 1 | 0 |
| `internal/k8ssync` | [internal/k8ssync/INVARIANTS.md](../internal/k8ssync/INVARIANTS.md) | 2 | 2 | 0 |
| `operator/internal/controller` | [operator/internal/controller/INVARIANTS.md](../operator/internal/controller/INVARIANTS.md) | 4 | 4 | 0 |
| **Total** | | **517** | **512** | **5** |

## Highest-priority UNGUARDED gaps

One UNGUARDED item is flagged as materially more important than the rest, and one guarded
item has a known CI gap. Re-checked 2026-10-30 against `origin/main`.

- **ADR-103's Postgres RLS tenancy layer is a ratified design with zero implementation and
  zero tests** (`internal/storage/INVARIANTS.md` INV-STORAGE-31/32) — confirmed by direct grep:
  `rg -i 'ROW LEVEL SECURITY|app\.current_tenant|keyorix_migrator' internal/storage` matches only
  `internal/storage/INVARIANTS.md` itself, no code or test.
- **`web/src/types` drift check does not run on an `openapi.yaml`-only PR** (INV-WEB-05,
  `web/src/INVARIANTS.md`). The guard exists (`openapiDrift.test.ts` and its calibration
  `openapiDrift.engine.test.ts`), but `web-ci.yml` is path-filtered to `web/**`. The fix is
  adding `server/http/handlers/openapi.yaml` to that workflow's `paths` (a `.github/**` change,
  not done here).

No longer gaps, each guard re-run on 2026-10-30 and green: INV-CLI-11 (reserved
environment-variable filter in `cli/cmd/run.go`, `cli/cmd/run_env_filter_test.go`) and
INV-ENCRYPTION-25 (`TestWipeBytesSweep_EveryKeyLocalIsWipedOnEveryReturn`, the `wipeBytes`
completeness sweep). The sibling `internal/core` gap (INV-CORE-34) has
`internal/core/guards/besteffort_callsite_guard_test.go`.

## Ledger gaps (informational, not filed as issues)

Seeded 2026-11-11 (LEDGER-SEED-1): `docs/adr-conformance-enforced.d/` now holds rows for
`server/middleware` (5), `server/grpc` + `interceptors` + `services` (7) and `cli` (2), each
re-run before it was transcribed. Only invariants whose guard also enforces a property an ADR
states got a row; the rest of those packages' guarded invariants (CSRF, cookie attributes,
security headers, body cap, rate limits, the interceptor chain, the `run` env filter, ...)
state no ADR property and stay guarded by their tests alone. That is a deliberate scope, not a
ledger gap.

## Maintaining this index

- The table is written by hand; no generator exists. `TestInvariantsIndexHasNoDuplicateRowsAndTotalsAddUp`
  (`internal/docsdrift`) fails on a package listed twice, on a row whose Invariants is not
  Guarded + UNGUARDED, on a Total that is not the column sums, and on any line of this table
  that matches neither the package-row nor the Total pattern (it would otherwise be left out
  of the sums). It does not check a row against its package's files or that the linked file
  exists. When two PRs both change a row, keep ONE row with the current counts.
- Package-count and guarded/unguarded totals above are a snapshot (re-counted 2026-11-11,
  including `INVARIANTS.d/` fragments, which are one invariant per file). They drift as
  invariants are added, closed, or re-guarded — re-derive by
  counting `- **INV-<PKG>-NN` bullets per file plus the `INVARIANTS.d/` fragments, and per
  bullet or fragment whether its own text contains
  `UNGUARDED`. **Do not `grep -c UNGUARDED` the whole file** — every file's own intro line
  ("Format: `INV-<PKG>-NN ... UNGUARDED (#issue)`") contains the literal word and will inflate
  a naive count by one per file (this is exactly what happened on the first draft of this
  table: a raw `grep -c` gave 50 UNGUARDED/169 guarded; the bullet-boundary-aware count caught
  that, then a second pass found INV-STORAGE-34 was already resolved by a guard discovered in
  a different package's research — `cli/internal/depguard` — moving it from UNGUARDED to
  guarded. Both corrections landed before any issue was filed against a wrong number; final:
  36 UNGUARDED / 183 guarded).
- When a package not yet covered here gets its first `INVARIANTS.md`, add a row.
