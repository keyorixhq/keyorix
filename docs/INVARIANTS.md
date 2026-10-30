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
| `internal/core` | [internal/core/INVARIANTS.md](../internal/core/INVARIANTS.md) | 131 | 129 | 2 |
| `internal/storage` | [internal/storage/INVARIANTS.md](../internal/storage/INVARIANTS.md) | 43 | 40 | 3 |
| `internal/storage/store` | [internal/storage/store/INVARIANTS.md](../internal/storage/store/INVARIANTS.md) | 67 | 67 | 0 |
| `internal/encryption` | [internal/encryption/INVARIANTS.md](../internal/encryption/INVARIANTS.md) | 40 | 40 | 0 |
| `internal/auditverify` | [internal/auditverify/INVARIANTS.md](../internal/auditverify/INVARIANTS.md) | 20 | 20 | 0 |
| `server/middleware` | [server/middleware/INVARIANTS.md](../server/middleware/INVARIANTS.md) | 33 | 32 | 1 |
| `server/http` (+ `handlers`) | [server/http/INVARIANTS.md](../server/http/INVARIANTS.md) | 40 | 39 | 1 |
| `server/grpc` (+ `interceptors`) | [server/grpc/INVARIANTS.md](../server/grpc/INVARIANTS.md) | 20 | 18 | 2 |
| `server/grpc/services` | [server/grpc/services/INVARIANTS.md](../server/grpc/services/INVARIANTS.md) | 9 | 9 | 0 |
| `cli` | [cli/INVARIANTS.md](../cli/INVARIANTS.md) | 19 | 17 | 2 |
| `web/src` | [web/src/INVARIANTS.md](../web/src/INVARIANTS.md) | 11 | 7 | 4 |
| `internal/solewriter` | [internal/solewriter/INVARIANTS.md](../internal/solewriter/INVARIANTS.md) | 16 | 16 | 0 |
| `internal/pqwrap` | [internal/pqwrap/INVARIANTS.md](../internal/pqwrap/INVARIANTS.md) | 9 | 7 | 2 |
| `internal/serverguard` | [internal/serverguard/INVARIANTS.md](../internal/serverguard/INVARIANTS.md) | 2 | 2 | 0 |
| `server/admin` | [server/admin/INVARIANTS.md](../server/admin/INVARIANTS.md) | 2 | 2 | 0 |
| `internal/faultstorage` | [internal/faultstorage/INVARIANTS.md](../internal/faultstorage/INVARIANTS.md) | 3 | 3 | 0 |
| **Total** | | **465** | **448** | **17** |

## Highest-priority UNGUARDED gaps

A few UNGUARDED items are flagged as materially more important than the rest — worth reading
even if you skip everything else:

- **`cli/cmd/run.go`'s reserved-environment-variable filter has zero test coverage**
  (`cli/INVARIANTS.md` INV-CLI-11) — this is the fix for the exact bug class (#1816, a secret
  named `LD_PRELOAD` getting code-exec) the CLI-server split (ADR-108) was rebuilt to prevent.
- **ADR-103's Postgres RLS tenancy layer is a ratified design with zero implementation and
  zero tests** (`internal/storage/INVARIANTS.md` INV-STORAGE-31/32) — confirmed by direct grep,
  no `ROW LEVEL SECURITY`/`app.current_tenant` reference anywhere in `internal/storage`.
- **No structural completeness guard exists for "every key-shaped byte slice gets
  `wipeBytes`"** in `internal/encryption` (INV-ENCRYPTION-25) — a point-fix after live fuzz
  findings. The sibling gap in `internal/core` (INV-CORE-34, "every best-effort post-commit call
  recovers a panic") now has `besteffort_callsite_guard_test.go`.
- **`web/src/types` drift check covers only the schema'd wire types, and does not run on
  an `openapi.yaml`-only PR** (`web/src/INVARIANTS.md` INV-WEB-05) — guarded by
  `openapiDrift.test.ts`, but `web-ci.yml` is path-filtered to `web/**`.

## Ledger gaps (informational, not filed as issues)

`docs/adr-conformance-enforced.tsv` has zero rows for `server/middleware`, `server/grpc`,
`server/grpc/interceptors`, or `cli`, despite real, currently-passing tests enforcing several
properties documented in those packages' files. Seeding rows for these is a low-effort
follow-up distinct from the UNGUARDED gaps above (those have no test at all; these have a test
but no ledger entry).

## Maintaining this index

- The table is written by hand; no generator exists. `TestInvariantsIndexHasNoDuplicateRowsAndTotalsAddUp`
  (`internal/docsdrift`) fails on a package listed twice, on a row whose Invariants is not
  Guarded + UNGUARDED, and on a Total that is not the column sums. It does not check a row
  against its package's files. When two PRs both change a row, keep ONE row with the current counts.
- Package-count and guarded/unguarded totals above are a snapshot (re-counted 2026-10-30,
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
