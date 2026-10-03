# Package invariants index

Every core package has an `INVARIANTS.md` next to its code: the rules a change there must
keep, each linked to the automated check that enforces it, or marked `UNGUARDED` with a
follow-up issue (label `unguarded-invariant`). **Read the relevant file(s) before changing
code in any of these packages.** See the root `CLAUDE.md`'s "Spec first, independent tests,
package invariants" convention for when this is required.

These are not invented — every entry traces to an ADR, an existing test/fuzzer/static guard,
`docs/security-closures.tsv`, `docs/adr-conformance-enforced.tsv`, or a documented review
finding. If you discover or add an invariant while working in a package, add it to that
package's file in the same PR; if a change would have to break one, stop and ask rather than
silently removing it.

| Package | File | Invariants | Guarded | UNGUARDED |
|---|---|---|---|---|
| `internal/core` | [internal/core/INVARIANTS.md](../internal/core/INVARIANTS.md) | 40 | 33 | 7 |
| `internal/storage` | [internal/storage/INVARIANTS.md](../internal/storage/INVARIANTS.md) | 35 | 26 | 9 |
| `internal/storage/store` | [internal/storage/store/INVARIANTS.md](../internal/storage/store/INVARIANTS.md) | 20 | 15 | 5 |
| `internal/encryption` | [internal/encryption/INVARIANTS.md](../internal/encryption/INVARIANTS.md) | 27 | 23 | 4 |
| `internal/auditverify` | [internal/auditverify/INVARIANTS.md](../internal/auditverify/INVARIANTS.md) | 15 | 11 | 4 |
| `server/middleware` | [server/middleware/INVARIANTS.md](../server/middleware/INVARIANTS.md) | 22 | 19 | 3 |
| `server/http` (+ `handlers`) | [server/http/INVARIANTS.md](../server/http/INVARIANTS.md) | 19 | 18 | 1 |
| `server/grpc` (+ `interceptors`) | [server/grpc/INVARIANTS.md](../server/grpc/INVARIANTS.md) | 13 | 8 | 5 |
| `server/grpc/services` | [server/grpc/services/INVARIANTS.md](../server/grpc/services/INVARIANTS.md) | 8 | 7 | 1 |
| `cli` | [cli/INVARIANTS.md](../cli/INVARIANTS.md) | 13 | 9 | 4 |
| `web/src` | [web/src/INVARIANTS.md](../web/src/INVARIANTS.md) | 7 | 0 | 7 |
| **Total** | | **219** | **169** | **50** |

## Highest-priority UNGUARDED gaps

A few UNGUARDED items are flagged as materially more important than the rest — worth reading
even if you skip everything else:

- **`cli/cmd/run.go`'s reserved-environment-variable filter has zero test coverage**
  (`cli/INVARIANTS.md` INV-CLI-11) — this is the fix for the exact bug class (#1816, a secret
  named `LD_PRELOAD` getting code-exec) the CLI-server split (ADR-108) was rebuilt to prevent.
- **ADR-103's Postgres RLS tenancy layer is a ratified design with zero implementation and
  zero tests** (`internal/storage/INVARIANTS.md` INV-STORAGE-31/32) — confirmed by direct grep,
  no `ROW LEVEL SECURITY`/`app.current_tenant` reference anywhere in `internal/storage`.
- **No structural completeness guard exists for "every best-effort post-commit call recovers a
  panic"** in `internal/core` (INV-CORE-34) or for "every key-shaped byte slice gets
  `wipeBytes`" in `internal/encryption` (INV-ENCRYPTION-25) — both are point-fixes after live
  fuzz findings, the same recurring shape, in two different packages.
- **`web/src/types` has no generation/drift check against the server's own OpenAPI
  document** (`web/src/INVARIANTS.md` INV-WEB-05) — asymmetric with `cli/`'s generated API
  client from the same spec.

## Ledger gaps (informational, not filed as issues)

`docs/adr-conformance-enforced.tsv` has zero rows for `server/middleware`, `server/grpc`,
`server/grpc/interceptors`, or `cli`, despite real, currently-passing tests enforcing several
properties documented in those packages' files. Seeding rows for these is a low-effort
follow-up distinct from the UNGUARDED gaps above (those have no test at all; these have a test
but no ledger entry).

## Maintaining this index

- Package-count and guarded/unguarded totals above are a snapshot as of this writing
  (2026-10-03). They will drift as invariants are added, closed, or re-guarded — re-derive by
  counting `- **INV-<PKG>-NN` lines and `UNGUARDED` occurrences per file rather than trusting
  this table blindly if it looks stale.
- When a package not yet covered here gets its first `INVARIANTS.md`, add a row.
