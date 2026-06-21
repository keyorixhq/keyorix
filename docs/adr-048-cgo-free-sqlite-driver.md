# ADR-048: CGO-free SQLite driver for the embedded/air-gapped backend

## Status

Proposed.

Evaluate replacing the current CGO SQLite driver (`gorm.io/driver/sqlite` →
`mattn/go-sqlite3`) with a pure-Go driver (`modernc.org/sqlite`, with
`ncruces/go-sqlite3`/`gormlite` as the secondary candidate) for the embedded
single-node / air-gapped deployment profile and the test suite. SQLite is RETAINED
as a supported backend; this is a driver swap, not a backend change. Decision gated
on the full test suite passing green on the new driver.

## Context

Keyorix runs three storage backends behind `internal/storage/factory.go`:
PostgreSQL (production / HA / multi-replica default), SQLite (embedded single-node
+ air-gapped + tests), and remote. A recurring question is whether SQLite should be
removed or replaced to "unlock" features such as dynamic secrets.

That framing is incorrect and is recorded here so it stops resurfacing:

- Dynamic secrets, leases, and every other feature are plain GORM tables + store
  logic. They run on SQLite today. SQLite does NOT block any feature.
- SQLite's only real limitation is operational: it is single-writer / single-process
  and therefore cannot back an HA multi-replica deployment. That role belongs to
  PostgreSQL and already does. No embedded engine can fill the HA role — an embedded
  single-file DB is single-process by definition.
- Therefore there is no "better embedded database" that unlocks anything. The only
  embedded role is single-node air-gapped + tests, and on that axis SQLite (same SQL
  dialect as today, full GORM support, dialect parity with the Postgres path, and a
  very large existing test footprint) is the strongest option. Alternatives were
  considered and rejected: ObjectBox (object store, not SQL; rewrites the store layer;
  sync features commercial), KV stores BadgerDB/bbolt/NutsDB (not relational; lose
  GORM and the shared-store-over-Postgres design), DuckDB (OLAP shape, CGO).

The one genuine, contained improvement is the **driver**, not the database. The
current driver requires CGO. CGO works against the core wedge — air-gapped,
single-binary, sovereign deployment — because it complicates cross-compilation of
fully static binaries and adds a C toolchain dependency to the build. A CGO-free
SQLite driver yields cleaner static cross-compiled binaries and a stronger
single-binary story, while keeping the SQLite dialect (so SQL, migrations, and the
~100+ SQLite-backed `_test.go` files continue to work unchanged).

Candidate drivers (both permissive, AGPL-compatible, no commercial-license trap):

- `modernc.org/sqlite` — a complete pure-Go translation of SQLite, no CGO.
  Primary candidate.
- `ncruces/go-sqlite3` — Wasm-based pure-Go SQLite with its own `gormlite` GORM
  driver; higher memory use (each connection runs in a Wasm sandbox). Secondary
  candidate / fallback if a platform-support or behavior gap appears with modernc.

Risk to verify, not assume: `factory.go`'s migration code uses Postgres-flavored
SQL (`information_schema` queries, `TIMESTAMP WITH TIME ZONE`) that the current
SQLite driver tolerates. A pure-Go driver runs the same SQLite engine semantics, so
behavior should match `mattn` — but this MUST be proven by a green test run, not
taken on faith, given the size of the SQLite-backed test surface.

## Decision

(Proposed — pending the evaluation below.)

Adopt `modernc.org/sqlite` as the SQLite driver for the embedded/air-gapped backend
and tests, replacing the CGO `mattn/go-sqlite3` path, IF AND ONLY IF the full test
suite passes green on it. Keep PostgreSQL as the production/HA default and `remote`
unchanged. SQLite remains a first-class supported backend; only the driver changes.

## Tasks

1. Baseline. `go build ./...` and full `go test ./...` green on the current
   (`mattn`) driver — capture the baseline pass/fail set so regressions are
   distinguishable (stash → test → stash pop for any pre-existing failures).

2. Spike modernc on a branch. Swap the SQLite driver in `internal/storage/factory.go`
   (the `createLocalStorage` path) and in the test helpers
   (`internal/testhelper`, `internal/storage/store/*_test.go`, and any `_test.go`
   that opens SQLite directly) from `gorm.io/driver/sqlite` to the
   modernc-backed GORM driver. Do NOT change the SQL or migration logic.

3. Run the full suite on modernc. The ~100+ SQLite-backed `_test.go` files must be
   green. Pay specific attention to: the `information_schema`-based `tableExists`/
   `columnExists` helpers, `TIMESTAMP WITH TIME ZONE` columns, the additive
   `ALTER TABLE` migration blocks, and any pgx-specific workaround paths that must
   NOT trigger under SQLite.

4. Build verification. Confirm a CGO_ENABLED=0 fully static cross-compile succeeds
   for the target air-gapped platforms (at minimum linux/amd64 and linux/arm64) —
   this is the actual payoff and must be demonstrated, not assumed.

5. If a blocking gap appears with modernc (platform support, behavior, or memory),
   evaluate `ncruces/go-sqlite3` + `gormlite` as the fallback before abandoning the
   change. Note the memory tradeoff (Wasm sandbox per connection) if chosen.

6. Decide. If green + static build demonstrated → mark this ADR Accepted, record the
   chosen driver, and merge. If neither pure-Go driver passes clean → mark Rejected,
   keep `mattn`, and record the specific failure so this is not re-litigated.

## Acceptance criteria

- SQLite remains a supported backend; `factory.go` still offers postgres / sqlite /
  remote. PostgreSQL stays the production/HA default. No SQL or migration logic
  changed by the driver swap.
- `go test ./...` is green on the selected pure-Go driver, with no regressions versus
  the `mattn` baseline.
- A `CGO_ENABLED=0` static binary cross-compiles for linux/amd64 and linux/arm64.
- The `mattn/go-sqlite3` (CGO) dependency is removed from the build once the pure-Go
  driver is adopted.
- This ADR records the final chosen driver and the rationale, including the explicit
  note that SQLite is an embedded/test backend and never an HA backend, and that no
  embedded engine "unlocks" features — that is Postgres's role.

## Consequences

- Cleaner single-binary, fully static, CGO-free air-gapped builds — directly
  reinforcing the sovereignty wedge.
- No feature change, no backend change, no dialect change — lowest-risk path that
  still improves the deployment story.
- Possible memory increase only if the Wasm fallback (`ncruces`) is selected.
- Closes the recurring "replace SQLite to unlock features" question with a recorded
  rationale.
