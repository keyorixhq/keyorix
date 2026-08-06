# ADR-078: GORM as the storage-layer ORM

## Status

Accepted, as-built. Backfill ADR — GORM's adoption predates the ADR series and has
always been treated as settled fact by later ADRs (ADR-048, ADR-049 both assume and
build on it rather than re-justifying it). Recorded now per the M2 "ADR backfill"
backlog item.

## Context

Keyorix supports three storage backends behind a single interface
(`internal/storage/factory.go`, `DefaultStorageFactory.CreateStorage`): PostgreSQL
(production / HA default), SQLite (embedded, single-node, air-gapped, and the test
suite's default), and `remote` (an HTTP client to a running Keyorix server, for the
CLI's client mode). `cfg.Storage.Type` selects among them; an unrecognized value is
a hard error rather than a silent fallback.

The storage-layer needs, from the earliest design, were:

- **One model definition, two SQL dialects.** `internal/storage/models/models.go`
  defines roughly 76 struct types that must map identically onto Postgres and
  SQLite without hand-written dialect-specific SQL in application code.
- **Migrations that work for both an operator-managed Postgres instance and an
  embedded single-file SQLite database**, without a separate migration-file
  toolchain to maintain per backend.
- **A local vs. remote split that stays structurally identical** — `local_*.go`
  files (GORM-backed) and `remote_*.go` files (HTTP calls to a running server)
  implement the same Go interface, so core business logic never needs to know which
  backend it's talking to.

## Decision

Adopted **`gorm.io/gorm`** (currently v1.31.2) with `gorm.io/driver/postgres` for
production/HA and a SQLite path for the embedded/air-gapped/test backend, reached
through `internal/storage/store/`'s `local_*.go` files. `remote_*.go` files
implement the same storage interface over HTTP for the CLI's client mode
(`internal/storage/remote/client.go`), so `core` business logic is written once
against the interface and never branches on backend.

**The SQLite path is not GORM's stock driver** — `internal/storage/sqlitedialect`
is a small local fork of `go-gorm/sqlite`'s `sqlite.go` (MIT-licensed, attribution
preserved), with the underlying `database/sql` driver swapped to
`modernc.org/sqlite` (pure Go, CGO-free) per ADR-048. That ADR covers the driver
swap itself in detail; this ADR is the missing piece it assumed — why GORM was the
ORM being forked in the first place, rather than switched away from.

**AutoMigrate is used for schema management**, not a separate migration-file
toolchain — `migrateDatabase` (`factory.go`) is the entry point, driving roughly 34
individual `db.AutoMigrate(&models.X{})` calls plus one loop over the bulk model
set. This has one well-documented, recurring footgun, called out at ~15 call sites
in `factory.go`'s own comments: running a full `AutoMigrate` against an existing
table whose columns were already hand-altered (via targeted `db.Migrator()` column
additions) can poison pgx's prepared-statement cache and make subsequent
`information_schema` existence checks spuriously return false — which then
re-triggers full AutoMigrate against a table it shouldn't touch, corrupting state.
The house rule, repeated at every call site rather than solved once centrally:
**never full-AutoMigrate an existing table once it has been column-altered outside
AutoMigrate** — migrate it via targeted `db.Migrator()` calls instead.
`columnExists`/`tableExists` (`factory.go`) deliberately avoid GORM's own
`HasTable`/information-schema helpers for the same reason.

**Rejected alternatives, implicitly rather than via formal comparison** (no
contemporaneous doc weighing these exists — this is stated here as the honest
backfill, not a reconstruction of a debate that happened): `sqlc`/`sqlx` would
require hand-written SQL per dialect for all ~76 models, reintroducing exactly the
dual-dialect burden GORM removes; `ent` is a heavier code-generation-first ORM with
its own migration story that would have meant rewriting the storage layer rather
than adopting it incrementally; raw `database/sql` was rejected for the same reason
as `sqlc`/`sqlx` — it pushes dialect differences into application code instead of
the ORM layer.

## Consequences

- **Positive.** One model definition serves Postgres, SQLite, and (indirectly, via
  the shared struct shapes) the remote client's JSON encoding. ADR-048's
  CGO-free driver swap and ADR-049's "route all storage access through the
  factory" rule were both straightforward to layer on top precisely because GORM
  already centralized backend selection in one place.
- **Negative / accepted tradeoff.** AutoMigrate's pgx prepared-statement-cache
  interaction is a genuine footgun with no framework-level fix — the mitigation is
  procedural (the "never re-AutoMigrate an altered table" rule) rather than
  structural, and depends on every future migration author knowing and following
  it. This ADR exists partly to make that rule discoverable instead of tribal
  knowledge scattered across `factory.go` comments.
- Not revisited: switching ORMs now would mean rewriting `internal/storage/store/`
  end to end for no functional gain — GORM has not blocked any shipped feature
  (dynamic secrets, machine identities, and every other post-2026 feature are all
  plain GORM tables), so there is no open question this ADR needs to leave for a
  future decision.
