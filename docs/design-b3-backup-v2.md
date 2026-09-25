# Design: `keyorix-server admin backup`/`restore` v2 — backend-neutral, authenticated, streaming

**Status:** Draft for review (Andrei). Follow-up to PR #2099 (v1: SQLite-only,
`VACUUM INTO`-based, ADR-108 §B3). No code in this PR. Does not touch
`server/admin/backup.go` or `server/admin/restore.go` — those are v1's files,
in flight in #2099; this document specifies what changes once v1 lands.

## 1. Scope note: what v1 ships vs. what v2 adds

v1 (#2099) ships a **physical, SQLite-only** backup: `VACUUM INTO` produces a
byte-for-byte consistent copy of the SQLite file, bundled with every
`internal/keyfiles.Registry` key-material file into a checksummed tar.
Postgres refuses loudly (`docs/SELF_HOSTING.md` §5's manual `pg_dump`/`psql`
path stands). This is real, working disaster recovery for the common
single-node SQLite deployment — not a stopgap to throw away.

v2 does not replace that mechanism so much as generalize the *archive format*
underneath the same `admin backup --output` / `admin restore --input`
surface, closing four gaps ADR-108 §B3 already scoped together (it lists
"consistent offline backup and restore," "version-skipping upgrades," **and**
"the SQLite → PostgreSQL move" as one bucket — v1 only did the first fully):

1. **Backend-neutral logical format** (§2) — the same archive restores into
   SQLite *or* Postgres. This is also, by construction, the SQLite → Postgres
   move ADR-108 already named as a sibling requirement — not a separate
   feature, the same mechanism.
2. **Postgres backup consistency** (§3) — a single `REPEATABLE READ`
   snapshot, because Postgres deployments are the ones running HA (ADR-039)
   and cannot tolerate v1's SQLite answer to consistency (stop everything,
   hold the exclusive admin lock for the whole dump).
3. **An authenticated manifest** (§4) — HMAC-SHA256 over the manifest,
   derived from the KEK exactly like the existing audit-checkpoint key
   (`internal/core/audit_checkpoint.go`), so archive tampering is caught
   *before* any byte reaches the restore target, not only by a post-hoc
   `verify-audit`.
4. **Rollback protection** (§5) — restoring an old backup is a legitimate
   disaster-recovery operation, but it also silently un-revokes any user or
   token revoked *after* that backup was taken. Detected via the audit chain's
   signed high-water mark; blocked by default, overridable with an explicit
   flag.
5. **Streaming** (§6) — v1 reads the whole database into memory
   (`os.ReadFile` → `[]byte` → one tar entry). Fine at today's typical
   install size; not fine indefinitely, and doubly not once Postgres
   deployments (larger, by the kind of customer who chooses Postgres) are in
   scope.

## 2. Backend-neutral logical format

### 2.1 Why logical, not "teach VACUUM INTO to also speak Postgres"

There is no Postgres equivalent of `VACUUM INTO` that produces a
SQLite-compatible file, and no tool reads a raw Postgres heap file
independent of a running Postgres of the exact same major version. A
byte-identical *physical* copy is inherently single-backend. The only format
that can restore into either backend is a **logical** one: table name → rows,
independent of on-disk representation. This is also exactly what a
SQLite → Postgres move needs — you cannot "physically" turn a SQLite file
into a Postgres cluster; you read rows out of one and insert them into the
other.

### 2.2 Table enumeration: derive it, don't hand-list it

The schema has 90 GORM model structs today (`internal/storage/models/*.go`)
across `internal/storage/factory.go`'s `AutoMigrate` calls, and that number
only grows. **Do not hand-enumerate the table list in backup/restore code.**
This codebase has already been burned by hand-picked model lists silently
drifting from the real schema — see the `internal/storage/store` test-fixture
incident where a hand-picked `AutoMigrate` subset let 40 fixtures bypass
`core.CreateUser` folding undetected. The fix there was "derive the table set
from something that can't drift," and the same fix applies here:

- Build the table list from GORM's own schema registry — call
  `db.Migrator().CurrentDatabase()` / iterate the same model slice
  `factory.go` already passes to `AutoMigrate` (refactor that slice into an
  exported `storage.AllModels()` so both migration *and* backup consume the
  single real list — one source of truth, not two hand-maintained ones,
  per this repo's "generate it, or derive-and-check it" preference order).
- A CI test asserts `len(storage.AllModels())` table names round-trips
  against `db.Migrator().GetTables()` on a freshly migrated database in both
  backends — this is the check that fails loudly the day a model is added to
  `AutoMigrate` and forgotten in the backup list, instead of silently
  exporting a partial backup.

### 2.3 Per-table row encoding

Each table becomes one streaming NDJSON (newline-delimited JSON) tar entry —
`tables/<table_name>.ndjson` — one JSON object per row, GORM column name as
key, using the same JSON encoding GORM/the API layer already uses for typed
columns (so no new marshal/unmarshal logic for e.g. `time.Time`,
`encoding/json` `RawMessage` columns, or nullable fields). NDJSON over a
single-JSON-array-per-table for one reason: it's streamable in both
directions without holding the whole table in memory (§6) — a JSON array
requires either buffering the whole thing or a streaming array-aware decoder;
NDJSON just reads one line at a time.

### 2.4 Restore ordering and referential integrity

Rows must be inserted in an order that satisfies foreign-key constraints (or
constraints must be deferred). Two real options, not both required:

- **Topological order.** Derive a dependency graph from GORM's own
  relationship tags (or a hand-verified static order, checked by a test that
  fails if a new model's FK target isn't already earlier in the list — same
  "derive and check" discipline as §2.2, not a second hand-maintained list to
  drift from the first).
- **Deferred constraints.** Postgres supports `SET CONSTRAINTS ALL DEFERRED`
  inside a transaction — insert in any order, check at commit. SQLite's FK
  enforcement is off by default and, even with `PRAGMA foreign_keys=ON`, has
  no deferred mode; `PRAGMA defer_foreign_keys=1` defers *within one
  transaction* to statement-end, which is enough for a single-transaction
  bulk restore.

Recommend: deferred constraints where the backend supports it (simpler, no
graph to keep in sync), topological order as the documented fallback for
SQLite if `defer_foreign_keys` turns out to have some restore-breaking edge
case in testing. Either way, restore runs as one transaction per backend
connection — partial restore on failure is not an acceptable state (same
principle v1 already applies with `refuseNonEmptyExisting` and archive-clean
error handling).

### 2.5 Format versioning and v1 compatibility

v1's `backupFormatVersion = 1` const already exists as the guard. v2 bumps to
`FormatVersion: 2` and changes `Backend` from a single string (`"sqlite"`) to
something that names the *logical* format explicitly (e.g.
`"logical-v1"`) — restore refuses any `FormatVersion` it doesn't recognize
(v1 already does this; keep it). New backups always write v2/logical — there
is no reason to keep producing the old physical format once the logical path
exists and is tested, since v2 is a strict superset of what v1 backup/restore
does. `admin restore` keeps a v1-format code path for one deprecation window
(read the old physical SQLite archive, same as today) so an archive taken
under #2099 before this ships is not stranded; print a deprecation warning
recommending a fresh backup under the new format. Drop the v1 reader once a
release cycle has passed — track that removal like any other deprecation, not
silently.

## 3. Postgres backup consistency: `REPEATABLE READ` vs. the admin lock

v1's SQLite path gets consistency from `serverguard.AcquireExclusive` (a hard
exclusive `flock`, held for the whole run — see
`internal/serverguard/serverguard.go`) plus `VACUUM INTO`'s own atomicity.
That's the right tradeoff for SQLite: those deployments are inherently
single-process, so "briefly refuse to start a server while a backup runs" is
cheap.

It is the wrong default for Postgres. `serverguard.AcquireExclusive` already
supports Postgres today (`pg_try_advisory_lock`, non-blocking, session-scoped)
— reusing it verbatim for backup would work, but it means **every replica in
an ADR-039 HA deployment refuses to (re)start for the entire duration of the
backup**, which is exactly the downtime story Postgres deployments choose
Postgres to avoid. A large deployment's backup can run for minutes; that is
not an acceptable server-availability window.

**Recommended default for Postgres: a single `REPEATABLE READ` transaction,
no exclusive lock.** `BEGIN ISOLATION LEVEL REPEATABLE READ` takes one MVCC
snapshot at `BEGIN` and every subsequent read in that transaction sees exactly
that snapshot, regardless of concurrent commits — this is Postgres's own
built-in answer to "consistent multi-table dump without blocking anyone,"
and it's the same mechanism `pg_dump` itself uses
(`pg_dump --serializable-deferrable` is stronger still, but plain
`REPEATABLE READ` is what `pg_dump`'s ordinary mode uses and is sufficient
here). Read every table's rows through this one transaction/connection;
nothing else needs to stop.

**Tradeoff to document, not hide:** a long-held `REPEATABLE READ` transaction
holds back Postgres's `xmin` horizon for its duration — `VACUUM` cannot
reclaim rows deleted or updated by concurrent transactions until this backup
transaction finishes. On a large, write-heavy table this is the same
well-known operational cost `pg_dump` itself carries on a big database, not a
new problem this design introduces — but it should be called out in the
command's `--help` text and in `docs/SELF_HOSTING.md`, the way v1's own
`--help` text already tells the operator to store the archive off-host.

**Keep `--exclusive` as an explicit opt-in**, wired to the existing
`serverguard.AcquireExclusive`, for an operator who wants v1's stronger
guarantee (zero concurrent writes at all, not just snapshot isolation) and is
willing to pay for it with the availability hit — e.g. a maintenance-window
backup before a major upgrade. Default remains `REPEATABLE READ` (no flag
needed) because it is strictly better for the common case and is not a new
invention, just Postgres's own standard tool for this exact problem.

SQLite keeps its existing `VACUUM INTO` + exclusive-lock path unchanged for
the physical-format case, and gains the same logical-format
table-by-table export for parity with Postgres (needed for SQLite → Postgres
restores in the other direction, and so both backends are exercised by the
same restore code, not two).

## 4. Authenticated manifest

### 4.1 Threat this closes

v1's manifest already carries a SHA-256 checksum per file
(`backupFileEntry.SHA256`), verified before restore
(`verifyChecksum`/`validateKeyFileSet`). That catches accidental corruption
(bit rot, a truncated copy) but is **not an authenticity control**: the
checksums live in the same file an attacker who can modify the archive
controls, so they can recompute a matching checksum for tampered content.
Detecting deliberate tampering needs a MAC keyed by something the attacker
does not have — exactly the gap `verify-audit` closes for the live audit
chain (ADR-029) but which v1's *archive* has no equivalent of. Today,
tampering would only surface later, if at all — e.g. via `verify-audit`
after the restored server is already running.

### 4.2 Key derivation: same pattern as the audit checkpoint key

`internal/encryption/keymanager_lifecycle.go` already derives the
audit-checkpoint HMAC key from the KEK via HKDF-SHA256 with a fixed `info`
string (`deriveAuditCheckpointKey`, distinct `info` from
`evidenceSignKeyInfo`) — chosen over the DEK specifically so a routine DEK
rotation does not invalidate it (`#502`). Reuse the exact same construction
for the manifest key, with its own `info` string for domain separation:

```go
const backupManifestKeyInfo = "keyorix-backup-manifest-signing-key-v1"

func deriveBackupManifestKey(kek []byte) (key []byte, keyID string, err error) {
    // identical shape to deriveAuditCheckpointKey — HKDF-SHA256(kek, nil, info)
}
```

No new key-management surface: this is the fourth HKDF-from-KEK derivation
in the same file (evidence-signing, audit-checkpoint, and now this), all
following one established pattern.

### 4.3 Verification order: before the restore target is touched, not before the archive is touched

The real constraint: on a **fresh host** (the common restore case — the data
directory being restored into is empty by definition, per v1's
`refuseNonEmptyExisting`), the KEK itself only exists *inside* the archive
being restored. Verifying the manifest signature requires the KEK; getting
the KEK (for `key_provider.type: file`) requires the archive's own key files.
This is circular if "verify before restore" is read as "verify before writing
any byte to disk at all."

**Resolution: stage, then verify, then commit — never write directly to the
final target before verification succeeds.**

1. Parse the archive (streaming — §6) into a temporary staging directory
   (`os.MkdirTemp`, mode 0700), same checksum-per-file verification v1
   already does.
2. Unwrap the KEK using the **staged** key files, through the exact same
   `internal/encryption` code path `admin diagnose`'s "KEK/passphrase access"
   step already uses today — no new unwrap logic, just pointed at the staging
   directory instead of the real key-file paths.
3. Derive the manifest key (§4.2), canonicalize the manifest (fixed field
   order, mirroring `checkpointCanonical` in
   `internal/core/audit_checkpoint.go` — same idiom, new struct), compute
   HMAC-SHA256, compare with `hmac.Equal` (constant-time, matching this
   codebase's existing convention for every other secret comparison; see
   `crypto/subtle.ConstantTimeCompare` calls elsewhere).
4. **Only on success**: move the staged database and key files into their
   real target paths (rename within the same filesystem is atomic; still
   subject to v1's non-empty-target refusal, checked once before staging even
   begins, so a doomed restore fails fast without doing the work).
5. On any failure — checksum, signature, or otherwise — delete the staging
   directory and refuse. The real target directory is never touched.

This satisfies "detected before restore" in the sense that matters: nothing
at the operational target (the database and key files a running server will
actually read) is ever written unless the manifest signature checks out. It
costs one temporary on-disk copy during restore, which §6's streaming design
already has to reckon with regardless (see §6.3).

**Open question (§8, Q1):** a stronger variant avoids even the temporary
on-disk copy by unwrapping the KEK from in-memory buffers directly, which
would need a small refactor to `internal/encryption`'s key-loading functions
to accept `io.Reader`/`[]byte` instead of requiring materialized file paths.
Recommend deferring that — the staging-directory approach reuses 100% of the
existing, already-reviewed unwrap code path, at the cost of a temp directory
that's deleted within the same command invocation and never exposed outside
it.

### 4.4 What the signature covers

Every field needed to detect a meaningful tamper: `FormatVersion`, `Backend`,
`CreatedAt`, the full `DBFile`/table-entry checksum list, `KeyFiles` checksum
list, and the new `AuditHighWater` fields from §5 — i.e., the whole manifest
except the `Signature` field itself. An attacker who can modify archive
content but not derive the KEK cannot produce a matching signature for any
combination of those fields, including silently dropping a table or
substituting a different key file than the one actually backed up.

## 5. Rollback protection

### 5.1 The threat

Restoring is index-blind to *when* the backup was taken relative to
subsequent legitimate changes. A backup taken at T1, restored at T3 after a
user or machine credential was revoked at T2, silently resurrects that
access — the restored database simply doesn't know T2 happened. This is a
real, not hypothetical, category for a secrets manager specifically (compare
the "auth-boundary lockout-vs-bypass asymmetry" principle already in
CLAUDE.md: a revoke is exactly the kind of action whose accidental undo must
fail loud, not silent).

Genuine disaster recovery *legitimately* restores an old backup sometimes —
this must not be blocked outright, only require the operator to say so
explicitly.

### 5.2 Detection: the signed audit high-water mark, plus a host-local witness

`internal/core/audit_checkpoint.go` already maintains exactly the primitive
needed: `auditHighWaterKey` (`system_metadata` key
`audit_checkpoint_highwater`), a single overwritten row holding the greatest
signed `chained_events` count this install has ever certified, HMAC-signed
with the same checkpoint key so it can't be forged without it
(`auditHighWaterFloor`, `advanceAuditHighWater`). This is precisely "how far
has this install's audit trail legitimately progressed" — the same question
rollback detection needs answered.

**The subtlety: the high-water row itself lives inside the database being
restored.** An old backup's own embedded high-water row reflects the OLD
(lower) value — comparing the archive against *itself* proves nothing.
Detecting rollback needs a reference **outside** the archive, one that
survives being overwritten by whatever gets restored:

- A small **witness file**, outside the database and outside anything backup
  or restore ever bundles into an archive (e.g. `<data-dir>/.audit-highwater-
  witness`, sibling to the DB file, never listed in `keyfiles.Registry` and
  never a tar member) — holds the single greatest signed high-water value
  ever observed *on this host*, written every time the live server advances
  the real high-water (`advanceAuditHighWater`'s existing call site is the
  natural hook) and every time a restore completes.
- Every `admin backup` also records the archive's own high-water value (and
  its existing signature — no new signing scheme, reuse
  `auditHighWaterValue`/`signCheckpoint`'s existing format) at the top level
  of `MANIFEST.json`, so restore can read it without first opening the
  staged database.
- `admin restore`, after manifest-signature verification (§4.3) but before
  the commit step, compares the archive's recorded high-water against the
  witness file's value:
  - **Witness file absent** (genuinely fresh host, first restore ever on this
    machine): nothing to compare against — proceed, and write the witness
    file from the archive's value so *subsequent* restores on this host are
    protected. This is the legitimate bootstrap case, not a gap to close.
  - **Archive's high-water ≥ witness's value**: proceed normally — this
    backup is at least as current as anything this host has certified.
  - **Archive's high-water < witness's value**: refuse by default. Require an
    explicit `--allow-rollback` flag to proceed, and when it's used, print
    (and audit-log, once the restore completes and the chain is writable
    again) exactly how far back this goes — "restoring a backup that is N
    events behind this host's last known state; users/credentials revoked
    since then will be un-revoked."

### 5.3 Stated limitation

This is host-local. It defeats an attacker who steals a stale backup archive
and tries to restore it somewhere the real host's witness file already
exists — but an attacker with **both** an old archive and the ability to wipe
or never-had the witness file (a genuinely fresh replacement host, or
deliberate destruction of the witness alongside the rest of the data
directory) is indistinguishable from the legitimate "first restore on a fresh
host" case and is not caught. This is the same class of caveat this codebase
already states plainly elsewhere rather than pretending is solved — compare
`CheckpointAnchorVerifiable`'s own doc comment distinguishing "anchored" from
"anchor cryptographically re-verified." The external-notary anchoring
machinery already in `internal/core/audit_checkpoint.go`
(`SetCheckpointNotary`, RFC 3161 receipts in `internal/notary`) is a stronger
answer *if configured* — an anchored checkpoint's timestamp is attested by a
third party outside this host entirely, so a host-wipe-and-replay can't
antedate it. Whether to require or recommend notary anchoring specifically
for installs that care about this threat is an open question (§8, Q2), not
folded into this design as a hard requirement, since it's an existing
opt-in feature this design doesn't need to change.

## 6. Streaming

### 6.1 What v1 does today

`snapshotSQLiteDatabase` returns `[]byte` (the whole database), and
`writeBackupArchiveContents` takes `dbBytes []byte` plus `keyBlobs [][]byte`
— the complete backup payload is held in memory at once, both directions
(`readBackupArchive` similarly collects everything into `dbBytes`/
`keyBlobsByName` before returning). Acceptable at today's typical SQLite
install size; not something to carry forward unchanged once Postgres
deployments (larger by self-selection) are in scope, and not something to
carry forward for the logical, per-table format either — buffering 90 tables'
worth of rows defeats half the point of moving to a row-streamed format.

### 6.2 Backup-side streaming

Chain writers directly, no intermediate full-payload buffer:
`os.File` → `gzip.Writer` → `tar.Writer`, and for each table, a Postgres
cursor (`DECLARE ... CURSOR` inside the `REPEATABLE READ` transaction from
§3, or GORM's row iterator) / SQLite `rows.Next()` loop that encodes each row
as one NDJSON line and writes it straight into the current tar entry via
`tw.Write` — bounded memory is "one row plus encoder overhead," not "one
table" and certainly not "the whole database." `tar.Writer` requires knowing
an entry's size up front in its header for the classic API; use
`tar.FileInfoHeader`-style streaming with a known-in-advance size only for
the small fixed entries (`MANIFEST.json`), and for per-table NDJSON entries
either buffer just that one table to determine its size (acceptable — single
tables, not the whole DB, are still far smaller than a whole-DB buffer) or
switch to PAX headers, which support a still-unknown size via GNU/PAX
sparse-entry extensions — pick whichever `archive/tar` cleanly supports;
this is an implementation detail to resolve during the PR, not a design
blocker.

### 6.3 Restore-side streaming

Read the tar/gzip stream forward-only, one entry at a time (`tar.Reader`
already supports this — no need to seek). For each table entry, decode
NDJSON line-by-line and batch-insert (e.g. groups of a few hundred rows via
a single multi-row `INSERT`, not row-by-row — GORM's `CreateInBatches` is the
natural fit and would be new usage in this codebase, not existing precedent,
so budget review time for it) inside the one restore transaction from §2.4.
Key files and the manifest are small and fine to hold in memory as today;
only the potentially large per-table row streams need this treatment.

Combined with §4.3's staging-then-verify sequence: the archive is read
*once*, streamed into the staging directory's files, verified, then the
already-staged files are what get inserted/moved — there is no second full
read of the archive after verification succeeds.

## 7. Test plan

### 7.1 Core correctness property: `restore(backup(state)) == state`

The load-bearing test, across both backends and both directions
(SQLite → SQLite, Postgres → Postgres, SQLite → Postgres, Postgres → SQLite):
seed a database with representative rows across every table (or, better,
derive the seed from the same `storage.AllModels()` list from §2.2 so a new
model automatically gets covered — same "derive, don't hand-list" discipline
applied to the test as to the implementation), `admin backup`, wipe the
target, `admin restore`, then assert the restored database is
row-for-row equal to the pre-backup state (compare via a canonical
per-table row dump, not a raw byte comparison, since backend-neutral
means the physical bytes are never expected to match across SQLite ↔
Postgres). This generalizes v1's existing
`TestAdminBackupRestore_SQLite_RoundTrip`, which already checks the
audit-chain-length invariant (`chainedCount` before backup equals
`chainedCount` after restore, plus exactly one more for the restore's own
audit event) — keep that exact assertion, it's still correct and still the
right way to catch a subtly incomplete restore.

### 7.2 Cross-backend move test

A dedicated `TestAdminBackupRestore_SQLiteToPostgres` (gated on
`KEYORIX_TEST_PG_DSN`, this repo's existing convention for Postgres-only
tests) exercising exactly the "SQLite → PostgreSQL move" ADR-108 names: back
up a SQLite install, restore into a fresh Postgres database, confirm
`verify-audit` reports VALID and the row-equality check from §7.1 holds. This
is the test that proves §2's backend-neutral format claim is real, not
theoretical.

### 7.3 Consistency test (Postgres)

Start the `REPEATABLE READ` backup transaction, then — from a second,
concurrent connection — commit writes to a table already read and to a table
not yet read by the in-progress backup. Assert the resulting archive reflects
neither concurrent write (true snapshot isolation, not "whatever happened to
be visible when each table was scanned").

### 7.4 Manifest authenticity: red/green plus a genuine tamper

Following this repo's "validate a mechanism against a real failure, not the
one imagined" discipline (per CLAUDE.md's core-principle section): 

- **Green**: an unmodified archive restores successfully.
- **Red — tampered payload, untouched signature**: flip a byte in a table's
  NDJSON content (or a key file) without recomputing the manifest signature.
  Restore must refuse at the signature-verification step in §4.3 — before
  anything is written to the real target — distinctly from v1's existing
  per-file-checksum refusal (`TestAdminRestore_ChecksumMismatchDetected`
  already covers that layer; this test proves the *authenticity* layer, not
  just the corruption-detection layer, actually fires).
- **Red — content AND its checksum both altered to match, but the manifest
  signature left stale**: this is the case plain checksums (v1's existing
  control) cannot catch and HMAC verification specifically exists to catch —
  the test that would have caught the checksum-only design's actual gap if
  it existed today.
- **Fuzz**: extend `checkpoint_key_fuzz_test.go`'s existing pattern
  (`internal/core`) with a sibling fuzz target over manifest
  canonicalization/signing with adversarial field content — same rationale
  that file already documents for the checkpoint case, applied to the new
  canonical-encoding function from §4.4.

### 7.5 Truncation / corruption fuzz

A fuzz target feeding truncated and randomly-mutated archives (gzip stream
cut short, tar header corrupted mid-entry, an entry claiming a size it
doesn't have) into the restore parser (§6.3) — the property under test is
"never panics, never partially writes to the real target, always either
restores completely or refuses cleanly with the staging directory cleaned
up." This is a new fuzz target, not an extension of an existing one — closer
in spirit to `fuzz_encryption_command_fault_test.go`'s fault-injection style
than to a pure-parsing fuzz target, since the property being checked spans
"did the staging/verify/commit sequence uphold its own atomicity guarantee,"
not just "did the parser crash."

### 7.6 Rollback protection

- Witness-file-absent (fresh host): archive with a low high-water restores
  without `--allow-rollback` and the witness file is created from it.
- Witness-file-present, archive is current or ahead: restores normally, no
  flag needed.
- Witness-file-present, archive is behind: refused without
  `--allow-rollback`; succeeds with it, and the printed/audited message
  states the actual event-count gap (assert on the message content, not just
  the exit code — matching this repo's "assert the effect, not the return
  value" convention for a control whose whole point is a specific,
  human-readable warning).

## 8. Open questions for Andrei

1. **§4.3: staging-directory verify-before-commit, or invest in an
   in-memory-only KEK unwrap to avoid the temporary on-disk copy entirely?**
   Recommend staging directory for v2 — reuses the existing, already-reviewed
   unwrap code path unchanged, at the cost of a temp directory deleted within
   the same command run. Revisit only if a customer's threat model
   specifically excludes "attacker can read this host's temp filesystem
   during a restore run," which staging does not defend against and
   in-memory-only would.
2. **§5.3: should notary anchoring (`SetCheckpointNotary`) become a
   recommended or required companion to rollback protection for
   installs that care about a host-wipe-and-replay attacker?** Recommend
   documenting it as a stronger option in `docs/SELF_HOSTING.md`, not
   requiring it — it's an existing opt-in feature (RFC 3161 TSA), and coupling
   backup/restore to requiring it would be new scope beyond what ADR-108 §B3
   asks for.
3. **§2.5: how long is the v1-physical-format restore compatibility window
   kept?** Recommend one release cycle, then remove — tracked as a normal
   deprecation, not indefinitely.
4. **§3: is `REPEATABLE READ` as the Postgres default (vs. requiring
   `--exclusive` always, matching v1's SQLite posture exactly) the right
   call, given the `xmin`-horizon/vacuum tradeoff in §3?** Recommend yes —
   it's Postgres's own standard tool for this problem (the same one
   `pg_dump` uses) and the availability cost of the alternative is the
   specific thing HA Postgres deployments exist to avoid — but this is a
   product/ops tradeoff worth Andrei's explicit sign-off, not purely a
   technical call.
5. **§2.4: deferred constraints vs. a maintained topological insert order** —
   recommend attempting deferred constraints first during implementation;
   fall back to topological order only if testing surfaces a real
   restore-breaking edge case (e.g. a self-referential FK, or a Postgres
   deferred-constraint interaction with `CreateInBatches` batching that
   doesn't hold up). Not worth deciding definitively before implementation
   starts.
6. **Should `admin backup` gain a `--format=physical` escape hatch for
   SQLite (keep producing v1's exact `VACUUM INTO` archive on request), or
   is logical-only, full stop, the right call once v2 ships?** Recommend
   logical-only — §2 already establishes the logical format is a strict
   superset for the SQLite case, and maintaining two archive-writer code
   paths indefinitely is exactly the kind of unnecessary-abstraction cost
   this repo's engineering practices warn against paying for a hypothetical
   need.
