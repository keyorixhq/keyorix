# Design note: signed audit checkpoints and the standalone verifier (RD-AUDIT-CKPT-1)

Status: R&D prototype R8, design for decision, 2026-10-23. Nothing here is
implemented. Decision record: `docs/adr-116-signed-audit-checkpoints.md`
(Proposed). Demo script: `docs/demo/rd-audit-ckpt.md` (written against the
future CLI, not implemented).

## 1. Summary

Each audit checkpoint also becomes a **statement**: a small canonical record
of the chain head, the statement chain, the owed-audit set and the signing key
epoch, signed with Ed25519 **and** ML-DSA-65. A standalone `keyorix-verify`
binary checks an evidence bundle (statements plus audit rows in an exact
export format) against a pinned key id, with no server, database, secret or
network. Old statements stay verifiable after any key change, which answers
RUNBOOKS-1 gap 5 offline. Owed records become part of what is signed, so an
owed row that disappears before the backfill is detectable.

## 2. What exists today (checked on origin/main 760e92e32)

| Fact | Where |
|---|---|
| Entry hash: SHA-256 over `prev_hash` then 13 fields, each prefixed with a big-endian uint64 length | `internal/auditverify/hash.go` `ComputeEntryHash` |
| Checkpoint canonical form `v1\0count\0head_id\0head_hash\0key_version`, HMAC-SHA-256 | `internal/core/audit_checkpoint.go` `checkpointCanonical`, `signCheckpoint` |
| Checkpoint key HKDF-derived from the KEK, info `keyorix-audit-checkpoint-kek-v2`, id prefix `ack-` | `internal/encryption/keymanager_lifecycle.go` `deriveAuditCheckpointKey` |
| Checkpoint writes serialised by `WithAuditCheckpointLock` across replicas | ADR-029, `WriteAuditCheckpoint` |
| Optional RFC 3161 receipt over the checkpoint canonical bytes | `anchorCheckpoint`, `internal/notary` |
| Offline verifier reads a DB, independent reimplementation, stdlib plus DB drivers, forbids `internal/core` and `internal/storage` imports | `internal/auditverify`, `dependency_guard_test.go` |
| Owed rows: effect plus `pending_audit_events` record in one transaction; claim and append in one transaction; backfill appends at the tail, oldest first; break-glass rows keep their original time | `internal/core/audit_owed.go` |
| The backfilled row carries no reference to its pending record (only a "recorded late" sentence in `description`) | `BackfillPendingAuditEvents` |
| Export carries `prev_hash`/`entry_hash` but not the exact hashed values (`impersonated_by`/`acting_as` as names, `success` as a plain bool, `diff` re-compacted by `encoding/json`) | `server/http/handlers/audit.go` `AuditExportEntry` |
| `crypto/mldsa` present in the Go 1.27.2 toolchain: `NewPrivateKey(params, seed)`, 32-byte seed, `Options.Context`, pure ML-DSA only (no pre-hash API) | `$GOROOT/src/crypto/mldsa` |
| No ML-DSA use in the repo. Ed25519 used for licenses, bundles and `trust` | `pkg/licenseverify`, `pkg/bundleverify`, `pkg/trust` |

## 3. Statement format (v1)

Encoding: a sequence of `tag (1 byte) | length (4 bytes, big-endian) | value`.
All 16 tags are present exactly once, in increasing order, with no trailing
bytes. Fixed-size fields must have their exact size. A decoder re-encodes and
compares, so only one byte string per statement is accepted (checked in the
prototype by `FuzzDecode`, about 30 million executions, no counterexample).

| Tag | Field | Size | Meaning |
|---|---|---|---|
| 1 | domain | 27 | `keyorix/audit-checkpoint/v1` |
| 2 | kind | 1 | 1 checkpoint, 2 key genesis, 3 key change, 4 retention purge, 5 seal (reserved) |
| 3 | log_id | 32 | random, created at genesis, one per install |
| 4 | seq | 8 | 1 for genesis, then +1 per statement |
| 5 | prev_stmt | 32 | SHA-256 of the previous statement's bytes (zero for genesis) |
| 6 | certified | 8 | chained + purged events, as the HMAC checkpoint certifies today |
| 7 | head_id | 8 | id of the head row (0 for an empty chain) |
| 8 | head_hash | 0 or 64 | the head row's `entry_hash`, lowercase hex |
| 9 | purged | 8 | cumulative purged chained events (from the retention anchor) |
| 10 | owed_count | 8 | open `pending_audit_events` records at signing time |
| 11 | owed_digest | 32 | SHA-256 over `"keyorix/audit-owed-set/v1\0"` then, sorted by id, `pending_id (8) | SHA-256(owed event JSON) (32)` |
| 12 | key_epoch | 4 | signing key epoch, 1 at genesis |
| 13 | key_id | 32 | SHA-256(Ed25519 pk ‖ ML-DSA-65 pk) of the signing epoch |
| 14 | segment | 4 | seal segment, 0 until a seal exists (recovery-options §2 constraint 7) |
| 15 | issued_at | 8 | signer clock, Unix microseconds, advisory only |
| 16 | new_pub | 0 or 1984 | genesis and key change only: Ed25519 pk (32) ‖ ML-DSA-65 pk (1952) |

Kind 4 (retention purge) reuses tags 6 to 9 for the new first surviving row:
`certified` = purged count, `head_id` = first surviving id, `head_hash` = that
row's `prev_hash`. That lets a bundle start after a purge with an
authenticated seed for the walk. A design point, not prototyped.

Prototype sizes (format facts, not measurements): checkpoint statement 356
bytes, key change statement 2276 bytes, hybrid signature 3373 bytes, hybrid
public key 1984 bytes.

## 4. Signatures and keys

### Signing

- `sig = ed25519_sig (64) ‖ mldsa65_sig (3309)`.
- Ed25519 (RFC 8032 pure Ed25519 [VERIFY]) over
  `"keyorix/audit-checkpoint/v1 ed25519\0" ‖ statement`.
- ML-DSA-65 over `statement` with `Options.Context =
  "keyorix/audit-checkpoint/v1"`.
- Verification requires both. Any size mismatch fails before any crypto.
- A key change statement carries two signatures: old epoch first, new epoch
  second, both over the same bytes.

Why AND, and why this shape: the statement's job is to stay unforgeable if
either primitive falls (classical to a quantum computer, ML-DSA to a new
cryptanalytic result or an implementation bug). AND keeps it unforgeable as
long as one holds. The key id inside the signed bytes binds both public keys,
so an attacker cannot pair a valid component with a substitute key. The
prototype's tamper matrix flips a byte in each component and truncates the
ML-DSA half; each is BROKEN.

### Key material (Q1, recommended option a)

- `audit-signing.key`: a 32-byte random seed, wrapped under the KEK with the
  same AES-256-GCM wrapping as `dek.key` (when RD-PQWRAP-1's keyset lands, it
  is one more keyset slot).
- Derivation: `ed_seed = HKDF-SHA-256(seed, info "keyorix-audit-ckpt-ed25519-v1", 32)`,
  `ml_seed = HKDF-SHA-256(seed, info "keyorix-audit-ckpt-mldsa65-v1", 32)`.
- Registered in `internal/keyfiles/registry.go`, in the key-set manifest
  (#3607 when merged), in `admin backup`, wiped from memory on shutdown like
  the other KEK-protected keys.
- `rotate-kek` and `migrate-provider` re-wrap the file and do not change it.
- `keyorix-server admin audit signing-key rotate` (offline, exclusive lock)
  creates a new seed. Steps and crash points in §8.
- Options b (derive from the KEK) and c (off-host signer) are compared in §10.

### Key id, pin and log id

- Key id = SHA-256 of the 1984 public-key bytes, printed at genesis and by
  `keyorix audit signing-key show`.
- The genesis statement is self-signed and carries the public keys. The
  verifier needs `--pin <key id>`. With a pin that does not match, BROKEN.
  Without a pin, at most INDETERMINATE ("key not pinned").
- `log_id` keeps statements of two installs apart. A staging copy restored
  from a production backup must run `signing-key genesis --new-log`, or an
  auditor holding production statements will see a fork.

### HA

Every replica holds the seed, as every replica holds the checkpoint HMAC key
today. Statements are written inside `WithAuditCheckpointLock`; `seq` and
`prev_stmt` are read from the newest statement row under that lock, so two
replicas cannot both write statement N.

## 5. Owed-audit interplay

### What already holds

The backfill appends owed rows at the tail of the chain. A statement certifies
a prefix (count and head), so later appends never invalidate it. This is the
property the brief asks for ("owed-audit backfill keeps checkpoints valid"),
and the prototype shows it: an owed record created between statements 2 and
3 and backfilled after a key change leaves all six statements VALID.

New invariant to add with the implementation: **no write path inserts an
audit row with an id below the head of the newest statement.** Today this
holds by construction (ids come from the sequence, and the chain append takes
the head under the chain lock). The guard is the verifier itself plus a core
test that writes a statement, backfills, and re-verifies.

### What becomes checkable

1. `owed_ref` on the backfilled row: `"<pending id>:<hex SHA-256 of the owed
   event JSON>"`, a new field in the entry hash, empty for every other row.
   It is a chain-encoding change. The prototype appends it as an optional
   trailing length-prefixed field; the implementation instead adds it as a
   14th field under an explicit encoding version, with the same migration
   discipline as #1452 (old rows keep the old encoding, both verifiers know
   both, and a verifier that does not know the version refuses the row
   rather than guessing).
2. Each statement commits to the owed set (§3 tags 10 and 11). The writer
   reads the pending table inside the same lock and transaction.
3. The evidence bundle carries, per statement, the owed set the digest
   commits to (ids and digests only, never the event JSON, so no event
   content leaks through the owed list).

Verifier rules:

- the owed list in the bundle must hash to `owed_digest` and have
  `owed_count` entries;
- for consecutive checkpoint statements N and N+1, every record in N's list
  is either in N+1's list or appears as an `owed_ref` in a row between the two
  heads;
- an `owed_ref` appears at most once in the whole chain.

What this adds over today: a DB-level actor who deletes a
`pending_audit_events` row after a statement listed it (before the backfill
writes it) makes the bundle BROKEN. Today that deletion is invisible. A
record created and deleted between two statements is still invisible: the
statement interval bounds that window. RD-TLA-OWED-1's model (#3647) can carry
the rule as an invariant (`CommittedOwedNeverVanishes`) once the model has a
checkpoint action; listed in the plan.

### Event times

Break-glass backfilled rows keep their original `event_time`; other backfilled
rows carry the backfill time. The verifier orders by id and treats time as
data. A statement's `issued_at` is not compared with row times.

## 6. Evidence bundle and chain-exact export

A directory (or a tar of it):

| File | Content |
|---|---|
| `manifest.json` | format version, log id, first and last statement seq, first and last row id, producer version, SHA-256 of every other file |
| `statements.ndjson` | one object per statement: `seq`, `raw` (base64), `sigs` (base64 list), optional `tsa` (RFC 3161 token over `raw`) |
| `owed.ndjson` | per statement seq: list of `{pending_id, digest}` |
| `events.ndjson` | rows in the chain-exact format, ascending id |

Chain-exact format (`GET /api/v1/audit/export?format=chain-v1`, same gates as
today's export, `audit.read` and `system.read`): every hashed field as the
exact string the hash consumed (`user_id` as the decimal string or empty,
`success` as `true`/`false`/empty, `event_time` as Unix microseconds, `diff`
as the stored string, `impersonated_by`/`acting_as` as decimal ids), plus
`id`, `prev_hash`, `entry_hash` and the encoding version. Display names are
not part of it. The exporter is generated from the same field list as the
hash, and a test recomputes the hash of every exported row.

A bundle may start at any statement S: its first row's `prev_hash` must equal
S's `head_hash` (or a retention-purge statement's seed). This keeps monthly
bundles small: an auditor verifies only the new range plus the statement
chain from genesis (statements are small; the chain of statements is always
complete).

Privacy: the bundle contains full rows, including IP addresses. It is an
export for an auditor under the same access rules as today's export. A
redacted bundle cannot be verified with the current entry hash, because the
hash streams `prev_hash` first and then every field, so a verifier needs every
field to recompute it. Selective disclosure needs a different leaf hash or a
Merkle tree (Q6, deferred).

## 7. Verifier rules (`keyorix-verify`)

Input: bundle, `--pin`, optional `--since <statement file>`, optional
`--tsa-roots`.

1. Check `manifest.json` hashes.
2. Statement chain: the first statement is a key genesis with `seq = 1`
   whose key id equals the pin; every next statement has the same log id,
   `seq + 1`, the right `prev_stmt`, the current epoch's key id, and a hybrid
   signature under the current epoch's key. A key change needs both
   signatures and moves the epoch.
3. Owed lists match their digests (§5).
4. Rows: ascending ids; `prev_hash` links; recompute `entry_hash` under the
   row's encoding version. At each checkpoint statement whose certified count
   is reached: the head id and hash match, and the owed rule holds.
5. A statement that certifies more rows than the bundle holds: BROKEN
   (truncation).
6. `--since`: the bundle must hold the same statement byte for byte; a newer
   `seq` than the bundle's last is a rollback; a different, validly signed
   statement for the same `seq` is a fork, and the tool writes both statements
   to `fork-proof.json`.
7. TSA receipts, when present and `--tsa-roots` given, are verified with
   `internal/notary`'s logic (reimplemented or vendored into `pkg/auditproof`
   under the stdlib-only rule; open point for the implementation).

Verdicts and exit codes follow `admin verify-audit`: 0 VALID, 1 BROKEN, 2
INDETERMINATE, 3 usage or I/O error. Key ids are displayed as `ask-<64 hex>`.
The report has a "not proven" list that always includes: rows after the newest statement are
uncertified; deletion of the newest statements is detected only against
`--since` or a TSA receipt; the signing key is on the host (ADR-116, "What
this proves, and what it does not").

## 8. Key changes, rotate-kek and RUNBOOKS-1 gap 5

### rotate-kek / migrate-provider

The audit signing seed is re-wrapped under the new KEK in the same two-phase
key-file commit as `dek.key`. The signing key does not change, so no
statement is needed, and every old statement verifies with the same pinned
key. The HMAC artefacts still change key; #3648 carries them across online.
After both, RUNBOOKS-1 gap 5 is closed offline (statements) and online
(#3648).

### Signing-key rotation (offline command)

| Step | Writes | Crash after this step | Next start |
|---|---|---|---|
| 1 prepare | new seed as `audit-signing.key.next` (wrapped) | old key active, `.next` present | removes `.next`, logs it; nothing signed with it |
| 2 commit | rename: current → `.prev`, `.next` → current | new key active, `.prev` kept | completes step 3 with `.prev` and current |
| 3 complete | key change statement signed by `.prev` then current, in the statement table under the lock | statement written | deletes `.prev` |
| 4 cleanup | delete `.prev` | done | nothing |

Until step 3 is done the server writes no checkpoint statement (it would be
under an epoch the log has not introduced). Step 3 is idempotent: if the
newest statement is already the key change to the current key id, it only
deletes `.prev`. A `.prev` that does not match the newest statement's key id
is refused with an error naming the runbook section.

### Compromise

If the signing seed may be exposed, an attacker can sign statements for the
old epoch with any `seq`. Statements the auditor already holds still pin the
honest history (fork detection). The runbook rotates the signing key at once,
publishes the key change statement off-host (TSA receipt), and tells auditors
the last honest seq of the old epoch.

## 9. Prototype evidence (throwaway, not committed)

A Go prototype (Go 1.27.2, stdlib only) of the statement codec, hybrid signer
and verifier ran in this session against a toy chain using the same entry-hash
shape as `ComputeEntryHash`. Results:

- Tamper matrix, each case BROKEN with the expected reason: modified row;
  modified and re-hashed row; whole suffix rewritten and re-hashed; deleted
  middle row; reordered rows; truncation below the newest statement; deleted
  middle statement; reordered statements; a flipped byte in the ML-DSA half; a
  flipped byte in the Ed25519 half; the ML-DSA half stripped; an edited
  certified count; an edited owed list; an old-epoch key signing after a
  rotation; an owed record deleted before backfill; an owed record settled
  twice; a re-seeded log under another key; a rewrite by the key holder
  checked against a held statement (fork, with both statements verifying under
  the same key).
- VALID cases: the full log across a key change and an owed backfill; the
  pre-rotation prefix with only the pinned genesis key id (gap 5).
- Honest residuals, written as passing tests: a row appended after the newest
  statement and removed is not detected; deleting the newest statements is
  detected only with `--since`.
- Mutation check: 10 verifier checks were each disabled in a scratch copy (ML-DSA
  verify, Ed25519 verify, seq continuity, owed vanish, truncation, `--since`,
  key epoch, pin, owed settled twice, head check). Each mutant made at least
  one test fail.
- `GODEBUG=fips140=only`: the signer and verifier ran with no
  `WithoutEnforcement` exemption; a control showed X25519 alone refused in the
  same run.
- Statement decoder fuzzed for 60 s (about 30 million executions): no
  non-canonical acceptance, no panic.
- Signing and verification timings were taken locally for the session report
  only; no numbers are recorded here.

## 10. Alternatives considered

| | Chosen | Alternative | Why not |
|---|---|---|---|
| Key source | random seed wrapped under KEK | derive from KEK | every KEK rotation would change the signing key and need a key change statement; the auditor's pin would change with each provider migration |
| | | off-host signer (KMS asymmetric sign, HSM) now | the only option that constrains the host admin, but needs ML-DSA support in each KMS [VERIFY] and a provider interface; kept as a follow-up provider behind the same statement format |
| Composition | AND, own encoding | IETF composite ML-DSA [VERIFY] | not final when written; our encoding is small and documented; re-encode later if needed |
| Statement encoding | TLV | C2SP signed note [VERIFY] | note format assumes a Merkle root and text lines; our fields are richer; TLV matches the chain's length-prefixed style |
| Statement per | each checkpoint | each row | about 3.4 KB of signature per row and a signing operation on the write path |
| Inclusion proofs | linear chain | Merkle tree (RFC 9162 style [VERIFY]) | O(log n) single-row proofs and redaction, but a new tree over the existing chain; deferred until R6 needs per-record proofs |
| Verifier home | `pkg/auditproof` + `cmd/keyorix-verify` | `keyorix-server admin verify-audit --bundle` | the auditor should not need the server binary or its dependency tree; a stdlib-only package is small enough to review |

## 11. Field and standard mapping

Every external claim below is unverified in this session (no standard text
was read) and is marked [VERIFY].

| Need | Mechanism here | Reference |
|---|---|---|
| Integrity and non-repudiation of logs | signed statements over the hash chain, fork proofs | NIS2 Directive Art. 21(2) risk measures [VERIFY]; DORA Art. 9 ICT security and Art. 12 logging [VERIFY]; ISO/IEC 27001:2022 Annex A 8.15 logging [VERIFY] |
| Automatic logging for AI systems (R6 export bundles) | the same bundle and verifier | EU AI Act Art. 12 [VERIFY] |
| Post-quantum signature | ML-DSA-65 | FIPS 204 [VERIFY] (API facts read from Go source) |
| Classical signature | Ed25519 | RFC 8032 [VERIFY]; FIPS 186-5 lists EdDSA [VERIFY] |
| Hybrid transition | AND composition | BSI TR-02102-1 and ANSSI guidance recommend hybrids during the transition [VERIFY] |
| Trusted time | RFC 3161 receipt over the statement | RFC 3161 (implemented in `internal/notary`) |
| Append-only log commitments | statement chain, fork evidence | RFC 6962 / RFC 9162 [VERIFY] |

## 12. Upgrade, rollback, mixed versions

- New tables: `audit_checkpoint_statements` (seq primary key, kind, raw, sigs,
  owed set) and the `owed_ref` column. Additive migrations, guarded the way
  ADR-029 adds columns.
- Upgrade: the first start with the feature writes a genesis statement and
  then a checkpoint statement for the existing chain. That statement proves
  the chain as it stood at that moment, not that earlier history was untouched
  before it (earlier history keeps today's HMAC protection). The report says
  "statements since <time>".
- Mixed versions in HA: an older replica keeps writing HMAC checkpoints
  without statements. The newer replica's next statement certifies the longer
  chain; nothing breaks. An older replica cannot write rows with `owed_ref`;
  rows it backfills have none, and the verifier reports their owed records as
  vanished. So the backfill must run only on new binaries: the implementation
  gates `BackfillPendingAuditEvents` on the encoding version in the schema
  marker, and UPGRADING says "upgrade every replica before the backfill
  resumes".
- Rollback to an older binary: it ignores the statement table and cannot
  verify `owed_ref` rows (it must refuse them as unknown encoding, never
  accept). A rollback after rows with `owed_ref` exist reads BROKEN online in
  the older binary, which is fail-closed and documented.

## 13. Implementation plan (next session, after approval)

Split to respect the PR size rule (about 400 lines and 8 files): five PRs,
each green on its own, each commit with red tests first.

**PR A: `pkg/auditproof` (statement codec and hybrid verify), no wiring**
1. red: KAT vectors file, codec round-trip and rejection tests,
   `FuzzParseStatement`, hybrid verify tamper tests against a stub.
2. green: codec, hybrid sign/verify, key id; dependency guard (stdlib only);
   independent cross-check of the vectors with a second ML-DSA implementation
   outside the repo (as RD-PQWRAP-1 did).
3. INVARIANTS fragment `INV-AUDITPROOF-stdlib-only`, fuzz target conf,
   changelog `### Internal`.

**PR B: signing key and statement writer**
4. red: `internal/encryption` tests for the seed file (wrap, rotate-kek
   re-wrap, wipe sweep); core tests: a checkpoint write produces statement
   N+1 linked to N, on SQLite and Postgres, HA lock test with two stores.
5. green: key file, registry, manifest, backup inclusion; statement table
   migration; writer inside `writeAuditCheckpointLocked`; genesis on first
   start; `keyorix audit signing-key show`.
6. docs: CONFIGURATION, key-rotation runbook §5, threat-model rows AUDIT-6
   to AUDIT-9 updated from GAP to mitigated with their tests, closures.

**PR C: owed set and `owed_ref`**
7. red: core tests (backfill writes `owed_ref`; a deleted pending record
   after a statement makes verification BROKEN; older encoding refused);
   auditverify differential test extended.
8. green: encoding version with the 14th field, migration, backfill change,
   owed set in the statement, online check in `VerifyAuditChain`.
9. TLA: `Checkpoint` action and `CommittedOwedNeverVanishes` in
   `OwedAudit.tla` with a seeded-bug config (after #3647 merges).

**PR D: chain-exact export, evidence bundle, `keyorix-verify`**
10. red: export test that recomputes every row's hash; bundle round-trip;
    verifier tamper matrix over a bundle built by the real server (CLI journey).
11. green: `format=chain-v1`, `keyorix audit evidence-bundle`, `cmd/keyorix-verify`,
    Makefile and release targets (no `.github` edit; the release workflow
    change is its own PR), SBOM.
12. docs: auditor guide, demo script marked implemented, changelog `### Added`.

**PR E: rotation, publication, fork proofs**
13. red: crash matrix for `signing-key rotate` (§8), `--since` rollback and
    fork tests, TSA receipt over statement bytes.
14. green: the command, the anchoring call, `fork-proof.json`.
15. runbooks: signing-key compromise, staging clone `--new-log`.

Checks before each push: `go build ./... && go vet ./...`, `go test` on the
touched packages (Postgres via kpg for `internal/core`),
`go test ./internal/threatmodelcheck`, `scripts/check-adr-numbers.sh`,
`scripts/changelog-assemble.sh --check`. Container and VM checks: pending e2e
VM.
