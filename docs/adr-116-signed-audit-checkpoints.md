# ADR-116: Signed audit checkpoints (hybrid Ed25519 + ML-DSA-65) and a standalone offline verifier

## Status

**Proposed** (2026-10-23, RD-AUDIT-CKPT-1, R&D prototype R8). Andrei answered
all ten open questions on 2026-10-23 and approved implementation to start
with the status staying Proposed; the answers and their binding conditions are
under "Decisions (Andrei, 2026-10-23)". The ADR moves out of Proposed only
through the normal ADR process. Nothing in this ADR is implemented.

Design detail, formats, verifier rules and the commit plan:
`docs/design-rd-audit-ckpt.md`. Demo script (against the future CLI, not
implemented): `docs/demo/rd-audit-ckpt.md`.

Related: ADR-029 (hash chain, HMAC checkpoints), ADR-112 Amendment 6 and the
owed-audit backfill (`internal/core/audit_owed.go`), the offline verifier
design (`docs/design-b4-offline-audit-verify.md`), the recovery options note
(`docs/design/recovery-options.md` §2 and §4). Open PRs this ADR depends on in
reading, not in code: #3648 (audit key-transition record), #3621 (fail-closed
verification state), #3662 (RD-PQWRAP-1 hybrid wrapping conventions), #3647
(TLA+ model of owed-audit).

Sibling drafts, numbered together on 2026-10-23: ADR-117 TPM-sealed KEK
(#3667), ADR-118 agent evidence ledger (#3668), ADR-119 attestation-gated
secret release (#3666), ADR-120 attenuating agent tokens (#3669). This ADR is
referenced by them as ADR-116.

## Context

ADR-029 makes the audit trail tamper-evident with a SHA-256 hash chain and
closes truncation on-box with checkpoints: `(chained_events, head_id,
head_hash, key_version)` MACed with HMAC-SHA-256 under a KEK-derived key
(`internal/core/audit_checkpoint.go`, `checkpointCanonical`). That design has
three limits that matter for an auditor, an accelerator reviewer or an ENISA
assessor who wants to check the trail without trusting Keyorix:

1. **Verifying needs the secret.** An HMAC can only be checked by a holder of
   the key, and every holder can also forge. `admin verify-audit
   --checkpoint-key-file` hands the auditor a key that lets them write
   checkpoints. A checkpoint held by the auditor is therefore not evidence
   against the operator in a dispute, and an auditor cannot check one
   without receiving a secret.
2. **A key change orphans the past.** `rotate-kek` and `migrate-provider`
   change the checkpoint key. Offline, older checkpoints then read BROKEN
   unless the old key is kept and supplied (RUNBOOKS-1 gap 5; premise row 4 of
   `docs/design/recovery-options.md`). #3648 carries the online state across
   with a record MACed under both keys, but its old-key MAC can only be
   checked by a holder of the old key.
3. **Offline verification needs the database.** `admin verify-audit` reads the
   SQLite file or a Postgres DSN. An auditor usually receives an export, not
   database access. The current export (`GET /api/v1/audit/export`,
   `AuditExportEntry`) carries `prev_hash`/`entry_hash` but not the exact
   hashed field values: `impersonated_by`/`acting_as` are exported as user
   names where the hash covers numeric ids, `success` loses its null state,
   and `diff` is re-encoded by `encoding/json` (checked in this session:
   `json.RawMessage` output is compacted). From an export alone an auditor can
   check the links but cannot recompute an `entry_hash`.

Two more facts shape the decision:

- The owed-audit backfill (ADR-112 Amendment 6, #3345) appends owed rows at the
  chain tail in the order they were owed. It never inserts in the middle, so a
  checkpoint over a prefix stays valid. Nothing today ties a backfilled row to
  its `pending_audit_events` record, and nothing outside the database knows
  which records were owed. A database-level actor who deletes a pending record
  before the backfill leaves no trace in the chain.
- Go 1.27 ships `crypto/mldsa` (FIPS 204; read in this session from the Go
  1.27.2 source: ML-DSA-44/65/87, 32-byte seeds, `Options.Context` up to 255
  bytes, ML-DSA-65 public key 1952 bytes, signature 3309 bytes). `go.mod` says
  `go 1.27`, toolchain `go1.27.3`. The repo uses no ML-DSA today; Ed25519 is
  used for license and bundle verification (`pkg/licenseverify`,
  `pkg/bundleverify`, `pkg/trust`).

## Decision

### 1. Checkpoint statements, signed with a hybrid public-key signature

Every checkpoint write also produces a **checkpoint statement**: a canonical,
length-prefixed binary record (exact layout in the design note §3) of

- a domain label `keyorix/audit-checkpoint/v1` and a statement kind;
- the **log id** (32 random bytes created with the signing key, one per
  install);
- a **statement sequence number** and the SHA-256 of the previous statement
  (the statements form their own chain);
- the certified count (chained + purged, as today), the head id and the head
  `entry_hash`, the purged count and the retention anchor digest;
- the **owed set**: the number of open `pending_audit_events` records and a
  digest over `(pending id, SHA-256 of the owed event)` pairs;
- the signing key epoch and key id, the seal segment number (for the future
  seal command, recovery-options §2 constraint 7) and the signer's clock.

The statement is signed with **Ed25519 and ML-DSA-65, both required** (AND
composition). Ed25519 signs the statement bytes under a domain prefix; ML-DSA-65
signs them with the context string `keyorix/audit-checkpoint/v1`. Both public
key fingerprints are inside the signed bytes, so neither signature can be
stripped or swapped for one under another key. There is no classical-only and
no PQ-only acceptance, and no runtime algorithm switch (the same rule as
RD-PQWRAP-1, #3662).

Kinds: key genesis (self-signed, introduces the first key), checkpoint, key
change (signed by the old **and** the new key), retention purge (authenticates
the new first row of the chain), seal (reserved for the seal command).

The HMAC checkpoint, high-water mark, retention anchor and verification state
stay as they are for the online path. The statement is written in the same
transaction as the HMAC checkpoint, under `WithAuditCheckpointLock`, so the
statement chain is serial across replicas. Retiring the HMAC checkpoint is a
later decision, not part of this ADR.

### 2. The signing key

A random 32-byte seed in a new key file, wrapped under the KEK exactly like
`dek.key`, registered in the key-file registry and the key-set manifest, and
carried in backups. Both private keys are derived from the seed with
HKDF-SHA-256 under fixed labels. A KEK rotation re-wraps the seed and leaves the
signing key, and therefore every statement and the auditor's pinned key id,
unchanged. A signing-key rotation is its own offline command; it writes a key
change statement signed by both keys. On a suspected host compromise the
runbook rotates the KEK **and** the signing key.

At genesis the server prints the **key id** (SHA-256 of both public keys). The
operator gives it to auditors through a channel the host does not control; the
verifier takes it as `--pin`. Without a pin the verifier reports
INDETERMINATE, never VALID.

### 3. Owed-audit backfill keeps checkpoints valid, and becomes checkable

- Backfill already appends at the tail, so every earlier statement stays
  valid. This ADR keeps that rule and states it as an invariant: no write path
  may insert an audit row below the head of a signed statement.
- A backfilled row gains a hashed `owed_ref` field: the pending id and the
  SHA-256 of the owed event JSON (a chain-encoding change, design note §5).
  Rows in the previous encoding version stay valid: the verifier accepts both
  versions (see Q5 obligation below).
- Verifier rule: every owed record listed by statement N must, by statement
  N+1, either still be listed or appear exactly once as an `owed_ref` in the
  rows between them. A record that disappears without reaching the chain is
  BROKEN. This makes the "pending record deleted before backfill" case
  detectable offline, which it is not today.
- Break-glass rows backfilled with their original `event_time` keep working:
  the verifier orders by id, not time (`TestVerify_ChainWithNonMonotonicTimestampsIsValid`).

### 4. Standalone offline verifier `keyorix-verify`

A new binary built from a new package `pkg/auditproof` that imports only the
Go standard library (enforced by a dependency guard like
`internal/auditverify/dependency_guard_test.go`). ML-DSA-65 is in the standard
library at the repo's Go version (checked 2026-10-23: `go.mod` says `go 1.27`,
toolchain `go1.27.3`; `crypto/mldsa` exists in the Go 1.27.2 source tree
with `MLDSA65()`, public key 1952 bytes, signature 3309 bytes), so no circl or
other third-party module is needed and the binary is described as
**stdlib-only**. If an implementation step ever needs a non-stdlib module
(for example for TSA receipt parsing), the binary must instead be described as
"minimal-deps" in the ADR, the release notes and `--version`, and the
dependency guard stays with an explicit allowlist. It reads an **evidence
bundle** (design note §6): statements, the owed sets the digests commit to, and
audit rows in a new **chain-exact export** format that carries every hashed
field verbatim. It needs no server, no database, no Keyorix secret and no
network. It reports VALID, BROKEN or INDETERMINATE with the same honesty rules
as `admin verify-audit` (a "not proven" list).

`--since <statement>` takes a statement the auditor kept from an earlier
bundle. The new bundle must contain it byte for byte. A different, validly
signed statement with the same sequence number is reported as a fork, and the
two statements together are a portable proof that the key holder signed two
histories.

### 5. RUNBOOKS-1 gap 5 (rotate-kek makes older checkpoints read BROKEN offline)

Resolved offline by §1 and §2: statements are verified with public keys, the
key log is part of the bundle, and a key change statement is signed by both
keys. An old statement keeps verifying forever with no old secret. Under §2 a
KEK rotation does not change the signing key at all. The online HMAC artefacts
still need #3648 (re-sign and carry the state across), which this ADR keeps.

## What this proves, and what it does not

- **Detects**, offline and from the bundle alone: a modified row, a deleted or
  inserted row in the middle, reordered rows, truncation below a statement, a
  deleted, reordered or replayed statement, an edited or stripped signature
  component, a statement signed by the wrong key epoch, an owed record that
  vanished, an owed record settled twice, a re-seeded log under another key.
  Every one of these is a test in the throwaway prototype (design note §9),
  and the verifier's checks were each disabled once to show a test fails.
- **Does not detect without more input**: rows appended after the newest
  statement and later removed (they were never certified), and the deletion of
  the newest statements. `--since` closes the second for every statement the
  auditor holds. Publishing each statement off-host (RFC 3161 receipt over the
  statement bytes with the existing notary, or a push to the auditor) closes
  both up to the publication time.
- **Does not stop the key holder.** The signing seed is on the host, as the
  HMAC key is today. A host administrator with the KEK can still sign any
  history going forward. What changes is that a statement already given to
  someone else is a signed commitment: a rewrite after that point is a
  detectable fork, provable by the two signatures. Moving the signing key off
  the host (KMS asymmetric signing, HSM, TPM-sealed seed per ADR-117) is the way to
  constrain the host administrator, and is listed as a later option.

## Decisions (Andrei, 2026-10-23)

All ten questions were answered on 2026-10-23, each with the recommended
option (a). The status stays Proposed: implementation is approved to start as
Proposed. Q5 and Q7 carry binding conditions.

| # | Question | Decision | Reason |
|---|---|---|---|
| Q1 | Signing key source | **(a)** random seed in a new key file wrapped under the KEK, like `dek.key`; `rotate-kek` only re-wraps. Off-host signer (c) remains a follow-up provider. | The auditor's pinned key id survives KEK rotation and provider migration. |
| Q2 | Hybrid composition | **(a)** AND of Ed25519 and ML-DSA-65 with our own domain prefix and context; both key ids inside the signed bytes. Re-encode later if the IETF composite work is final. | The IETF encoding is not final; ours is small and documented. |
| Q3 | Statement encoding | **(a)** own length-prefixed TLV. | Canonical, unambiguous and fuzzable; matches the chain's encoding style. |
| Q4 | HMAC checkpoint | **(a)** keep it for the online path; write the statement next to it in the same transaction under `WithAuditCheckpointLock`. Retiring HMAC (and #3648's machinery) is a later ADR. | Smallest blast radius. |
| Q5 | `owed_ref` on backfilled rows | **(a)** 14th hashed field under an explicit chain-encoding version, #1452-style migration. **Obligation:** the verifier (`keyorix-verify` and the server's verify) keeps accepting rows in the previous chain-encoding version; the implementation plan has a test with old-version rows next to new-version rows (design note §13, PR C). | Lets the offline verifier prove an owed record reached the chain; the count-only alternative cannot tell which record vanished. |
| Q6 | Merkle tree / selective disclosure | **(a)** defer; linear chain in v1. Recorded as a prerequisite for the agent evidence bundles of ADR-118 (R6), which need redacted per-record proofs. | The current entry hash needs every field of every row, so redacted proofs need a new leaf hash or a tree. |
| Q7 | Verifier home | **(a)** separate `keyorix-verify` binary built from `pkg/auditproof`, with checksum, SBOM and a dependency guard. **Condition checked:** ML-DSA-65 is in the Go standard library at the repo's Go version (`crypto/mldsa`, `go 1.27`, toolchain `go1.27.3`; source read in the 1.27.2 tree), so the binary is **stdlib-only**. If any step needs circl or another third-party module, the ADR and the binary say "minimal-deps" instead, and the dependency guard stays either way. | Auditors need neither the server binary nor its dependency tree. |
| Q8 | Publication | **(a)** export command plus the existing RFC 3161 notary over each statement's bytes; witness co-signing later. | Deleting the newest statements is detectable only against a copy held elsewhere. |
| Q9 | Signing-key rotation | **(a)** its own offline command, `admin audit signing-key rotate` with prepare/commit/complete and a key change statement signed by both keys; `rotate-kek` only re-wraps. | Keeps the auditors' pinned key stable across KEK changes; the compromise runbook rotates both. |
| Q10 | Unpinned verification | **(a)** without `--pin`, `keyorix-verify` reports INDETERMINATE with reason "key not pinned", never VALID. | An unpinned genesis key is trust-on-first-use; a log re-seeded under an attacker key would otherwise verify. |

## Consequences

- One more key file, in the key-set manifest and in backups. A restore needs
  it, like `dek.key`. A clone of production restored into staging shares the
  log id and would look like a fork to an auditor holding production
  statements; the runbook gets a `--new-log` genesis for clones.
- Each checkpoint row grows by about 3.7 KB of statement and signature (the
  sizes are format facts: a 356-byte checkpoint statement in the prototype,
  3373 bytes of signature). At the default scheduler interval this is small;
  the design note gives the formula, not measurements.
- The chain encoding gains a field for backfilled rows. Older binaries cannot
  recompute those rows and must refuse, not skip, them (fail closed); the
  UPGRADING note says so.
- A new release artefact (`keyorix-verify`, its checksum and SBOM).
- In a prototype run under `GODEBUG=fips140=only` (Go 1.27.2, darwin/arm64),
  Ed25519, ML-DSA-65, HKDF-SHA-256 and SHA-256 signed and verified with no
  enforcement exemption, while X25519 alone was refused. This is a statement
  about the Go module's runtime mode, not a FIPS validation claim.

## New vs state of the art

- Signed tree heads in Certificate Transparency (RFC 6962 / RFC 9162 [VERIFY])
  and the Go checksum database's signed checkpoints [VERIFY] give
  third-party-verifiable, fork-evident commitments to an append-only log. They
  are classical (ECDSA/Ed25519) and they log public data. This ADR applies the
  same commitment model to a private security audit trail inside one product,
  with a hybrid post-quantum signature, so a statement handed to an auditor
  today stays verifiable after a quantum break of the classical half.
- Secure audit logging (Schneier and Kelsey 1999; Bellare and Yee forward
  integrity; Crosby and Wallach 2009 [VERIFY]) uses MAC chains, evolving keys
  or Merkle trees. MAC-based schemes need the verifier to hold a secret. Here
  the verifier holds only a public key id.
- New, as far as we found (a search claim, not a proof): commitments to the
  set of **owed** audit records, so that "an effect committed but its audit
  row was lost" becomes a checkable property of the signed log rather than a
  promise of the writer. This connects the asymmetric owed-audit policy that
  RD-TLA-OWED-1 (#3647) models with the tamper-evidence layer.
- Commercial secret managers [VERIFY]: HashiCorp Vault and OpenBao audit
  devices write HMAC-protected fields to an external sink; we know of no
  public-key signed, offline-verifiable checkpoint format in them.

## Technical risks

- **Composite signature design.** Our own AND composition is simple, but it is
  not a standard encoding. Mitigation: domain separation and both key
  fingerprints inside the signed bytes; an external cryptographic review
  before GA (same ask as RD-PQWRAP-1 §17).
- **ML-DSA in Go is new.** `crypto/mldsa` is in the Go 1.27 release line. A
  bug or API change there affects every statement. Mitigation: known-answer
  vectors pinned in tests and an independent cross-check (as RD-PQWRAP-1 did
  with circl), done in the implementation series.
- **Verifier drift.** A second implementation of the entry hash (in
  `pkg/auditproof`) can disagree with the writer. Mitigation: the existing
  differential pattern (`TestDifferential_TamperMatrix`) extended to the new
  package.
- **Key-on-host limit.** Stated above. If the claim is ever phrased as "even
  the operator cannot rewrite history", it is false until the signer is off
  the host.
- **Export fidelity.** The chain-exact export must stay byte-exact as fields
  are added to the chain. Mitigation: the exporter is derived from the same
  field list as the hash, with a test that recomputes every exported row.
- **Statement size on Postgres replicas and backups.** About 3.7 KB per
  checkpoint. A very short scheduler interval multiplies it. Mitigation: a
  floor on the interval; numbers to be measured on the bench VM, not here.
- **Clock.** `issued_at` is the signer's clock and proves nothing about time;
  only an RFC 3161 receipt does. The verifier reports it as advisory.
