# Audit key transition: carrying the audit verification state across a key change

Status: implemented by AUDIT-ROTATE-TRANSITION-1 (issue #3642). This is option C of
`docs/design/recovery-options.md` §4, which includes option A. Decisions taken on
2026-10-23: `ro1-rotate-kek-checkpoint` = a, `avs1-key-epoch-discontinuity` = a.
The accept-loss / seal command is a separate follow-up (AUDIT-ACCEPT-LOSS-1).

## Problem

Four audit artifacts are MACed with the KEK-derived checkpoint key:

- the checkpoint rows;
- the high-water mark;
- the retention anchor;
- the verification state.

`rotate-kek` and `migrate-provider` change that key and write nothing to the database.
With #3621 (fail closed), the next server reads the state row as a sticky
`other key epoch` discontinuity, so an honest rotation and a relabelled row look the same.
On an install with a retention purge, the online walk also needs genesis and reads BROKEN
(RECOVERY-OPTIONS-1 F2).

## Construction

A key change runs in two steps around the key-file commit.

**1. Prepare** runs before the new key files are written, while the command holds both
keys. Under `WithAuditCheckpointLock`, with the OLD key:

1. A full verification (`VerifyAuditChain`: walk, checkpoint, high-water, retention anchor).
2. The verification state is loaded and saved as usual. That records any discontinuity
   the load finds. A failed walk is recorded as a sticky failure (source
   `key-transition`), so a broken chain is carried over as broken.
3. A second walk gives the exact head. Then the record is appended to the
   `audit_key_transitions` system_metadata row.

A record is the JSON payload `P`:

```
{v, seq, old_kid, new_kid, at, head_id, head_hash, certified, chain_valid, reason,
 state, high_water, anchor, checkpoint_id, checkpoint, prev}
```

In `P`:

- `state`, `high_water` and `anchor` are SHA-256 digests of the stored values.
- `checkpoint` is the SHA-256 of the latest checkpoint's canonical bytes plus its signature.
- `prev` is the digest of the previous record (`sha256(P)`).

The record is stored as:

```
akt-v1 \x1f b64url(P) \x1f macOld \x1f macNew
macOld = HMAC(K_old, "auditkeytrans-v1\x00old\x00" || P)
macNew = HMAC(K_new, "auditkeytrans-v1\x00new\x00" || P || "\x00" || macOld)
```

Records are joined with `\n`. A record whose `old_kid` is the current key is *pending*:
the key files were never committed. The next prepare replaces it rather than appending
after it.

**2. Complete** runs with the NEW key: in the command right after the key files commit,
and again at every server start before the scheduler runs. Under the lock, it first checks
the last record:

- its `new_kid` must be the current key;
- `macNew` must verify;
- the stored state must still hash to `state`.

If all hold, it runs these steps:

1. Re-sign the retention anchor and the high-water mark (when they still hash to the
   recorded digests).
2. If `chain_valid`, write a fresh checkpoint through the normal write path. The carried
   pin and the high-water floor still apply.
3. Save the state under the new key with `key_epoch {seq, digest}`.
4. Append one in-chain `system.audit_key_transition` event naming the record digest.

Every step can be re-run safely. Until the event exists, a read accepts the old state row
through the record (same digest, `macNew` valid), so a crash after the key files commit does
not raise an alarm. The event is appended after the state save. Once it exists, the old row
put back (a rollback that erases what was recorded since) is no longer accepted and reads as
a discontinuity.

## Why this construction

- **Two MACs, one per key, over the same payload naming both epochs.**
  - `macNew` stops a DB-only actor (no key) from inventing or editing a transition. The
    online server can check it.
  - `macOld` stops a holder of the new key alone from forging a transition out of an
    arbitrary pre-rotation state, such as a truncated chain or a state with its failure
    removed. Anyone who holds the old key can check it: an auditor with the exported old
    checkpoint key (`verify-audit --previous-checkpoint-key-file`), or an external anchor
    taken before the rotation.
  - The online server after the rotation cannot check `macOld`: it holds only the new key.
    That is inherent to symmetric MACs. A holder of the new key can already fabricate
    everything signed after the rotation, so it gains nothing online that it did not
    already have.
- **Direction labels** (`old` / `new`) keep either MAC from standing in for the other,
  even if the two keys were equal.
- **`macNew` covers `macOld`:** the new-key holder attests to the exact old-key
  attestation it saw.
- **Both kids, `seq` and `prev` are inside `P`.** A record cannot be replayed for another
  epoch pair or reordered, and a middle record cannot be dropped without being noticed.
  Each such case reads BROKEN: "wrong epoch".
- **Digests, not copies.** The old artifacts stay in place until completion re-signs
  them. Old checkpoint rows are append-only and stay signed under the old key. The record
  names the latest one (`checkpoint_id`, `checkpoint`), which is the "verifiable under the
  old key reference".
- **Prepare before the key-file commit.** Nothing the old-key server trusts changes: a
  pending record is ignored. After the commit the old key is gone for good (new salt), so
  anything left to do needs only the new key and the record. This is why the record is
  written first, contrary to the "DB step after the files" ordering in
  recovery-options.md §4: that ordering would leave a crash between the two steps with no
  way to carry the state over.
- **In-chain event.** The event is hash-chained and certified by the fresh checkpoint.
  Deleting the metadata row then still leaves proof that a transition existed.
  Installs rotated by older binaries have neither the event nor the row, and keep their
  previous behaviour.

## Verification rules (online and offline)

Let E be the current key epoch: the server's key version online, or the authenticated
latest checkpoint's key version offline.

- No row and no transition event: nothing to check (no rotation, or an older one).
- A transition event, or a state carrying `key_epoch`, but no row: BROKEN (missing).
- The row is malformed, or `seq` / `prev` / kid linkage breaks: BROKEN.
- The last record has `new_kid` = E: `macNew` must verify under the current key (forged
  otherwise). Its head must still be in the chain with that hash, unless a signed
  retention purge removed it.
- The last record has `old_kid` = E: it is pending. `macOld` must verify under the
  current key, and the record before it (if any) must have `new_kid` = E.
- Any other last record: BROKEN (wrong epoch).
- Offline, for every supplied previous key that verifies the record's checkpoint (as the
  old key of that epoch), `macOld` must verify under it (forged otherwise).

Online, each BROKEN case is a sticky discontinuity of kind `key transition`.

## Crash points

| Kill after | State on disk | Next step | Result |
|---|---|---|---|
| prepare (record pending) | old key files, pending record | server on the old key ignores it; a re-run of the command replaces it | VALID under the old key |
| key files written, not renamed | as #3607 / KEYSET-MANIFEST-1 handles | unchanged by this change | unchanged |
| key files committed, before complete | new key, old artifacts, active record | server start (or the command) completes it | VALID, no alarm in between |
| any step inside complete | partly re-signed | completion re-runs; each step is idempotent, the event is last | VALID |
| old state row put back after completion | event exists, old-key row | completion refuses | `other key epoch` discontinuity |
| record or state edited before complete | digest mismatch | completion refuses | fail closed: `other key epoch` / `key transition` discontinuity |

## Not covered

- A damaged record list (malformed, broken linkage) does not block a key change, which may
  be the response to a compromise. Prepare starts a new list (`reset` names the damage). The
  state load has already recorded a sticky `key transition` discontinuity. Offline, the
  earlier transition events name records the new list does not hold, so it reads BROKEN.
- Rotation while other PostgreSQL replicas keep writing under the old key is unsupported,
  as before. A state row changed after prepare no longer matches its digest and reads as a
  discontinuity (fail closed).
- The evidence-signing key and the backup-manifest key are not carried over (evidence
  packs keep "superseded key version").
- Accepting a real loss: AUDIT-ACCEPT-LOSS-1.
