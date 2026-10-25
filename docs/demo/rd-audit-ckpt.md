# Demo: an auditor verifies the audit trail offline (5 minutes)

> **NOT IMPLEMENTED.** This script is written against the CLI that
> `docs/adr-116-signed-audit-checkpoints.md` (Proposed) and
> `docs/design-rd-audit-ckpt.md` §13 describe. None of the commands
> `keyorix audit signing-key`, `keyorix audit evidence-bundle`,
> `keyorix-verify` or `admin audit signing-key rotate` exist yet. Do not run it
> against a release; it is the acceptance script for the implementation.

What it shows: an auditor with one public key id and a bundle of files checks
that the audit trail was not modified, shortened or reordered, without the
server, the database or any Keyorix secret. Then the same check catches three
kinds of tampering, survives a key rotation, and catches an owed audit record
that was deleted before it reached the chain.

Needs: a demo server with checkpoints on (`scripts/demo/up.sh` with the
demo's own `KEYORIX_DEMO_*` names), the `keyorix` CLI logged in as an admin,
`sqlite3` for the tamper steps, and the `keyorix-verify` binary.

## 0:00 – 0:40 The problem (talk)

- "The audit log is hash-chained. Today an auditor who wants to check it needs
  database access and a secret key that would also let them forge it. And
  after a key rotation, old checkpoints can't be checked offline at all."
- "Now every checkpoint is a signed statement, Ed25519 and ML-DSA-65 together.
  The auditor holds only a fingerprint."

## 0:40 – 1:30 The fingerprint and the bundle (run)

```
keyorix audit signing-key show
keyorix audit checkpoint
keyorix audit evidence-bundle --out demo-bundle/
ls demo-bundle/
```

Expected: a key id `ask-…` (64 hex characters), "checkpoint statement #N
written", and the four files `manifest.json`, `statements.ndjson`,
`owed.ndjson`, `events.ndjson`. Say: "The fingerprint goes to the auditor once,
by a channel the server doesn't control. The bundle can go by email."

## 1:30 – 2:10 Verify offline (run)

```
keyorix-verify --bundle demo-bundle/ --pin <key id from the step above>
```

Expected: `VALID`, the statement range, the number of rows, "signatures:
Ed25519 + ML-DSA-65 on every statement", and the "not proven" list (rows after
the newest statement are uncertified; the signing key is on the server host).
Say: "No server, no database, no secret, no network."

## 2:10 – 3:20 Three kinds of tampering (run)

Copy the bundle three times and change one thing in each.

```
cp -r demo-bundle t1; cp -r demo-bundle t2; cp -r demo-bundle t3
# t1: change one word in one row's description
# t2: delete one row in the middle of events.ndjson
# t3: swap two rows
keyorix-verify --bundle t1/ --pin <key id>
keyorix-verify --bundle t2/ --pin <key id>
keyorix-verify --bundle t3/ --pin <key id>
```

Expected: each `BROKEN`, with "entry_hash mismatch (row modified)" for t1 and
"prev_hash does not link" for t2 and t3, naming the row id. Then delete the
last 20 rows of `events.ndjson` in a fourth copy: "statement #N certifies M
events, only M-20 present (truncation)". Exit code 1 on BROKEN, the same
contract as `admin verify-audit`.

## 3:20 – 4:10 A key rotation does not orphan the past (run)

```
keyorix-server admin audit signing-key rotate      # offline, server stopped
keyorix audit checkpoint
keyorix audit evidence-bundle --out after-rotation/
keyorix-verify --bundle after-rotation/ --pin <the ORIGINAL key id> --since demo-bundle/statements.ndjson
```

Expected: `VALID`, "key epochs: 2 (key change at statement #K, signed by both
keys)", and "--since: statement #N found unchanged". Say: "The auditor kept
the original fingerprint. Statements signed before the rotation still verify,
with no old secret. That is RUNBOOKS-1 gap 5."

## 4:10 – 5:00 An owed record that vanished (run)

With the demo's audit log made to refuse writes (the break-glass runbook's
outage switch), suspend a secret: the revocation commits and its audit row is
owed. Take a checkpoint, then delete the pending record with `sqlite3` before
the backfill runs, restore the audit log, and checkpoint again.

```
keyorix audit evidence-bundle --out owed/
keyorix-verify --bundle owed/ --pin <key id>
```

Expected: `BROKEN`, "owed record <id> committed at statement #N vanished at
statement #N+1 without reaching the chain". Say: "Revocations never wait for
the audit log. If the record of one is lost on purpose, the signed log says
so."

## If asked

- "Can the operator forge it?" The signing key is on the server host, as the
  HMAC key is today. A host administrator can sign a new history from now on.
  They cannot change a statement the auditor already holds: `--since` reports a
  fork, and the two signed statements prove it.
- "Why two signatures?" If either algorithm is broken, the other still holds.
  The ML-DSA half is the post-quantum one.
