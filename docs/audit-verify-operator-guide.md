# Offline audit-chain verification: operator guide

`keyorix-server admin verify-audit` re-walks the ADR-029 tamper-evidence hash
chain directly against a database artifact — a detached copy, or this host's
own configured database — without trusting or needing a running Keyorix
server. This page is the operational how-to; the design rationale and full
trust model live in
[`design-b4-offline-audit-verify.md`](design-b4-offline-audit-verify.md).

**Read the "what this does not prove" output on every run, not just the
verdict line.** A bare re-walk (no `--checkpoint-key-file`, no `--anchor`,
no `--tsa-roots`) catches tamper on rows still present in the table, but
cannot detect tail-truncation or a genesis re-seed — see §2 of the design
doc for why, and which flags close that gap.

## Quick reference

| Flag | Purpose |
|---|---|
| `--db <path>` | Verify this SQLite file directly (read-only), instead of the configured database |
| `--pg-dsn <dsn>` | Verify this Postgres DSN directly (see GRANT snippet below) |
| `--checkpoint-key-file <path>` | The derived audit-checkpoint signing key (hex or base64) — enables checkpoint/high-water/truncation checks |
| `--anchor <path>` | A JSON checkpoint snapshot held externally — cross-checks the live chain against a copy this host does not control |
| `--tsa-roots <path>` | PEM bundle of trusted RFC 3161 TSA root certs — independently re-verifies a checkpoint's or `--anchor`'s timestamp token, needing no shared secret at all |
| `--json` | Emit the result as a structured document instead of a human report |

Exit codes: `0` VALID, `1` BROKEN (tamper detected), `2` INDETERMINATE
(couldn't fully verify — e.g. an unauthenticated retention gap), `3`
usage/input error. Never `0` when something was silently left unverified.

## Running against a detached copy (recommended for auditors)

Take a copy of the database (a SQLite file, or a `pg_dump`/replica restored
elsewhere) and point the command at it directly. This never touches the live
server and never takes `serverguard`'s lock:

```
keyorix-server admin verify-audit --db /path/to/copy/secrets.db --json
```

## Running against the live configured database

Without `--db`/`--pg-dsn`, the command verifies the database named in the
server's own config and acquires the same exclusive lock every other `admin`
subcommand does, refusing to proceed (unless `--force`) if a server or
another admin command already holds it:

```
keyorix-server admin verify-audit --config /etc/keyorix/config.yaml
```

## Postgres: minimum read-only access

Verification only needs `SELECT` on the three tables the chain and its
checkpoints live in. Create a dedicated read-only role rather than handing
out broader credentials:

```sql
CREATE ROLE keyorix_audit_verify LOGIN PASSWORD '<set a strong password>';
GRANT CONNECT ON DATABASE keyorix TO keyorix_audit_verify;
GRANT USAGE ON SCHEMA public TO keyorix_audit_verify;
GRANT SELECT ON audit_events, audit_checkpoints, system_metadata TO keyorix_audit_verify;
```

Then point `--pg-dsn` at that role:

```
keyorix-server admin verify-audit \
  --pg-dsn "postgres://keyorix_audit_verify:<password>@db.internal:5432/keyorix?sslmode=verify-full"
```

No `INSERT`/`UPDATE`/`DELETE` grant is ever required — the command opens
Postgres the same way it opens SQLite: strictly read-only.

## Closing the truncation gap: `--checkpoint-key-file`

A bare re-walk cannot tell a legitimately shorter chain from a truncated
one — see design §2. Supply the *derived* checkpoint signing key (not the
KEK, not a passphrase) to additionally check the chain length against the
certified high-water mark:

```
keyorix-server admin verify-audit --db copy.db \
  --checkpoint-key-file /secure/path/audit-checkpoint.key
```

The key file may be hex- or base64-encoded. Extract it once, out of band,
from whatever KEK-derivation process the server itself uses; this command
never derives it from a KEK or passphrase itself (by design — see design
Q1).

## Closing the "host admin holds everything" gap: `--anchor` and `--tsa-roots`

`--checkpoint-key-file` alone does not constrain a host admin who holds
*both* the database and that key — they can rebuild a fully self-consistent,
validly-checkpointed history. Closing that requires an anchor genuinely held
outside the host:

- `--anchor <bundle.json>` — a signed checkpoint snapshot captured earlier
  and archived off-box (e.g. from a prior `verify-audit --json` run, or
  `keyorix audit export`). Cross-checked against the live chain once
  authenticated by the checkpoint key and/or an RFC 3161 token.
- `--tsa-roots <roots.pem>` — a PEM bundle of trusted third-party
  time-stamping-authority root certificates. This is the strongest leg of
  the trust model: it needs no shared secret from this host at all, only
  the TSA's public root, so it constrains even an admin who holds the
  checkpoint key.

```
keyorix-server admin verify-audit --db copy.db \
  --anchor /secure/path/checkpoint-2026-09-01.json \
  --tsa-roots /etc/ssl/tsa-roots.pem
```

## What this tool never proves

Stated in full in design §2, and always echoed in the report's own "what
this run does NOT prove" section: a host admin who holds both the database
and its checkpoint signing key, with no external anchor to check against,
can fabricate a fully self-consistent history that this tool cannot
distinguish from genuine. Only a `--anchor` or `--tsa-roots` check taken
from a point *before* the tampering closes that gap, and only from that
point onward.
