# Rotating encryption keys

Two independent rotations exist: the **DEK** (data encryption key — what actually
encrypts secret values) and the **KEK** (key-encryption key, derived from your master
passphrase — what wraps the DEK at rest). Every command below was run for real against a
fresh SQLite install with a real secret in it while writing this page.

Both commands need exclusive access to the database — stop the server first.

## Rotate the DEK (re-encrypts every secret)

Preview first — this makes no changes:

```bash
keyorix-server admin encryption rotate --config ./keyorix.yaml --dry-run
```

Expected:

```
🔍 Dry run: previewing what a DEK rotation would re-encrypt — no changes will be made to the database or the DEK...
✅ Dry run complete — no changes were made
📋 secret_versions: 1, api_tokens: 0, api_clients: 0, password_resets: 0, mfa_secrets: 0, dynamic_secret_configs: 0, dynamic_secret_leases: 0 (legacy AAD upgraded: 0)
```

Then actually rotate:

```bash
keyorix-server admin encryption rotate --config ./keyorix.yaml --confirm
```

Expected:

```
✅ DEK rotated and full re-encryption sweep complete. New version: v1790408589
```

A kill at any point during this is safe — the design guarantees exactly one of the old or
new DEK stays consistently active and every row stays decryptable under it, never a
half-rotated database.

## Rotate the KEK (change the master passphrase)

This re-wraps the DEK under a new passphrase; it does **not** touch any database row.

```bash
keyorix-server admin encryption rotate-kek --config ./keyorix.yaml --confirm --new-passphrase-stdin
# (enter the new passphrase when prompted, or pipe it in)
```

Expected:

```
KEK rotation complete.
  Evidence-signing key fingerprint:      esk-...
  Audit-checkpoint key fingerprint:      ack-...

Update the master passphrase in your deployment configuration to the new value before restarting the server.
```

The env var to update is `KEYORIX_MASTER_PASSWORD` (or your `key_provider`'s equivalent) —
the command's own output doesn't name it explicitly, so: whatever you use to set the
passphrase today, set it to the new value before the next start.

Note: evidence packs and audit checkpoints signed **before** this rotation will report as
"superseded key version" (not tampered) under `compliance verify` afterward — expected,
not a problem.

## Verify nothing broke

```bash
keyorix-server --config ./keyorix.yaml   # restart with the NEW passphrase after rotate-kek
keyorix secret get --id <id> --show-value
keyorix audit logs --limit 20
```

The secret's value should be unchanged, and `audit logs` should show an
`admin.encryption.rotate` (or `.rotate-kek`) event with the timestamp of your rotation.
