# DEK rotation across hosts: what the DEK epoch closes, and the hole it left

DEK-ROTATE-SAFETY-1 item 2 (backlog DEK-ROTATION-CROSS-HOST, raised by STORAGE-2).

## Question

`dek.lock` (`internal/encryption/exclusive_lock.go`) is a flock on one host's key
directory. With several replicas on one PostgreSQL database, can a replica on another
host keep writing under the old DEK after `admin encryption rotate` swept, so its
versions become undecryptable once the old DEK is retired?

## What is already closed (verified against origin/main dd34c1da0)

The DEK epoch (#3337, HA-SECRET-KEYS-1 / #3344; `internal/encryption/dek_epoch.go`,
INV-ENCRYPTION-dek-epoch-cross-replica) closes the cases STORAGE-2 described:

| Case | Closed by | Test |
|---|---|---|
| Replica with the old `dek.key` STARTS after the rotation | `StartDEKEpochGuard`: refuses unless the epoch is its own DEK | `TestDEKEpoch_Postgres_SeedRefusedForStaleDEK`, `server/dek_epoch_cross_replica_postgres_test.go` |
| Replica keeps RUNNING through a rotation on another host | fence `rotating:<old>` + `dekEpochFenceWait` > `dekEpochMaxStaleness`: every `Service.Encrypt*` refuses (`ErrDEKWriteFenced`) | `TestDEKEpoch_Postgres_RunningReplicaFencedByRotationElsewhere` |
| A write transaction open when the sweep starts | the sweep's `SHARE ROW EXCLUSIVE` table lock waits for it and re-encrypts its rows | `TestDEKEpoch_Postgres_SweepWaitsForInFlightWriter` |
| Rotation from a host whose key set is stale | `fenceDEKEpochForRotation` refuses on epoch mismatch | `TestDEKEpoch_Postgres_RotateRefusedFromStaleHost` |
| Encrypt paths that skip the gate | none in the server: it builds one `encryption.Service`, and `EncryptSecret`, `EncryptSecretWithAAD` and `EncryptLargeSecret` all call `checkWriteEpoch`. `AuthEncryption` builds its own Service but is used only by the `admin encryption auth` CLI commands, which hold the exclusive database lock | code reading (`rg NewAuthEncryption`) |

Normally none of this is even reached: `admin encryption rotate` takes the exclusive
server-presence lock (`internal/serverguard`), which every live server holds shared, so a
rotation cannot run while any replica, on any host, is attached.

## The hole that remained

The epoch gate runs when a value is ENCRYPTED, not when its row is INSERTED. A replica
that encrypted a value while its DEK was still current, and whose INSERT starts after
the sweep took its table lock (a stall of more than `dekEpochFenceWait -
dekEpochMaxStaleness` = 5 s between the two: GC pause, connection-pool wait, a lock wait
earlier in its transaction), blocks on the lock and then commits its old-DEK row right
after the sweep commits. The epoch file listed this as "not covered" with the condition
"the presence guard is also bypassed".

That condition was reachable on purpose: in the default `key_dir_lock: flock` mode
`admin encryption rotate --force` proceeds when the presence lock is held by a live
server (only `key_dir_lock: database` refused `--force`). `dek.lock` does not see a
replica on another host, so the rotation ran next to it.

Reproduced: `server/admin/rotate_force_cross_replica_postgres_test.go`
(`TestAdminEncryptionRotate_Postgres_ForceNextToLiveReplica_NoStaleDEKRow`), two key
directories on one database, replica B holding presence and running the epoch guard.
On main:

```
DATA LOSS: replica B's version (id=1) committed after the rotation is under the retired DEK
(rotate err=<nil>): failed to decrypt data (AAD mismatch or corruption): cipher: message authentication failed
```

## Fix

`admin encryption rotate` and `admin encryption auth-encryption rotate` (the same
`RotateDEKWithSweep`) on PostgreSQL refuse when `--force` let them past the exclusive
database lock (`server/admin/rotate_force_guard.go`). A `rotate --dry-run` is not
refused. The PG test runs once per command, and
`server/admin/rotate_force_guard_family_test.go` fails on any admin function that reaches
`RotateDEKWithSweep` without calling the refusal first (the first version of this fix
guarded `rotate` only; REVIEW-3750-DEEP-1 F1). Closing the window inside the write itself would need the INSERT to re-check the
epoch in its own transaction after the table lock, i.e. a change to the storage write
path or a database trigger that can tell which DEK a ciphertext is under (the
ciphertext metadata does not carry it; `key_version` is only set by a rotation). The
presence lock already gives the guarantee, so the fix keeps `--force` from dropping it.

## Still not covered

- A server whose presence lock is lost (connection killed) keeps serving until
  `sidecarWatch` notices and it shuts down; an in-flight request that drains during that
  shutdown could still land its row after a rotation that started in between.
- A server binary that predates the epoch does not check it at all: item 3
  (DEK-EPOCH-N1-ROTATION) and the runbook rule "upgrade every replica before rotating".
- SQLite is single-node; nothing here applies.
