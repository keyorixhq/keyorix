# Encryption keys with more than one server replica

Status: implemented (`storage.encryption.key_dir_lock: database`), HA-READY-1; Helm Secret
mode (`server.keysSecret`, the supported HA mode), HA-SECRET-KEYS-1.
Live Kubernetes verification is pending (see the end of this page).
Operator summary: [SELF_HOSTING.md, "Running more than one replica"](SELF_HOSTING.md#running-more-than-one-replica).

## The problem

Until this change a server took an exclusive `flock(2)` on `<key dir>/dek.lock` before it
generated or loaded keys, and held it for its whole lifetime (`server/main.go`,
`initializeEncryption`; INV-ENCRYPTION-01/02). That lock does two jobs on one host:

1. First boot: two processes racing a fresh key directory cannot both generate a DEK.
2. Lifetime: `keyorix-server admin encryption rotate` (a separate process) cannot replace
   `dek.key` while a server still has the old DEK in memory (#92).

Two replicas that share one key directory, which is what the Helm chart's
`server.replicas > 1` asks for (a ReadWriteMany keys volume, #3305), then depend on how
the filesystem implements `flock`:

| Filesystem behaviour | Result with the flock |
|---|---|
| flock enforced across clients (NFSv4 on Linux, CephFS, EFS, most CSI RWX drivers) | The second replica cannot take the exclusive lock and **refuses to start**, on any node. Only one replica ever runs. |
| flock local to each node (NFS mounted `local_lock=flock`, some FUSE drivers) | Both start, but the lock protects nothing across nodes: two first boots can each generate a DEK, and a rotation on node A ignores a live server on node B. |
| No lock support (`ENOLCK`) | No replica starts. |

None of these is a working HA mode. `TestKeyDirLock_Flock_SecondReplicaOnSharedKeyDirRefuses`
reproduces the first row on one host.

## What lives in the key directory

Paths are the Helm chart's (`/app/keys`); the names follow `storage.encryption.dek_path` and
`salt_path`.

| File | Content | Written by | Read by | Needed at start-up | At rotation |
|---|---|---|---|---|---|
| `data.key` (`dek_path`) | DEK wrapped by the KEK (AES-GCM) | first boot; `admin encryption rotate`, `rotate-kek`, `migrate-provider` (temp file + rename) | every server at start-up; admin commands | yes, by every replica, and it must be the same file everywhere | replaced; every replica must restart onto the new one |
| `kek.salt` (`salt_path`) | PBKDF2 salt, `password` provider only | first boot; `rotate-kek` | every server at start-up | yes, the same everywhere (with the same master password) | replaced by `rotate-kek` only |
| wrapped KEK (`key_provider.wrapped_key_path`) | KMS/TPM-wrapped KEK (`aws-kms`, `gcp-kms`, `azure-kms`, `tpm`) | first boot; `migrate-provider` | every server at start-up | yes | replaced by `migrate-provider` |
| `data.key.pending` | staged DEK during a rotation | rotate / rewrap / rotate-kek | crash recovery at start-up | only if a rotation crashed; recovery promotes or deletes it | transient |
| `data.key.backup.*`, `data.key.migrate-backup.*` | old wrapped DEKs | rotate, migrate-provider | operator only | no | left behind |
| `dek.lock` | empty; `flock` handle | server (lifetime, exclusive), admin commands | — | flock mode only | — |
| `data.key.lock` (`<dek_path>.lock`) | empty; `flock` handle for key-file rewrites (#195, #2602) | rotate, rewrap, rotate-kek (exclusive); live `admin backup` (shared) | — | no | taken by the rewriting command |

Nothing else is written there. The evidence-signing, audit-checkpoint and backup-manifest
keys are derived from the KEK in memory (`keymanager_lifecycle.go`), so they are not files.
The `file`/`env`/`exec`/`shamir` KEK providers read their material from outside the key
directory.

So a replica needs **read-only** access to `data.key`, plus `kek.salt` or the wrapped KEK,
at start-up and never writes them while running. Writes happen only at first boot, during
crash recovery, and in admin commands. With the flock, the server also wrote `dek.lock`.

## Design: `storage.encryption.key_dir_lock: database`

An opt-in mode, PostgreSQL only (config validation refuses it with SQLite or remote storage).
The default `flock` mode, SQLite and single-replica deployments are unchanged.

Every exclusion the flock gave is moved onto a PostgreSQL advisory lock. Advisory locks are
per database, are released when the holding connection ends (a crashed replica leaves no
stale lock), and work through a transaction pooler as transaction-scoped locks held in a
pinned transaction (`internal/serverguard`).

| Exclusion | flock mode | database mode |
|---|---|---|
| Two first boots on a fresh directory | exclusive `dek.lock`, loser refused | key-initialisation lock `872343` (`serverguard.WithKeyInitLock`): the loser **waits** (up to 2 min), then finds the files and loads them |
| Crash recovery (promote/discard `data.key.pending`) | under `dek.lock` | under the same key-initialisation lock |
| Rotation/restore while a server runs (#92) | server's lifetime `dek.lock` (and the presence lock) | the presence lock `872342` alone: every replica holds it **shared** for its lifetime, key-changing admin commands need it **exclusive** (already true on main) |
| Admin `--force` past a held presence lock | still stopped by `dek.lock` | **refused**: `--force` cannot override in this mode (`server/admin/admin.go`) |
| Live `admin backup` vs a rotation | `data.key.lock` shared vs exclusive | additionally holds the presence lock **shared** for the whole backup, so a rotation cannot start meanwhile. It does so when its own config says `database` **or** the database records it (as `--force` does); if the record cannot be read the backup is refused |
| Admin command vs admin command | `data.key.lock` | the presence lock exclusive (unchanged) |

One more check, which the flock made unnecessary: **first-boot generation is refused when the
database already holds secret versions or a recorded DEK epoch**. With the flock, a replica that got
its own empty key directory (a per-pod volume, or a Secret that failed to mount) could not start
next to a sibling on the shared directory. Without the flock it could, and it would generate a
second DEK. Now it exits with "refusing to generate a new DEK", before it writes any key file. The
check looks at the `dek.epoch` row in `system_metadata` (written by the first replica's boot, so it
also covers a fresh database with no secret yet) and at `secret_versions`, including soft-deleted
rows. Two replicas with separate empty key directories that boot at the very same instant are
covered as well: the first records the DEK epoch
([#3344](https://github.com/keyorixhq/keyorix/pull/3344)) before it releases the
key-initialisation lock, so the second, which waits on that lock, finds the epoch and is refused
before it writes any key file (`TestKeyDirLock_Database_ConcurrentStartOwnEmptyDirsSeedsEpochUnderLock`).

A server in this mode also records `key_dir_lock.mode = database` in `system_metadata`, right after
the migrations and before key initialisation, so the record is there for the whole time the server
holds the presence lock. `admin` commands read it (and a live `admin backup` does too, to decide
whether it must hold the presence lock): `--force` cannot override a held lock when the database says its replicas run
this mode, even if the admin command's own config does not set `key_dir_lock`. On PostgreSQL,
`--force` is also refused when the row cannot be read (the database cannot be opened, or the query
fails): an unverified record is treated as database mode. The row is never
removed automatically; if you go back to `flock`, delete it
(`DELETE FROM system_metadata WHERE key = 'key_dir_lock.mode'`) or `--force` stays refused.

The server no longer writes to the key directory after first boot, so in this mode it can be:

- **a shared ReadWriteMany volume**, whatever its flock semantics. The first replica generates
  the keys; the others wait and load them. Rotation runs as an admin command (a Job) on the
  same volume while every replica is stopped. The server supports this, but the Helm chart
  refuses it for `server.replicas > 1` (Secret mode instead): a writable shared volume is not a
  separately backed-up key store.
- **read-only key material per replica**, e.g. a Kubernetes Secret (or CSI secret-store volume)
  holding `data.key` plus `kek.salt` or the wrapped KEK. This is the Helm chart's **Secret
  mode**, the supported HA mode: see [Secret mode](#secret-mode-helm-serverkeyssecret) below.
  `TestKeyDirLock_Database_ReadOnlyKeyDir` boots from a directory the server cannot write to.
  A replica still holding an old key set is refused by #3344's DEK epoch.

What a replica needs, by phase:

| Phase | Needs |
|---|---|
| First boot (fresh install) | write access to the key directory for the one replica that wins the key-initialisation lock; the others need only read access |
| Every later start | read access to the same key set; the presence lock (shared); the key-initialisation lock for a moment |
| Running | nothing from the key directory (the DEK is in memory) |
| DEK/KEK rotation, provider migration, restore | every replica stopped (the admin command needs the presence lock exclusively); write access for the admin command only; every replica then restarts onto the new key set |

### Limits, stated

- Read-only admin commands (`admin encryption status`, `validate`) still take a shared flock on
  `dek.lock`. On a filesystem without lock support they fail. They change nothing, so run them
  from a pod with a local copy.
- The admin commands that rewrite key files still take `data.key.lock`. They already hold the
  presence lock exclusively, so the flock is redundant there; where flock fails with `ENOLCK`
  they fail closed.
- The presence lock is cooperative. A binary older than the presence guard, or one started
  with a different database, is not seen. Every replica must run a version with this setting
  and the same configuration.
- Losing the presence lock while running (a pooler or a `pg_terminate_backend`) is STORAGE-3
  item 2 (POOLER-LOCKLOSS-SESSION), which waits for #3299. Until that lands, a replica whose
  presence connection was killed keeps serving without the lock. #3344's runtime epoch poll
  fences its writes during a rotation.

## Not chosen

- **Keep the flock, take it shared in the server.** That still needs working flock on the RWX
  volume (the `ENOLCK` and per-node rows above), and it loses the first-boot exclusion.
- **Wrapped DEK in the database** (`system_metadata`), so that no key volume is needed at all and
  only the KEK comes from a Secret or KMS. **Decided against (Andrei, 2026-10-16):** with the
  `password` provider a database dump alone could then be attacked offline (wrapped DEK plus
  password guesses), and keys and data would no longer be backed up apart. Secret mode below is
  the HA mode instead.

## Secret mode (Helm `server.keysSecret`)

The supported way to run more than one server replica in Kubernetes (HA-SECRET-KEYS-1). Every
replica reads the same key files **read-only** from one Kubernetes Secret, no replica ever
generates keys, and the key Secret is backed up on its own, apart from the database.

Decided 2026-10-16 instead of storing the wrapped DEK in the database: a database dump alone must
not be enough to attack the keys offline (with the `password` provider, the wrapped DEK plus a
guess at the master password is). Keys and data stay in separate places, with separate backups.

### What the chart renders

```yaml
server:
  replicas: 2
  keysSecret:
    enabled: true
    name: keyorix-keys-1      # holds data.key and kek.salt (keyset.manifest.json if present)
  keysPersistence:
    enabled: false
```

- An init container (`prepare-keys`) copies `data.key`, `kek.salt` (and `keyset.manifest.json`
  when the Secret has it, #2900) from the Secret into a memory-backed `emptyDir`, `0600` and owned
  by the server's uid, which the startup key-file permission check requires and a Secret volume
  (root-owned) is not. The server mounts that `emptyDir` **read-only** at `/app/keys`. A missing
  file fails the init container, so the pod never starts. The script prints nothing.
- `storage.encryption.key_dir_lock: database` (the read-only directory takes no flock).
- No keys PVC. The chart never creates the key Secret and never sees key material: nothing about
  the keys is in Helm values or release history.

Refused at render time (`deploy/helm_server_keys_secret_test.go`, `deploy/helm_server_ha_test.go`):

| Values | Why |
|---|---|
| `server.replicas > 1` without Secret mode | replicas would generate or share writable keys |
| `server.replicas > 1` with a ReadWriteMany keys PVC | a shared writable keys volume is not an HA mode: it depends on the filesystem's flock, and it is not a separately backed-up key store |
| `keysSecret.enabled` with `keysPersistence.enabled` | one key source only; the old PVC is kept (`helm.sh/resource-policy: keep`) |
| `keysSecret.enabled` without a valid `keysSecret.name` | also checked by `values.schema.json` |
| `replicas > 1` with `singleWriter` | unchanged (#3305) |

SQLite cannot be combined with replicas: the chart renders PostgreSQL only, and the server's own
config validation refuses `key_dir_lock: database` on SQLite. One replica keeps today's behaviour
(keys PVC, generated at first boot) unless `keysSecret.enabled` is set.

### KEK providers in a pod

| Provider | In Secret mode |
|---|---|
| `password` (the chart's) | `data.key` + `kek.salt` in the key Secret; the master password stays in the auth Secret (`KEYORIX_MASTER_PASSWORD`). Use a separate `auth.existingSecret`, not `auth.masterPassword` in values. |
| `aws-kms`, `gcp-kms`, `azure-kms` | Fit a pod: the KMS-wrapped KEK goes in the key Secret, the KMS key stays in the cloud HSM, and the pod reaches it with workload identity. The chart does not render `key_provider` yet, so this is not available through Helm today. |
| `tpm` | No: a TPM-sealed KEK can only be unsealed by the TPM of the host that sealed it, so replicas on other nodes cannot use a copy. `key-secret` refuses it. |
| `shamir` | No: the shares belong to separate custodians and never sit next to the wrapped DEK. `key-secret` refuses it. |
| `file`, `env`, `exec` | The KEK comes from outside the key directory, so only `data.key` is in the key Secret. Not rendered by the chart. |

### First install: who creates the first key

**Chosen: an operator-run command that writes the Secret manifest**,
`keyorix-server admin encryption key-secret generate`, run on an admin workstation with the
release binary. Not chosen: an init Job that runs `admin encryption init` and writes the Secret
through the Kubernetes API.

- The Job needs a ServiceAccount allowed to create Secrets. Kubernetes RBAC cannot limit `create`
  to one Secret name, so that account could create any Secret in the namespace, and the account
  lives in the namespace for as long as the release does. The command needs no in-cluster
  privilege at all.
- The Job would also need a Kubernetes client (another image, or client-go in the server) and Helm
  hook ordering, and its output (stdout) is the pod log. The command writes the manifest to a new
  `0600` file, or to stdout only when stdout is a pipe. It refuses a terminal, stdout inside a pod
  (`KUBERNETES_SERVICE_HOST`) and stdout under systemd (`JOURNAL_STREAM`), where stdout is a log.
- The operator has to keep a copy of the key set anyway (the separate key backup below). With the
  command, that backup exists from the first minute.
- A mistaken `generate` cannot reach data: it needs no database, and a server whose database is
  already encrypted under another DEK refuses to start with the new key set (DEK epoch, #3344).

```sh
# minimal config: the provider and the key file names the chart uses
cat > keygen.yaml <<'EOF'
storage:
  encryption:
    enabled: true
    dek_path: /app/keys/data.key
    salt_path: /app/keys/kek.salt
EOF
# the master password, from a 0600 file (or --passphrase-fd / --passphrase-stdin)
keyorix-server admin encryption key-secret generate --config keygen.yaml \
    --passphrase-file ./master-password \
    --name keyorix-keys-1 --namespace keyorix --out keyorix-keys-1.yaml
kubectl create -f keyorix-keys-1.yaml          # before helm install
helm install keyorix deploy/helm/keyorix -n keyorix \
    --set server.replicas=2 --set server.keysSecret.enabled=true \
    --set server.keysSecret.name=keyorix-keys-1 --set server.keysPersistence.enabled=false ...
```

`generate` creates the key set in a private temporary directory (the files are named after the
config's paths: `data.key`, `kek.salt`), writes the manifest and removes the temporary files.
The manifest is an `immutable` Secret labelled `keyorix.io/key-set: "true"` and annotated with
`keyorix.io/dek-fingerprint`: the value the database's `dek.epoch` row will hold. Store
`keyorix-keys-1.yaml` with your key backups (below) and delete other copies. Until the Secret
exists, the pods wait in `ContainerCreating`; none generates keys.

Moving an existing single-replica install (keys PVC) to Secret mode: scale the server to 0, copy
the key files out of the PVC into an empty directory, run
`keyorix-server admin encryption key-secret export` there, `kubectl create -f` the manifest, then
`helm upgrade` with the values above. The PVC is kept; delete it once the replicas run on the
Secret and its key set is in your key backups.

### Rotation in Secret mode

Every key-changing command needs every replica stopped: it takes the presence lock exclusively,
`--force` cannot override that in `database` mode, and the command refuses while any replica runs.
The replicas' key directory is read-only, so the command runs in a **workspace**: a writable
directory on durable storage (the admin workstation's disk, or a PVC of a maintenance pod),
**never an `emptyDir`**. After a DEK rotation commits, the workspace briefly holds the only copy of
the new DEK. Each rotation ends in a **new** Secret with a new name; the Secret the replicas used
is never edited, so it stays intact until the new key set is verified.

DEK rotation (`admin encryption rotate`):

1. `kubectl get secret keyorix-keys-1 -n keyorix -o yaml > current.yaml` (0600; or use your
   backup copy), then
   `keyorix-server admin encryption key-secret unpack --in current.yaml --dir ws`.
   `unpack` refuses a non-empty directory.
2. Scale to 0: `kubectl scale deploy/<release>-keyorix-server -n keyorix --replicas=0` and wait
   for the pods to be gone.
3. In `ws`, with a config whose `dek_path`/`salt_path` are `data.key`/`kek.salt`, the database
   settings of the release (reachable, for example via `kubectl port-forward`) and
   `key_dir_lock: database`: `keyorix-server admin encryption rotate --confirm`.
4. `keyorix-server admin encryption key-secret export --name keyorix-keys-2 --namespace keyorix --out keyorix-keys-2.yaml`,
   then `kubectl create -f keyorix-keys-2.yaml`. Store it with your key backups now.
5. `helm upgrade ... --reuse-values --set server.keysSecret.name=keyorix-keys-2`. The pod template
   changes, so the Deployment rolls out new pods at the release's replica count.
6. Verify: pods Ready, a secret read, `keyorix-server admin verify-audit`. Then wipe `ws`. Keep
   `keyorix-keys-1` (or its manifest) as long as you keep database backups taken before the
   rotation: they need the old DEK.

No replica can write under a stale DEK during this: the rotation commits the new DEK epoch in the
same transaction as the re-encryption (#3344, merged), a pod that starts with the old Secret
refuses to start (`this server's DEK is not the DEK the database is encrypted under`), and a
replica still running would have kept the rotation from starting (presence lock). Not covered, as stated
in `internal/encryption/dek_epoch.go`: a write stalled for several seconds between its encryption
and its INSERT on a replica whose presence lock was bypassed or lost (STORAGE-3 item 2), and server
binaries older than the DEK epoch. Upgrade every replica before the first rotation.

Master password change (`admin encryption rotate-kek`): the same steps with
`rotate-kek --confirm` and `--new-passphrase-file` in step 3. The DEK, and so the DEK epoch, is
unchanged; `data.key` and `kek.salt` change. Create the new auth Secret as well (a new name, same
keys, the new `KEYORIX_MASTER_PASSWORD`; `kubectl create secret generic --from-file=...`, never
`--from-literal`) and switch both names in one `helm upgrade`
(`server.keysSecret.name`, `auth.existingSecret`). The old key Secret still opens with the old
password: delete it, and its copies, once the new pair is verified, or the change bought nothing.

`admin encryption migrate-provider` re-wraps the DEK for another KEK provider (there is no
separate `rewrap` command; `RewrapDEK` is its step). It works in a workspace the same way, but the
chart renders only the `password` provider today, so a migration to a KMS provider cannot be
deployed through Helm yet.

#### Crash at any step

| Crash during | State | Recovery |
|---|---|---|
| 1–2 | nothing changed | start again; scale back up if needed |
| 3, before the sweep commits | the database is under the old DEK (one transaction, rolled back); `ws` may hold `data.key.pending` | run a key writer in `ws` again (`upgrade-aad` changes nothing else; or `rotate --confirm`): its crash recovery discards the uncommitted pending file. Or start over. Replicas on `keyorix-keys-1` start normally. |
| 3, after the sweep committed, before the rename | rows, epoch and redo marker under the **new** DEK; `ws/data.key.pending` is the **only copy** of it | do not delete `ws`, do not unpack over it (refused). Run `keyorix-server admin encryption upgrade-aad` in `ws`: its crash recovery promotes the pending DEK. Then step 4. Replicas started meanwhile with `keyorix-keys-1` are refused (epoch) and leave the rotation's redo marker alone (`INV-ENCRYPTION-redo-marker-kept-for-the-pending-keydir`; before HA-SECRET-KEYS-1 such a start removed it and the next recovery in `ws` discarded the new DEK). |
| 3, after the rename | `ws/data.key` is the new DEK | step 4 (`export` refuses while a `.pending` file is present) |
| 4 | `ws` holds the new key set; the Secret may not exist yet | run `export` / `kubectl create` again (`--out` refuses an existing file: choose a new name) |
| 5 | some pods on each Secret | pods on `keyorix-keys-1` are refused (epoch); finish the `helm upgrade`. A `helm rollback` to the old revision points at the old Secret and is refused the same way: never a stale write |
| `rotate-kek`, any step | the database is untouched and the DEK unchanged; the old key Secret + old password still open it | if `ws` holds a `.pending` file or the new set was never exported, discard `ws` and start over from the current key Secret; otherwise finish steps 4–5 with the new pair |

### Backups: keys apart from data

| What | Where | Holds |
|---|---|---|
| database backups | your PostgreSQL backups (dumps, PITR) | ciphertext and the `dek.epoch` row |
| key Secret manifests (`key-secret generate`/`export` output) | a separate store with separate access (a secrets vault, an offline medium) | wrapped DEK, KEK salt |
| master password | a third place (a password manager, sealed envelope) | the KEK input |

No one of these opens a secret alone, and a database dump alone is not enough to attack the keys
offline. Match them by fingerprint: a database backup's `system_metadata` row `dek.epoch` equals
the `keyorix.io/dek-fingerprint` annotation of the key Secret it needs. Keep every key Secret
manifest as long as a database backup that needs it is retained. `keyorix-server admin backup`
archives the key files next to the database; in Secret mode prefer the separation above, or treat
that archive as key material too.

## Verification

- Native, kpg PostgreSQL: the `server/key_dir_lock_postgres_test.go` tests, the
  `internal/serverguard/keyinit_postgres_test.go` tests, and
  `server/admin/backup_key_dir_lock_postgres_test.go` (pg-gated), plus
  `TestAcquireDatabaseLock_ForceRefusedWithDatabaseKeyDirLock` and `TestValidate_KeyDirLock`
  (default CI). Red runs are recorded in the PR.
- Secret mode: `deploy/helm_server_keys_secret_test.go` and `deploy/helm_server_ha_test.go`
  (every render guard, `helm template`); `internal/encryptionops/key_secret_test.go`
  (generate, export, unpack, their refusals, and `rotate` / `rotate-kek` run in an unpacked
  workspace); `internal/encryption/rotation_marker_other_keydir_postgres_test.go` (pg-gated: a
  replica on another key directory leaves an interrupted rotation's redo marker alone). Driven
  with the real binary on PostgreSQL: two servers on read-only key directories unpacked from one
  generated manifest, rotation refused while they run (also with `--force`), rotation in a
  workspace, the old key set refused and the exported new one accepted.
- **Pending e2e VM:** `scripts/k8s-e2e/multi-replica-secret.sh`: kind, two replicas in Secret
  mode, cross-replica write/read, a DEK rotation through a new Secret, a rolling restart and
  `admin verify-audit`.
