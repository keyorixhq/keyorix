# Changelog

All notable changes to Keyorix are documented here. This project follows
[Semantic Versioning](https://semver.org/).

**Unreleased entries now live in `changelog.d/`** (one fragment file per PR; see
`changelog.d/README.md`) and are assembled into this file at release time by
`scripts/changelog-assemble.sh`. Do not add new entries to "Unreleased" below;
that section is the text written before the switch.

## v0.97.0 — 2026-11-14

### Security
- **PostgreSQL `verify-full` now needs a named CA: `storage.database.ssl_root_cert`.** The server
  had `ssl_mode: verify-full` but no way to say which CA signed the database's certificate, so the
  driver verified against whatever it found (`PGSSLROOTCERT`, `~/.postgresql/root.crt`, the OS
  store). The new key is passed as `sslrootcert` (a PEM file, relative to the config file's
  directory, or `system` for the OS store). `verify-full`/`verify-ca` without it, or with a
  missing, unreadable, empty, key-bearing or group/world-writable CA file, **refuses to start**
  with an error naming the key; the same check runs on every connection an `admin` command opens,
  and applies to `sslrootcert` in a `dsn`. `ssl_root_cert` with `dsn` or with `ssl_mode: disable`
  is refused rather than ignored. `admin init` and `admin validate --posture` report the
  database TLS posture (a `database-tls` deviation when the server would refuse to start). Helm:
  `externalDatabase.sslRootCert`. **Upgrade note:** a config that already uses `verify-full`
  must add `ssl_root_cert` (or `sslrootcert=` in the dsn) before upgrading; see
  docs/UPGRADING.md and docs/CONFIGURATION.md "PostgreSQL TLS".
- **The settings the driver connects with are re-checked against what the TLS check validated.**
  After the connection config is built (the password set on the driver's own parse of the DSN, see
  the `KEYORIX_DB_PASSWORD` entry), Keyorix refuses to start unless its host, port, database and
  user are the configured ones and every connection attempt is encrypted and, for `verify-ca`/
  `verify-full`, verifies against exactly the validated CA (and the host name for `verify-full`).
  This catches any difference between how the check and the driver read a connection string.
- **A FIFO named as the CLI's CA file (`--ca-file` / `KEYORIX_CA_FILE` / `ca_file`) is refused instead of hanging the command.** `apiclient.LoadCAPool` now opens the file non-blocking and refuses a non-regular file on the opened descriptor with `read CA file <path>: not a regular file`. A regular file, or a symlink to one (Kubernetes Secret volumes), still loads.
- **A FIFO (or any non-regular file) named at a CLI input path is refused instead of hanging the command.** Every operator-supplied file the CLI reads — `compliance verify --file/--sig`, `bundle verify`/`bundle import --license`, `license` token files, `secret export --encrypt-to` / `secret import --decrypt-with` key files, `secret render <template>`, `secret import --file` (all formats), `secret create/update --from-file`, the `NAME_FILE` credentials, the stored credentials file, the legacy config detection, and files found by `secret scan` / `secret fix` in a scanned tree — now goes through `cli/internal/regularfile`: a non-blocking open plus an fstat of the opened descriptor, refusing with `<what> <path>: not a regular file`. A regular file, or a symlink to one, still works; `-` / stdin is unchanged. `TestCLIFileReadsGoThroughRegularfile` is the cli-module twin of the root-module AST guard and fails on any new bypass.
- **A FIFO at an operator-supplied file path is refused instead of hanging the server or an admin command.** The server CA bundle, license file and SAML IdP metadata file, `admin verify-audit` (`--anchor`, `audit.offline_anchor_path`, `--tsa-roots`), `admin recovery-key rotate --recipient`, `admin restore --input` (v1 and v2 archives and the post-restore anchor), the startup database check and the k8s-sync `--config` now open non-blocking and refuse a non-regular file with `<what> <path>: not a regular file` (`secretenv.OpenRegularNamed` / `ReadRegularFile`); a symlink to a regular file still works. The AST guard `TestSecretFileReadsGoThroughOpenRegular` now covers these files and `internal/k8ssync` and `internal/startup`.
- **PostgreSQL `ssl_mode` is checked against what the connection really does.** `ssl_mode` next
  to a `dsn` used to be silently ignored, so `ssl_mode: verify-full` with a dsn saying
  `sslmode=disable` connected in plaintext and was not reported. Now, when both are set, the
  dsn's own `sslmode` must equal `ssl_mode` or the server **refuses to start**. An `ssl_mode` (or
  dsn `sslmode`, or `PGSSLMODE`) outside `disable`, `allow`, `prefer`, `require`, `verify-ca`,
  `verify-full` is refused at start-up with the list of valid values. The insecure-settings warning
  (`storage.database.insecure_disable_database_tls`) and `admin validate --posture` now read the
  effective sslmode: the dsn's, then `PGSSLMODE`, then the driver default `prefer`, including the
  URL `ssl=true` alias. **Upgrade note:** see docs/UPGRADING.md.
- **The Compose stack's PostgreSQL now serves TLS, and the server connects with `ssl_mode: verify-full`.**
  `keyorix.docker.yaml` had `ssl_mode: prefer`, which falls back to plaintext whenever the TLS
  attempt fails (anything on the network path that answers "no TLS" gets the password exchange in
  the clear). `scripts/selfhost/init-secrets.sh` now also generates a self-signed Postgres
  certificate and key (`secrets/postgres_tls.crt`, `.key`, named `postgres`, needs `openssl`); the
  `postgres` service runs with `ssl=on` from them and the server uses the certificate as its
  `ssl_root_cert`, so the connection is encrypted and the server is authenticated, and a Postgres
  without TLS (or with another certificate) makes the server refuse to start. **Upgrade from
  v0.96.x:** pull the new files, run `./scripts/selfhost/init-secrets.sh` (it keeps every existing
  secret and adds the pair), bump the image pins, `docker compose up -d`; the data volume is not
  touched (docs/UPGRADING.md). Guarded by `TestComposeSecureConfig_NoInsecureSettingInEffect`,
  `TestComposeConfig_DatabaseIsVerifyFullWithRootCert` and the init-secrets tests in deploy/.
- **`ssl_mode: prefer` and `allow` are now a registered insecure setting.**
  `storage.database.insecure_allow_plaintext_database_fallback` is in effect when the effective
  sslmode (including a `dsn` with no `sslmode`, which is the driver's default `prefer`) can fall
  back to plaintext. `admin validate --posture` counts it as a deviation and the server logs it at
  boot. If you run an external Postgres with `prefer`/`allow`, switch to `require`, or better
  `verify-full` with `ssl_root_cert`.
- **Suspending a user revokes their re-auth step-up grants.** A user suspended right after re-authenticating
  (passkey re-auth mints a grant, not a session) kept a short-lived elevated grant. Suspend, deactivate,
  delete and SCIM deprovision now delete the user's step-up grants right after the account change commits, and spending a grant re-checks that the account is still active, so a grant created between a
  suspension's check and its insert is refused with the same generic "invalid code or password" as an
  absent grant.
- **Deleting a project no longer leaves secret ACL grants to come back on restore.** `deleteProjectCascade` revoked shares but not `SecretACL` rows, so a grantee regained access after `RestoreProject` with no re-authorization; the cascade now deletes the ACLs of every project secret in the same transaction (#2798).
- **Approved secret-scoped access requests no longer revive on restore.** `DeleteSecret` and the project delete cascade now move approved restricted-read requests to `expired` in the delete transaction, so `RestoreSecret`/`RestoreProject` cannot re-open the approval gate (#2797).
- **A suspended secret can no longer be resumed inside a deleted environment or project.** `ResumeSecret` takes the environment secret guard and re-checks project liveness in the same transaction as the status write, like the create paths (#2794).
- **Purging a deleted project now removes its machine-identity role grants.** `PurgeDeletedProjectsBefore` left `machine_identity_roles` rows that `GetMachineRoleIDsAt` read as live (#2795).
- **Behaviour change at boot: a weak SCIM token is refused (#3397).** With `scim.enabled: true`, the server now refuses to start when the SCIM bearer token passes the 20-character minimum but is obviously not random: one byte repeated, fewer than 10 distinct bytes, a known placeholder or sample value (`changeme`, `password`, `example`, `secret`, `test-token-...`, the docs' sample shapes), or the same value as any other configured secret. The message (`SCIM token is too weak: ...`) names `KEYORIX_SCIM_TOKEN` and says to generate one with `openssl rand -base64 32`; it never prints the token, and for a reused secret only names the other one. Upgrade: ADR-112 grace period, like the other secure-by-default refusals: an upgraded deployment (users exist) only warns until its first start with a passing token, recorded as `adr112.scim_token_strength.enforced`; a fresh install refuses from its first start. The 20-character floor is refused as before, grace or not. Guarded by `TestCheckSCIMTokenShape_*` (internal/core/rules, including a fixed-seed sweep that `openssl rand -base64 32`/`-hex 32` shaped tokens are never refused) and `TestEnforceSCIMTokenStrength` (server: fresh refuses, upgrade warns, ratchet, floor never softened, secret reuse).
- **Behaviour change at boot: `insecure_allow_kms_context_fallback` is refused once nothing is left to migrate (#3398).** For aws-kms and gcp-kms, when the stored wrapped KEK already decrypts with its `kms_encryption_context`, the server refuses to start with the flag set; the message says the flag is no longer needed and can be removed. A legacy KEK that still needs the no-context retry starts as before. No new config key. A key-provider fallback chain stops on this refusal instead of moving on to the next provider. Remove the flag before upgrading if your migration is done. Guarded by `TestAWSKMS_ContextFallbackFlag_*`, `TestGCPKMS_ContextFallbackFlag_*`, `TestKMSKeyProvider_ContextFallback` and `TestMultiKeyProvider_StopsOnContextFallbackRefusal`.
- **Deleting a project now suspends the machine identities that only had access there, so their tokens stop working.** Before, a machine token of a soft-deleted project kept authenticating on every route, warm cache or cold. It could act wherever the identity still held a role, and it worked again on restore. The project delete now suspends every active machine identity whose only live roles are in that project, in the same transaction as the cascade. It writes one `machine_identity.suspended` audit event per identity, with the deleting admin as the actor and "project soft-delete" as the reason. Other replicas refuse the token on their next request, because the auth cache re-reads the identity state on every hit. Identities with a role in another live project keep working. Restoring the project re-activates exactly the identities the delete suspended (`machine_identity.activated`, reason "project restore"). An identity an admin suspended, or changed during the deletion window, stays as the admin left it. Schema epoch 4 adds `machine_identities.cascade_suspended_project_id` and `cascade_suspended_at`; the compatibility floor stays 2 (#3433).
- Break-glass works while the audit log is down and is never unrecorded (BREAKGLASS-OWED-1, ADR-112 Amendment 6). When the audit log refuses an activation's rows, the activation, its role grant and an owed-audit record of each row commit in one transaction instead of failing; the activation is marked degraded, expires after `break_glass.degraded_ttl` (default 15m, never longer than a normal activation), is logged at ERROR, counted in `keyorix_breakglass_degraded_activations_total`, notified to the project's admins, shown in a web banner and `GET /api/v1/system/info` (`security.break_glass_degraded`), and must be reviewed at once. The owed-audit backfill writes its rows into the hash chain with their original times and marks it settled; `verify-audit` reports unsettled ones (INDETERMINATE). If even the owed record cannot be written, activation is refused with 503 `BreakGlassUnrecordable` naming the offline `recover-admin` procedure.
- **A SCIM `active=false` (PATCH or PUT) now revokes the user's personal access tokens, as a SCIM `DELETE` already did.** Before, the tokens were refused only while the account stayed deactivated, and an IdP `active=true` (re-hire, undo, sync glitch) made them valid again with no re-authorization. The revocation runs in the same transaction as the deactivation, and the tokens are evicted from the auth cache right after commit. Profile-only updates and reactivation do not touch tokens. (#3419)
- **SCIM no longer treats an account that signed in through SSO as one it manages.** SCIM and SSO share the `external_id` column, and the first SSO sign-in of a native account (matched by verified email) writes an `sso:<provider>:<subject>` value there. That used to satisfy the SCIM ownership check, so a holder of the SCIM bearer token could read, rename, re-email, deactivate or delete any such account, administrators included, or add it to a SCIM group. There is now one ownership rule: an account is SCIM-owned only when its external ID is set and does not use the `sso:` scheme. Such accounts answer 404 "not a SCIM-managed account" on every SCIM route and are no longer listed or returned by the `userName` filter. Accounts SCIM created are unchanged. Consequence: accounts the IdP creates just-in-time through SSO also use the `sso:` scheme, so SCIM does not manage those either. (#3418)
- **A role or share update that both narrows and widens access is applied as two commits, so an audit outage can no longer roll its revocation back.** A role update (`PUT /api/v1/roles/{id}`, gRPC `RoleService.UpdateRole`) that removes some permissions and adds others now removes first (never blocked by the audit log, its record owed and backfilled) and then applies the description and the added permissions (only with their audit rows). A share update (`PUT /api/v1/shares/{id}`, gRPC `ShareService.UpdateSharePermission`) that lowers the permission and extends or clears the expiry, or the reverse, first applies the narrower value of each, then the requested share. If the second part cannot be recorded, the narrowing stays applied and the request answers HTTP 503 / gRPC `Unavailable` with the same machine-readable body as the other split requests (`error: MutationPartiallyApplied`, `details.code: mutation_partially_applied`); retrying the same request is safe. A role or share update that only narrows access or changes none now owes its audit rows (recorded with the change, backfilled if the append is refused) instead of writing them best-effort after the commit.
- **Role grants at "no project, one environment" are refused on every route and reported where they already exist (#2857).** A grant at `project_id: 0` with an `environment_id` applies inside that environment, but the project's access review never listed it, so a recertification could pass with a grant missing (ISO 27001 A.5.18). New grants of this shape have been refused since #3546 (HTTP 400 / gRPC `InvalidArgument`: "environment_id requires project_id"). Route-walk tests now check this on every HTTP route and gRPC method that can create or change a role assignment. Existing grants are not changed. At startup the server logs a `WARNING` for each one, giving the project it applies in and the fix. The access review of that project (`GET /api/v1/projects/{id}/access-review`, and every campaign opened from it) is marked `degraded`, with one `degraded_reasons` entry per grant, until the grant is fixed. To fix one, grant the role again with the environment's `project_id`, then remove the old grant: `DELETE /api/v1/user-roles` with `project_id: 0` and the `environment_id`, or `DELETE /api/v1/groups/{id}/roles/{roleId}?project_id=0&environment_id=X`.
- **Audit verification no longer starts over when its signed state row is deleted, garbled or replaced.** With incremental verification, a verification state row that was deleted, garbled or truncated, signed under another key epoch, claimed audit rows the chain no longer has, or was an older row put back over a recorded break used to be replaced by a fresh state that read valid again after one rolling cycle, erasing the evidence that rows were lost. It is now a sticky **verification state discontinuity**: `keyorix audit verify` (incremental and `--full`), the compliance posture and gRPC report `BROKEN` with the reason `audit verification state discontinuity (<kind>)`; `keyorix_audit_verify_failure_recorded` and the new protected gauge `keyorix_audit_verify_state_discontinuity` read 1; the new counter `keyorix_audit_verify_state_discontinuities_total` increments; a `system.audit_verification_state_discontinuity` event is appended. No verification clears it. New rows keep being checkpointed. A fresh install or an upgrade from a release without the state still starts normally: the state now keeps a `system.audit_verification_state_initialized` marker event in the chain, which is how a deleted row is told from a first start.
- **Behaviour change:** after `encryption rotate-kek` or `migrate-provider` the status now reads `BROKEN` (`other key epoch`) instead of returning to `VALID`, because a key change does not yet carry the verification state over and is indistinguishable from a relabelled row. There is no command to accept a discontinuity yet; options are in `docs/design-audit-reseal-options.md`. See `docs/operator/audit-chain-break-runbook.md`.
- **Upgrade note:** stop replicas running an older version before upgrading. An older replica that saves the audit verification state drops the fields that place it against the audit chain, and the state then reads `BROKEN` (`before a recorded break`). A binary rollback to an older version followed by a re-upgrade does the same, because the older binary re-signs the state the same way. A state row an older version signed is still continued on the first start after an upgrade.
- **A failed SCIM deactivation or DELETE no longer tells the IdP the user is gone.** `PUT`, `PATCH` and `DELETE /scim/v2/Users/{id}` answered every error `404`, including a storage failure that rolled the deprovision back. An IdP that gets `404` marks the user deleted and stops retrying, so the account stayed active, with its sessions and personal access tokens, after the IdP believed it was offboarded. `404` now means only "no such user, or not SCIM-managed". A storage failure is `500` with a generic message (the cause is logged with the request id), write contention or a concurrent change to the same user is `503` with `Retry-After`, an email or `externalId` already in use is `409` with `scimType: uniqueness`, and the last-admin refusal is `409`. `GET /scim/v2/Users/{id}` no longer answers a storage failure `404`, and `POST /scim/v2/Users` no longer answers one `400`. The status table is in `docs/CONFIGURATION.md` (scim). The Groups endpoints still have this problem (#3620). (#3494)
- `storage.database.single_writer`: the fence census now also covers the functions run by the store's own triggers on the security tables (role-permission generation, secret-node cache epoch and suspend marker, audit retention anchor). Replacing one of them, even with an identical definition, makes the server stop trusting its caches within one poll, as replacing a fence function already did.
- With `storage.encryption.key_dir_lock: database`, a replica whose key-initialisation lock ends while it generates or recovers the key files (backend terminated, PostgreSQL failover, pooler timeout) now refuses to start instead of serving: a sibling replica may have generated its own keys at the same time.
- An admin command run with `--force` without the exclusive database lock now says so in its audit event (it was printed to the terminal only).
- `keyorix-server admin recover-admin` with a wrong recovery key now writes an `admin.recover_admin_failed` audit event (the host user, the target account and the key generation; never the key).
- On SQLite, a server and an admin command now exclude each other when one names the database as a `file:` URI (`file:/data/secrets.db`, `file:///...`, percent-encoded) and the other as a plain path, and a database in a directory whose name contains `mode=memory` is guarded too.
- **Role-permission cache generation triggers are re-checked every 30 seconds (PostgreSQL).** The per-request proof only showed that the triggers exist and are `ENABLE ALWAYS`. The owner of the trigger function, which is the server's own database role, could replace the function's body, re-create a trigger on fewer events, or disable, write and re-enable inside one transaction. After that, a permission removed with direct SQL kept authorizing from every warm replica's cache until a restart. A background check now compares the function's body and settings and each trigger's definition with this release's, and compares the catalog rows' versions with the previous reading. When either differs, the server logs a `SECURITY:` line, increments `keyorix_role_permission_generation_tamper_total`, restores the triggers and invalidates every replica's permission cache. The migration now also re-creates a generation trigger whose definition differs, and no longer rewrites a function that is already correct. Design and residual risk: `docs/design/trigger-rowdigest.md`.
- **Trigger functions pin `search_path`, and a failed integrity repair is retried (PostgreSQL).** `keyorix_bump_role_permissions_generation()` and the `secret_nodes` cache-epoch function now run with `search_path = pg_catalog, pg_temp`. Before, a session whose `search_path` put a schema ahead of `pg_catalog` could shadow the `+` operator the bodies use, so its direct writes moved neither the permission-cache generation nor the secret cache stamp. The next boot re-creates an older unpinned function. If the integrity check cannot commit its repair, it now keeps retrying the repair and cache invalidation on every tick instead of accepting the catalog as it next finds it.
- **`encryption rotate-kek` and `migrate-provider` now carry the audit verification state over to the new key.** Before any key file is written, the command verifies the audit chain under the current key. It then records a key transition signed by the old checkpoint key and, over that, by the new one. Once the new key files commit, the command finishes the transition: the verification state, the audit high-water mark and the retention anchor are re-signed under the new key, a `system.audit_key_transition` event is appended, and a fresh checkpoint is written. If the command is interrupted, the server finishes the transition at its next start. After an honest key change, `keyorix audit verify` and offline `verify-audit` with the new checkpoint key read `VALID`. This supersedes the `other key epoch` behaviour change listed for #3621, and it fixes installs with a retention purge reading `BROKEN` after a key change. A recorded break or discontinuity is carried over, never cleared, and only artifacts that authenticate under the old key are re-signed: a forged anchor, high-water mark or state row stays unauthenticated after the change. A missing, forged or wrong-epoch transition record reads `BROKEN` (`audit verification state discontinuity (key transition)`). New `verify-audit --previous-checkpoint-key-file` (repeatable) checks each transition's old-key signature. Rotate with the new binary only: a later key change by an older binary reads `BROKEN`.
- **A DEK rotation now decrypt-verifies every rewritten row before it commits.** `admin encryption rotate` round-trips a sample of the newest secret versions through the new DEK before the sweep, then reads back every row it rewrote, in every swept table, and decrypts it with the new DEK, all inside the sweep transaction. One row that does not decrypt aborts the rotation: nothing is committed, the old DEK stays active, the PostgreSQL write fence is lifted, and the error names the table and row id (never a value). Before, a sweep that wrote one undecryptable ciphertext committed it and retired the old DEK. The sweep reads every row twice now, so rotations take longer. Guard: `internal/encryption/sweep_verify_test.go` (DEK-ROTATE-SAFETY-1).
- **`admin encryption rotate --force` and `admin encryption auth-encryption rotate --force` no longer run next to live replicas on PostgreSQL.** `dek.lock` only sees servers on its own host; a replica on another host could encrypt a value just before the rotation's fence and insert it after the sweep, leaving a version under the retired DEK. Both commands rotate the DEK and now refuse when `--force` would skip the server-presence lock (a `rotate --dry-run` is still allowed). Stop every server on every host before rotating. Finding: `docs/findings/2026-10-27-FINDING-dek-rotation-cross-host.md`.
- **Deactivating a user can no longer leave the install without an administrator when a named lock is lost.** SuspendUser, UpdateUser, DeleteUser, the SCIM update/deprovision paths and the user-to-machine migration now re-check the last-admin guard inside their write transaction, behind a row lock on the global admin grants. Before, two deactivations overlapping in the lock-loss window of a `WithNamedLock` section (POOLER-LOCKLOSS-1) could both commit. Every named-lock section is inventoried, with a verdict, in `docs/design/named-lock-overlap.md`, and a guard test keeps that list complete.
- **Every other named-lock section now keeps its invariant when its lock is lost, too.** A new storage method, `LockNamedKeyInTx`, takes a section's key as a transaction-scoped advisory lock inside its write transaction (PostgreSQL; nothing to take on SQLite), and every write transaction under a named lock now starts with a fence that takes that key or the rows the competing writers lock, then re-runs the section's own check: removing a group member, a group role or a whole group (also through SCIM and access review) can no longer leave the install or a project with no administrator; no grant, group join or group grant can complete a separation-of-duties pair; a revoked project membership can no longer keep the role its activation granted; removing a user's project roles (members, role sets, break-glass revoke) keeps the last project administrator; two dependency edges can no longer form a cycle; a secret can no longer be created, restored or resumed into an environment being deleted; and a non-administrator can no longer restore a group that just gained an admin role. The inventory in `docs/design/named-lock-overlap.md` now lists every site as safe or fixed.
- **The evidence-delivery webhook no longer logs or returns its configured endpoint URL (#3762).** The endpoint can carry a token in the userinfo, path or query. The `insecure_skip_verify` startup warning, the endpoint-validation errors (invalid URL, plaintext `http://`, unsupported scheme, private target) and the delivery errors from a failed POST all printed it, the last two through the wrapped `*url.Error`. They now name the destination as scheme and host only and drop the `*url.Error` layer, keeping `errors.Is` on the underlying failure.
- **Configured endpoint URLs no longer reach logs and error text elsewhere (#3762).** A new repo-wide guard (`internal/urlleakguard`) flags `log.*`, `fmt.Errorf`, `errors.New` and `slog` calls that format a value named like `Endpoint`, `URL` or `DSN`. Its hits are fixed: the RFC 3161 checkpoint-notary URL (startup log lines, validation errors and the delivery error, including the wrapped `*url.Error`), the evidence-webhook and notification-webhook "enabled" startup lines, the `keyorix-k8s-sync` startup lines, the SSO `redirect_url` validation error, and the redirect-refusal errors of the Kubernetes dynamic-secrets client, the k8s-sync fetcher, the MCP client and the notary, which quoted a server-controlled redirect target. They name the destination as scheme and host only.
- **Invalid-URL errors and the audit checkpoint `anchor_provider` no longer carry configured URL credentials (#3762).** When a userinfo password held an unescaped `/`, `?` or `#`, the URL parse error quoted part of it as an "invalid port"; parse failures now read "not a valid URL". The RFC 3161 notary's provider name, stored as `audit_checkpoints.anchor_provider` and returned by audit verify, the checkpoint API, gRPC and the admin export, is now `rfc3161:<scheme>://<host>` instead of the full configured TSA URL. Checkpoints anchored before this change keep the full URL in that column.
- `admin encryption rotate`, `upgrade-aad`, `rotate-kek` and `migrate-provider` refuse missing key files before they open the database, so on SQLite a run from the wrong directory no longer leaves an empty database file behind.
- `admin encryption auth-encryption status`, `validate`, `rotate` and `migrate` refuse missing key files before they open the database (same SQLite empty-file defect), and all five auth-encryption commands now close the database they open.
- **`verify-audit` now checks the server's verification state row.** A database-write actor who cut the audit tail and erased the checkpoint rows and the high-water mark (with or without the `audit_verification_state` row) got VALID from `verify-audit --checkpoint-key-file` while the server reported a sticky discontinuity. Offline verification now applies the server's deleted / garbled / past-the-head / head-gone / recorded-discontinuity rules, and its rule for an older row put back over a recorded discontinuity; a pending key transition's row is accepted as the server accepts it.
- **`verify-audit` verifies every row in `audit_events`.** A row with id 0, or (with a hand-edited schema) a NULL or duplicated id, was never visited by the walk and sat unverified; it is now BROKEN.
- **`verify-audit --db` opens exactly the file named, read-only.** A path containing `?`, `#` or `%` opened a different file, read-write.
- **Key-set manifest writes can no longer tear each other.** Each write stages under its own name, so writers racing past a broken key lock cannot rename a mix of both into place. `admin encryption key-secret export` still refuses a directory where a manifest write was interrupted, and server start (or a key command) removes such leftover staging files, with a warning, under the key lock.
- **A user joining a group while a role is granted to that group can no longer end up with a forbidden separation-of-duties pair.** The join and the grant shared no lock, so a join checked against the group's old roles and a grant checked against the group's old members could both commit. The join's write transaction now takes the group's key, and the grant re-reads the group's members inside its transaction under the same key, so whichever commits second is refused. SCIM and SSO group sync are unchanged: they run no separation-of-duties check by design.
- **The bootstrap token and the Vault connector token now come from the file `config.Load` read, not a second open (#3830).** `KEYORIX_BOOTSTRAP_TOKEN` (which claims the first admin) and the Vault connector token (`VAULT_TOKEN` or the connector's `token_env`) were re-read with `secretenv.Lookup` after the boot checks had judged a snapshot of the `*_FILE`, so a file swapped in between was used without ever passing the permission check. They are now answered from the same snapshot (`config.LookupSecretEnv`). `TestNoLiveSecretenvLookupOfConfigSecrets` fails on any non-test file outside `internal/config` and `internal/secretenv` that calls `secretenv.Lookup` on one of those secrets.
- **Notification webhook startup errors no longer carry the webhook URL (#3805).** A Slack or Teams webhook URL is itself the credential. The invalid-URL, plaintext, scheme, private-address and resolve errors from the notification webhook and chat channels printed it, including through the wrapped `*url.Error`; they now name scheme and host only. The same fix covers the `keyorix-k8s-sync` `keyorix_url` checks, the MCP client `KEYORIX_URL` check, the OIDC `jwks_uri` scheme check and the evidence object-store endpoint check. The URL-leak guard now also treats the first string parameter passed to `url.Parse` as a URL whatever it is named.
- **An MFA-reset approver demoted or suspended mid-approval can no longer complete the reset (#3800).** The approver's admin role, active state and second factor were checked only before the approval transaction. They are now re-checked on the approver's row lock inside it, with the requester, approver and target locked in ascending user-ID order, so two admins approving each other's requests cannot deadlock.
- **A user whose MFA was reset must enrol a new second factor even without `security.require_mfa` (#3799).** The account-setup gate (HTTP and gRPC) now reads `users.mfa_enrolment_required`: such a session is confined to enrolment until a factor is enrolled, and TOTP activation clears the flag. Users who were never reset are unaffected.
- **The crypto inventory / CBOM is no longer sent when its read could not be audited (#3716).** `GET /api/v1/compliance/crypto-inventory` records `compliance.crypto_inventory_read` before answering, and answers 503 `audit_unavailable` (Retry-After) with no inventory when the row did not land.
- **Vault, Azure Key Vault and Kubernetes endpoint validation errors no longer echo the configured URL.** `connect` (Vault `address`), `azurekms` (`kms_key_id` and the vault origin) and `dynamic` (Kubernetes `api_server`) named the full value, and the wrapped `url.Parse` error quotes the raw input, so userinfo, a `?token=` query or a password in a malformed port could reach a startup error. The Vault connector's non-200 read error and its link-local refusal (also used for Azure Key Vault) printed the raw `address` into the server log the same way, and the Vault token lookup (run at boot), mount-info lookup and secret read, plus the Kubernetes TokenRequest and bound-Secret calls, passed on net/http's request error, which quotes the full request URL with only a password masked. They now name scheme and host only (`netutil.RedactURLHost`, `netutil.RedactErrorURLs`). This clears the ten `urlleakguard` reports left by #3835.
- **A step-up grant can no longer outlive a suspend, deactivate or delete that raced it.** `VerifyMFAStepUp` checked the account, then wrote the grant with a plain insert; a suspend/deactivate/delete committing in between left a live MFA step-up grant, which the sweep's own purge had already missed. The grant insert now re-checks its owner inside the same transaction (the same row-locking re-check sessions and PATs use since #2701) and the step-up is refused. Proven on real Postgres (`TestCTAReview_StepUpGrant_vs_{SuspendUser,DeleteUser}_CrossReplicaPostgres`).
- **A role granted in a project or environment that no longer exists authorizes nothing.** The role lookups treated a grant whose project or environment row had been purged as live, so a purged project's leftover grants kept authorizing at that project id. Every role lookup (including the single-statement permission check on every request, the batch secret authoriser and the machine value-read path) now requires the row to exist and be live (#2795).
- **Share lists at the storage row cap are refused instead of silently shortened.** The gRPC/CLI `ListUserShares` now answers `FailedPrecondition` (the HTTP list's `422 ShareListOverCap`), and the shared-with-me secret listing refuses too; the dashboard's shared-secret counts are marked degraded instead of showing a floor as a count.
- **Release SBOM tooling: `undici` override raised from 7.29.1 to 7.30.1.** The root `package.json` override (added in #3134 as a floor above cdxgen 12.8.5's vulnerable pin) became a ceiling once cdxgen 12.9.0 pinned the fixed 7.30.1 itself, and kept the release-SBOM toolchain on a version affected by GHSA-2m5v-pch6-74hx (TLS certificate validation bypass), GHSA-4w7w-5xrc-9h26, GHSA-xjj6-f33q-929c, GHSA-qrxm-fqhp-jwvm, GHSA-f72v-6w45-q472, GHSA-4qv8-2p9j-2685, GHSA-9fm3-97px-rjf6 and GHSA-55wc-3pg8-jfw6. Affects only the root `keyorix-ci-tools` package (release SBOM generation), not the shipped server, CLI or web UI.
- **A role grant whose project row is missing no longer authorizes (#2795).** The role readers joined `projects` with a `LEFT JOIN` and treated a scoped grant as live when `projects.deleted_at IS NULL`; with no projects row at all that test is also true, so a `user_roles`, `group_roles` or `machine_identity_roles` row left behind after a project was hard-deleted or purged still granted. Every reader (`GetUserRoleIDsAt`, `GetUserGroupRoleIDsAt`, `GetMachineRoleIDsAt`, the combined principal-permission statement, the batch authoriser's `ListUserRoleGrants` and the machine read-path prefetch) now also requires `projects.id IS NOT NULL`, on SQLite and PostgreSQL. Global grants (project 0) are unchanged. Guarded by `TestEveryProjectsJoinRequiresTheRow`, which fails on a new `JOIN projects` in store code without the row test.
- **Azure Key Vault and Google Cloud KMS clear the unwrapped KEK when its integrity check fails.** `azurekms` dropped the unwrap result without zeroing it when a version-pinned envelope's MAC did not match, and `gcpkms` did the same with the decrypt plaintext on a `PlaintextCrc32C` mismatch, so recovered key material stayed in memory after the error. Both now `clear` the buffer before returning. `awskms` has no discard path after the unwrap.
- **A project admin can no longer make the server read or send its own files or ambient credentials through a dynamic-secret `admin_dsn`.** Only the host of an `admin_dsn` was checked. A MySQL DSN with `allowAllFiles=true` let a rogue MySQL server (on any public address) answer the first statement with a `LOCAL INFILE` request, and the driver sent back any file the server could read (config, key material). MongoDB `tls*File` / `ssl*File` and PostgreSQL `sslrootcert`, `sslcert`, `sslkey`, `passfile`, `servicefile` and `service` made the driver read paths on the server's disk (an existence and parse oracle; the errors were already masked). A MongoDB DSN with `authMechanism=MONGODB-OIDC` (also `MONGODB-AWS`, `GSSAPI`) made the driver present the server's own credentials to the target host: the pod service-account token (or the file named by `AZURE_FEDERATED_TOKEN_FILE` / `AWS_WEB_IDENTITY_TOKEN_FILE`), the Azure/GCP metadata-endpoint tokens, or the AWS environment credentials. PostgreSQL also filled a password the DSN left out (or set empty) from the server's own `PGPASSWORD`, service file or `~/.pgpass`, and presented the server's default client certificate (`~/.postgresql/postgresql.crt`), to whatever host the DSN named. These options and mechanisms are now refused when the config is created and again on every connection, so configs stored earlier are covered too; the API names only the refused option. A PostgreSQL `admin_dsn` is now parsed with an allow-list of keys (`host`, `port`, `dbname`, `user`, `password`, `sslmode`, `sslsni`, `connect_timeout`, `application_name`, `target_session_attrs`, `channel_binding`, `require_auth`), must contain the admin password itself, and never presents a client certificate; a stored config that relied on another key or on the server's ambient password fails at issue time with an error naming the option. Guarded by `TestMySQLEngineNeverSendsLocalFilesToTheServer`, `TestLocalFileOptionsCoverTheDrivers`, `TestPostgresTextualCheckAgreesWithPgxOnEverySeparator` and `TestPostgresEngineNeverSendsTheServersAmbientPassword`.
- **The audit high-water mark and the signed verification state survive a lost checkpoint lock.**
  Both were written with a last-write-wins upsert whose "only ever advances" held only while
  `WithAuditCheckpointLock` was exclusive. After a silent lock loss (a connection pooler dropping
  the advisory lock), a slower replica could write a lower high-water mark after a faster one, so a
  truncation of the newest events went unseen, or save an older verification state over one that
  had just recorded a sticky failure. They are now written with a compare-and-set on the value
  read (new storage method `CompareAndSetSystemMetadata`); a lost write re-reads and skips or
  retries once. `docs/design/pooler-lock-loss.md` row 15 is now covered.
- **Incremental audit verification no longer reads a forged row with id 0 as valid until the next rolling cycle (#3808).** With incremental verification on, `GET /api/v1/audit/verify` and gRPC `VerifyAuditChain` check only the tail after the latest checkpoint, and that walk counted only the rows after its starting row. A row inserted with `id = 0` (or a NULL id, or a second row under the starting row's id on an altered schema) was outside every such check until the rolling cycle next walked from the chain start, up to a full cycle later. The tail check and every rolling-cycle segment now also count the rows no id-ordered walk reaches, so the next request reads broken. The chain-encoding migration (`POST /api/v1/audit/migrate-chain-encoding`) refuses the same rows instead of re-encoding around them.
- **Adding a member no longer tells a refused caller whether a user exists.** With a membership domain allowlist set, `POST /api/v1/projects/{id}/members`, `PUT /api/v1/projects/{id}/members/{userId}` (new member), `POST /api/v1/projects/{id}/memberships` and `POST /api/v1/groups/{id}/members` (and the gRPC group-member RPC) looked the target user up before checking that the caller may grant the role. A `roles.assign` holder who may not grant it got "user not found", "email domain is not on the allowlist" or the permission refusal depending on the user ID. The permission check now runs first, so a refused caller gets the same answer for every user ID; a caller who may grant the role still gets the specific errors. A new core guard (`TestTargetLookupsFollowActorAuthorization`) fails on a target-user lookup that runs before the actor's authorization. The ownership-transfer case (#3794) was already fixed by #3815.
- **Creating a user now requires the permissions of the baseline role it grants.** Every new user receives the `system_viewer` baseline role (`system.read`), but only user creation with a `role` or `project_assignments` checked that the creating actor held that role's permissions. An actor with `users.write` but without `system.read` could create accounts holding a permission it did not hold itself through `POST /api/v1/users` with an admin-set password, a one-time password (`generate_one_time_password`) or a setup link (`deliver_setup_link`), and through gRPC `CreateUser` with a one-time password or setup link. Every one of these paths now checks the actor first and refuses with HTTP 403 / gRPC `PermissionDenied`; no account is created. A storage failure during the check answers 503 / `Unavailable`. Machine identities are judged by their own permissions. Paths without a creating actor (SCIM, SSO JIT, invitation acceptance, bootstrap) are unchanged.
- **Upgrade note: custom user-admin roles need `system.read`.** A custom role or machine identity that creates users with `users.write` but does not hold `system.read` now gets 403 / `PermissionDenied` on every user creation, including plain admin-set-password creation that used to return 201. Add `system.read` to those roles (built-in `system_admin` and `admin` already hold it).
- **Changed for machine callers:** `PUT /api/v1/projects/{id}/members/{userId}` on a member who already belongs to the project now runs the privilege ceiling for a machine caller on the role it names, as it already did for a new member. Before, when the request added nothing, no ceiling ran: a machine holding only `roles.assign` at the project could name the role the member already held (200, plus a `role_confirmed_unchanged` audit row) or name one of several roles the member held, which removed the others (200). Such a machine is now refused with 403 and nothing changes. A machine that holds `roles.assign` and every permission of the named role is still allowed, as on main. Human callers and `DELETE /api/v1/projects/{id}/members/{userId}` are unchanged. (#3990)
- **`keyorix-server admin recover-admin` no longer lifts a suspension or deprovisioning silently.** An admin
  account that is `suspended` or `deprovisioned` (or whose `account_state` is a value Keyorix does not
  recognise, which login already fails closed on) is now refused by default, with nothing changed and an
  `admin.recover_admin_failed` audit event. The new `--force-unsuspend` flag recovers it anyway; it still
  requires the recovery key and a global-admin target, and the audit event and the notification to every
  admin then name the state that was lifted. The state is checked again on the row lock inside the reset
  transaction, so a suspension that lands during the run (for example under the admin `--force` lock
  bypass) is not lifted either. Scripts that relied on recover-admin reactivating a suspended admin must
  add `--force-unsuspend`.
- **Machine token issuance cannot widen the caller's own credential.** A machine caller may not issue a token for itself. It is also refused when its own credential carries a CIDR allowlist or is a federated OIDC/Kubernetes JWT, so a CIDR-restricted or federated credential cannot mint an unrestricted, durable `kx_machine_` token (the machine counterpart of the restricted-PAT rule). The caller credential's own expiry is not checked. A machine caller is also refused a target whose role is admin-tier by name or permission bundle, not only by the admin-bypass flag, and a target holding any permission the caller does not hold at that scope, so it cannot gain permissions through a peer's token that it could not grant itself.
- **The DAST authenticated ZAP scan no longer puts its bearer token on the `docker run` argv.** `scripts/dast/scan-zap-auth.sh` passed the token as `-z "-config replacer...replacement=Bearer <token>"`, visible in `ps` and `docker inspect`. It now writes the token to a properties file in a per-run 0700 directory (0600 file, readable by the container's zap uid through a POSIX ACL when the script runs as another uid), mounted read-only, and passes `-z "-configfile ..."`. The script fails closed: it aborts when the zap uid cannot be granted access without widening the file (unless `ZAP_AUTH_ALLOW_WORLD_READ=1`), when a probe container cannot read the file, or when the token has characters outside `[A-Za-z0-9._~+/=-]`. `TestDocsShowNoLiteralSecretOnCommandLine` now also fails on a `-z` option that carries a Bearer or replacement token in `scripts/**/*.sh`.
- **Access log redacts query-string values by default.** The access log (text and JSON formats and the panic-context line) now logs a query value only for an allowlisted parameter (pagination, sorting, enumerations, numeric and time identifiers) and only when the value matches that parameter's own grammar: digits for pagination, counts and ids, `true`/`false`/`1`/`0` for switches, a date/time shape for time bounds, or a short lowercase enum (up to 32 of `a-z0-9_.:-`, never a `kx_` prefix). Every other value, including anything with `%`, `;`, `/` or `+` and any Keyorix token, is logged as `[redacted]`. A short all-lowercase secret sent under an enum parameter is not covered. Operators lose the query values of other parameters in the access log. Guarded by `TestRedactSensitiveURI_QueryRedactedByDefault`, `TestRedactSensitiveURI_AllowlistedValueShapeChecked`, `TestRedactSensitiveURI_NoCredentialShapeSurvivesUnderAnyAllowlistedKey` and `TestLogger_NeverLogsArbitraryQuerySecret`.
- **Updated `crewjam/saml` to v0.5.2 (GO-2026-6909).** The SAML library now returns an error instead of panicking on a signed assertion without `Subject`, `Conditions` or `SubjectConfirmationData`, and binds `NameID` and the other assertion children to the SAML assertion namespace. It also requires a bearer `SubjectConfirmation` and an `AudienceRestriction`: an IdP that omits either is now rejected at the ACS.
- **The webhook and Slack/Teams notification sinks (`internal/notifychan`) now refuse IPv6 encodings of a private or link-local IPv4 address, and the unspecified address.** `https://[64:ff9b::a9fe:a9fe]/` (NAT64) and `https://[::a9fe:a9fe]/` (IPv4-compatible) both stand for cloud IMDS `169.254.169.254` and were accepted at construction and at dial time, as were `0.0.0.0`, `0.x.y.z` and `[::]`, which connect to the local host. Loopback (including `[::1]`) is still permitted as a development target. (#3427)
- **A profile edit no longer reverts a concurrent email or username change.** `PUT /api/v1/users/{id}`, gRPC `UserService.UpdateUser` and `PUT /api/v1/auth/profile` now build their write from the user row as it is under the row lock, applying only the fields the request changes. Before, a display-name edit, including a session-only one from `PUT /auth/profile`, could write back the email or username it had read before an admin's concurrent change, which put the old password-reset address back. `PUT /auth/profile` also drops an email equal to the one its re-auth check read, so the unchanged email the web page always resends cannot become an email change that skipped re-auth. Password, suspension, MFA and lockout columns were already protected (#2785). Closes the rest of #2653 and #2654. Guarded by the `TestUserRowNarrow_*` race tests (SQLite, default CI), their Postgres twins, and `TestUpdateUserWrites_AreBuiltFromALockedRead`.
- **Three 400 responses no longer quote the caller's input (#4059).** `GET /auth/sso/{provider}/login` (unauthenticated) for an unknown provider, `POST /api/v1/notification-channels` with an invalid `type`, and `GET /api/v1/secrets/{id}/access-log/export` with an unsupported `format` answered a 400 that quoted the rejected value back. They answer fixed messages now (`unknown SSO provider`, `invalid notification channel type: must be one of webhook, slack, teams, email`, `unsupported export format: must be csv or json`); the fix is in core, so gRPC and every other caller get the same text. The request-echo canary harness no longer allowlists these three echoes and fails if one comes back.
- **A plain suspend's audit row is never silently lost.** Suspending a secret (without
  clearing synced copies) still blocks reads at once and is never blocked by the audit log.
  When the audit log refuses the `secret.suspended` row, the server now logs a `SECURITY:`
  line with the details, counts it, reports it to administrators in
  `GET /api/v1/system/info` (`security.audit_owed`), shows a warning bar in the web UI, and
  writes the row (exactly once, also across replicas) as soon as the audit log accepts writes
  again (`audit_owed_backfill` job, every minute). Upgrade note: adds the
  `pending_audit_events` table (schema epoch 3; an epoch-2 binary can still start).
- **`encryption migrate-provider` never tears the DEK on rollback and never overwrites an earlier backup.** When verification under the target provider fails, the previous wrapped DEK is now written to `<backup>.restoring` and renamed over `dek_path` (it used to be rewritten in place, so a crash or a full disk mid-restore left a torn `dek.key`). Each run's backup is created with O_EXCL as `<dek_path>.migrate-backup.<nanoseconds>-<random>`; the old one-second name let a second run in the same second overwrite the first backup.
- **`encryption migrate-provider cleanup` holds the key-directory lock.** It now takes `dek.lock` exclusively for its whole run (`--dry-run` included), so it is refused while a server or a `migrate-provider` runs. `--force` only goes past the database lock, so a forced cleanup can no longer delete the backup an in-flight migration's rollback needs. Upgrade note: stop the server before running cleanup.
- **`encryption shamir-split` refuses `--shares` above 255 up front.** The bound (and `--threshold` below 2) is checked before any output name is allocated or `--out-dir` is looked at; a huge `--shares` used to allocate one name per share first.
- **A live PostgreSQL `admin backup` fails when its presence lock is lost.** Under `key_dir_lock: database` a live backup holds the shared server-presence lock so no key rotation or restore runs beside it. If that lock is lost mid-backup (its backend terminated, a failover), the backup now stops writing, removes the partial archive and exits non-zero with the reason; it used to finish and report OK although a rotation may have run in the window.
- **Air-gapped server build refuses `server.http.tls.auto_cert` at startup.** `keyorix-server-airgap` (`-tags noaws,noazure,nogcp`) used to accept ACME / Let's Encrypt, resolve `acme-v02.api.letsencrypt.org` at the first TLS handshake and fail every handshake while start-up looked healthy. It now refuses to start with `server.http.tls.auto_cert: true is not available in this build`, whether or not `tls.enabled` is set; the message says to configure `cert_file` and `key_file` from an internal CA instead. The full build is unchanged and still accepts `auto_cert`. Guarded by `TestAirgapProfile_RefusesHTTPAutoCert` (run with the air-gap tags), `TestValidateAutoCertForProfile` and `TestValidate_HTTPAutoCertMatchesProfile`.
- **A secret change can no longer commit without its audit record.** Secret create, update (both HTTP paths), rotate, version rollback and delete, folders included, over HTTP and gRPC, now write their `secret.*` audit row (and its access-log row) in the same database transaction as the change, on SQLite and PostgreSQL. If that row cannot be written the request fails (HTTP 500 / gRPC Internal) and nothing changes: no secret row, no version, no audit row. The row exists when the response is sent. A rotation of a secret with no rotation backend, and every rollback, now also commits its timestamp in that transaction, so a failure part-way leaves the secret as it was (#2842; its fuzz tolerance is removed). An on-demand rotation of a backend-bound secret refuses to call the upstream when its `secret.rotate_backend_started` row cannot be written. The transaction commits durably even at `audit_durability: standard`. Guarded by `TestSecretMutationAudit_RowExistsIffMutationCommitted`, `TestSecretMutationAuditFailure_FailsClosedChangesNothing`, `TestSecretMutationAudit_StandardDurabilityNeverRelaxesTheMutationCommit` and `TestTracker_SecretMutationWithItsAuditRowIsOneFencedWrite`.
- **An owed audit row whose pending record could not be written is now queued after the commit instead of lost.** When a revocation's pending audit record could not be written in its own transaction (the revocation still commits: it is never blocked by the audit log) and the audit log then refused the row, that row and the other rows of the same change were only logged as "NOT queued" and never retried. They are now written to `pending_audit_events` right after the commit, so the scheduled backfill writes them, also after a restart. The row is lost only if that late record fails too (still logged loudly and counted in `audit_owed_failures`).
- **Replacing a user's roles during an audit outage no longer loses a role or reports "nothing was changed" (#3488).** `PUT /api/v1/users/{id}/roles` and `PUT /api/v1/projects/{id}/members/{userId}` removed roles one at a time, then granted the new ones fail closed; when the audit log refused the grant, the old compensating re-grant failed the same way, so the user lost a role they held and the answer said nothing had changed. A replacement is now applied in two transactions: the removals (never blocked by the audit log, their records owed and backfilled), then the additions (only with their audit rows). If the additions cannot be recorded, the removals stay applied and the request answers HTTP 503 with the same machine-readable body as the other split requests (`error: MutationPartiallyApplied`, `details.code: mutation_partially_applied`, `applied` / `not_applied` naming the role IDs); retrying the same request is safe. An addition the separation-of-duties gate refuses now refuses the whole request before any removal commits, judged on the role set after the removals. Changing the role of a project's only administrator to another administrator role is one transaction: during an audit outage it changes nothing instead of leaving the project with no administrator. The web admin and project-members views re-read the roles after such an answer.
- **A proven loss of audit rows can be accepted with the checkpoint key: `keyorix-server admin audit accept-loss`.** A genuine break (rows deleted from the audit chain, or a tail truncation a signed checkpoint proves) used to leave the chain broken forever, with every checkpoint refused, so new tampering was no longer notarised. The new offline command (server stopped, exclusive database lock, master passphrase) verifies first and refuses anything that is not a proven loss at exactly the ids named with `--first-broken-id`: a modified row, the pre-#1452 encoding, a key mismatch, an unauthenticated store, an untrusted verification state or an altered earlier seal. It prints what it will accept and writes nothing without `--confirm`. A re-run completes an acceptance that stopped part way, and refuses when a checkpoint, the high-water mark or the verification state signed after the seal certifies rows that are gone, or when one of them was deleted or garbled. On SQLite it also checks the host's `.audit-highwater-witness`, so a rollback of the database to a copy from before the acceptance is refused, and it never lowers that witness. The resume plan says when, by whom and why the seal was recorded: do not confirm a resume you did not start. `--operator` (at most 256 bytes) and `--reason` (at most 1024 bytes) may not contain control or format characters or line separators. Then it writes a seal record (MACed with the checkpoint key, naming the lost range, operator, OS user, time, reason and an evidence digest), one in-chain `system.audit_loss_accepted` event, a fresh checkpoint and high-water mark, and the verification state. `--anchor` binds it to an `export-checkpoint` file that must cover the lost range. See `docs/operator/audit-chain-break-runbook.md` §7 option 3.
- **A sealed chain is never valid again.** `keyorix audit verify`, `GET /api/v1/audit/verify` (incremental and full), the full-verification job, gRPC and the compliance posture report status `sealed` (`valid: false`, `state_reason` names each seal). Offline `admin verify-audit` reports `SEALED` with the new exit code **4**, and BROKEN without `--checkpoint-key-file` (a seal is trusted only with the key). Deleting, altering, moving or replaying the seal record, removing its event, or removing or putting back rows around a sealed gap reads BROKEN on both verifiers. Checkpoints and the high-water mark written after a seal sign a new v2 canonical form that includes the seal count and the newest seal's digest. `rotate-kek` and `migrate-provider` carry the seal over (the key transition record names it). `admin recover-admin` never seals.
- **Upgrade note:** an older binary that opens a database with a seal reports the chain BROKEN: it does not know the record, so it sees the gap and cannot verify the v2 checkpoints. Do not downgrade after accepting a loss. `admin restore` orders the `.audit-highwater-witness` by seal count first, so an archive from before a seal is refused as a rollback (`--allow-rollback` overrides it, audited).
- **Restoring a deleted secret can no longer commit without its `secret.restored` audit record.** `RestoreSecret` now writes the audit row in the same database transaction as the undelete, on SQLite and PostgreSQL; if the row cannot be written the request fails and the secret stays deleted. Guarded by the `restore` kind of `TestSecretMutationAudit_RowExistsIffMutationCommitted` and the restore op of `TestSecretMutationAuditFailure_FailsClosedChangesNothing`.
- **The edge crash soak now fails on a missing mutation audit row by default.** `scripts/edge/crash-soak.sh` no longer needs `--strict-mutation-audit`; `--lenient-mutation-audit` (or `KEYORIX_SOAK_STRICT_MUTATION_AUDIT=0`) restores the old log-only behaviour.
- **Refused secret-value reads are audited (#3273, ADR-112 Amendment 4).** A refused
  native read now writes a `secret.read` audit row with `success=false`, `outcome=denied`
  and a `reason=` class: `forbidden`, `not_found`, `outside_schedule`, `expired`,
  `suspended`, `max_reads_exhausted`, `classification_gate` or `mfa_required`. A read that
  breaks is recorded as `internal_error` with `outcome=failed`. This covers REST
  `GET /secrets/{id}?include_value=true`, `/secrets/value`, render, copy, environment copy
  and clone, and gRPC `GetSecretValue`, at both `insecure_audit_skip_reads` settings.
  Before this, only federated (`connect.secret_read`) denials were audited. Responses are
  unchanged. A missing and a forbidden secret still answer the same, and their rows name no
  secret or project on any column the caller can see. A burst is aggregated per principal,
  reason, path and target: the first refusal is written at once, then one summary row per
  60-second window carries the count, with per-principal and global caps. The row is
  best-effort: if it cannot be written, the refusal stands and the failure is logged.
  Dashboard read counts, top readers, billing machine reads and access-review activity now
  count only successful reads.
- **An audit checkpoint is no longer re-baselined over a truncated chain on an unauthenticated key-version claim.** When the latest checkpoint or the high-water mark failed its signature under a different `key_version`, the next checkpoint write treated it as a signing-key change and re-certified the current, possibly shorter, chain. A database-level actor without the key could use that to hide a tail truncation. The signed verification state now pins the newest certified count and head row. It is signed with the same key, so a genuine key change (`rotate-kek`, `migrate-provider`) invalidates it too and re-baselining works as before. While it still authenticates under the current key, every checkpoint write, full or incremental, refuses a chain it proves was truncated. The refusal is a recorded verification failure (`keyorix_audit_verify_failure_recorded`, `system.audit_chain_verification_failed`), and it also increments the new protected counter `keyorix_audit_checkpoint_truncation_refused_total`. Guarded by `TestAuditCheckpointLaunder_*` (`internal/core`, SQLite and PostgreSQL).
- **Nothing is signed against an untrusted audit seal record.** While the `audit_seals` row cannot be trusted (garbled, forged, replaced or left unfinished), no checkpoint or high-water mark is signed or authenticated against it. A key change (`rotate-kek`, `migrate-provider`) completed in that state now stops its audit transition with "the audit seal record cannot be trusted" and re-signs nothing. The server retries it at every start (REVIEW-3757-DEEP-3 finding 1; `INV-CORE-audit-seal-untrusted-binding-signs-nothing`).
- **`admin audit accept-loss` counts the host witness.** On SQLite, an authenticated `.audit-highwater-witness` counts in "certified before the loss". The plan says when confirming lowers it, and a head of it that is gone must be named as a truncation. The apply refuses, before writing anything, to lower a witness higher than the plan named. A witness signed under a seal list the database no longer holds is refused as a rollback of the database. The runbook (§8) now states exactly what a whole-trail rollback leaves undetected (REVIEW-3757-DEEP-3 finding 2).
- **`admin audit accept-loss` no longer seals rewritten rows as a loss (#3802).** The audit entry hash is unkeyed, so a database writer could rewrite rows before the gap, recompute their hashes and delete the next row. The break then looked like a genuine deletion, and the seal certified the forged rows. The command now refuses:
  - a break with no id missing;
  - a signed certification taken after the rows before the gap that still counts every surviving row;
  - any row whose hash differs from what a signed checkpoint (every checkpoint, not only the latest), the high-water mark, the retention anchor, the signed verification state, the host witness, an earlier seal or `--anchor` certified.

  Surviving rows before a gap that nothing signed pins are listed in the plan as unauthenticated and recorded in the seal (`unpinned`).
- **Resuming an unfinished `admin audit accept-loss` now needs `--resume-seal <digest>` (#3803).** A database put back to look like an acceptance that stopped part way used to be completed by a habitual re-run with `--confirm`, and the operator never saw the warning. A resume now writes nothing, and exits 1, until `--resume-seal` names the record digest its plan prints. The post-crash message says so instead of "run this command again".
- **`admin audit accept-loss` refuses a garbled host witness that claims the current key.** A `.audit-highwater-witness` whose signature fails under the current key version was reported as "written before a key change" and overwritten. It is now refused, at the plan and again before anything is written, as the resume path already did. On a resume, the refusal for a higher pre-seal witness now says what to do (compare with an off-host anchor, then move the witness aside), instead of "re-run accept-loss", which refuses the same way.
- **The online audit-chain verification no longer reads a forged row with id 0 as valid (#3808).** The server's `VerifyAuditChain` walks by `id > ?` from 0, so it never visited an `audit_events` row inserted with `id = 0`. It also missed a NULL id, or a duplicated id on a batch boundary, on an altered schema. It now counts the rows in the range it walked, once per verification, and reads broken when one was not walked, as `admin verify-audit` already did.
- **A role grant, credential or other access-granting change can no longer commit without its audit record.** Role grants (direct, JIT, SSO-mapped, baseline backfill, project member add, access-request approval), group role grants and memberships, permission and role-definition changes, break-glass activation, secret shares and share or role updates that widen access, secret ACL grants, machine identity create / token issue and rotate / role grant, PAT create, user create (with or without assignments, setup link, one-time password), project and environment create, and SoD policy create/delete now write their audit rows in the same database transaction as the change, on SQLite and PostgreSQL. If a row cannot be written the request fails and nothing changes; a crash at the audit append leaves no unaudited grant. Revocations (role/share/ACL/token/session removal, suspend, delete) are unchanged: they are never blocked by the audit log and still audit after their commit. A role or share update is classified per call: one that only removes permissions or narrows a share (write to read, a shorter expiry), or changes no access, is a revocation and still commits during an audit outage, so an admin can strip a permission in the web role editor; one that adds anything, even alongside a removal, fails closed. Inventory: `docs/specs/security-mutation-audit-inventory.md`. Guarded by `TestSecurityMutationAudit_RowExistsIffMutationCommitted` (error, effect-then-error, panic and crash at the append), `TestSecurityMutationAuditFailure_FailsClosedChangesNothing` (30 REST/gRPC operations), `TestSecurityMutationAudit_UpdateRole_ByDirection`, `TestRoleEditorUpdate_AuditFailure_ByDirection` and `TestTracker_GrantWithItsAuditRowIsOneFencedWrite` (single_writer).
- **Every remaining security-relevant change now writes its audit record in its own transaction, and no revocation can lose its record.** Project and environment update / restore, group create / update / restore, user update / reactivate / restore, one-time password reissue, SCIM user and group provisioning writes, invitations, access-request create / approval, and the configuration changes (notification channels and retry policy, anomaly config, rotation policies, alert escalation policies, risk exceptions, legal hold, machine and token classification, access-review campaigns) commit with their audit row on SQLite and PostgreSQL; if the row cannot be written the request fails and nothing changes. Revocations (role, group, permission, share, ACL, token, session and PAT revoke; user suspend, deactivate and delete; project and environment delete; turning a project's MFA requirement on; SCIM deprovision; break-glass revoke; rejecting or withdrawing an access request; expiry sweeps) are still never blocked by the audit log, but they now commit together with a record of the audit row they owe: a refused append or a crash right after the commit queues the row for the existing backfill instead of losing it, and the cache eviction runs before the append so the audit log never delays a revocation taking effect. Inventory: `docs/specs/security-mutation-audit-inventory.md`. Guarded by `TestSecurityMutationAudit3_RowExistsIffMutationCommitted`, `TestRevocationAudit_EffectCommitsAndRowIsOwedNeverLost` (error, effect-then-error, panic and crash at the append, SQLite and PostgreSQL) and the router-level `TestAuditTx3Mutation_AuditFailureFailsClosedChangesNothing` and `TestAuditTx3Revocation_AuditFailureDoesNotBlockAndRowIsOwed`.
- **A failed session or token cleanup no longer rolls back a suspension or deactivation on PostgreSQL, and moving a suspended account to "password reset required" now needs its audit row.** The best-effort session / personal-access-token cleanup inside a suspend or deactivate runs in its own savepoint, so a failed statement can no longer abort the whole transaction and undo the change at commit. Suspended → password-reset-required re-opens login, so it fails closed like any other widening change instead of being treated as a revocation. Owed audit rows of group, role, project-member, machine-role and user deletions are appended after the last-admin / project-admin lock is released, so an audit outage no longer holds that lock for the append timeout. The owed-audit fuzz oracle now checks every owed row of an operation (including the SSO callback's second one and the SAML ACS), the SSO group and role reconcile runs in a stable order, and the sweep pins what each operation owes.
- **A request that both narrows and widens access is applied as two commits, so an audit outage can no longer roll its revocation back.** Deactivating a user while changing their username or email (REST, gRPC, SCIM), a SCIM group change that removes members and also adds members or renames the group, turning a project's MFA requirement on while renaming it, a one-time password reissue, and a machine token rotation (`replace_credential_id`: the old credential is revoked first, the new one issued second) now commit the narrowing part first (never blocked by the audit log, its record owed and backfilled) and the rest second (only with its audit row). If the second part cannot be recorded, the narrowing stays applied and the request answers HTTP 503 / SCIM 503 / gRPC `Unavailable` with a machine-readable body (`error: MutationPartiallyApplied`, `details.code: mutation_partially_applied`, `revocation_applied: true`, `remainder_applied: false`; SCIM: the `urn:keyorix:params:scim:api:messages:2.0:PartialMutation` extension; gRPC: `google.rpc.ErrorInfo` reason `MutationPartiallyApplied`); retrying the same request is safe. After a partial MFA-on + rename, the rename needs a second factor, since the requirement now applies to the administrator too. A reissue's first step is audited as `user.one_time_password_reissue_restricted`.
- **A wrong current password now costs what a wrong login password costs.** `POST /auth/change-password` and `PUT /auth/profile` (email change) checked the current password with a bare bcrypt comparison, so a stolen session or PAT could guess it with no bound. Both now feed the per-account login lockout (counted on a wrong password, refused while the account is locked even with the right one, cleared only after the change commits on an account with no second factor) and spend the per-IP login budget (`429` once spent; a failure keeps its slot, any other outcome returns it). A wrong current password is audited `auth.login_failed` (with the IP and the account), so it shows in the failed-login count. A `PUT /auth/profile` without `current_password` (a display-name edit) is not throttled.
- **The authenticated second-factor re-checks spend the login budget too.** MFA activate / disable / recovery-code regenerate, `POST /auth/mfa/stepup` and passkey register-finish / delete take a guessable code or password and were bounded only by the per-account lockout, so one IP holding stolen sessions for many accounts could guess on each of them. They now share `/auth/login`'s per-IP budget (`429` once spent, failures only). Responses are otherwise unchanged.
- **A setup or password-reset link now has its full effect or none** (#3298). The consume used to spend the token first and then set the password, revoke PATs and mint the session separately, so a storage fault in between answered "link could not be completed" over a spent link and a changed password (and could leave an undelivered session). The token, the password, the PAT revocation and the session (or MFA challenge) now commit in one transaction, the response identity is read before it, and a commit that reported an error is read back and delivered. A failed consume leaves the link usable. Unlike before, a reset whose PAT revocation fails is refused instead of completing with old PATs alive. Failed consumes are now audited (`setup_token.consume_failed`, `setup_token.consume_error`), and a token lookup that failed on storage no longer counts against the per-IP login budget.
- **A storage fault on a re-auth endpoint now answers like a wrong code or password.** Disable MFA, regenerate recovery codes and the WebAuthn register/delete endpoints used to answer a fault that kept the code or password from being checked with a distinct "an internal error occurred" text, telling a caller which step failed. They now answer the same 400 "invalid code or password" a wrong credential gets, as `POST /auth/login` already does for a failed username lookup. The fault is still audited as `mfa.error` and still not counted toward the lockout. Guarded by `TestReauthEndpoints_PreVerdictStorageFaultIsIdenticalToAWrongCode`.
- **Core `ShareSecret` now refuses a group recipient.** Group shares go through `ShareSecretWithGroup`, which checks that the group holds a role in the secret's project; `ShareSecret` has no such check, so accepting `IsGroup: true` there would have let a caller share a secret with a group from another project. No behaviour changes for any request: both the HTTP and gRPC share endpoints already send groups to `ShareSecretWithGroup` and pass `IsGroup: false` here, so the refused input is unreachable today (#3422).
- **Ownership transfer authorizes the caller before it looks at the new owner.** `POST /api/v1/secrets/{id}/transfer-ownership` checked "already owned by that user" and whether the new owner exists before it checked the caller's right to transfer, so a caller with secrets.write but no right to the secret could tell which user IDs exist and who owns the secret. An unauthorized caller now gets the same 403 for every `new_owner_id`.
- **Secret access-request approve/reject authorize first.** `PUT /api/v1/secret-access-requests/{requestId}` has no route permission gate; its admin-authority check ran after the request's kind, state, expiry and secret checks, so any signed-in user could read a request's existence and state off the error (and approving an expired one wrote it to `expired`). A caller without authority at the request's project now gets the 404 a missing ID gets, and nothing is written.
- **Bulk access-request approve/reject and secret copy no longer reveal IDs in other projects.** A bulk item in a project where the approver lacks roles.assign answered "permission denied" while a missing ID answered "access request not found"; both now answer "access request not found". `POST /secrets/{id}/copy` and `.../copy-secrets` answer a target environment of another project like a missing one.
- **Suspension no longer commits with PATs silently left live.** The account-state change (suspend, deactivate, require-password-reset, OTP reissue, user-to-machine migration) discarded the errors of its PAT listing and of its session/PAT revocation. Each now retries once, and a persistent failure is reported after commit (per-user auth-cache eviction, `SECURITY:` log line, `auth.session_revocation_failed` audit event); the state change itself still commits.
- **The share list writes one `share_access_elevated` audit row per call, not one per secret (#3456).** `GET /api/v1/shares` and `/shares/owned` name each secret the caller may read; a name readable only through a share used to write its own `share_access_elevated` row on every list call. The list now writes a single row with action `shares.list`, the count and up to 50 secret/share ID pairs (`truncated` when there are more). A caller whose role already allows every read writes none. An elevated read or write of one secret is still audited per action, as before. See `docs/SECRET_SHARING_API.md`.
- **The admin-rank ceiling reads the target's roles in one statement (#4025).** The check that stops an administrator from changing, suspending, deleting or impersonating a user who holds more authority listed the target's scopes and then read the roles at each scope separately, so a role grant another administrator moved from one project to another in between could be missed and the check passed. The target's role grants are now read with one statement and every scope they name is checked. Verdicts without a concurrent change are unchanged. Guarded by `TestAdminRankCeiling_ConcurrentScopeMoveSeenWhole` (SQLite and Postgres) and `TestAdminRankCeiling_SnapshotVerdictUnchanged`.
- **gRPC group/user/role mutations now require the group's read permission, not just the write permission.** `GroupService.{CreateGroup,UpdateGroup,DeleteGroup,RestoreGroup,RemoveGroupMember,AddGroupMember}`, `UserService.{CreateUser,UpdateUser,ReissueOneTimePassword,DeleteUser}` and `RoleService.{CreateRole,UpdateRole,DeleteRole}` now gate on both the matching read permission (`users.read`/`roles.read`) and the existing write/delete/assign permission, mirroring HTTP's outer-plus-per-route permission layering on the `/groups`, `/users` and `/roles` route groups. Previously a principal holding only the write permission could mutate groups/users/roles over gRPC in cases the REST API would deny (authzdiff cross-layer differential harness waiver known-01).
- **A machine actor holding `roles.assign` (and every permission the target role bundles) can now add or update project members as itself.** `AddProjectMember`/`UpdateProjectMember` never tagged the request context for a machine-authenticated caller, so the escalation-by-proxy ceiling treated every machine actor as an untagged relay and refused it unconditionally, regardless of its real authority (authzdiff cross-layer differential harness waiver known-06).
- **`AddProjectMember` now returns 403, not 500, for a ceiling refusal.** Its error-status switch was missing the `errors.Is(err, core.ErrPermissionDenied)` case `UpdateProjectMember`'s otherwise-identical switch already had.
- **A panic while clearing the failed-login counter no longer turns a delivered login into a reported failure (#3556).** After a successful login (`/auth/login`, `/auth/mfa/verify`, WebAuthn login), MFA step-up or re-authentication, the server clears the account's failed-login counter. That clear runs after the session or grant is already written, and on a login after the session cookie is already set. A panic in it used to answer HTTP 500 while the client still received a working session cookie (or a live grant), and the login was not audited. The clear is now best-effort: the login or step-up is delivered and audited normally, and a counter that could not be cleared stays as it was.
- **Two more post-verdict panics are handled like their errors (#3557).** A panic in the password-expiry gate's write (accounts whose password has passed `max_age_days`) is now refused with the same 401 and lockout count as a wrong credential and audited `auth.login_error`, instead of a 500 that a wrong credential never gets. A panic while consuming a recovery code on `/auth/mfa/verify` or `/auth/mfa/stepup` is now answered like that write's error ("try again", audited `mfa.error`), so a recovery code that was burned before the panic is no longer lost without an audit trace.
- **A database error during the auth-cache re-check now refuses the request instead of serving the cached login.** On an HTTP auth-cache hit the server re-checks the credential's revocation state live (PAT, machine token, interactive session's account and session row). When that read failed it used to authenticate the request from the cached login for up to ~30 seconds, so a credential revoked on another replica during a database outage kept working. It now answers `503` with `Retry-After` and a fixed message (no error text), the same response a cache miss gets when it cannot reach the database. A definitive verdict still denies `401` and evicts; a session whose account row is gone (deleted user) is now such a verdict. Federated OIDC / Kubernetes-JWT machine principals now re-check their machine identity's state on every cache hit; before, their re-check could never succeed and the cached login was always served, so a suspended federated identity kept authenticating for up to ~30 seconds on other replicas. gRPC has no auth cache and already refused on a lookup error (`Unavailable`); that is now pinned by a test. **Behaviour change:** a brief database outage now rejects cached credentials with `503` instead of serving them; clients should retry. Guarded by `INV-MW-cache-hit-recheck-fails-closed` (supersedes INV-MW-05's transient half), `server/middleware/cache_hit_fail_closed_test.go`, `server/grpc/interceptors/auth_storage_error_fail_closed_test.go`. See `docs/UPGRADING.md` §6h.
- `POST /system/init` no longer returns the raw error text on a server-side failure (for example a database error naming a host and role). The client gets the standard 500 body; the detail is logged. Bad or missing bootstrap token and weak-password rejections (403) are unchanged.
- Alert-escalation and recover-admin webhook/Slack POSTs now re-validate the destination at send time (https only; private, loopback, link-local and IMDS IP literals refused), in addition to the create/update-time check and the existing dial-time guard, so a stored or injected-client destination can no longer reach 169.254.169.254 / 127.0.0.1 (CodeQL #1209).
- **Webhook URLs are secrets in the CLI and the web form (CLI-UX-2).** `keyorix notification channel add|update` take the URL with `--url-file <path>` or `--url-file -` (stdin); `--url` is refused like the other secret flags (`KEYORIX_ALLOW_INSECURE_SECRET_FLAGS=1` warns instead). `channel get` says the URL shown is masked. The web form uses a password-type field, and an existing channel shows its masked URL with a "Replace URL" button. The server side (create-only full URL, encrypted at rest with a startup backfill) was already in #3438; see `docs/UPGRADING.md` 6x.
- **The CLI refuses secrets given as flags.** `login --password/--mfa-code`, `mfa activate --password/--code`, `mfa stepup --code`, `change-password --current-password/--new-password`, `system init --admin-password/--bootstrap-token`, `user create --password` and `secret create|update|rotate --value` used to be accepted with a warning; a flag is visible to every local user through `ps` and stays in shell history and CI logs. They are now hidden from `--help` and fail with the safe way to supply the value (hidden prompt, `KEYORIX_*` variable or `KEYORIX_*_FILE`, a file, or stdin). Scripts not yet moved can set `KEYORIX_ALLOW_INSECURE_SECRET_FLAGS=1` to get the old warning instead. `TestSecretFlagsAreAllClassified` audits every flag and positional of every command, so a new secret-carrying flag has to be refused or explained.
- **Code-scanning cleanup (Go).** Model IDs are narrowed to uint32 in the gRPC services without an `int` round trip (`uintToU32`); retry/scheduler jitter uses `crypto/rand`; the gRPC TLS configs set `MinVersion` in the literal; the invitation resend-throttle response sends a fixed message constant instead of `err.Error()`; the one-time-password lifetime config fields are renamed in Go (YAML keys unchanged).
- **Code-scanning and Dependabot cleanup (round 2).** `fast-uri` 3.1.9 (CI SBOM tooling lockfile) and `undici` 8.12.3 (web dev dependency via jsdom); the last-used coalescer's flush backoff jitter reads `crypto/rand`; the HTTP TLS config literal sets `MinVersion` itself (the hardening step still sets the final floor); an nginx comment that a header-redefinition scanner matched as a directive was reworded (no directive changed).
- **`admin migrate` refuses a config that `serve` refuses (#2854).** `keyorix-server admin migrate` now runs `Config.Validate()` before it opens the database and fails with the same `Configuration is invalid: ...` message `serve` prints, so a config that cannot boot no longer gets its schema migrated. Guarded by `TestAdminMigrate_RefusesConfigThatValidateRejects` (asserts the database file is never created).
- **Session and CSRF cookies are `Secure` behind a trusted TLS-terminating proxy.** The `kx_session`, `csrf_token` and `kx_admin_session` cookies (set and cleared) get the `Secure` attribute when the request came from a peer in `server.http.trusted_proxies` that says `X-Forwarded-Proto: https`, as well as when the server serves TLS itself. Before, behind a load balancer they went out without `Secure`. One per-request decision (`middleware.RequestIsHTTPS`) now drives both these cookies and HSTS. A client outside `trusted_proxies` cannot change it by forging the header, and `Secure` is never removed where it is set today. If your load balancer talks to the server directly, list it in `server.http.trusted_proxies`. See docs/CONFIGURATION.md ("Secure cookies") and docs/SELF_HOSTING.md. Guarded by `INV-MW-secure-cookie-follows-effective-https`.
- **`server.grpc.trusted_proxies` and `server.grpc.hsts_preload` now log a start-up warning.** Both keys are HTTP-only and were silently accepted and ignored under `server.grpc`. Set them under `server.http`.
- **A secret access approval no longer survives a concurrent delete.** Approving a restricted-read access request while the secret (or its project) was being deleted could commit the approval after the delete had closed the secret's approved requests, so restoring the secret from the recycle bin brought the approval back with no re-review. The approval now re-checks the secret under a row lock in its own transaction and is refused with "cannot approve: secret N no longer exists" when the delete won. Guarded by two-pool Postgres and SQLite race tests in `internal/core`.
- **A self role-set replacement that would lose the grant ceiling is refused before anything changes (#3684).** `PUT /api/v1/users/{id}/roles` or `SetProjectMemberRole` on the caller themselves, replacing a role that carries `roles.assign` with roles only it let them grant (a second admin present), removed the role, then refused the grant: the caller was left with no role at that scope and got 503 `MutationPartiallyApplied` with `retry_safe: true`, but every retry was refused. The ceiling is now also judged on the role set the removals leave, before they commit; the request is refused and nothing changes. A refusal that still happens after the removals (the caller's authority revoked by someone else in between) now says `retry_safe: false`.
- **A machine token's IP allowlist stored as `null`, `[]` or whitespace no longer drops the IP pin (#3396).** Such a row (never written by Keyorix, which stores an empty column for "no restriction") was read as unrestricted. It is now decoded like a personal access token's allowlist: a non-empty value that names no CIDR blocks every source address until the token is re-issued. A personal access token whose allowlist column is whitespace only is now refused the same way (it was read as unrestricted).
- **A late MFA enrolment can no longer replace an activated TOTP secret (#2692).** If
  `ActivateMFA` committed between `BeginMFAEnrollment`'s check and its write, the enrolment
  overwrote the activated secret with a fresh seed it returned to the caller, and that seed
  then passed MFA on an MFA-enabled account. The write is now conditional and the late
  enrolment is refused with the existing "MFA is already enabled" error. A pending
  (not activated) secret is also no longer accepted by login, re-auth or step-up
  verification.
- **Deleting a user no longer reverts a concurrent password change (#2677).** `DeleteUser`
  wrote back the user row it had read before its lock, so a password change (or suspension,
  MFA enable) committing in between was undone, and a later `RestoreUser` let the old
  password in. It now writes only the columns it changes, under the row lock; `RestoreUser`
  does the same.
- **Last-admin guards no longer count an environment-scoped grant as a global admin
  (#2857).** An admin role granted at project 0 with an environment set (accepted by
  `POST /api/v1/user-roles`) applies only inside that environment, but the core-side
  last-admin guards counted it as a surviving global administrator, so the install's only
  real global admin could be suspended. The global holder query now matches the storage-side
  guard.
- **A deleted machine credential or personal access token is refused immediately on every replica.** Previously a credential row removed after it had authenticated could keep working from the auth cache on other replicas for up to 30 seconds; it is now refused like a revoked token, with the same response as an unknown token.
- **A role description edit can no longer undo a concurrent scope narrowing (#3909).** On PostgreSQL with more than one replica, `PUT /api/v1/roles/{id}` (and gRPC `UpdateRole`) without an `assignable_scope` wrote back the scope it had read, so a narrowing (for example `any` to `project`) committed by another administrator in between was reverted and the role could again be granted at the wider scope. The keep-scope update now leaves the column untouched. SQLite installs were not affected.
- **`github.com/klauspost/compress` bumped to v1.20.2.** Clears GO-2026-6865 (fixed in
  v1.20.2), flagged by `govulncheck` as reachable. No code changes; `go build`, `go vet` and
  the affected packages' tests pass unchanged.
- **Dependency: `github.com/crewjam/saml` v0.5.2 → v0.6.3.** Keeps the v0.5.2 fix for GO-2026-6909 (nil dereference in `validateAssertion`, `Subject.NameID` matched in any namespace) and picks up the 0.6 hardening: exactly-one-signature child checks, untrusted-XML unmarshalling, and a required `AuthnStatement` in a bearer assertion. Behaviour changes to be aware of: an assertion without `AuthnStatement` is now refused, and a response whose `InResponseTo` this SP never issued is refused even with `AllowIDPInitiated`. SAML test fixtures were adjusted (single assertion signature, `AuthnStatement` in the transitive fuzz control response); the `internal/saml` suite is green.
- **`github.com/digitorus/pkcs7` updated to `v0.0.0-20261104113855-bd33e0b11a3d`.** Picks up the
  upstream CBC decryption padding fix (GHSA-cj86-7jch-72f4, PR #25). Keyorix does not call the
  decrypt path (`internal/notary` only parses and verifies), so this is not reachable from the
  server; the update keeps scanners quiet and the dependency current. The earlier BER fixes
  (GHSA-3xqc-rpq8-wgp9, GHSA-73j8-gqc5-c98v) were already in the previous pin.
- **Leases of a dynamic-secret config stored before #3952 can be revoked again (#3980).** #3952 refuses `admin_dsn` options that make the driver read a server file on every connection, and that also blocked `Revoke` and the expiry sweep: such leases ended `revoke_failed` and their database users stayed live on the target (MongoDB and MySQL users never expire on their own). Issue and renew from such a config still fail. `Revoke` now removes the option and connects with the rest, without reading the named file: PostgreSQL `sslcert`/`sslkey`/`sslpassword`/`passfile` and MySQL `allowAllFiles` are dropped; PostgreSQL `sslrootcert` becomes `sslrootcert=system` (system trust store, `verify-full`, no plaintext fallback) and MongoDB `tls*File`/`ssl*File` are dropped with `tls=true` kept, so a target signed by a private CA fails the handshake and the lease stays `revoke_failed` with the option named. PostgreSQL `service`/`servicefile` and MongoDB `authMechanism=MONGODB-AWS`/`MONGODB-OIDC`/`GSSAPI` stay refused, now with the option in the lease's `revoke_error`. Upgrade: the server logs `WARNING: dynamic secrets:` at startup with the number of such configs and their live leases; see `docs/upgrading.d/dynamic-admin-dsn-revoke-strips-file-options.md` and the table in `docs/CONFIGURATION.md`. Guarded by `TestPostgresRevokeStripsLocalFileOptions`, `TestPostgresRevokeWithSSLRootCertFailsClosed`, `TestMySQLRevokeStripsAllowAllFiles`, `TestMongoRevokeStripsTLSFileOptions`, `TestMongoRevokeWithTLSCAFileFailsClosed` and `TestDynamicSecrets_RevokeLease_StoredConfigWithRefusedFileOption`.
- **`digitorus/pkcs7` advisory GHSA-3xqc-rpq8-wgp9 is public** (2026-09-14): the BER-length memory-amplification DoS in `pkcs7.Parse` is fixed in the pinned version. The security docs no longer describe the pkcs7 finding as embargoed, and the closure ledger records it with `FuzzDigitorusPKCS7BoundedWork` as the regression guard. Documentation only; no behaviour change.
- **Per-project MFA gate no longer fails open on a "not found" error text.** The HTTP (`ProjectMFABlocked`) and gRPC (`enforceProjectMFA`) per-project MFA checks let an interactive session without a second factor through whenever the project lookup failed with an error whose text contained "not found". They now pass only a genuinely missing project (the new `storage.ErrProjectNotFound` sentinel, so the endpoint's own 404/NotFound still answers) and deny on every other lookup error, in every locale. `GetProject`, `GetProjectByName` and `GetEnvironment` wrap `ErrProjectNotFound` / `ErrEnvironmentNotFound` for a missing row only; the error text is unchanged.
- **A failed session listing no longer silently skips auth-cache eviction on revocation.** Password change, MFA/WebAuthn enrolment, setup-token consume, suspend, deactivate, delete, SCIM deprovision and the admin session purge listed the user's session-token hashes with the error discarded, so a read failure evicted nothing and logged nothing while the code promised "immediately". The listing is now retried once; if it still fails the revocation still succeeds, a `SECURITY:` line is logged, an `auth.session_revocation_failed` audit event is written, and every auth-cache entry of the user, including impersonation sessions the user started, is evicted (new `middleware.InvalidateUserTokenCache`; a validation in flight at the eviction, including one on the same clock tick, cannot re-cache). Guarded by `TestSessionListFailure_*` (internal/core) and `TestInvalidateUserTokenCache_*` (server/middleware).
- **Server text no longer reaches connector, fetcher and access-log output.** The Azure Key Vault connector answers a 2xx reply other than 200 with a fixed message and the status code instead of the response headers and body (#4061). The Kubernetes sync fetcher reports a response that does not decode (for example a malformed `expiration`) with fixed text instead of the decoder's error, which quoted the server's value (#4062). The access log redacts the whole token segment of `GET /auth/setup/{token}` (and the invite and password-reset look-alikes), including a token that contains an encoded slash (`%2F`), whose tail used to be logged (#4045).
- **Expired pending exemptions resolved; guards warn 3 days ahead.** The #2671/#2673 exemption rows (landed in #2785) no longer carry expiry dates, and `TestChildParentLiveness_PendingRowsNotExpired` / `TestFullRowWriteGuard_PendingRowsNotExpired` log a `WARNING` for rows expiring within 3 days while still failing hard once expired.
- **A FIFO (or other non-regular file) at the audit high-water witness path is refused instead of hanging `admin backup`/`admin restore` and the server's witness advance.** `auditverify.ReadWitness` now opens the witness non-blocking, checks the same descriptor and fails with `witness file <path>: not a regular file`, never treating it as "no witness yet"; a symlink to a regular file still works. `internal/auditverify` cannot import `internal/secretenv`, so it carries a local copy of the reader, and `TestSecretFileReadsGoThroughOpenRegular` now scans it.
- **A KEK shorter than 112 bits is refused, not a panic under `GODEBUG=fips140=only`.** The evidence-signing, audit-checkpoint and backup-manifest keys derived from the KEK now return a typed `KEKTooShortError` for a KEK under 14 bytes, the same way in every Go FIPS mode, and no key is set. Before, `crypto/hkdf` panicked on such a KEK under `fips140=only` and a key was derived from it otherwise. Real KEKs are 32 bytes and were already rejected earlier on the boot path, so no existing install changes. Valid KEKs derive the same keys as before, so stored audit checkpoints and evidence signatures still verify.
- **Auth-budget writes survive a transient storage error without leaving the shared table.** The per-IP password-reset, SSO-begin and failed-login budgets recorded each attempt with one plain write: a single transient error moved the attempt into the per-process in-memory fallback (other replicas never counted it, and an `auth.rate_limit_error` event was audited), and a write that landed but reported an error was counted twice. They now use the login reservation's keyed, once-retried idempotent write, so the attempt is stored exactly once; only a write that fails twice falls back, as before (#2837).
- **More post-verdict panics no longer reveal that a credential or setup link was valid (#3277 follow-up).** A panic in a storage call made after the credential was accepted used to reach the recovery middleware, which answered HTTP 500, a status a wrong code or a dead link never gets. It is now answered exactly like the same call failing with an error, on the MFA step-up (the TOTP mark and the step-up grant), on the MFA challenge `/auth/login` and setup consume issue for an account with a second factor, on impersonation start, and on every step of `/auth/setup/consume` after the token is validated (the generic "could not be completed" 400). No session, impersonation session or step-up grant written before the panic is left usable.
- **A failed MFA step-up no longer leaves a live step-up grant behind.** When the grant write reported an error after the grant had in fact been stored, the step-up was refused but the grant stayed usable for the rest of its window. The grant is now consumed and the event audited (`mfa.undelivered_stepup_grant_revoked`).
- **A panic in a login's storage write no longer reveals that the credential was correct (#3277).** After the credential has matched, a login writes the TOTP anti-replay mark (`/auth/mfa/verify`) and the session (`/auth/login`, `/auth/mfa/verify`, WebAuthn login). A panic in either write used to reach the recovery middleware, which answered HTTP 500, a status a wrong credential never gets. It also skipped the lockout count and the audit event. The panic is now handled exactly like the same write failing with an error: the wrong-credential 401, the attempt counted toward the lockout and the per-IP limit, the same audit event (`auth.login_error`, or `mfa.error` for the TOTP mark), and no session. A session row written before the panic is deleted and its token is never returned, and a TOTP code accepted before the panic stays used. Guarded by `server/faultops` `TestPostVerdictWritePanic_AnsweredLikeItsError` and by panic subtests that run through the production recovery middleware.
- **A panic in a login's identity read no longer reveals that the credential was correct (#3267).** On `/auth/mfa/verify`, `/auth/login` and WebAuthn login (second factor and passwordless), the user's roles and permissions are read after the credential has matched. A panic in that read used to reach the recovery middleware, which answered HTTP 500, a status a wrong credential never gets. It also skipped the lockout count and the `auth.login_error` audit event. The panic is now handled exactly like the same read failing with an error: the wrong-credential 401, the attempt counted toward the lockout and the per-IP limit, `auth.login_error` audited, and no session. A TOTP code accepted before the panic stays used. Guarded by `server/faultops` `TestPostVerdictIdentityReadPanic_AnsweredLikeItsError` and by panic subtests that run through the production recovery middleware.
- **Setting a member's roles is judged on every requested role.** `PUT /api/v1/projects/{id}/members/{userId}` and `PUT /api/v1/users/{id}/roles` used to check the granter ceiling only on roles the request added, so a caller who may not grant a role got 200 when the target already held it and 403 otherwise, which revealed the target's roles. Now a caller who may not grant a requested role gets 403 whatever the target holds, including for a request that changes nothing or only removes other roles. See `docs/UPGRADING.md`.
- **A loose Shamir share file is refused when it is read.** A `shamir_share_files` file that fails the secretenv owner + mode rule now refuses the unseal unconditionally, like `shamir_share_env` + `_FILE` and the file KEK provider, judged on the descriptor that is read. **Upgrade note:** a loose share file that only warned in the warn or ADR-112 grace modes now stops the server from booting; fix it with `chmod`/`chown` before upgrading (docs/upgrading.d/shamir-share-file-refused.md). Guarded by `TestShamirKeyProvider_ShareFileRefusedAtRead`.
- **Server, operator, MCP and k8s-sync images now build with Go 1.27.3, and the web image upgrades `libx11`.** The four Go Dockerfiles still pinned `golang:1.27.2-alpine` after `go.mod` moved to `toolchain go1.27.3`; the official golang images set `GOTOOLCHAIN=local`, so the binaries were compiled with 1.27.2 and the docker-publish Trivy gate failed them on HIGH CVE-2026-111943. The `keyorix-web` image pins `libx11>=1.8.14-r0` (CVE-2026-88806, HIGH) on top of the pinned nginx base. A new deploy test fails when a Dockerfile's golang tag differs from the `go.mod` toolchain.
- **Go toolchain bumped from 1.27.3 to 1.27.4 (GO-2026-6859).** The stdlib `net/http` HTTP/1 server race in `MaxBytesReader` (it sets `Connection: close` without synchronization, racing with a handler writing headers; CVE-2026-97054) is reachable from our SAML ACS path (`CompleteSAML` -> `PostFormValue`) and is fixed in go1.27.4. `go.mod`, `operator/go.mod`, the devtools modules, every CI workflow `go-version` and the fuzzing CT script now pin 1.27.4. No `docs/govulncheck-exceptions.d/` row was added: the bump is the fix.
- **`govulncheck` can now carry a documented, ID-scoped exception for a reachable finding with
  no upstream fix.** A bare `govulncheck ./...` had no exclusion mechanism, so the day
  `GO-2026-6909` (`crewjam/saml`, no fixed version) was published, `static-analysis` — and
  `build-and-test` behind it — went red for every PR and the merge queue with no way to land
  anything. `scripts/ci/check-govulncheck.sh` now decides pass/fail itself (`govulncheck -format
  json` always exits 0): any other reachable finding still fails exactly as before, and a
  reachable finding only passes when `docs/govulncheck-exceptions.d/<ID>.tsv` carries a dated row
  naming the confirmed mitigation and an expiry for re-review (`docs/govulncheck-exceptions.d/
  README.md`). Added the first (and so far only) row: `GO-2026-6909` — both halves of the
  advisory (the nil-`Issuer` panic in `validateAssertion`, and the namespace-blind
  `Subject.NameID`) are already mitigated at Keyorix's only SAML call site
  (`internal/saml/provider.go`'s `parseResponseRecovered` and `strictAssertionShape`), each with
  an existing, currently-passing test. `GO-2026-6865` (`klauspost/compress`, fixed in v1.20.2)
  needs no row — it is fixed by a dependency bump, not by this mechanism.
- **SAML: `github.com/russellhaering/goxmldsig` bumped to v1.6.1 (GHSA-qhrp-hfff-vphr, traversal limit in `etreeutils.NSDetatch`).** Behaviour change: a SAML response with more than 1000 XML elements in total is now refused at the ACS endpoint (logged as `saml: response has more than 1000 elements`, the login fails with the usual SSO error). A typical response is about 50 elements plus one per group value, so this only affects an IdP that sends roughly 950 or more group values in one assertion; such users must have their group claim filtered at the IdP. The etree stack-overflow fix that v1.6.1 also pulls in (GHSA-qm2r-qg5g-crr3) was already in place through etree v1.8.1.
- **Roles carry an assignable scope (#3546, Phase 2).** Where a role may be granted is now a property of the role (`assignable_scope`: `global`, `project` or `any`), not its name. Built-in `project_*` roles are `project` (only with a `project_id`), `system_*` roles and `alert_operator` are `global` (only without one), and the legacy `admin`/`editor`/`viewer`/`auditor`/`super_admin` roles are `any`, so granting them per project keeps working exactly as before (for example `keyorix machine grant-role <name> --project default --role viewer` or `keyorix rbac assign-role --user <email> --role admin --project payments`), as does granting them install-wide. **A new custom role is `project` by default**, so a grant of it without a `project_id` is refused with HTTP 400 / gRPC `InvalidArgument`; an administrator can widen it to `any` or `global`. Custom roles that existed before the upgrade are set to `any`, so nothing that worked before breaks. A scope change never changes existing grants, and widening a role's scope is recorded like adding a permission (refused while the audit log is down).
- **A system role offered on one project is refused.** `system_admin`, `system_auditor`, `system_viewer` and `alert_operator` granted with a `project_id` (user and group grants, project members, project invitations, access-request approval, user creation with project assignments via `POST /users` or gRPC `CreateUser`, project membership invites) now get 400 instead of a grant that applied only to that project or a 500.
- **Every grant route answers a scope refusal with 400.** Project member add/role change, access-request approve (single and bulk), break-glass, membership invite/transition and project invitations used to return 500 for it. SSO/SAML sign-in shows "ask your administrator to fix the provider's default_role".
- **SSO JIT provisioning checks `default_role` in the same transaction that grants it, and fails closed.** If the role cannot be read, or is not assignable install-wide at that moment (for example an administrator just narrowed it to `project`), the new user's sign-in is refused and nothing is written.
- **SSO JIT provisioning with a project role as `default_role` refuses every NEW user** of that provider at sign-in (existing users are not affected) until `default_role` names a role assignable install-wide, e.g. `system_viewer`. The startup warning names each such provider, now including custom roles.
- **Accepting an old invitation that grants a project role install-wide** fails before the account is created and before the link is used up; the startup warning lists these pending invitations so they can be revoked and re-sent.
- **A failed `PUT /users/{id}/roles` no longer drops a legacy grant**: the undo of a partial update restores a pre-#3546 global project-role grant it had removed.
- **Review after upgrading.** The startup `WARNING` now lists every existing grant held at a scope its role does not allow (a project role held globally, or a system role held at a project), and pending invitations that can no longer be accepted. Nothing is changed or deleted automatically.

- **A role update that leaves out `assignable_scope` keeps the stored scope**, so it can no longer undo a narrowing another administrator made at the same time.
- **A project role granted without a project no longer applies in every project (#3546, High).** A grant of `project_admin`, `project_developer`, `project_viewer` or `project_auditor` with no `project_id` was stored at the global scope, where it applies in EVERY project. The web UI's group *Manage Roles* sent exactly that, so a group member could become a developer of every project. Every grant path now refuses it with HTTP 400 / gRPC `InvalidArgument` ("role project_developer is project-scoped; specify a project_id"): user and group grants (permanent and time-bound), `PUT /users/{id}/roles`, user creation and global invitations with a project role as `role`, access-request approval, break-glass, machine-identity grants, and SSO JIT provisioning. An `environment_id` without its `project_id`, or one from a different project, is refused the same way. Global grants of `system_*` and the legacy `admin`/`editor`/`viewer` roles are unchanged, and so are custom roles, whatever their name.
- **Review existing grants after upgrading.** Grants written before this release are left as they are, because some may be relied on. At startup the server logs a `WARNING` for each user or group that holds a project role at the global scope. For each one, grant the role on the intended project(s), then remove the global grant. Any API client that has been granting project roles without `project_id` now gets 400 and must send the project.
- **SSO: project roles in `default_role` / `group_role_map` are refused.** Both settings grant at the global scope. With a project role as `default_role`, JIT provisioning through that provider is refused until it names a system role (for example `system_viewer`). A project role in `group_role_map` is not granted, but the login still goes ahead and the `auth.sso_roles_synced` audit event records the refusal. The server logs a startup `WARNING` for each such setting. To give an IdP group project access, map it to a Keyorix group that has a project-scoped role grant.
- **A replica booting from another key directory no longer discards an interrupted DEK rotation's new key.** With several key directories on one PostgreSQL database (`key_dir_lock: database`, the Helm chart's Secret mode, a key copy per host), a server that started between a rotation's sweep commit and its `dek.key.pending` rename cleared the rotation's redo marker; the next recovery in the rotating directory then deleted the pending file, the only copy of the DEK every row was under. The marker is now kept unless this directory promotes the pending DEK or the DEK epoch proves it already holds the new one (`INV-ENCRYPTION-redo-marker-kept-for-the-pending-keydir`).
- **BREAKING: a pinned `KEYORIX_BOOTSTRAP_TOKEN` must be at least 32 characters.** The server refuses to start when `KEYORIX_BOOTSTRAP_TOKEN` (or `KEYORIX_BOOTSTRAP_TOKEN_FILE`) holds fewer than 32 characters: `KEYORIX_BOOTSTRAP_TOKEN too short (min 32 characters): generate one with: openssl rand -hex 32`. The token authorises claiming the first admin over `POST /system/init`, so a short phrase on a fresh, reachable server was a guessable admin seizure. Unset is unchanged (the server generates a 256-bit token). The smoke / web-e2e / release-QA scripts now generate the token with `openssl rand -hex 32`. See docs/UPGRADING.md §6g.
- **Bootstrap-token and metrics-token guessing is throttled.** `POST /system/init` (before the system is initialised) and `GET /metrics` (with `metrics_token` set) accepted unlimited wrong tokens. Per client IP, 5 wrong bootstrap tokens (then one per 30s) and 10 wrong metrics tokens (then one per 6s) are allowed before the route answers `429` without checking the token. Correct tokens never spend the budget, so Prometheus scrapes and idempotent init calls are unaffected.
- **Request bodies are capped per route class.** The unauthenticated credential routes (`/auth/*`, `/system/init`) now accept at most 64 KiB (the SAML ACS 1 MiB) instead of the 10 MiB API default, and raising or disabling `server.http.max_request_body_bytes` no longer lifts those caps. A body whose `Content-Length` is over its route's cap is answered `413` with the standard JSON error body before authentication or any handler runs (handlers used to see the truncated body and mostly answered `400`).
- **No internal error text in 5xx responses.** Bulk delete/rename/rotate, owner reassignment and the secret-dependency endpoints sent the underlying error's text (storage or driver messages) on their 500 branch; a 5xx now carries only the generic message and the error is logged. Every `sendError` call in the handlers is checked for this in CI.
- **Uniform error responses.** The router's own 404 (unknown API paths, missing static assets), 405 and the `/metrics` 401 now return the JSON error body with `Cache-Control: no-store` instead of `text/plain` or an empty body; a missing static asset's 404 is no longer marked cacheable for a year.
- **Every listener now bounds its connections.** REST/web: request headers capped at 64 KiB (was net/http's 1 MiB, 431 above it), and the response write deadline is now longer than the 60s handler deadline, so a timed-out request gets its 504 instead of a reset connection. gRPC: a new connection must finish its handshake within `server.grpc.keepalive.handshake_timeout` (default 10s, grpc-go's own default was 120s), a connection with no RPC in flight is closed after `server.grpc.keepalive.max_connection_idle` (default 15m, was never), at most 128 concurrent RPCs per connection (was unlimited) and 64 KiB of metadata (was 16 MiB). The `keyorix-k8s-sync` probe listener sets read, write and idle timeouts and a header cap. Neither new key can be set to 0 to switch the bound off.
- **TLS certificates rotated on disk are picked up without a restart.** Both the HTTP and gRPC listeners loaded the cert/key pair once at start and served it until the process restarted, so a renewed certificate (cert-manager, ACME, manual rotation) was not used and the old one could expire in service. The files are now re-checked at most every 30 seconds during handshakes; a rotated pair that does not load (half-written, key mismatch) is logged and the previous pair keeps being served.
- Helm chart (low): the web pod's `/health`, reachable through the public ingress, no longer proxies the server's `/health` body (rate-limit state, uptime, other detail) to unauthenticated callers. It answers a fixed `200 ok` or `503 unavailable` driven by the backend's health (#3910). Probe paths are unchanged: liveness `/nginx-health`, readiness `/health`.
- **The backend sends HSTS behind a trusted TLS-terminating load balancer.** `keyorix-server` now sends `Strict-Transport-Security` when the request's TCP peer is in `server.http.trusted_proxies` and says `X-Forwarded-Proto: https`, as well as when it serves TLS itself. It reuses the trust check that already governs `X-Forwarded-For`. It never sends HSTS for plain http, and a client outside `trusted_proxies` cannot turn it on by forging the header. The web nginx is unchanged: it keeps its own HSTS decision and strips the backend's header. See docs/CONFIGURATION.md ("Strict-Transport-Security"). Guarded by `INV-MW-hsts-only-over-tls-or-trusted-proxy`.
- **SCIM deactivation sent as a string is applied, not silently ignored.** Microsoft Entra ID sends `active` as the string `"False"` (`{"op":"Replace","path":"active","value":"False"}`); the strict boolean decode dropped it, the PATCH answered 200 and the user stayed active with its PATs and sessions. PATCH (path and path-less forms), PUT and POST now accept a JSON boolean or `"true"`/`"false"` in any case, and answer `400 invalidValue` for any other `active` value instead of a 200 that changes nothing.
- **Image and dependency bumps for the nightly trivy gate.** `golang.org/x/net` is now v0.62.0 in the root module, `operator/` and `migrate/` (CVE-2026-78661, HIGH, `x/net/html` denial of service), which clears the finding in the server, airgap and operator images. The web image's `apk add --upgrade` floors gain `brotli-libs>=1.2.1-r0` (CVE-2026-111497, CRITICAL), `curl` and `libcurl>=8.23.0-r0` (CVE-2026-92392) and `musl-utils>=1.2.6-r3` (CVE-2026-107891), and the floor list is now sorted by package. The nightly `docker-publish` trivy gate, which has failed on main since 2026-11-02, is expected to pass after this merges; that is confirmed only by the next nightly run.
- **`offline-install.sh setup --postgres-dsn` refuses a password in any letter case.** `Password=`, `PASSWORD=`, `pwd=`, `passwd=` and the URL forms (`user:password@`, `?Password=`) are refused like `password=`; the password goes in `secrets/db_password`. Guarded by `TestOfflineInstallRefusesPasswordInPostgresDSN`.
- **A share revoke can no longer be undone by a concurrent re-share, and a time-bound share that loses the create race keeps its expiry (#2801, #2802).** `CreateShareRecord` used to persist the share it had read with a full-row `Save`, so a revoke committed between its lookup and its write was reverted (the same row live again with the re-share's permission), and its unique-violation fallback dropped the caller's `ExpiresAt`, turning a 1-hour share permanent. Both paths now write `permission`, `expires_at` and `updated_at` through one conditional helper (`WHERE id AND deleted_at IS NULL`); if the share was revoked meanwhile the lookup is re-run once, and otherwise the call fails closed with "share not found" (retry to grant again). Guarded by `TestCreateShareRecord_IsColumnScoped` and race tests on SQLite and Postgres.
- A credential with no role grant reads no tenant data on any REST GET route, now
  checked rather than assumed: a route walk over the live router (every GET route,
  every path parameter bound to canary objects, SQLite and Postgres) asserts it for a
  fresh machine identity, a user with every role removed and that user's PATs, and a
  machine identity whose only grant was just removed (cached token reused). No route
  leaked on main. A fresh machine identity listing projects gets 200 with an empty
  list (deliberate since #2780), not 403; the SDK contract suites that expect 403 are
  out of date (MACHINE-IDENT-DENY-1).
- **Behaviour change for upgraded installs: the `security.require_mfa` grace period now ends** (#2923, ADR-112 Amendment 5). An upgraded deployment whose config never set `require_mfa` used to stay unenforced forever. The grace period now ends at the first administrator MFA enrolment (TOTP or passkey) or 30 days after the first start on this release, whichever comes first, while the server runs. After that, users without a second factor are sent to MFA enrolment when they sign in (not locked out; PATs and machine credentials are unaffected; break-glass is unchanged). The start is stored in `system_metadata` (`adr112.require_mfa.grace_started`), never derived from the clock alone, and a clock set back cannot extend it. Any value that cannot be read fails closed (MFA enforced). Until then the web UI shows a persistent banner with the days left, `keyorix login` warns, the server logs a WARN line with the days left, and `admin validate --posture` names the end date. If an administrator already has MFA, enforcement starts at the first start on this release. To enforce at once set `require_mfa: true`, or set `false` to opt out visibly. See docs/UPGRADING.md "MFA after an upgrade".
- `keyorix-migrate vault plan-access` / `apply-access` / `audit-access` no longer report a `--path-map` scope as equivalent to a Vault policy when another KV mount holds paths the default convention names into that scope: with `--path-map secret/data=<id of team-a>:<id of dev>`, `kv1/team-a/dev/x` lands in team-a/dev by name, so a grant there reached it although the policy never allowed it. Such a policy is now unmappable (`cross-mount-scope`), the report prints the other mount's path, and `apply-access` re-checks it. A mount that cannot be listed counts as holding the path. Mapping the other mount's paths to their own scope with `--path-map` clears it.
- The same check covers the policy's own mount: with `--path-map secret/data/legacy=<id of team-a>:<id of dev>`, `secret/team-a/dev/x` is outside `secret/data/legacy/*` but lands in team-a/dev by name, and the evidence called that directory "policy mount". It is now judged like any other mount (`secret/team-a/dev/: present (policy mount, outside the policy)`) and the policy is `cross-mount-scope`.
- **Notification channel URLs are now treated as the bearer credentials they are (#3425, #3426).** A webhook/Slack/Teams channel URL carries its token in the path. A failed delivery used to log and return the full URL (`url.URL.Redacted()` masks only userinfo), including through the wrapped transport error and the recover-admin alert broadcast; errors now name the destination by scheme and host only, and the same applies to the URL-parse error shown for a rejected channel URL. **API change (user-visible, contract v2):** `GET /api/v1/notification-channels` and `GET /api/v1/notification-channels/{id}` no longer return the channel URL to `alerts.write` callers. `url` is now scheme+host with the path elided (e.g. `https://hooks.slack.com/…`), and a new boolean `url_set` says whether one is stored. The full URL is returned exactly once, in the `POST /api/v1/notification-channels` response; the `PUT` response is the elided shape too. A `PUT` that omits `url` keeps the stored URL, and an explicit `url` replaces it. A `PUT` (or create) whose `url` is the elided form (ends in `/…`, e.g. echoed back by a GET-then-PUT client or a cached old web UI) is rejected with a 400 and changes nothing, so the stored credential is never overwritten by the display form. Scripts that read `url` back from list or get to reuse the credential must keep the value from the create response instead (the `keyorix notification channel` CLI prints the elided form until its next release). The web edit form no longer prefills the URL: leave it blank to keep the current one.
- **An expired federated OIDC / Kubernetes-JWT token no longer keeps authenticating from the auth cache.** The server cached a verified JWT's login for up to ~30 seconds without regard to the token's own `exp`, and cache hits do not re-verify the token, so a token kept working for up to ~30 seconds after it expired. The cache entry now ends at the token's `exp`, and a token that is already expired, within 5 seconds of expiring, or reports no `exp` is not cached (it is re-verified on every request). Tokens expiring later than the 30-second window behave as before. No configuration change. Guarded by `INV-MW-oidc-cache-capped-at-exp` and `server/middleware/oidc_cache_expiry_cap_test.go`.
- **A PostgreSQL CA that the connection would never check is refused.** With `ssl_mode: allow`
  or `prefer`, the driver loaded `storage.database.ssl_root_cert` (or a dsn's `sslrootcert`) but
  skipped certificate verification and could still fall back to plaintext, so a config naming a
  CA looked authenticated and was not. The server now **refuses to start** on a CA file with
  `ssl_mode` `disable`/`allow`/`prefer`, in the fields and in a `dsn` (a dsn with no `sslmode` is
  `prefer`), and on `sslrootcert=system` with `disable`. `system` with allow/prefer (the driver
  runs verify-full) and a CA with `require` (the chain is verified) are unchanged. The Helm chart
  fails the render on the same `externalDatabase.sslRootCert` shapes. New walk-through:
  docs/operator/postgres-tls.md (private CA, verify-full, wrong-CA check). **Upgrade note:** a
  config with a CA and `ssl_mode: prefer`/`allow` must switch to `ssl_mode: verify-full` (or drop
  the CA) before upgrading.
- **Updated `jackc/pgx/v5` to v5.13.0 (from v5.11.0).** The update fixes a panic in
  `Rows.Values()` when a PostgreSQL server sends a DataRow with fewer values than its
  RowDescription declares (GHSA-w9rp-vfrh-q8vv, low: a malicious or compromised database server,
  or an on-path attacker without TLS, could crash a client that calls `Values()`). It also takes
  in the v5.12.0 fixes for `require_auth` / `channel_binding=require` being bypassable
  (GHSA-95fj-3fxw-g62g) and for SQL injection in simple-protocol batches (GHSA-j38q-h3ph-jjpq;
  Keyorix uses the extended protocol).
- **The server's own PostgreSQL client certificate is still never offered to a project
  `admin_dsn` target.** pgx v5.12.0 and later install the `sslcert`/`sslkey` (and default
  `~/.postgresql/postgresql.crt`, `PGSSLCERT`) certificate through a private loader that
  emptying the TLS config no longer stops, so the admin-DSN parse now also sets
  `sslcertmode=disable`. `TestPostgresEngineNeverPresentsTheServersDefaultClientCert` covers it.
- pgx v5.12.0 added `Tx()` to `pgx.BatchResults`; the audit-chain pipeline results reader
  implements it by returning nil, as it never begins a transaction through `pgx.Batch.BeginTx`.
- **`admin validate --posture` no longer overstates the integrity tier.** A release-manifest match whose signature is not verified (any `checksums.txt.sig`, `.sigstore.json` or `.bundle` file, even empty, unlocked the comparison) now prints `ok (signature not verified)` and does not count toward tier 3, which is fs-verity only. `tpm-sealing` prints `ok (weaker fallback configured: <kind>)` and does not count toward tier 5 when a fallback weaker than a TPM is configured. Guarded by `internal/integrity` and `server/admin` tests; see `docs/security/integrity-posture.md`.
- New `keyorix-migrate vault audit-access` (read-only) lists Keyorix grants that `keyorix-migrate` v0.96.0–v0.96.3's `apply-access` created wider than their source Vault policy (a policy path narrower than the project/environment it was mapped to, or a stanza's `list` granted as `secrets.read`: `list`-only and KV v2 `metadata/` stanzas, and write stanzas that also list, such as `["create", "update", "list"]`) and that a migrated machine identity still holds, each with the API call that revokes exactly that grant; it exits 1 when it finds any, and also when the audit is incomplete because a Vault input could not be read or the Keyorix token cannot see every project (`--json` reports `complete: false`). Installs that ran `apply-access` with those releases should run it with the same flags (docs/UPGRADING.md §6y).
- `keyorix-migrate vault plan-access` / `apply-access` no longer turn a narrow Vault policy into a wider Keyorix grant. A policy path that covers only part of the Vault subtree mapped to a project/environment (an exact secret path, a deeper subtree, part of a `--path-map` prefix, or one of two `--path-map` entries into the same scope) is now Unmappable (`path-narrower-than-scope`) instead of a scope-wide grant, and KV v2 `metadata/` stanzas and `list`-only stanzas are Unmappable (`metadata-only`) instead of `secrets.read`. Shipped in v0.96.0–v0.96.3: installs that ran `apply-access` with those releases should check their migrated grants (see the release notes for the audit command). Found by the RD-SMT-SPIKE-1 SMT check.
- `keyorix-migrate vault plan-access` lists every KV mount's `<project>/` and `<project>/<env>/` keys (names only) and reports a default-convention policy as Unmappable (`cross-mount-scope`) when another KV mount holds paths in the same project/environment, or cannot be listed; previously `secret/data/team-a/prod/*` was granted on `team-a/prod` even when `kv1/team-a/prod/` secrets land there too. `apply-access` lists the tree again and applies nothing if it changed since the reviewed plan (plans written by earlier releases are refused: re-run `plan-access`), and a reviewed machine-role grant now only authorises the same grant in the same project/environment. `audit-access` reports such grants made by earlier releases.
- `plan-access` names every Vault policy whose migrated `secrets.read` grant also lets the identity list secret names and read version metadata that the Vault policy did not grant (no matching `metadata/` stanzas): "Access added beyond Vault" in the report, `implied_access` in the JSON plan. Never values; a documented residual in ADR-114.
- **A revocation's audit row is no longer silently lost when the owed-audit record is refused and the process then dies.** When `pending_audit_events` refused the record inside a revocation's transaction, the revocation still committed (it is never blocked by audit), but its owed audit rows lived only in memory until after the up-to-5 s append wait. A crash in that window lost them with no record and no log line naming them (found by the TLA+ model, `docs/formal/owed-audit/pendingfault_silent.cfg`). The record is now written right after the commit, before the append wait, so a crash at the append leaves it for the backfill. Every row that commits without its record is also named in a `SECURITY:` log line before the commit. What remains is loud and named in INV-CORE-revocation-audit-owed: a crash before that late record commits, or the pending table refusing it too and then a crash before the direct append.
- **Administrator MFA reset for a user who lost the authenticator and has no recovery code.** A local non-admin user had no supported reset. Two paths now exist, and both are a full credential reset, never "MFA off": the TOTP secret, recovery codes, WebAuthn credentials and step-up grants are removed, every session and personal access token is revoked, the password is replaced by a one-time password and the account is marked as owing a new MFA enrolment (`users.mfa_enrolment_required`). The audit rows commit in the reset's own transaction: if they cannot be written, nothing is reset.
  - `keyorix-server admin reset-mfa --user <name|email|id> --recovery-key -` on the server host: needs the key files, the recovery key and the exclusive database lock (refuses while the server runs). Audited as `admin.reset_mfa` / `admin.reset_mfa_failed`.
  - Online, two administrators: `POST /api/v1/mfa-reset-requests` (admin A), `POST /api/v1/mfa-reset-requests/{id}/approve` (a different admin B, returns the one-time password once), `.../cancel`, `GET /api/v1/mfa-reset-requests`. Both admins must be human global admins with a second factor, proven afresh for each step; neither may be the target. Self-approval is refused and audited, a request is single-use and expires after 24 h. Audited as `mfa.reset_requested`, `mfa.reset_approved`, `mfa.reset`, `mfa.reset_cancelled`; the user and every admin are notified.
  - Refused for global admins (use `recover-admin`), SSO/SCIM accounts, suspended or inactive accounts and machine identities. Schema epoch 8, floor unchanged (docs/UPGRADING.md). Runbook: docs/operator/lost-totp-runbook.md §4.
  - The account-setup gate reads `mfa_enrolment_required` (#3799): a reset user must enrol a new second factor before reaching any other endpoint, whether or not `security.require_mfa` is on. No `keyorix` CLI subcommand for the online flow yet.
- **A key directory mixed from two generations is refused at start-up (#2900, #2424).** The server keeps `keyset.manifest.json` next to the DEK: a SHA-256 and a generation number for every key file (salt, wrapped DEK, KMS/TPM blob, Shamir shares), updated by first boot, `rotate`, `rotate-kek`, `migrate-provider` (and its rollback) and `restore`. Every start compares the files with it and refuses one that matches neither its recorded nor a staged hash, naming it — including a set assembled with plain `cp`, where every modification time is identical. The best-effort modification-time heuristic it replaces is removed. A restore interrupted between its file installs is refused instead of booting into a decrypt failure: `admin restore` installs the manifest as one more entry of its restore journal, after the key files, so `admin restore --recover` installs or discards it with them, and while the journal exists the server names `--recover` before any key-set check. The hashes are not keyed: this catches accidents, not someone who can already write the key directory.
- **An interrupted `rotate-kek` is finished at start-up.** When `rotate-kek` stopped after replacing the DEK but before the salt (the DEK no longer unwraps under the on-disk salt, which used to surface as "wrong passphrase"), the server completes the rename from `kek.salt.pending` once the manifest proves it holds the staged salt, logs a WARN and records an `encryption.keyset_rotation_finished` audit event; the master passphrase is then the new one. A rotation interrupted before it changed any active file only logs that its staging files can be deleted.
- **`admin restore` installs key files and data together or not at all (restore journal).** With `--overwrite-existing`, restore used to install the archive's key files before loading the data. A load that then failed left the live install with the archive's keys and its own rows: on PostgreSQL over any populated database (duplicate key), and on either backend whenever the load's mandatory checks refused. After a DEK rotation, existing secrets no longer decrypted. Now the key files are staged next to their targets and installed only after the data has committed: on PostgreSQL in one transaction, which also empties the target's tables so an in-place restore over a populated database works; on SQLite into a staged database file installed with the keys. A failed restore leaves the live keys, rows and audit trail unchanged. A restore killed after the commit point leaves `.keyorix-restore-journal.json`. Until the new `admin restore --recover` finishes the restore (data committed) or undoes it (not committed), the server, `admin backup` and new restores refuse to run. Sequence resync inside the load transaction never lowers a sequence. See `docs/operator/restore-failure-modes.md`. Guarded by `TestAdminRestore_Overwrite_*` (both backends, including kill points) and `TestVerifyKeyFileSetConsistency_RefusesWhileRestoreJournalExists`.
- **`admin restore --recover` refuses a staged key file it cannot vouch for.** Before the restore journal is written, every directory holding a staged file is now fsynced, and the journal records the SHA-256 of each staged file. Recovery checks every entry before renaming anything: a staged file lost to power loss counts as installed only if the live file is the restored one, and a staged file whose content changed is never installed. Otherwise recovery refuses, keeps the journal and changes nothing, instead of pairing the restored data with the old keys. Recovery also refuses a journal whose rollback-protection witness path is not the deployment's own. Staged files orphaned by a restore killed before its journal was written are removed by the next restore or `--recover`. The journal records absolute paths and an `installed` phase. See `docs/operator/restore-failure-modes.md`.
- **Dynamic-secret `admin_dsn` host check now covers every host the driver dials.** The register-time private-network/IMDS check read the DSN one way and pgx, the MySQL driver or the MongoDB driver another: a repeated, quoted or space-separated `host=`, a `?host=` query parameter, a percent-encoded URL host, an `@` in the wrong place or `@tcp(` inside a MySQL password let the check approve a public host while the driver connected to a different one. The dial-time guard still refused those connections; the check at registration now refuses them too. A DSN whose *password* happens to look like a private address can now be refused at registration; move the credential out of the DSN or percent-encode it.
- **A corrupted PAT scope or CIDR column no longer widens the token.** A stored `null`, `[]` or blank entry (never written by Keyorix) decoded as "no restriction"; it now denies, like an unreadable column already did.
- **`recover-admin` refuses a recovery key that is not well-formed** (52 symbols of the key alphabet) before comparing hashes, so a damaged recovery-key record cannot be satisfied by an empty or short key.
- **A wiped encryption service refuses to encrypt or decrypt.** After DEK rotation or shutdown, the discarded service's AES key schedule could still be used through a lingering reference; it now returns an error.
- **Key-changing admin commands finish an interrupted DEK rotation instead of destroying it.** After `admin encryption rotate` was killed between committing its re-encryption sweep and renaming `dek.key.pending`, `upgrade-aad`, `rotate-kek`, `migrate-provider` and `auth-encryption rotate`/`migrate` deleted, overwrote or wrote around the pending new DEK, making every re-encrypted row undecryptable. They now take the exclusive key lock and run the same crash recovery as server start-up first. A rotation whose final rename fails, or whose database COMMIT returns an error, now keeps `dek.key.pending` for that recovery instead of deleting it.
- **Admin encryption commands no longer create keys when the key files are missing.** Every command except `admin encryption init` used to generate a new salt and DEK when `dek_path` did not resolve (run from the wrong directory, a wrong path, an unmounted volume); `rotate-kek` and `migrate-provider` then reported success on those new keys. They now refuse with the resolved path and create nothing. `upgrade-aad` and `auth-encryption migrate` now take the key lock exclusively.
- **`admin encryption shamir-split --out-dir` never overwrites existing share or commitment files.** It refuses before generating a KEK when any target exists.
- **The rolling-upgrade database triggers (#3359, #3362) are re-enabled as ENABLE ALWAYS at every start-up**, like the other Keyorix triggers, so one left ordinary by `pg_restore --disable-triggers`, replica-only or disabled is repaired.
- **`migrate-provider --to-type shamir` now requires `--to-shamir-commitment`.** Without it, someone holding threshold-1 shares could forge one more share and get the DEK wrapped under a KEK they chose (#429). Pass the commitment that `shamir-split` printed. A blank `shamir_commitment` in the config now counts as unset: the start-up warning and posture report it, and the provider logs the #429 warning. A commitment of the wrong length is refused with an error that says so.
- **`admin encryption auth-encryption` enable/rotate/migrate/validate refuse when `storage.encryption.enabled` is false.** Before, migrate wrote plaintext reset tokens into `encrypted_token` and called them migrated. Validate reported every check passed, and `enable --force` reported (and audited) an enablement that never happened. These commands now also report why a `--passphrase-file`/`--passphrase-fd` was refused, instead of "master passphrase must not be empty".
- **`rotate-kek` names leftover `<dek_path>.migrate-backup.*` files.** Each one is the DEK wrapped under an older KEK, so the old passphrase still unwraps it. Run `migrate-provider cleanup --confirm` if you rotated because the old passphrase leaked. With a non-password key provider, `rotate-kek` now refuses up front and points at `migrate-provider`.
- **The read cache no longer trusts a PostgreSQL session that skips triggers (#3361).** With `session_replication_role = replica` (Helm `postgresql.settings`, `ALTER ROLE/DATABASE ... SET`, a DSN option or an operator's session) the `secret_nodes` cache-epoch trigger did not fire, so a suspended secret could keep reading as active. The trigger is now `ENABLE ALWAYS` (converged at start-up), the cache trusts its stamp only for an `ENABLE ALWAYS` trigger on an `origin` session, the server (and the DEK-rotation admin command) refuses to start unless `session_replication_role` is `origin`, and the Helm chart refuses `postgresql.settings.session_replication_role`. Upgrade note: a database or role with a non-`origin` default must have it removed before the new server starts.
- **Postgres rotation no longer depends on `standard_conforming_strings`.** The PostgreSQL rotation backend now sends the new password as an `E'...'` string with backslashes and quotes doubled. Before, on a server, database or role with `standard_conforming_strings = off`, a value passed to on-demand rotation (`secrets.write`) that contained `\'` could end the literal and run further SQL as the backend's admin DSN. Default Postgres settings were not affected. Guarded by `TestQuoteLiteral_SafeWithStandardConformingStringsOff` and the real-server `TestQuoteLiteral_StandardConformingStringsOff_Postgres`.
- **Rotation `allowed_refs` treats non-ASCII letters as part of a name.** An entry such as `myapp` no longer admits `myappé_admin` (a byte above 0x7F used to count as a segment boundary, unlike `myapp2`, which was already refused). Applies to the postgresql, mysql and azure-app backends. If you relied on a non-ASCII character as the delimiter, add an ASCII delimiter (`myapp_`) or list the exact name.
- **CSV exports neutralise line-feed and full-width formula triggers.** Cells that begin with a line feed or with the full-width `＝ ＋ － ＠` now get the leading `'`, like `= + - @`, TAB and CR already did (OWASP's CSV-injection list). Affects every server CSV export (audit, machine audit, inventory, access review, compliance). Guarded by `TestNeutralize_OWASPTriggerList`.
- **Best-effort step failures are logged on one line.** The `best-effort step ... failed` and `SECURITY: best-effort step ... panicked` log lines now quote the error or panic text, so a newline in it (for example from an SMTP or webhook reply) can no longer forge a separate log line. Log searches for the step name are unaffected; the message text is now in Go-quoted form.
- **The server process is now non-dumpable on Linux.** `RLIMIT_CORE=0` alone did not stop core dumps on hosts whose `kernel.core_pattern` pipes to a handler (systemd-coredump, apport; containers inherit the host setting): the kernel does not apply the limit to piped dumps, so a crashing server's memory still reached the handler. The server now also sets `PR_SET_DUMPABLE=0` at startup. This also stops same-user processes without `CAP_SYS_PTRACE` from attaching a debugger or reading the server's `/proc/<pid>/mem` and `environ`; to debug a live server, run the debugger as root or with `CAP_SYS_PTRACE`.
- **Usernames and role names are validated where they are chosen.** Creating or renaming a user now requires an ASCII username (letters, digits, space, `.`, `_`, `@`, `+`, `-`) with no leading, trailing or repeated whitespace, and `CreateRole` applies the project-name identifier rule on every transport (gRPC previously checked only length). Fullwidth, no-break-space and padded look-alikes of an existing name can no longer be created as a separate principal. Login, lookup and token validation are unchanged, so existing accounts and roles whose names fail the rule keep working; SCIM and SSO/SAML just-in-time provisioning still normalize IdP names to `[a-z0-9]` and are not affected.
- **Warning when SCIM and SSO JIT provisioning are enabled together.** Accounts JIT-created by SSO (`external_id` `sso:<provider>:<sub>`) are not SCIM-managed since #3493, so SCIM does not deactivate them and their PATs and sessions survive until expiry. When `scim.enabled` and an enabled SSO provider with `auto_provision` coexist, the server logs a `SECURITY:` line at start, `keyorix-server admin validate` lists it under warnings, and `GET /api/v1/system/info` carries `security.scim_jit_unmanaged_warning`. The ownership rule is unchanged. See `docs/security/threat-models/scim-and-sso-accounts.md` (SCIM-7).
- **`scripts/k8s-e2e/run.sh` (J6) no longer passes the master, admin and database passwords to `helm` with `--set`** (visible in `ps`); they come from a 0600 values file via `-f`, like the other k8s-e2e installs. `TestDocsShowNoLiteralSecretOnCommandLine` now also fails on `helm --set`/`--set-string` with a credential key (password, token, secret, passphrase, apiKey; `existingSecret`/`secretName` references are fine) and on `kubectl --from-literal` with a credential key, in `scripts/**/*.sh` and `deploy/**/*.sh`.
- **Script credentials stay off jq argv.** `scripts/airgap-e2e.sh` built its login, `/system/init` and secret-create payloads with `jq --arg` (admin password, bootstrap token and secret value in jq's argv, visible in `ps`); the values now reach jq through its environment (`env.X`) and the payload files are unchanged. The no-secrets-on-command-line guard (`cli/cmd/docs_no_literal_secrets_test.go`) now flags `jq --arg`/`--argjson` whose name or `$VARIABLE` value says it carries a credential in `scripts/**/*.sh` and `deploy/**/*.sh`.
- **The DAST stack's server config no longer says `ssl_mode: prefer`.** `scripts/dast/keyorix-dast.yaml` now states `ssl_mode: disable` with a comment: that stack's PostgreSQL is stock `postgres:15-alpine` with no TLS and no CA, so verify-full is not possible there, and an explicit plaintext setting is reported honestly as `storage.database.insecure_disable_database_tls` instead of a silent plaintext fallback.
- **Shell scripts no longer put secrets on a command line.** `scripts/smoke.sh`, `scripts/release-qa/*`, `scripts/k8s-e2e/run.sh`, `scripts/demo/vault-migration-demo.sh` and `scripts/demo-keyorix.sh` passed admin/login passwords, MFA codes, bootstrap tokens, secret values and Vault/PAT tokens as flags (visible in `ps` and CI logs). They now use `KEYORIX_*` environment variables, `--from-file`, a stdin pipe, `keyorix-migrate`'s `VAULT_TOKEN`/`KEYORIX_TOKEN`, curl `-H @file` / `--data-binary @-`, `docker --env-file`, and helm `-f` values files. `TestDocsShowNoLiteralSecretOnCommandLine` now also scans `scripts/**/*.sh` and `deploy/**/*.sh` (no allowlist), so a secret flag in a script fails CI.
- **Shell scripts no longer put bearer tokens, login JSON or container secrets on an argv.** `scripts/airgap-e2e.sh`, `docker-webui-embedded-check.sh`, `demo/up.sh`, `demo/check.sh`, `dast/*.sh`, `e2e/web-real-smoke.sh`, `vault-migration-testbed/seed.sh`, `fuzzing/nightly-cross-replica.sh` and `pgbouncer-matrix.sh` passed `curl -H "Authorization: Bearer ..."`, `X-Vault-Token`, `X-Keyorix-Bootstrap-Token`, `curl -d '{"password":...}'` and `docker run -e *PASSWORD/TOKEN=...` (visible in `ps` and CI logs). They now use `-H @file` (0600), `--data-binary @-`, `docker --env-file`, and (inside the air-gapped container) a token read from `exec -i` stdin. `TestDocsShowNoLiteralSecretOnCommandLine` now also fails on those shapes in `scripts/**/*.sh` and `deploy/**/*.sh`; its header lists what it still does not see (variable-held headers/bodies, helm `--set`, `--from-literal`, interpreter argv).
- **Script secrets stay off curl argv when the body sits in a variable.** `scripts/vault-migration-testbed/seed.sh` sent every Vault request body (user passwords, secret values) as `curl -d "$body"`; it now pipes the body to `--data-binary @-`. The no-secrets-on-command-line guard (`cli/cmd/docs_no_literal_secrets_test.go`) now flags `curl ... -d "$var"` (flag and variable on any line of a continuation) in `scripts/**/*.sh` and `deploy/**/*.sh`; the three ntfy alert senders opt out with a reasoned `docs-secrets:allow` marker.
- **Notification-channel webhooks can no longer target the Keyorix host through 0.0.0.0.** The channel SSRF guard refused loopback but not the unspecified address, which Go dials as the local system: a channel URL of `https://0.0.0.0:<port>/…` or `https://[::]…`, or a hostname that resolves to 0.0.0.0 when an alert escalates, connected to the server's own loopback services. The guard now refuses `0.0.0.0/8` and `::` at create/update time, at send time and at dial time (found during the CodeQL #1209 triage).
- **Dev-tooling alert fixes.** The web test toolchain moves to vitest 4.1.12 (fixes the `@vitest/mocker` advisories, development scope only). `scripts/metrics/surfacewalk startup` now refuses a probe URL whose host is not loopback, because its readiness probe skips certificate verification.
- **Secret files must be owned by root or by the server's user (#3393).** The server
  now also checks who owns a secret file read through a `<NAME>_FILE` variable, not only
  its mode. The owner of a file can always rewrite it, so a master-password, KEK or
  Shamir-share file owned by any other account let that account swap the key material
  (for example on a server running as root). Such a file is now refused at boot, and the
  error names the file and its owner uid. Key material (`KEYORIX_MASTER_PASSWORD_FILE`,
  `key_provider.env_var`, `shamir_share_env`) is always refused. The other secret files
  are refused under `security.enable_file_permission_check` (the default) and only
  warned about without it. There is no list of extra trusted owners.
  **Upgrade action for the Docker Compose install:** `scripts/selfhost/init-secrets.sh`
  leaves `secrets/*` owned by the user who ran it, so hand the files to root and keep
  their group before upgrading: `sudo chown root:"$KEYORIX_SECRETS_GID" secrets/*`
  (the script now prints this). For other installs: `chown root:<group> <file>` for a
  group-readable `0440` mount, or `chown <server user> <file>` for a `0600`/`0400` file.
  Kubernetes Secret volumes are root-owned already and need no change.
- The CLI (`KEYORIX_TOKEN_FILE`, `KEYORIX_PASSWORD_FILE`, `KEYORIX_MFA_CODE_FILE`, `KEYORIX_ADMIN_PASSWORD_FILE`, `KEYORIX_BOOTSTRAP_TOKEN_FILE` and the other `*_FILE` credentials) and the container entrypoint (`KEYORIX_ADMIN_PASSWORD_FILE`, `KEYORIX_BOOTSTRAP_TOKEN_FILE`) now refuse a secret file owned by anyone other than the running user or root, as the server already does (#3393). Another account that owns the file can rewrite it, so it could substitute the credential, for example to choose the first admin's password. Fix: `chown` the file to the user the command runs as, or to root.
- A relative `*_FILE` value is no longer printed in any error. Someone who sets `KEYORIX_DB_PASSWORD_FILE=hunter2` (the value instead of a path) used to get `KEYORIX_DB_PASSWORD_FILE="hunter2": ... no such file or directory` in the boot log. Now the server, the CLI, `keyorix-k8s-sync` and the container entrypoint say `KEYORIX_DB_PASSWORD_FILE (a relative path, not shown: it may be the secret itself): ...`. Relative paths such as `KEYORIX_TOKEN_FILE=./token` still work, and an absolute path is still shown.
- **keyorix-mcp: `KEYORIX_TOKEN_FILE`.** The MCP server can read its machine-identity token from a file (Docker secret, Kubernetes Secret volume) instead of the environment, where `/proc/<pid>/environ` and child processes see it. The file is judged like server key material (regular file, 0600/0400 owned by the running user or root, or a root-owned 0440 mount in a held group; 1 MiB cap; one trailing newline stripped), and setting both `KEYORIX_TOKEN` and `KEYORIX_TOKEN_FILE` is refused. Guarded by `TestMainSubprocess_TokenFile_*` (cmd/keyorix-mcp).
- **`--passphrase-file` size cap.** The master-passphrase file is now bounded by the same 1 MiB cap and error as `*_FILE` secrets (one shared `secretenv.ReadCapped`), so a mis-pointed path to a large file is refused instead of read into memory. Guarded by `TestReadPassphraseFile_SizeCap`.
- **`*_FILE` secrets are read once, from the judged descriptor.** The server used to re-read a `*_FILE` secret on every accessor call, so the value a boot check judged (duplicate-secret check, SCIM token strength, file permissions) could differ from the value used, and the permission check stat'ed the path separately from the read. `config.Load` now reads each non-key-material `*_FILE` secret once (`secretenv.Snapshot`) and the accessors, `ValidateSecretSources`, the duplicate-secret check, the file-permission check and the SCIM strength check all use those bytes and the verdict on their descriptor. A read failure still fails closed. A changed secret file is picked up on restart. Guarded by `TestSecretSnapshot_*` (internal/config).
- **Posture names too-open secret files.** In each warn mode (`enable_file_permission_check: false`, `insecure_allow_unsafe_file_permissions`, the ADR-112 upgrade grace) `keyorix-server admin validate --posture` now names every `*_FILE` secret that fails the owner + mode rule (variable and path, never the contents) on that mode's deviation line. The deviation count is unchanged. Guarded by `TestPosture_NamesTooOpenSecretFileInEachWarnMode`.
- Reconciled the three security policies into one canonical `SECURITY.md`: one reporting address (`security@keyorix.com`), the two-line support commitment (current and previous minor release line), scope, and the advisory, CVE and patch-release announcement process. `docs/SECURITY.md` and `web/SECURITY.md` now link to it instead of carrying their own, conflicting, commitments.
- Added an RFC 9116 `security.txt` source (`docs/security/security.txt`, with a CI format and expiry check) and a draft incident response plan and first tabletop exercise under `docs/security/`.
- **An admin command on SQLite stops when its lock file is deleted.** Deleting or replacing `<database>.server.lock` while a `keyorix-server admin` command ran let a server start beside the command, and both wrote to the database. The command now checks the file every 5 s, as the server already does, takes the new file so no server can start, and stops with exit status 1 and an error naming the cause. The lock file is never stale: do not delete it.
- **`admin backup` leaves no archive when its lock is lost.** A backup whose database lock was lost while it ran (a PostgreSQL connection died, or the SQLite lock file was deleted) could leave a partly written archive at `--output`: with `--exclusive` on PostgreSQL the command stopped without removing it, and a loss just before the archive was closed was missed. The partial archive is now removed at every point up to the close, and the command exits non-zero with an error saying the backup is not usable.
- **On SQLite, deleting `<db>.server.lock` under a running server no longer lets an admin command run beside it.** The server checks every 5 seconds that the lock file is still the one it holds; if it was deleted or replaced, it re-creates it and takes the lock again, or, when an admin command took the new file first, shuts down with exit status 1 (as on a lost PostgreSQL presence lock). A lock file deleted between opening and locking it is detected at acquisition too. A filesystem without `flock` support or inode numbers is now refused at start with an error saying so. See docs/operator/j7-troubleshooting.md.
- Share permission updates (`PUT /api/v1/shares/{id}`, gRPC, web, CLI) now read the share with a row lock (`SELECT … FOR UPDATE` on PostgreSQL) before deciding whether the change widens access, and hold it until the write. Before, on PostgreSQL a concurrent narrowing (write→read, a shorter expiry) committing between that decision and the write could be silently undone by an update classified as "no change": a widening that skipped the fail-closed audit rule and, during an audit outage, left no audit row. An update that does not touch the expiry now keeps the expiry the share has at write time. A concurrent update or revoke of the same share waits for the other to commit. SQLite was not affected.
- **The secret metadata cache's `cache_epoch` trigger is re-checked every 30 seconds too (PostgreSQL).** The server's own database role could replace `keyorix_secret_nodes_bump_cache_epoch()` with a body that keeps the old stamp, re-create the trigger as `AFTER UPDATE`, or disable it while changing a row and let the next boot re-enable it. A secret suspended that way kept reading as active from every warm replica until the cache entry expired. The background check that watches the role-permission generation triggers now also compares this trigger and function with this release's and with the previous catalog reading. On a difference it logs a `SECURITY:` line, increments `keyorix_secret_node_cache_epoch_tamper_total`, restores the trigger and moves `cache_epoch` on every live secret, so every replica re-reads. The migration no longer rewrites a correct function on every boot, and re-creates a same-named trigger of another shape. Both checks now also report a database session whose `session_replication_role` is not `origin`.
- **A SQLite database given as a `file:` URI is now pre-created at mode 0600 and migration-locked like its plain path.** `storage.database.path: file:/data/secrets.db` (or `file:///...`, `file://localhost/...`, percent-encoded) made the server pre-create a junk relative `file:/data/...` path, so the real database was born at the process umask until the post-open permission check corrected it, and a process on the URI and one on the plain path took different migration locks on the same database. The database file, its `-wal`/`-shm` permission check and the migration lock now resolve the path with the same rules as the server lock sidecar, and only a `file:` URI whose last `mode` query key is exactly `memory` is in-memory: a directory named `mode=memory` is a real directory, a `file:` URI with `_journal_mode=memory`, `xmode=memory`, `mode=memory&mode=rwc` or `mode=memory` after a `#` is the real file, and a plain path with `?mode=memory` (the driver drops a plain path's query) is the real file, so these now get the 0600 pre-create, the server lock sidecar and the migration lock.
- **Key files must belong to the server's user or root (#3410).** `--passphrase-file`, the file KEK provider (`key_provider: file`), the wrapped DEK, the KEK salt and the TLS private keys were judged by their mode only, so a `0600` file owned by another unprivileged account passed, although that account can rewrite it. They now follow the owner rule the `KEYORIX_*_FILE` secrets got in #3393: the running user or root. `--passphrase-file` and the KEK file are refused outright; the DEK, salt and TLS keys follow `security.enable_file_permission_check` like a too-open mode (refuse when it is on, warn in the ADR-112 upgrade grace or when it is off; a TLS key only warns while the setting is unset). **Upgrade note: this can stop an install that booted before** when one of these files was copied in by hand as another user. The error names the file and its owner uid; fix it with `chown <server user> <file>` (or `chown root`). Compose: `docker compose run --rm --no-deps --user 0 --cap-add CHOWN --entrypoint chown backend -R 1001:1001 /app/keys /app/tls`. The shipped Compose stack, Helm chart, systemd unit and launchd plist already satisfy the rule. Guarded by `TestModeChecksAlsoJudgeTheOwner` (any mode check in the key-file packages must also judge the owner).
- **DEK rotation is safe with several replicas (#3337).** On PostgreSQL the database now records which DEK it is encrypted under (the DEK epoch, a fingerprint in `system_metadata`). A server whose DEK is not that one refuses to start, so a replica started with an old `dek.key` after a rotation on another host can no longer write rows that become undecryptable once the old DEK is gone. A running server refuses encrypted writes (reads and revocations continue) while a rotation is in flight or after one finished elsewhere; `admin encryption rotate` fences writes on every replica, waits about 10 seconds and locks the encrypted tables against writes during its sweep. SQLite is unchanged. Upgrade every replica before the next rotation; see `docs/UPGRADING.md` §6s and `docs/operator/j6-key-rotation.md`.
- **Role-permission cache: the generation proof now requires triggers that fire for every writer.** On PostgreSQL the role->permission cache trusted its generation while a generation trigger was ENABLE REPLICA or an ordinary trigger (which a writer in `session_replication_role = replica` skips), and on a reading connection in replica role. A permission removed by direct SQL in those states kept authorizing from a warm cache. The proof now uses the secret-node cache-epoch condition: ENABLE ALWAYS on a connection in `origin`. The next migration re-issues ENABLE ALWAYS. Guarded by the pg-gated `TestRolePermissionGeneration_*_Postgres` tests in `internal/storage/store`.
- **Updating a custom role can no longer bring back a role deleted at the same time.** `UpdateRole` stored the role with a full-row `Save`, which re-inserted a role a concurrent delete had just removed (same id, stale name and description). It now writes only `description` and `assignable_scope` for that id, and a role deleted in between makes the update fail with "role not found" instead. Covered by race tests on SQLite and Postgres.
- **The role-permission cache sees direct database changes (#3259).** A change made directly in the database to `role_permissions` or `permissions` (operator SQL, a script, a restore into a live database) is now seen by every running server on its next authorization decision; before, a permission removed that way kept authorizing from each server's cache until a restart. Database triggers on both tables move the cache generation (PostgreSQL and SQLite, installed by the normal migration on upgrade), and if the triggers are missing or disabled the cache is bypassed instead of trusted.
- **The trigger integrity check now also covers `system_metadata`, the table every role-permission generation bump writes (PostgreSQL, #3713).** The server's own database role could add a `BEFORE UPDATE` trigger that keeps the old generation, a rule, or forced row-level security that hides the generation row. Every bump then became a no-op, the check's own included, while the triggers and function it compared still read as correct, and a permission removed with direct SQL kept authorizing from warm caches. The 30-second check now also requires that `system_metadata` has no trigger except the audit retention-anchor one exactly as installed (plus, only with `storage.database.single_writer`, the write fence's own triggers, which the fence itself checks while it runs), no rule, and row-level security off. On a difference it logs a `SECURITY:` line, counts `reason="tamper"`, removes them and invalidates every replica's permission cache.
- **Unlocking a user and resuming a secret no longer happen without an audit record.**
  `POST /api/v1/users/{id}/unlock` (and the gRPC equivalent) cleared the login lockout first and wrote
  `account.unlocked` afterwards on a best-effort basis, and `ResumeSecret` did the same with
  `secret.resumed`, so an audit-log fault left an unrecorded lift of a brute-force refusal or a
  suspension. The change and its audit row now commit in one transaction: if the audit write fails the
  lockout stays set (or the secret stays suspended) and the call returns the standard 500 error body, as
  `keyorix-server admin clear-login-lockout` already did. The error contract is unchanged.
- **Web: bump transitive `follow-redirects` to 1.16.1.** Clears GHSA-q3jh-wrc6-jgq8 and GHSA-8r9p-f939-6h3c (reached through axios) that failed the Web CI `pnpm audit` step.
- **Web: bump transitive `follow-redirects` to 1.16.2.** Clears GHSA-mrwp-f3q8-3g9p (reached through axios) that failed the Web CI `pnpm audit` step.

### Added
- **Operator and k8s-sync: suspended and expired source secrets are reported, never deleted.** A referenced Keyorix secret that is expired is retained in the cluster; one that is suspended is retained by default, or its managed keys are emptied with the new `KeyorixSecret` field `spec.onSuspend: Retain|Clear` (k8s-sync: `on_suspend: retain|clear`, Helm `onSuspend`). The Secret object is never deleted and a Secret the operator does not own is never touched; resuming restores the data on the next reconcile. Each state raises a `SourceSecretHealthy=False` condition (operator), a Warning Event `SourceSecretSuspended` / `SourceSecretExpired` (operator; a log line in k8s-sync) and a metric (`keyorix_operator_source_secrets{state}`; `keyorix_k8s_sync_secrets_total{outcome="source_suspended|source_expired|source_expiring"}`), cleared on recovery. Warnings also fire 30, 7 and 1 days ahead of an expiry. Fetch failures (server unreachable, timeouts, 5xx) still never modify the target Secret. The CRD change is additive and the default keeps the previous behaviour for the held keys. **A held source freezes only its own keys:** when one reference of a target is expired, or suspended under `Retain`, only that reference's keys are kept exactly as they are (never overwritten or deleted); the target's other keys keep syncing in the same single update, so a rotation of a readable sibling propagates (operator and k8s-sync). While a key is held the operator's `Ready` stays `False` with reason `SourceSecretExpired` / `SourceSecretSuspended` and the message names the held keys; nothing is written only when every reference is held. `onSuspend: Clear` is now applied to a suspended reference even while another reference of the same target is expired (only the suspended reference's keys are cleared).
- **gRPC `UpdateSecret` can now remove a secret's expiry and read limit.** `UpdateSecretRequest` gains additive `clear_expiration` (field 7) and `clear_max_reads` (field 8), matching REST. Each is mutually exclusive with the value it clears (`InvalidArgument`), an absent field keeps the stored value, and clearing an existing expiry or limit stays a lifecycle-permission action, so a write share does not elevate it (#3172).
- **Helm: `externalDatabase.caSecret` mounts the external PostgreSQL's CA.** Set
  `externalDatabase.caSecret.name` (and `.key`, default `ca.crt`) to a Secret holding the CA's
  PEM: the chart mounts it read-only (0440) at `/app/db-ca/ca.crt` in the server pod and renders
  it as `storage.database.ssl_root_cert`, so `externalDatabase.sslMode: verify-full` against a
  private CA works without patching the Deployment. `externalDatabase.sslRootCert` (`system` or
  your own mount) still works; setting both, `caSecret` with the bundled PostgreSQL, or
  `caSecret` with a non-TLS `sslMode` fails the render, and so does `sslMode`
  `verify-full`/`verify-ca` with no CA at all (the server would refuse to start).
- **Break-glass in the web UI (#3148).** Each project has a new **Break-glass** tab. A member requests emergency access with a justification and a lifetime and sees their own activations with status and a live countdown to expiry. Anyone who holds `roles.read` at the project sees every activation (who, when, justification, status), and `roles.assign` adds **Revoke** behind a confirm dialog. A server with break-glass off says "Break-glass is not enabled on this server", a project that requires MFA surfaces the server's MFA refusal with a link to enrolment, and a non-member gets a refusal instead of a list. The server still decides everything; the tab never caches one user's activations for another.
- **Break-glass refusal "disabled" has a typed error code.** Activating while `break_glass.enabled` is false still answers 403 with the same message, in the same order of checks, but the REST `error` field is now `BreakGlassDisabled` (was `Error`) and gRPC adds a `google.rpc.ErrorInfo` detail with reason `BreakGlassDisabled` (domain `keyorix.breakglass`) to the same `PermissionDenied`. The web tab switches on the code and keeps matching the old message text only against older servers.
- **The server's break-glass limits come with the activations list.** `GET /api/v1/projects/{id}/break-glass` and `BreakGlassService.ListBreakGlassActivations` now return `settings` (`enabled`, `emergency_role`, `default_ttl_seconds`, `max_ttl_seconds`; the effective values activation enforces) to exactly the callers the list already allowed (a project member, or `roles.read`); no secret and nothing admin-only. A non-member still gets the same 403 and none of it. The web "How long" picker offers only lifetimes up to the maximum and shows the server default, and a server that reports break-glass off shows that up front instead of a form. OpenAPI, the web types and the CLI client are regenerated.
- **Suspend a secret and also clear its synced Kubernetes copies (a compromise response).** The suspend request takes an optional `clear_synced_copies: true` (`POST /api/v1/secrets/{id}/suspend`; web: the suspend dialog's checkbox *Also clear copies synced to Kubernetes clusters*, with a note recommending rotation; CLI: `keyorix secret suspend --id N --clear-synced-copies`). For that one suspension the Kubernetes operator and `keyorix-k8s-sync` treat the secret as `onSuspend: Clear` whatever the resource's own setting says, with exactly the Clear semantics (they empty only the keys Keyorix manages and never delete a Secret or touch one they do not own). The server carries the choice on the `409 SecretSuspended` answer as `details.clear_synced_copies: true`; a client that ignores it behaves as before. Resuming removes the choice and the next sync restores the copies. It needs the same permission as suspending and the `secret.suspended` audit event records it (`clear_synced_copies=true`); suspending an already-suspended secret with the flag adds the choice (audited), and a plain suspend never removes one. Secret responses carry `clear_synced_copies` while it is set. Additive: a new `secret_nodes.suspend_clear_synced_copies` column (default false), no change for existing suspensions. Keyorix does not record which clusters hold copies, so the dialog offers the option without listing them; the gRPC API has no suspend call, so there is no gRPC field. The choice also holds when the secret has expired as well: the server checks expiry first, so the `409 SecretExpired` answer carries `details.clear_synced_copies: true` too when (and only when) the secret is also suspended with the choice, and the operator and `keyorix-k8s-sync` clear the copies in that case; an expired secret that is not suspended with the choice keeps its copies as before.
- **Freeze a whole project and also clear its synced Kubernetes copies.** `POST /api/v1/projects/{id}/secrets/suspend-all` takes the same optional `clear_synced_copies: true` as the single-secret suspend (web: a checkbox in the project's *Freeze all secrets* dialog, with the rotation note; CLI: the new `keyorix project suspend-secrets --id N [--reason ...] [--clear-synced-copies]` and `keyorix project resume-secrets --id N`). It needs the same permission as the project freeze, and each secret it suspends gets the per-suspension marker exactly as a single-secret suspend does (an already-suspended secret without it is upgraded, one with it is left alone); `resume-all` clears it. One `secret.bulk_suspend_attempted` audit event records the choice (`clear_synced_copies=true`) and the number of secrets targeted before any secret is touched; if that event cannot be recorded the request fails and nothing is suspended. The same fail-closed rule applies per secret: if a secret's own audit row is refused, the freeze stops there and the request answers 500 (`details.suspended` / `details.failed`) instead of 200; secrets already suspended stay suspended, so retry. Any other secret that could not be suspended (a storage or commit failure, a concurrent change) is counted the same way, and the request answers 500 with the counts rather than 200. A plain freeze is unchanged, apart from that event now being written before the freeze (its count is the secrets targeted, not the ones that succeeded). The project suspend/resume routes are now in the OpenAPI document.
- `storage.database.pooler` (`none`, `pgbouncer-session`, `pgbouncer-transaction`; Helm `externalDatabase.pooler`): run the server behind PgBouncer. In transaction mode every PostgreSQL connection runs statements unprepared and every advisory lock held across statements (named, scheduler, bootstrap, audit-checkpoint, migration and server-presence locks) is a transaction-scoped lock inside a transaction held for the critical section, so locks keep excluding across replicas. A server behind transaction pooling without the setting refuses to start when it can detect it. See docs/postgresql-poolers.md.

In transaction mode the lock transactions also set `transaction_timeout = 0` (PostgreSQL 17+, alongside `idle_in_transaction_session_timeout = 0`) for themselves only, so a database-wide timeout no longer drops a held lock silently, and the transaction-pooler check now runs before the server takes its presence lock. docs/postgresql-poolers.md lists what the server cannot protect against (PgBouncer's own timeouts, `idle_session_timeout` in session modes).
- **Prometheus alert rules, Grafana dashboard and alert runbook.** `deploy/observability/` ships 28 alerts covering availability, audit writes, owed audit rows and verification, database pools, auth abuse, encryption and TLS expiry, `single_writer`, and background jobs, each linking to its section in `deploy/observability/runbook.md`, plus an importable Grafana dashboard. `go test ./internal/metricsdoc` fails if a rule or panel names a metric or label the code does not define.
- **Operator-critical Prometheus metrics.** Audit append latency, failures and group-commit queue wait (`keyorix_audit_write_duration_seconds`, `keyorix_audit_write_failures_total`, `keyorix_audit_group_commit_wait_seconds`); database pool in-use/idle/max and wait counts per pool (`keyorix_db_pool_*`); rate-limit refusals by limiter for HTTP and gRPC (`keyorix_rate_limit_rejections_total`) and by auth budget (`keyorix_auth_budget_rejections_total`); `single_writer` guard state (`keyorix_single_writer_*`); encryption state, KEK provider, encrypt/decrypt failures and runtime KEK-provider downgrades (`keyorix_encryption_*`); and the expiry time of the certificate each TLS listener serves (`keyorix_tls_certificate_not_after_timestamp_seconds`).
- **Audit verification health, authenticated-only.** `keyorix_audit_verify_last_success_timestamp_seconds`, `keyorix_audit_verify_failure_recorded` and `keyorix_audit_verify_state_rejected`, plus `keyorix_audit_owed_pending` (owed audit rows, suspend and degraded break-glass, not yet backfilled), are served at `GET /api/v1/admin/scheduler-metrics` (permission `system.write`), not on the open `/metrics`, because they would tell an anonymous reader when an integrity check last passed and whether it found a break. The posture and tamper series are served there too, for the same reason: `keyorix_encryption_state`, `keyorix_encryption_kek_provider_info`, `keyorix_encryption_operation_failures_total`, `keyorix_encryption_kek_provider_downgrades_total`, `keyorix_audit_write_failures_total`, `keyorix_auth_budget_rejections_total` and `keyorix_single_writer_unattributed_bumps_total`. A Prometheus that alerts on them needs the `keyorix-protected` scrape job in `deploy/observability/README.md`. See `docs/operations/metrics.md`. The state gauges are published only for the newest generation, so a late status read of an older state cannot lower `keyorix_audit_verify_failure_recorded` after a newer save recorded a break, and an untrusted (replayed) state row that still carries a sticky failure raises it. A restarted server publishes the persisted state at startup, and the two flag gauges read NaN (unknown) until then, so a restart cannot resolve the audit-chain break page while the failure is still recorded.
- **Audit rows record the request that wrote them.** `audit_events.request_id` stores the server's id of the HTTP request (the value returned in `X-Request-ID`), so an audit row can be joined with that request's log lines. It is NULL for scheduler, startup and gRPC writes and for rows from older replicas. The field is outside the tamper-evident hash chain and advisory: verification ignores it. The SIEM forwarder includes it. Schema epoch 6 (additive, compatibility floor unchanged). Design: `docs/specs/audit-request-id.md`.
- **Age of the oldest owed audit row, with alerts.** `keyorix_audit_owed_oldest_pending_age_seconds` (0 when nothing is owed) on the authenticated `GET /api/v1/admin/scheduler-metrics`, next to `keyorix_audit_owed_pending`: the count cannot tell an owed audit row that is delayed from one that is stuck, the age can. New alerts in `deploy/observability/prometheus-alerts.yaml`: `KeyorixAuditOwedOldestPendingWarn` (above 1 hour) and `KeyorixAuditOwedOldestPendingCritical` (above 24 hours); the thresholds are the numbers in each rule's `expr` (see `deploy/observability/README.md`). The read is one index lookup on `pending_audit_events.created_at` with a 3-second bound and takes no lock. When the database cannot be read both owed-audit gauges answer NaN (never 0) and the new `keyorix_audit_owed_metric_scrape_errors_total` counts the failed reads; `KeyorixAuditOwedMetricUnreadable` alerts on it. Runbook sections in `deploy/observability/runbook.md`; operator notes in `docs/operator/break-glass-runbook.md`.
- **Hybrid post-quantum recipients for `admin recovery-key rotate --recipient`.** The command now accepts hybrid age recipients (`age1pq1...`, ML-KEM-768 + X25519). A classical recipient (`age1...` X25519 or `ssh-ed25519`) still works but prints one stderr warning that an age-encrypted recovery key harvested today opens to a future quantum attacker and names the hybrid alternative. A malformed recipient is refused before the old key is rotated. Documented in `docs/operator/j5-lost-admin.md`.
- New alert `KeyorixAuditVerifyStateDiscontinuity` (critical) on `keyorix_audit_verify_state_discontinuity`, with a runbook section that points to the audit-chain break runbook. Like the other audit-verification alerts it needs the `keyorix-protected` scrape job.
- `internal/metricsdoc` now checks the alert rule file as text (so it can be tested against a misspelt copy), accepts recording rules defined in the file, requires a severity and a `runbook_url` or `description` on every alert, and pins the owed-audit alert thresholds (1 hour warning, 24 hours critical) from the rule file. The thresholds are unchanged.
- **Release gate: `scripts/release/check-release-blockers.sh`.** Exits 1 while any issue labelled `release-blocker` is open and prints every one; a list that cannot be obtained or is not a JSON issue array exits 3, no lister or no credentials exits 4, and both mean stop (unknown is not a pass). Issue titles cannot forge a `release gate: PASS` line (control characters are stripped). `RELEASING.md` step 4 and `docs/releases/RELEASE-CHECKLIST.md` make it the hard step before `git tag`, chained with `&&` so a gate that does not pass stops the tag. `--self-test` covers the green, red, failing-lister, garbage, forged-line, no-lister and usage cases.
- **gRPC `VerifyAuditChainResponse.state_reason`** (field 14, additive). `VerifyAuditChain` now returns the same `state_reason` as `GET /api/v1/audit/verify`, so a client that sees `status: sealed` is told which accepted audit loss it is (and why a persisted verification state was ignored, when it was). The `status` comment now lists `sealed` next to `valid | broken | not_proven`. `TestAuditVerify_HTTPvsGRPC_SameReport` fails if a field HTTP can return is missing from the message.
- **A guard test fails when a migration adds a column the backup silently ignores.** `TestEveryBackedUpColumnIsMappedOrAllowlisted` (`server/admin`) compares the columns of every backed-up table, on a fresh SQLite and PostgreSQL schema and on the schema a v0.95.3 binary left behind, with the columns the backup writer maps; each unmapped column needs its own allowlist file (`backup_unmapped_column_<table>_<column>_test.go`) with a reason. Report-only until its first green nightly on main (`docs/guard-rollout.d/`).
- Helm chart: README and `values.yaml` now say to set `auditDurability: strict` on edge/PostgreSQL where audit loss is unacceptable. New tests pin the chart render matrix (1 and 2 replicas, bundled and external database, NetworkPolicy, Ingress, secure baseline, existing auth Secret; kubeconform-valid, no credential in a ConfigMap, fail-closed refusals) and the current behaviour that an external database is denied egress by the default NetworkPolicy until `networkPolicy.egress.databaseTo` or `extraRules` names it. A docs guard fails when a doc tells users to `--set` a chart key that is not in `values.yaml`; it caught `web.replicaCount` (the key is `web.replicas`) in the Kubernetes guide.
- **`admin verify-audit` checks a seal's recorded anchor and shows its unpinned rows.** An acceptance made with `admin audit accept-loss --anchor-sha256` recorded only the digest of an anchor file kept elsewhere, and nothing ever compared the file with it. `verify-audit --anchor <file>` now takes the file's SHA-256 (as `accept-loss` does) and reports, per seal, whether it matches, authenticates and covers the lost range (`--json`: `seal.seals[].anchor.check`). Each seal also lists the rows it recorded as `unpinned` (#3802). Neither changes the verdict; what is left unconfirmed is listed under "What this run does NOT prove". See docs/operator/audit-chain-break-runbook.md §7.
- `storage.database.fdatasync` (SQLite only, default `false`): commit with `fdatasync(2)` instead of `fsync(2)`. Ignored with one warning on macOS and Windows. See "Committing with fdatasync" in `docs/CONFIGURATION.md`, including the seccomp caveat. `scripts/powercut` adds a dm-flakey power-cut test for the SQLite backend.
- **Cursor paging for the audit log.** `GET /api/v1/audit/logs`, `GET /api/v1/audit/search` and gRPC `AuditService.GetAuditLogs` return `next_cursor` and accept `cursor` to continue after it, at the same cost on every page however deep. `include_total=true` asks for the exact total. The web Audit Log and the project Activity tab load further events with **Load more**; `keyorix audit logs` / `audit search` take `--cursor` (printed under each page) and `--include-total`. See `docs/specs/audit-list-keyset.md`.
- **Find the audit rows of a request by its id.** `GET /api/v1/audit/logs` and `/audit/search` accept `request_id=<id>` (exact match; the id is the `X-Request-ID` the server returned), and every audit entry, `/audit/export` and `/audit/export.csv` (new last column) now carries `request_id`. `keyorix audit logs|search` take `--request-id` (and `--wide` to show the id), and gRPC `AuditService.GetAuditLogs` has the same filter and `AuditLog.request_id`. The id is outside the tamper-evident hash chain and advisory: verification ignores it. The column has no index, so combine the filter with a time window.
- **gRPC calls get a server-minted request id.** An interceptor mints it, returns it in the `x-request-id` response header and stamps it on the audit rows the call writes (they were NULL before); a client-sent `x-request-id` is never stored.
- **Owed audit rows keep the original request id.** `pending_audit_events.request_id` carries the id of the request that owes a row (a plain secret suspend, a degraded break-glass activation), so the backfill writes it with that id. Schema epoch 9 (additive nullable column, compatibility floor unchanged at 3).
- **`storage.database.insecure_audit_skip_reads` (ADR-112 Amendment 4), default `false`.** When `true`, successful secret-value reads (REST, gRPC, render, copy, federated connector reads, and the CLI, k8s sync, MCP and operator through the API) write no audit row and no access-log row; secret writes, permission/role/share changes, authentication and its failures, denied reads, admin and break-glass actions and configuration/key operations are still audited. Loud per ADR-112: a `WARNING` and an `admin.audit_reads_skipped_at_startup` audit event at every start, the settings diff on change, a deviation in `admin validate` and `admin validate --posture`, and `security.audit_reads_skipped` in `GET /api/v1/system/info`. Config file only; a compliance profile refuses it. Independent of `audit_durability`. Read history, read counts, usage reports and anomaly detection do not see reads while it is on.
- **Web UI: a persistent "Secret reads are not audited" banner** on every page while the server runs with `storage.database.insecure_audit_skip_reads: true` (ADR-112 Amendment 4), read from `security.audit_reads_skipped` in `GET /api/v1/system/info`. It cannot be dismissed.
- **`KEYORIX_TOKEN_FILE`** (mode 0600/0400, or 0440 for a mounted Secret) as the file form of `KEYORIX_TOKEN`; a bad file is an error naming it, never a fallback. `keyorix doctor` names the token source.
- **`keyorix machine token issue --output-file <path>`** writes the token to a new 0600 file (refuses to overwrite; created before the token is minted) so it never passes through terminal scrollback.
- **A generated CLI reference and man page.** `docs/cli-reference.md` (every command, flag, default and example) and `docs/man/keyorix.1` are produced from the command tree by the new `keyorix docs markdown` and `keyorix docs man`, so they cannot drift from `--help`; a test fails when they are stale (`make -C cli docs` regenerates them). `keyorix docs man | man -l -` reads the page without installing it.
- **Shell completion is tested.** `keyorix completion bash|zsh|fish|powershell` (already provided by cobra) now has tests that the scripts load in the shell and that completion offers this CLI's commands and flags; install steps are in the reference under `keyorix completion`.
- **`keyorix doctor`: a read-only health checklist for the CLI's connection to the server.** It checks the configuration in use (server URL, token and CA file, and where each came from), that the server answers `/health`, the TLS chain and its expiry (against `--ca-file` or the system roots), API/minimum-CLI-version compatibility, clock skew against the server (TOTP codes and sessions break when a clock drifts), that the stored token is accepted and by whom, and the audit chain's integrity. Every problem prints the next step; checks that depend on an earlier failure are skipped, not failed. `-o json|yaml` for scripts; non-zero exit when any check fails (warnings do not fail it). It only sends GET requests and never starts the long full audit walk.
- **`--help` shows a runnable example on every CLI command.** Each leaf command now has an `Examples` section; `cli/cmd/help_examples_test.go` fails when a command has none, when an example uses a flag the command no longer has, or when an example puts a secret on the command line.
- **`-o/--output table|json|yaml` on the CLI's list and report commands.** `secret list`, `secret versions`, `project stats`, `project health`, `usage show` and `billing report` took `--format table|json`; they and every `list` / `list-*` command (`project list`, `user list`, `group list`, `machine list`, `pat list`, `request list`, `rotation list`, `rbac list-roles`, `anomalies list`, `risk list`, ...; all but `break-glass list`) now take the same `--output` flag, and `yaml` is new. `TestEveryListCommandTakesOutput` keeps it that way. json and yaml carry the same records as the table (an array; `user list`, which the server pages, is an object with `total` and `users`); an empty list is `[]` rather than a sentence. A mistyped format is refused up front, naming the choices (`usage show` and `billing report` used to fall back to the table silently).
- **`keyorix secret create|update --from-file -` reads the value from stdin** (`printf %s "$VALUE" | keyorix secret create ... --from-file -`): one trailing newline is dropped, nothing else is touched, empty input is an error.
- **`keyorix change-password` reads `KEYORIX_CURRENT_PASSWORD` / `KEYORIX_NEW_PASSWORD`** (each also as `*_FILE`) so it works in a script.
- **Complexity metrics per release.** `scripts/metrics/complexity.sh [ref]` measures code size, dependencies, artefact sizes, startup time and memory, the user-facing surface (config keys, env vars, CLI commands and flags, API operations, gRPC methods, doc pages) and internal weight for any ref; `scripts/metrics/complexity-diff.sh A B` compares two refs and names every new user-facing item. See `docs/operations/complexity-metrics.md`.
- **`admin validate --posture` warns when every administrator is IdP-managed (#2914).** A new WARN section (printed, not counted toward the exit code) appears when every global administrator was created by SSO or SCIM; the remediation is a local break-glass administrator and the local recovery procedure. See `docs/security/hardening-guide.md`.
- **Helm: `server.trustedProxies`** (default empty) sets the server's `http.trusted_proxies`. It is needed only if something other than the web pod reaches the server through a TLS-terminating load balancer. Entries are validated as IPs/CIDRs.
- **Environment list returns per-environment secret counts.** `GET /api/v1/environments` and `GET /api/v1/projects/{id}/environments` now include `secret_count` (live secrets, folders and soft-deleted secrets excluded), computed in one grouped query. The Secrets tab picks its default environment from it instead of issuing one secrets request per environment.
- **Helm: `postgresql.settings` for the bundled PostgreSQL.** Extra server settings, rendered as `postgres -c key=value` alongside the secure-baseline TLS args. Empty by default (rendered output unchanged). `synchronous_commit`, `fsync` and `full_page_writes` accept only durable values (an allow-list), and settings that would override the secure-baseline TLS/auth args or run commands (`ssl`, `ssl_*`, `hba_file`, `listen_addresses`, `password_encryption`, `archive_command`, and others) are refused. Guarded by `TestHelmPostgresSettings`.
- **Demo catalogue as Playwright journeys (`web/e2e/demo`, `make e2e-web-demo`).** Eight specs run the demo's acts against a real server through the console: login and forced MFA enrolment, secret create/rotate/history/rollback, share with expiry and revoke, machine identity and token, audit search, compliance evidence export and verify, an anomaly after a trigger, and break-glass in the audit log. They use the real-web harness (`scripts/e2e/web-real-smoke.sh`, one fresh server per file), which gains `KEYORIX_E2E_SPEC_DIR` and an `// e2e-server: anomaly_schedule=15s` directive. They are kept out of `web/e2e/real` so the pull_request profile does not run them.
- **Hosted demo deploy kit (`deploy/demo-hosted/`, phase 1).** One idempotent `install.sh` sets up a single Ubuntu/Debian VM with Keyorix + PostgreSQL through the production compose path, Caddy with automatic Let's Encrypt TLS for the hostname given at install, a basic-auth / IP allow-list gate, strict audit commit, a generated 0600 bootstrap token (at least 32 characters), a per-install KEK secret, a nightly and on-demand full reset to the demo seed, and an idle shutdown timer. The seed/scenario hook is a placeholder until the DEMO-LOCAL-2 scripts are merged. Checked offline by `go test ./deploy/demo-hosted/`; the real deploy is pending a VM.
- **Native demo without Docker, a live anomaly demo, and a repeatable scenario catalogue.** `scripts/demo/native-up.sh` runs the same calm demo on host binaries (SQLite or PostgreSQL); `scripts/demo/seed-demo.sh STATE_DIR` is the non-interactive, idempotent seed (MFA stays required; the admin's TOTP key goes to a 0600 file, the bootstrap token is generated). `scripts/demo/trigger-anomaly.sh` triggers real detections (bulk read, read burst, off-hours, new source, plus the audit-only failed-login burst and refused-read probing) and resets to calm; `scripts/demo/anomaly-check.sh` proves it. `scripts/demo/scenario-*.sh` script twelve demo scenarios; `docs/demo.md` is the talk track.
- **Independent break-glass review in the web UI.** The admin Break-glass tab now has a Review action (note of at least 10 characters) on an ended, unreviewed activation for a user with roles.assign who is not the requester, and a Reviewed badge afterwards; it is hidden otherwise. It uses the existing `POST /projects/{id}/break-glass/{activationId}/review`; the server rules (no self-review, not while active, once only) are unchanged (DEMO-WALK-4 finding 2).
- **Clock warnings for devices without a time source.** The server now logs, on every start, when the system clock reads earlier than the binary's build date (an unset or reset clock) and when a configured TLS certificate is expired, not valid yet on this clock, or within 30 days of expiry; while running, it logs when the wall clock steps by 30 s or more, saying that a backward step makes the server refuse secret value reads and second-factor logins until the clock catches up or the service restarts. None of these stop the server from starting.
- **Edge service definitions.** `deploy/edge/keyorix-server.service` (systemd) and `deploy/edge/io.keyorix.server.plist` (launchd) start the server at boot, restart it after any exit, wait for the data volume, run it unprivileged and pass the master passphrase as a credential file instead of through the environment. `deploy/edge/edge_units_test.go` runs the unit's real `ExecStart` against the built server, kills it and starts it again, and pins the directives an unattended device needs.
- **Boot self-test under `GODEBUG=fips140=only`.** When Go's FIPS 140-only mode is enforced, the server first runs every AEAD and KEK-derived-key path once with a throwaway key: DEK wrap/unwrap, secret encrypt/decrypt, PBKDF2 KEK derivation, and the evidence-signing, audit-checkpoint and backup-manifest keys. If any path fails, the server refuses to start and names that path. It logs `fips140 enforced: yes, self-test passed (N paths)`, or `fips140 enforced: no (self-test not run)` outside that mode, where the self-test costs nothing. `admin validate --posture` prints the same line after the `Go FIPS 140-3 mode` line and counts a failed self-test as a deviation. (For docs/CONFIGURATION.md, posture section: this line reports the runtime mode and the self-test result only. It is not a statement that the build or the deployment is FIPS validated.)
- **`keyorix-server admin init --storage-type postgres`** writes the config for PostgreSQL from the start (`storage.type: postgres`, no SQLite path), so a PostgreSQL deployment no longer gets an empty SQLite file from `admin init`. Default behaviour (SQLite) is unchanged; with an existing config of a different type init refuses and changes nothing.
- **Structure-aware (grammar-based) fuzz input generation for the ASN.1 DER and XML
  parsers.** New `internal/fuzzutil/grammar` package: a DER builder (TLV tree + a
  length-consistent-by-default mutation set — indefinite length, non-minimal length,
  length overflow/under-run, wrong tag class, long-form tags, trailing bytes, deep
  nesting), an XML builder (tree + mutation set — namespace-prefix rebinding, duplicate
  IDs, comment/CDATA splitting, DOCTYPE/entity shapes, attribute reorder, whitespace,
  deep nesting, wide siblings), and a decoder that turns a fuzzer's `[]byte` into a tree
  plus mutation choices so `go test -fuzz` mutates structural choices rather than raw
  octets. Three new targets consume it: `FuzzDERStructure` (the standalone
  `encoding/asn1` + `crypto/x509.ParseCertificate`/`ParseCertificateRequest` target the
  repo previously lacked), `FuzzDERPKCS7BoundedWork` (grammar-driven counterpart of
  `FuzzDigitorusPKCS7BoundedWork`), and `FuzzSAMLXMLGrammar` (grammar-driven counterpart
  of `FuzzSAMLXMLTransitive`). Every pre-existing oracle is preserved; each new target's
  doc comment states explicitly what it does not verify.
- **Helm: `GOMEMLIMIT` for the server from its memory limit.** The server container now gets a soft heap limit of `server.goMemLimitPercent` (default 85) of `server.resources.limits.memory`, so the garbage collector works harder before the pod is OOM-killed. Override with `server.goMemLimit` or turn off with `goMemLimitPercent: 0`. Compose and systemd settings are in `docs/runtime-tuning.md`.
- `assignable_scope` on roles: in `GET`/`POST`/`PUT /api/v1/roles` (and gRPC `Role`, `CreateRoleRequest`, `UpdateRoleRequest`), and a *Can be granted* field in the web UI's role create/edit forms. The group *Manage Roles* modal now uses the role's scope to tell you to pick (or clear) a project before sending.
- **`storage.encryption.key_dir_lock: database` for several server replicas (PostgreSQL).** With the default `flock`, every server holds an exclusive flock on `dek.lock` in the key directory for its lifetime, so a second replica on a shared ReadWriteMany keys volume refused to start wherever flock is enforced across nodes (NFSv4, CephFS, EFS), and got no protection where it is not. In `database` mode the server takes no key-directory lock: first-boot key generation and rotation crash recovery run under a PostgreSQL advisory lock (a second replica waits and loads the keys the first wrote), key-changing admin commands stay excluded by the server-presence lock, admin `--force` is refused (also when the database's record of the mode cannot be read), the live Postgres `admin backup` holds the shared presence lock (when its config or the database's record says `database`; an unreadable record refuses the backup), and first-boot generation is refused when the database already holds secret versions or a DEK epoch, which the first replica records before it releases the key-initialisation lock. The key directory may then be a shared volume with any flock semantics, or read-only (keys from a Kubernetes Secret). SQLite and the default mode are unchanged. Design: `docs/multi-replica-keys.md`.
- **Helm Secret mode (`server.keysSecret`), the supported way to run `server.replicas > 1`.** The key files come read-only from a Kubernetes Secret: an init container copies `data.key` and `kek.salt` into a memory volume the server mounts read-only, the server runs with `key_dir_lock: database`, and no replica generates keys. One replica keeps the keys PVC unless it opts in. Design, first install, rotation and crash recovery: `docs/multi-replica-keys.md`.
- **`keyorix-server admin encryption key-secret generate | export | unpack`.** `generate` creates a new key set straight into an immutable Secret manifest (no database needed), `export` writes the configured key directory's set (refused while a `.pending` staging file is there), `unpack` writes a manifest back into an empty directory as a rotation workspace. The manifest carries the DEK fingerprint (the database's `dek.epoch`) and goes to a new 0600 file, or to stdout only when stdout is a pipe: never a terminal, a pod log or the journal.
- **`mfa_grace {ends_at, days_left}`** on the login response and `GET /api/v1/auth/profile` (present only while the grace period runs and the account has no second factor), and `require_mfa_grace` on `GET /api/v1/system/auth-config`, whose `require_mfa` now reports what is enforced at that moment.
- **Structured JSON logs.** `server.log.format: json` writes every server log line as one JSON object (`ts`, `level`, `msg`), and the HTTP access log and panic lines also carry `request_id`, `principal_type` and `route`. The default stays `text`. See `docs/operations/logging.md`.
- **Request correlation.** Each request gets an id (the caller's `X-Request-ID`, cleaned, or a random one), returned in the response's `X-Request-ID` header and carried through core into audit-write failure logs.
- **Secret scrubber and canary guard.** In JSON mode Keyorix tokens, bearer values, JWTs, PEM keys, `password=`-style pairs and URL passwords are redacted from log lines, and a real-server test fails if a canary password or secret value reaches the server's output.
- `admin validate --posture` prints advisory, self-reported host integrity lines (POSTURE-INTEG-1, RD-INTEG-POSTURE-1 / RD-TIER-POSTURE-1): Secure Boot, kernel lockdown, IMA policy, fs-verity on the running binary, the binary's SHA-256 against a locally shipped release manifest, TPM sealing state and Keylime agent presence, plus a detected integrity tier 0 to 6. Every line is labelled "advisory (self-reported)", an unreadable source is "unknown", and none of it affects `/health`, startup or the exit code. See `docs/security/integrity-posture.md`.
- **`admin validate --posture` reports break-glass review gaps.** Every break-glass activation still unreviewed after `break_glass.review_window` is a `break-glass-review` deviation (activation id, project and activation time listed); a query failure is reported as "not evaluated", never a clean pass. An install with exactly one administrator also reports "independent review impossible" (even when every activation was reviewed; skipped while `break_glass.enabled` is false). The report also prints each TLS-terminating listener's TLS mode (default or `strict`) as an informational line, not a deviation (ADR-112).
- Helm chart: `server.replicas` is now honoured (it was ignored and pinned to 1). More than one replica renders a PodDisruptionBudget, node/zone `topologySpreadConstraints` (also for `web.replicas > 1`), RollingUpdate rollouts and `security.auth_rate_limit_fallback.replicas`, and is refused at render time unless the keys volume is persistent `ReadWriteMany` and `server.singleWriter` is off. New `server.singleWriter` renders `storage.database.single_writer`.
- Helm chart: `networkPolicy.ingress.controllerNamespaceSelector` restricts the web pods to the ingress controller's namespace, `networkPolicy.ingress.monitoringNamespaceSelector` admits Prometheus to the server port, and `networkPolicy.egress.databaseTo` / `kmsTo` / `kmsPorts` name the external PostgreSQL and key-management endpoints the server may reach. `helm install` warns when egress is restricted, the database is external and no destination is given.
- Helm chart: optional Prometheus Operator `ServiceMonitor` (`monitoring.serviceMonitor.enabled`) scraping `/metrics` over verified HTTPS with the generated bearer token.
- Helm chart: `values-production.yaml`, a documented production example (external PostgreSQL with `verify-full` TLS, credentials from `auth.existingSecret`, ingress TLS, secure baseline, top-level `auditDurability: strict`), rendered by a test.
- **`scripts/release/verify-release.sh TAG`: customer-side release verification.** Checks the GitHub Release (32 assets, `checksums.txt` vs every file, cosign/certificate/signature of `checksums.txt`, CycloneDX SBOMs, SLSA provenance of the 14 binaries), the release and docker-publish workflow runs including the Trivy gate steps, the 6 images (tags, platforms, BuildKit SBOM and provenance, cosign signature, GitHub attestation) and the 3 Helm charts (version, appVersion, signature). Read access only; exits 1 on any failure and 2 when checks could not run. Image and chart signatures need cosign >= 3 (they are OCI referrers; with an older cosign those nine checks are SKIPped with a precondition message, never FAILed), a GitHub API rate limit is a SKIP, not a FAIL, and the BuildKit SBOM layer is matched on its real predicate type `https://spdx.dev/Document`. `--self-test` runs it against fixtures with no network, including a real v0.96.3 BuildKit attestation manifest. Guide: `docs/operator/verifying-releases.md` (includes the air-gapped/mirror variant). Without cosign nothing proves who signed (the `openssl` certificate/signature checks accept a self-signed certificate and are labelled PARTIAL), so a SKIPped cosign signature check always exits 2, also with `--allow-skip`, including when the registry or one image/chart tag gives no HTTP answer; `--skip-images`/`--skip-charts` are a scope you choose and the summary says `SCOPE REDUCED`. `GITHUB_TOKEN`, registry bearer tokens and mirror passwords reach curl through its stdin config (quoted; control characters refused), never its command line. Mirror credentials (`REGISTRY_USER`/`REGISTRY_PASSWORD`) are sent to the registry only, never to github.com. `--commit` is checked against GitHub when online and reported as ASSERTED (SKIP) offline; TAG, `--repo` and `--commit` are validated as whole strings; BuildKit attestation manifests must hash to the digest the image index names.
- **`scripts/release/check-docs-version.sh TAG`: release check that the install docs pin the version being released.** It fails when README, `QUICK_START.md`, `INSTALL-WITH-AI.md`, `docs/SELF_HOSTING.md` or a compose file pins an image tag, release download URL, `V=` or helm `--version` other than TAG (intentional exceptions: `scripts/release/docs-version-exceptions.txt`); `--self-test` runs it against fixtures. RELEASING.md and the release checklist gain the item "README and QUICK_START at the release tag must match main for install commands" (v0.96.3 shipped docs pointing at v0.96.0).
- **Crypto inventory, quantum-risk score and CycloneDX 1.6 CBOM (R&D prototype).** `GET /api/v1/compliance/crypto-inventory` (`audit.read`, audited), `keyorix crypto inventory [--format table|json|cbom]` and a read-only table on the Compliance page list every key and certificate Keyorix holds (KEK, DEK, recovery-key verifier, TLS certificates, the derived audit-checkpoint / evidence / backup-manifest HMAC keys, WebAuthn and OIDC verification keys) with algorithm, size, dates and storage location, never key material. Each asset gets a 0-100 quantum-risk score from its remaining lifetime plus migration time against a configurable quantum horizon; classical public-key keys (RSA, ECDSA, Ed25519) are flagged and AES-256 scores low. New optional `crypto_inventory` config section (`quantum_horizon`, default 2035-01-01; `migration_years`, default 3; `unbounded_lifetime_years`, default 10). The CBOM is validated in tests against the vendored official CycloneDX 1.6 schema.
- **Crypto inventory / CBOM covers the listed gaps.** `GET /api/v1/compliance/crypto-inventory` and `keyorix crypto inventory` now list SAML IdP signing certificates, the database TLS client certificate (from the dsn's `sslcert`) and CA bundle, and backup archive encryption, each with algorithm, size, created/expiry and the existing quantum-risk score. WebAuthn passkeys are listed per COSE public-key algorithm (ES256/RS256/EdDSA, and ML-DSA when present) using the existing per-user credential listing; no storage method was added. The CBOM still validates against CycloneDX 1.6.
- **Post-quantum key exchange is verified and observable.** The HTTP and gRPC listeners and
  the CLI already negotiate the hybrid `X25519MLKEM768` TLS key exchange (Go's default; nothing
  in Keyorix narrows it). New integration tests assert the negotiated group on a real handshake
  and fail if a listener ever sets `CurvePreferences`. The server counts handshakes in
  `keyorix_tls_handshakes_total{listener,group}`, and `keyorix doctor` shows the group
  (`key_exchange` and `post_quantum_key_exchange` fields in its TLS report; existing fields
  are unchanged). Only the key exchange is post-quantum, not certificates or signatures.
  See `docs/post-quantum-transport.md` for how to verify with `openssl`, the
  `GODEBUG=tlsmlkem=0` revert switch and the behaviour under Go's FIPS 140-3 mode.
- **`GET /api/v1/groups/{id}/roles` returns each grant's `project_id` and `environment_id`.**
  The same role held globally, on a project and on one environment now comes back as
  distinguishable rows (`0`/`0` = global), so a client can show where a role is assigned.
  The group Manage Roles modal lists every grant with its scope and checks a role only when it
  is held at the scope selected above. Additive response fields; no request changes.
- **`keyorix rbac list-roles` shows where each role may be granted** (`[assignable: global|project|any]`).
- **The project Access Review tab shows `degraded` / `degraded_reasons`.** A degraded review warns
  that it may be incomplete and lists the reasons, and an empty degraded list no longer reads
  "No one has access".
- **Journey for invitation role scopes** (SQLite and Postgres): an install-wide role on a project
  invitation and a project-tier role on a global invitation are refused with 400 and create nothing.
- `keyorix-server admin restore` prints a progress line on stderr (table, rows loaded, elapsed) at each table boundary and every 10 seconds inside a large table, so a restore of millions of rows no longer looks hung. Shown when stderr is a terminal, or with the new `--verbose`; the stdout summary is unchanged.
- `scripts/release-qa/restore_compat_matrix.sh --tags N` adds the newest N release tags to the cross-version restore matrix.
- **`keyorix login`, `mfa activate` and `mfa step-up` take their secrets from the environment.** `KEYORIX_PASSWORD` and `KEYORIX_MFA_CODE` (each also as `*_FILE`, same rules as `KEYORIX_ADMIN_PASSWORD_FILE`) work without a terminal. Precedence is flag (still warned), then environment, then prompt. Before this, an MFA-enabled login without a TTY could only succeed with `--mfa-code` on the command line.
- A repository guard (`TestNoDirectEnvReadOfFileCapableVars`) fails when non-test code outside `internal/config` and `internal/secretenv` reads a secret that has a `*_FILE` form directly with `os.Getenv`/`os.LookupEnv`/`syscall.Getenv`, and tests pin that a bootstrap-token or Vault-token file wider than `0600` is refused at boot (#3830). No such read exists today; `KEYORIX_TOKEN_FILE` is already honoured by `keyorix-mcp` and `keyorix-k8s-sync`.
- **`storage.database.native_read_pool_max` sets the size of the Postgres native read pool.** The pool the machine credential lookup and the node-stamp read run on stays at 8 connections unless you set it (1 to 1000, never more than `max_open_conns`; Postgres only, refused elsewhere). The boot-time connection headroom warning counts the configured size. See `docs/CONFIGURATION.md`.
- **Helm: `auditDurability`.** Sets the server's `storage.database.audit_durability` (`strict` or `standard`; empty keeps the backend default). Any other value is rejected by `values.schema.json` and the template. Guarded by `deploy/helm_audit_durability_test.go`.
- **Refused suspend audit writes are now a metric.** `keyorix_audit_owed_failures_total` (authenticated `GET /api/v1/admin/scheduler-metrics` only) counts owed audit rows, such as a plain secret suspend's `secret.suspended`, that the audit log refused. It moves even when the pending record could not be written either, which `keyorix_audit_owed_pending` cannot see. Suspending is still never blocked by the audit log. See `docs/operations/metrics.md`.
- **`storage.database.single_writer` (opt-in, PostgreSQL, one server): holder lock, write fence and write epoch.** With the setting on, the server takes a per-schema advisory lock at start-up (a second server, a server without the setting, and `admin --force` are refused while it runs), installs triggers that refuse every direct database write to the security tables from any other session while it runs, and polls a write epoch with a 1 s lease. If the fence cannot be installed and verified, the server refuses to start. The live state is in the start-up log, `GET /api/v1/system/info` (`database.single_writer`) and `admin validate --posture`, with the emergency two-step for a direct change (docs/single-writer.md). The fence's fingerprint includes the trigger and function catalog rows' versions and any child table, so tampering that is undone before the next poll is still seen, and any inheritance or partitioning involving a fenced table and any change to a fenced table's columns; the fence checks every row (a write through a parent table or partition root is refused), resolves no name through the writer's `search_path` (a temp table or a function or operator of a catalog's name cannot change what it checks), and the poller compares the epoch row's version, so a write that passes the fence is seen even if the writer moves the counter back; the server's session tag is set through a bind parameter (not in `pg_stat_activity`); and `admin validate --posture` reports a deviation when the server's database role is a superuser (below-SQL changes are the one bypass the fence cannot see). The fence also refuses a foreign write to its own holder and epoch rows (it decides from the row as it was), the poller compares the holder row's pid, tag hash and version with its own, a lock another role takes on those tables stalls the poll without costing the server its lock session, and a trigger on a security table that is not part of the fence is reported by `admin validate --posture` and keeps the server from trusting its caches. This release changes no cache: reads still confirm against the database. Off by default; with it off nothing changes, except that a start-up refuses while a single-writer server holds the database and removes a fence one left behind.
- **`storage.database.single_writer`: the server's own writes to the security tables are tracked synchronously.** Every connection of a single-writer server reports its statements to an in-process tracker. A committed write to a fenced table moves a generation before the call returns, which the authoritative caches of the next change validate against. A savepoint rollback inside a transaction does not count as its end. Every move of the database's write epoch flushes the caches at the next poll; one no in-process write explains is also logged as an error and counted (`unattributed_bumps` in `GET /api/v1/system/info`). No cache consumes this yet; with the setting off nothing changes.

### Changed
- **The Kubernetes operator and the k8s sync agent now report "Keyorix could not answer" explicitly instead of a bare `SyncError` / `failed`.** When Keyorix is unreachable, a request times out, or the server answers 5xx, the target Secret is still kept untouched and the sync is retried with backoff, as before. The operator's `Ready=False` reason is **unchanged (`SyncError`)**, so existing alerts keep firing; the new detail lives in the condition message (it starts with `KeyorixUnreachable:`), in one Warning Event `KeyorixUnreachable` raised when the state is entered (not on every retry), and in the metric `keyorix_operator_fetch_errors_total{reason="unreachable|timeout|server_error"}`, which counts each failed reconcile. A Normal Event `KeyorixRecovered` follows the first successful read. k8s-sync counts the target `failed` and `keyorix_unreachable` (`keyorix_k8s_sync_secrets_total{outcome="keyorix_unreachable"}`, `/status` `keyorix_unreachable`, `keyorix_unreachable=N` in the pass summary) and logs `KeyorixUnreachable (reason)`. Classification comes from the transport error and the status code only; a cancelled context and a plain 4xx stay unclassified. Other operator failures (missing token Secret, apply error) are also `SyncError` but have no `KeyorixUnreachable` message. Decision: Andrei, 2026-10-13 (review REVIEW-3175B point 1, alert continuity as for `UpstreamAccessRevoked`). The operator and k8s-sync docs tables are updated.
- **The Kubernetes operator and the k8s sync agent no longer wipe synced Secrets on a 401.** A 401 from Keyorix means the operator's / agent's own credential is invalid, expired or rotated, not that a workload's grant was cut. Every synced Secret is now kept untouched, whatever `prunePolicy` / `pruneOnRevoke` say, and the failure is reported and retried with backoff: operator `Ready=False` keeps its historical reason `UpstreamAccessRevoked` (**for alert owners: the reason still fires on a 401, but the Secret is now kept, not wiped, so `UpstreamAccessRevoked` no longer means "the Secret was removed"; the message now starts with `KeyorixAuthFailed:`**), one Warning Event `KeyorixAuthFailed` on entry, counter `keyorix_operator_auth_failures_total`; k8s-sync counts the target `failed` and `auth_failed` (`keyorix_k8s_sync_secrets_total{outcome="auth_failed"}`, `/status` `auth_failed`, a `KeyorixAuthFailed` log line). Once the credential is fixed the next reconcile syncs normally. The classification comes from the HTTP status alone. A 403 / 404 for a specific secret (grant revoked / secret deleted) is unchanged: it still wipes per `prunePolicy` / `pruneOnRevoke`, behind the mass-revocation circuit breaker. Decision: Andrei, 2026-10-13. The operator and k8s-sync docs now carry a per-cause table (unreachable/5xx/401: keep; 403/404: prune per policy; suspended: `onSuspend`; expired: keep and warn).
- **Generated configs now set `environment:`.** `keyorix-server admin init` writes `environment: production`, so System Health, the dashboard and `keyorix system info` show the environment on source-built installs too (compose and Helm already did). `admin init --dev` writes `environment: local`, not `development`: the exact value `development` also replaces `server.http.allowed_origins` with the localhost dev origins, a relaxation the `--dev` banner does not name. The new tests pin that neither template turns on any dev relaxation.
- **Fewer round trips on a repeated machine secret read.** On a machine-token cache hit for `GET /api/v1/secrets/{id}`, the live credential re-check also reads the secret's node stamp, roles and schedule state in the same statement once this server has already served that machine that secret. The credential is judged by the same code at the same point; refusals, eviction and the network allowlist are unchanged.
- The PostgreSQL audit group commit now sends a batch in a single network round trip when the audit flusher already knows the hash-chain head (it wrote the previous batch), instead of two. The cached head is verified inside the transaction, after the audit lock, before COMMIT; if another replica, a restore or a purge moved the head, the batch is retried through the two-round-trip path, so the chain can never fork. Durability and chain bytes are unchanged; fast audit mode applies as before.
- **Audit-chain verification is incremental: no full walk on a request or at startup.** A
  full walk grows linearly with the audit table, so on large trails `GET /api/v1/audit/verify`,
  `POST /api/v1/audit/checkpoint` and `GET /api/v1/compliance/posture` hit the HTTP write
  timeout, and every start walked the whole chain.
  - The checkpoint scheduler now checks only the rows after the latest signed checkpoint,
    pinning the certified head row. It also re-walks 1/7 of the chain per tick, so every row
    is still re-hashed at least weekly (daily ticks).
  - Progress and results are kept in a signed state row. The row is bound to the signed
    checkpoint trail and carries a generation, so an older signed row that is put back
    (replay/rollback) is rejected. A rejected row is reported (`not_proven` plus a
    `system.audit_verification_state_rejected` audit event), never silently replaced.
    A recorded failure stays until a full verification that started after it and covers
    the failing row succeeds.
  - `/audit/verify` returns that state plus a bounded tail check. A new `status` field is
    `valid`, `broken` or `not_proven`; `valid` is true only for `valid`. Also new:
    `coverage`, `last_full_verification_at` and `rolling_cycle`.
  - `?full=true` runs a full walk as a background job (202 + `job_id`); poll
    `GET /api/v1/audit/verify/jobs/{id}`.
  - Posture reads the persisted result.
  - A restart with a fresh checkpoint defers the first tick.
  - `keyorix audit verify` prints NOT PROVEN (non-zero exit) and gains `--full`.
  - The web compliance page shows "Not yet proven".
  - **Upgrade note:** after upgrading, the status is `not_proven` until the first rolling
    cycle completes (about a week), or until `keyorix audit verify --full` succeeds.
  - Spec: `docs/specs/audit-incremental-verification.md`.
- **"Last used" and "last seen" stamps no longer cost a database write per request.**
  `last_used_at` on personal access tokens and machine credentials and `last_seen_at`
  on sessions are recorded in memory and written in the background, at most once per
  credential every 30 seconds and on a graceful stop, so concurrent requests with one
  credential no longer queue on its row lock. A use shows in the PAT list, the machine
  token list and My Account → Sessions within about 30 seconds; a server killed without a
  graceful stop loses at most 30 seconds of these stamps; replicas never move the stored
  value backwards. No access decision reads these columns. Under a slow or unavailable
  database the stamps degrade instead of piling up: one background flush at a time, at
  most 50 000 pending credentials (a stamp for a further credential is dropped and
  counted in a rate-limited log line), exponential backoff (1 s up to 60 s) after a failed
  flush, and a backlog written in transactions of 500 keys. See `docs/UPGRADING.md` §6r and
  `docs/specs/last-used-coalescing.md`.
- `docs/state-map/entrypoints.tsv` regenerated, and `go test ./internal/statemap` now fails when `docs/state-map/{entrypoints,stores}.tsv` differ from what `go run ./cmd/statemapgen` generates (`statemapgen` gained `-out <dir>`).
- Schema epoch 5 (additive; compatibility floor unchanged): `break_glass_activations.degraded`, `.audit_settled_at`, `pending_audit_events.break_glass_activation_id`. Break-glass activations carry `degraded` / `audit_settled_at` over HTTP and gRPC. The audit-owed banner now counts "audit records", not only suspensions.
- **Hosted demo: the demo seed is the default seed of the nightly reset, and the admin keeps their TOTP across it.** `scripts/demo/seed-demo.sh` gained env hooks for a kit that bootstraps the admin itself: the admin password is read from `KEYORIX_DEMO_ADMIN_PASSWORD_FILE` (never printed), `system init` is skipped when the admin already exists, and alice and security-officer get passwords generated per run into `STATE_DIR/demo-passwords` (0600) instead of the fixed ones from the repository. `deploy/demo-hosted` runs it after every reset with the seed state directory as its argument; the placeholder hook and `--require-seed` are gone and a reset without a seed script fails closed. The reset no longer deletes the key volume and carries the admin's encrypted TOTP secret and recovery codes across the database wipe, so the presenter's authenticator keeps working with MFA required. Checked offline by `deploy/demo-hosted/native-reset-check.sh` (the real `democtl.sh reset` twice on SQLite and PostgreSQL); the container run is pending the e2e VM.
- **The server always mints the request id.** A caller's `X-Request-ID` is no longer adopted as the request id; it is logged as `client_request_id`, and the response's `X-Request-ID` carries the server's id.
- **The anomaly Isolation Forest pass now lives in `internal/anomaly`.** `anomaly_ml.go` and `isolation_forest.go` (pure code: no `*KeyorixCore`, no import of `internal/core`) moved out of `internal/core` with their two tests; `internal/core` keeps aliases, so no caller changed. Detection behaviour is unchanged. First pure-leaf extraction under ADR-121.
- **`verify-release.sh --check-blockers`: the release gate as an opt-in first check (`release.blockers`).** Off by default: open `release-blocker` issues concern the next release, not the tag being verified, so a customer's verification of a published release (with or without `GITHUB_TOKEN`) never includes them and keeps its exit code. With the flag, open blockers are a FAIL (exit 1), and no token, `--offline` or a listing failure is a SKIP (exit 2). The guide (`docs/operator/verifying-releases.md`) says so; the two untested offline steps there (`skopeo copy --all`, a transferred Sigstore trust root) are marked pending e2e VM.
- Test coverage: the first-admin bootstrap now has a two-dialect test proving that a concurrent writer taking the same username answers "user already exists" (no raw constraint text) and leaves nothing seeded. The rename, SCIM, SSO and bootstrap username mappings themselves shipped in #3822.
- **`keyorix-server admin verify-audit` prints a seal's unpinned spans.** The surviving rows before an
  accepted gap that no signed artifact pinned when the loss was accepted were shown only in the
  seal record and the accept-loss plan; the report now names them under each seal, and the JSON
  report carries them as a new `unpinned` field on each seal (no field removed or renamed).
- **An administrator of a secret's scope can revoke a share on it without owning the secret.** Revoking a share (`DELETE /api/v1/shares/{id}`, gRPC `RevokeShare`) was owner-only, so cutting off a recipient during an incident meant taking over the secret first. A user who holds `secrets.manage` (or an admin role such as `project_admin`) at the secret's project/environment can now revoke any share on it, direct or group; the route still requires `secrets.write` there. A narrowed personal access token must allow `secrets.manage` at that scope, machine identities are refused, and an owner who has left the project is still refused. Creating and updating a share stay owner-only. The `share_revoked` / `group_share_revoked` audit entry names the acting administrator and says it was not the owner. The web sharing page still offers revoke only to the owner. Threat model row SHARE-15.
- Bumped `modernc.org/sqlite` to v1.62.0.
- **Dynamic secrets: binding a backend without admin authority is a permission denial (behaviour change).** `POST /api/v1/dynamic-secrets/configs` (and gRPC `DynamicSecretService.CreateConfig`) by a caller who holds `secrets.write` but no admin role at the config's scope answered gRPC `UNAVAILABLE` ("dynamic-secret backend operation failed", which tells a client to retry) and REST 400 with a generic internal-error text. It now answers gRPC `PERMISSION_DENIED` and REST 403 `Insufficient permissions`. A storage fault while resolving the caller's roles answers gRPC `UNAVAILABLE` with the `storage_unavailable` reason and REST 503 `storage_unavailable` + `Retry-After` (was the same untyped `UNAVAILABLE` / 400). Clients that retried on `UNAVAILABLE` stop retrying a refusal.
- **Dynamic secrets: lease refusals answer 409 / `FAILED_PRECONDITION` (behaviour change).** Issuing from a disabled config or past the active-lease limit (or from a sweeper-dependent backend while the sweeper is off), and revoking or renewing a lease that is no longer active, has expired, cannot be renewed or would not be extended, answered REST 502 (as if the target database had failed) and gRPC `UNAVAILABLE`. They answer REST 409 and gRPC `FAILED_PRECONDITION` now, with core's message. A `ttl_seconds` above the maximum answers 400 / `INVALID_ARGUMENT` (was 502 / `UNAVAILABLE`). The REST handler classifies these by sentinel (`core.ErrDynamicSecretPrecondition`); the message-text allowlist `isSafeDynamicSecretError` is gone, so a driver error that happens to contain one of its phrases stays masked. `openapi.yaml` declares 409 on the issue, renew and revoke routes and 400 on renew; the web types and the CLI client are regenerated.
- **Typed validation refusals in the groups, secrets, catalog, pat and sharing families.** 73 core refusals worded "Validation error: ..." were untyped; they match a sentinel now (`ErrValidation` for catalog, pat and sharing, `ErrSecretInvalidInput` for secrets and templates, `storage.ErrInvalidSecretACLRequest` for secret ACLs) with their text unchanged, so the handlers that still match the text answer as before. gRPC `GrantSecretACL` answers `INVALID_ARGUMENT` instead of `INTERNAL` for a user outside the secret's project or an invalid permission set. Two storage faults were worded as validation refusals: a failed read of the target environment while copying a secret (it quoted the driver error after "Validation error:") and a failed read of the requested parent folder while creating a secret (it answered REST 400 "parent folder N not found"). Both are storage faults now (gRPC `UNAVAILABLE` / `storage_unavailable`; REST 500 with the generic text until those handlers map the storage class to 503). New report-only guard `TestEveryValidationRefusalIsTyped`.
- **One classifier turns a core refusal into the HTTP or gRPC status (behaviour change on the routes below).** Handlers and gRPC services used to map core errors with per-route logic (substring matches on translated text, allow-lists ending in `default: 500`), so the same refusal was a 500 on one route and a 403 or 404 on its sibling (#4132, #3979, #4020). A shared classifier (`server/errclass`) now maps the core and storage sentinels to a closed set of classes, rendered by one REST adapter and one gRPC adapter, so the two transports agree by construction. Nothing changes in who is allowed; only the status and text of a refusal. Status changes for an existing request: `GET /api/v1/projects/{id}/machine-identities/{machineId}/tokens` for a machine in another project 500 → 404; `POST /api/v1/secrets/{id}/resume` when the secret's environment was deleted 500 → 404; `GET /api/v1/projects/{id}/stats` for a missing project 500 → 404; `POST /api/v1/secret-templates` with an over-long name or an unknown classification 500 → 400 (error code `ValidationError`); `POST /api/v1/rejection-reason-templates` without a name or reason keeps 400 with error code `ValidationError` (was `Error`); `POST /api/v1/folders` with a name the identifier policy rejects 500 → 400 in every locale; `GET /api/v1/secrets/{id}/certificate` and `GET /api/v1/secrets/{id}/access-log` by a machine token 500 → 400; `GET /api/v1/secrets/{id}/certificate` while the database is unreachable 500 → 503 `storage_unavailable`; `POST /api/v1/projects/{id}/access-review/revoke` of a role the principal does not hold 500 → 404, and on `.../access-review/revoke` and `.../access-review/attest` the "independent reviewer required" refusals (reviewing your own access, a group you belong to, or a machine identity you provisioned) 400 → 403 (the campaign route `POST .../access-review/campaigns/{campaignId}/items/{itemId}/decide` keeps 400); `POST /api/v1/projects/{id}/access-review/attest` with an unknown `source` 500 → 400; `DELETE /api/v1/projects/{id}/machine-identities/{machineId}/roles/{roleId}` for a role the machine does not hold 409 → 404 (parity with `DELETE /api/v1/user-roles` and gRPC `RemoveRole`); `PUT /api/v1/secrets/{id}` validation refusals answer 400 by sentinel in every locale (was 500 under a non-English locale).
- **A storage outage of the permission lookup inside a secret mutation answers 503, not 403 (#3873).** `PUT`/`DELETE /api/v1/secrets/{id}`, `PATCH .../description`, `PUT .../tags` and `POST .../move` authorize inside core; when that lookup failed (database unreachable) they answered 403 "access denied", which no client retries. They answer 503 + `Retry-After` with the fixed "authorization temporarily unavailable, please retry" now, as the gRPC `UpdateSecret`/`DeleteSecret` already did. A real denial stays 403. The last ten #3873 fault-oracle tolerance rows are gone.
- **A refused clear-synced-copies suspend now says how to cut access anyway.** When a
  suspend or project freeze that also clears the copies synced to Kubernetes clusters is
  refused because its audit event cannot be recorded (500, nothing changed), the API
  message, and therefore the CLI and web dialog, ends with "Retry, or suspend without
  clearing to cut access now". A plain suspend is never blocked by the audit log.
- **A DEK that does not unwrap names the leftovers of an interrupted key operation.** The `failed to unwrap DEK — wrong passphrase or corrupted key file` error now names an existing `<salt_path>.pending` (a `rotate-kek` killed between its DEK and salt renames: `mv` it over the salt and start with the new passphrase) and the newest `<dek_path>.migrate-backup.*` (a `migrate-provider` killed after its re-wrap: point `key_provider` at the target), with the recovery from docs/operator/key-rotation-runbook.md, "Interrupted rotate-kek or migrate-provider". What is accepted or refused is unchanged.
- **Admin commands name an unreadable server lock file.** When the SQLite `<database>.server.lock` cannot be opened (a foreign-owned or `0000` file), the refusal now says `cannot open the server lock file: <path>: <error>` and what to fix, instead of `cannot connect to the database`.
- **`admin audit accept-loss` prints the record digest when it stops part way (#3803).** The error of a run that fails after it built its seal record now names `--resume-seal <digest>`, and asks the operator to check that the next plan (run without `--confirm`) shows the same digest before completing it. A resume still writes nothing without `--resume-seal`, even with `--confirm` (since #3852). New tests cover the #3803 tamper scenario (a completed seal rolled back to look unfinished) with a wrong digest, on SQLite and PostgreSQL: the store is unchanged and the command exits non-zero.
- **`storage.database.audit_durability: strict | standard`, `standard` by default on PostgreSQL (ADR-112 Amendment 3).** At both levels the audit row is committed before the secret is returned and a failed audit write fails the request. `strict` also waits for the disk sync; `standard` skips only that wait (`SET LOCAL synchronous_commit = off` on the audit transaction), so an OS crash, power loss or PostgreSQL crash can lose up to ~600 ms of audit entries as a tail, never a gap or fork. Secret writes, revocations and rotations commit durably at both levels. SQLite runs `strict` only and refuses `standard` at start-up. **Upgrade: an existing PostgreSQL install that sets neither key moves to `standard`; add `audit_durability: strict` under `storage.database` to stay on `strict`** (docs/UPGRADING.md §6c). Every start logs one INFO line with the effective level; `admin validate`, `admin validate --posture` (informational, not a deviation) and `GET /api/v1/system/info` (`security.audit_durability`, replacing `audit_durable_sync_skipped` and `audit_durable_sync_skip_not_in_effect_reason`) report it; a level change between starts is audited by the settings diff, which replaces the per-start WARNING and `admin.audit_durable_sync_skipped_at_startup` event.
- **The audit list is ordered by event time, then id, and served by indexes.** `audit_events` gains `(event_time, id)`, `(project_id, event_time)`, `(secret_node_id, event_time)` and `(machine_identity_id, event_time)`; the last two composites replace the single-column `project_id` and `machine_identity_id` indexes. On PostgreSQL they are built with `CREATE INDEX CONCURRENTLY` after the schema migration, so audit writes (and secret reads) continue during the build. An interrupted build is detected and rebuilt at the next start, and a large table is indexed in the background while the server serves. On SQLite they are built during the startup migration, with a progress line per index. During a rolling upgrade, a replica still on an older version that runs its own schema migration can create the single-column indexes again; the next start of this version drops them again (on PostgreSQL, `CONCURRENTLY`).
- **Audit list totals are bounded by default.** `total` is exact up to 10,000 matching events; above that it reads 10,000 with `total_exact: false`. Pages past the newest 10,000 events by `page`/`offset` answer 400 with a pointer to the cursor. Results inside that range are unchanged for existing clients.
- **`GET /api/v1/audit/export.csv` streams** in batches over the index instead of loading the whole export first, and the SIEM export resolves `since` to the lowest id at or after it (exact, whatever the clock skew between replicas) before paging by id.
- **`GET /api/v1/audit/search` answers 400 for an `offset` that is not a non-negative integer**, or that reaches past the newest 10,000 events, instead of silently ignoring a malformed or negative value.
- **Project, environment and alert-escalation-policy audit rows are written by core, not the HTTP/gRPC handlers.** The handlers tag the request context with the actor; internal callers that do not tag it write no row from core, as before. Deleting a project now also owes its machine-identity cascade events (recorded with the delete, appended after it) instead of logging them best-effort. A SCIM `active=false` on a user who is already inactive revokes nothing and fails closed.
- **`admin init` names the database backend it set up (#3523).** For SQLite it prints `Database: SQLite (storage.type "sqlite"), file <path> created|already present`; a PostgreSQL config still creates no SQLite file and says so.
- **`server.grpc.tls.auto_cert: true` is refused at start-up.** gRPC has no ACME client: with gRPC TLS enabled the server started and every handshake failed, and with it disabled the listener served plaintext. `Config.Validate` and the gRPC server now both refuse the flag with a message naming the key; set `cert_file`/`key_file` instead (docs/UPGRADING.md §6t). `server.http.tls.auto_cert` is unchanged.
- **Dormant role grants use the recertification cadence as their threshold (#3459).** The compliance posture, the `dormant-access` control and the digest used to call a grant dormant after a fixed 90 days without use. They now use `recertification.cadence_days` (default 90, at most 366), the same window the access review's "last used" already uses. With the default cadence nothing changes. A shorter cadence flags more grants, a longer one fewer. See `docs/recertification-activity-window.md` and `docs/UPGRADING.md` §6w.
- **`.githooks/pre-push` now also catches two cheap merge-queue failures locally.** When the diff adds, removes or renames a `FuzzXxx` function or touches `scripts/fuzzing/targets.{conf,d}`, it runs the fuzz-targets checks (`gen-targets-conf.sh --check` plus the real-functions-vs-`targets.d` comparison, via `git grep` instead of compiling every package). When the diff adds or removes a root-module Go package or touches the review-coverage ledger, it runs `scripts/check-review-coverage.sh` (about 2 s). Each prints one line and a fix hint; a missing tool skips the check quietly; `git push --no-verify` still bypasses. The hook no longer exits early when `golangci-lint` is missing or no Go file changed, so the base-branch warning also runs on those pushes. Self-check: `scripts/pre-push-hook-test.sh`.
- Helm chart: `postgresql.auth.password` no longer ships an empty placeholder in `values.yaml` (CodeQL js/empty-password-in-configuration-file); the key is documented in a comment and the render still fails when no database password is supplied.
- **Refused secret flags and a bad `keyorix doctor --output` exit 2** (usage error); `doctor` is in the exit-code table of `--help` (exit 1 when a check failed). `doctor`'s `reachable` check shows the same plain-language transport description as every other command. Help examples use `-o json`, and a guard fails on any example that teaches a deprecated flag.
- **Dynamic-secret create/issue against a private-network target** answers with what was refused and which setting allows it (`dynamic_secrets.insecure_allow_private_network_dynamic_secret_targets`) instead of "an internal error occurred". The address a hostname resolved to and the DSN's credentials are not in the response.
- **`keyorix break-glass list` and the project Break-glass tab name the activating user.** The CLI's USER column prints the username (the ID when the server sends none, e.g. a deleted user); the web page uses the username for a user who is no longer in the project's member directory, and `User #<id>` only when there is neither. The gRPC break-glass list is unchanged (it carries no username).
- **`keyorix audit search --actor` help says what the server matches:** a case-insensitive partial match on a user's username or a machine identity's name. `docs/cli-reference.md` and the man page are regenerated.
- **`keyorix doctor` reports the token source from the same resolver the other commands use.** The `token from KEYORIX_TOKEN`, `KEYORIX_TOKEN_FILE` and `the credentials file` wording is unchanged. A token file that is unreadable, empty or too permissive is still reported as such, and the token is never printed.
- `keyorix`'s one-line description is now "Command-line client for the Keyorix secrets manager" (it was "Keyorix CLI -- see ADR-108").
- **The CLI exits with a code that says why it failed, and every failure names the next step.** `0` ok, `1` refused/failed, `2` usage error, `3` not logged in or session rejected (HTTP 401), `4` permission denied (403), `5` not found (404), `6` server unreachable or TLS certificate refused. The table is in `keyorix --help`. Before, every failure exited 1.
- **Plain-language messages instead of Go errors.** "not logged in: run `keyorix login --server <url>`" replaces `no server configured ... lstat ...`; a down server, a wrong hostname, a private-CA certificate and an https URL against a plain-http server each get one sentence with the fix (`--ca-file`, `keyorix status`) instead of `Get "...": dial tcp ...`; a 401 says to run `keyorix login`, a 403 says how to request access. A panic prints a one-line internal error (stack trace only with `KEYORIX_DEBUG=1`).
- **`--project` and `--env` are accepted on every CLI command that names a project or an environment.** Commands that defined `--project-id`, `--environment` or `--environment-id` keep those spellings and now also take the canonical one (`keyorix pat create --project 3 --env 5`). Commands that define both `--project` and `--project-id` with different meanings (`run`, `request`) are unchanged.
- Internal rename only: the one-time-password validity settings are now `OneTimePasswordExpiry` / `RecoveryOneTimePasswordExpiry` in code (config keys `security.one_time_password_ttl` and `security.recovery_one_time_password_ttl` are unchanged). Clears ten CodeQL clear-text-logging false positives caused by the old names.
- Internal refactor, no behaviour change: the federated-JWT verifier (`OIDCVerifier`, `OIDCTrustedIssuer`, `JWKSResolver`, `HTTPJWKSResolver`) moved from `internal/core` to the new leaf package `internal/oidcverify`, and `PATRestriction` and `Scope` moved to `internal/core/rules`; `internal/core` keeps every name as an alias. The fuzz targets `FuzzOIDCVerifierVerify`, `FuzzOIDCVerifierClaims` and `FuzzPATRestrictionAllows` moved with them, so their coverage map shrinks from about 481 KiB to 57 KiB and 35 KiB (ADR-109 Step 7, ADR-121).
- **The exemption-ledger review test (`TestExemptLedgers_EveryRowIndependentlyReviewed`) now reads each `docs/*exempt*.tsv` dual-way: the flat file plus every `*.tsv` in the sibling `<name>.d/` directory.** A key present in both the flat file and a fragment (or in two fragments) is reported with both locations. This lets `scripts/ledgers/migrate-to-fragments.sh` move `docs/check-then-act-lock-exempt.tsv` into fragments without every `.reviewed.tsv` row reading "matches no row". Test-only; no behaviour change.
- **Admin dashboard: failed logins, failed second factors and refused secret reads are three separate figures, never summed.** "Failed Logins (24h)" counts failed password/SSO logins only (`auth.login_failed`). The new "Failed Second Factors (24h)" card counts a refused second factor: a wrong TOTP or recovery code (`mfa.failed`) and a refused passkey assertion (`webauthn.failed`), counted by action so rows written before they were stored with `success=false` still count; `mfa.error` (a fault, no verdict) stays out. "Refused Secret Reads (24h)" is unchanged. `GET /api/v1/dashboard/stats`: `failedAuthAttempts24h` is now password/SSO failures only, and the new `failedSecondFactors24h` carries the second-factor count. Only `failedAuthAttempts24h` has a trend, so on the first dashboard snapshot after upgrade its arrow compares against an older count and can read as a one-day drop. This replaces the unreleased sum-with-breakdown (`failedLoginsWrongPassword24h`, `failedLoginsWrongSecondFactor24h`), which never shipped in a release.
- **Postgres audit commit: the id allocation and chain-head read are cheaper on the server.** The first audit flight looks up the `audit_events` id sequence once per statement instead of once per allocated id (a subquery the planner could inline ran `pg_get_serial_sequence` per row), and the chain-head read carries `LIMIT 1` in its text, so Postgres reuses its cached plan instead of planning it again on every flight. Same statements, same order, same lock and checks; guarded by `TestAuditAllocateIDsSQL_PostgresLooksUpTheSequenceOnce` and `TestCommitBatchAttempt_PostgresHeadReadReusesItsPlan`.
- **`audit_events` no longer indexes `prev_hash` and `entry_hash`.** No query looks an audit row up by either hash: chain verification, the chain head, checkpoints and anchors all read `audit_events` by `id`. The two indexes held random 64-character keys, made up most of the table's index storage, and were updated on every audit INSERT. The next boot drops them on SQLite and Postgres (`DROP INDEX IF EXISTS`, a short exclusive lock on `audit_events` on Postgres); fresh installs never create them. Downgrade: an older release recreates them on its first boot (`CREATE INDEX IF NOT EXISTS`), so no manual step is needed either way. Guarded by `TestAuditEventHashIndexes_DroppedOnUpgrade` (SQLite) and `TestAuditEventHashIndexes_Postgres_DroppedOnUpgrade`.
- **Pilot docs truth fixes (#3449, #3743).** `docs/CONFIGURATION.md` and `docs/SELF_HOSTING.md` now say which side verifies what for the server's `tls.cert_file` (the certificate it presents) and the CLI's `ca_file` (what the client trusts, e.g. the same self-signed `cert.pem`). `docs/UPGRADING.md` uses the `v` prefix for release versions and gives the exact steps to delete the deprecated `secrets.chunking` and `secrets.limits.max_secrets_per_user` keys after an upgrade (they are ignored today; the warning says they will be rejected after the next minor release). `docs/adr-062-air-gap-updates.md` now says the audit-checkpoint and evidence signing keys derive from the KEK, not the DEK.
- **Upgrade note: the first audit scans after an upgrade walk the history once.** Two background jobs do a one-off catch-up over the existing audit table, then read only new rows. Neither blocks startup and neither needs any action (the recover-admin walk is also described in `docs/UPGRADING.md`, section 6j). (1) The `recover_admin_alert` job (every 10 minutes) stores the highest audit id it has examined. An install that has never used recover-admin has no stored mark, so its first run reads ids from 0 up to the current highest id, in windows of 100,000 ids, saving the mark after each window. A restart or lease handover resumes at the last saved window, and each recover-admin use is still alerted exactly once. An install that has used recover-admin resumes from its last alerted id. (2) With audit checkpoints enabled, the audit-checkpoint scheduler re-walks the whole chain in 7 segments, one per tick (the default tick is 24 hours, so about a week; each segment is at least 100,000 ids). Until that first cycle completes, `keyorix audit verify` reports `NOT PROVEN` rather than `VALID`; run `keyorix audit verify --full` to get a definite answer immediately.
- **The web container's `/health` answers by status only.** `web/nginx.conf` asks the backend's `/health` through an internal subrequest and returns `200 healthy` when it answers 2xx and `503 unavailable` otherwise; the backend's response body is no longer proxied through the web container, so backend health detail does not leave through it. `/nginx-health` stays a local static `200`. Guarded by `internal/config/web_nginx_health_guard_test.go`. `nginx -t` and a real-container run (backend scaled to 0 gives 503) are pending an e2e VM run.
- **`admin init` refuses to generate a TLS certificate on an implausible clock.** A certificate stamped from a clock that was never set (the epoch, for example) would be expired as soon as the clock was corrected and, with TLS required, would take the server with it. The error says to set the clock or supply your own certificate and key.
- **Secret encryption and the key-file wrap no longer pass their own AES-GCM nonce.** The encryption service and the DEK wrap (`dek.key`) now use Go's `cipher.NewGCMWithRandomNonce`, which draws the nonce itself; before, both used `cipher.NewGCM` with a nonce read from `crypto/rand`, which `GODEBUG=fips140=only` refuses, so every encryption failed in that mode (other parts of the server are not yet checked under it). The stored format is unchanged in both directions: data and key files written before this change decrypt, and data written after it decrypts with the previous release (rollbacks and mixed-version replicas keep working). `admin validate --posture` shows one informational line with the Go FIPS 140-3 runtime mode (`off`, `on, not enforced`, `enforced`); it reports the runtime setting only. Guard: `internal/encryption/gcm_compat_test.go` (vectors written by the previous code, a run under `GODEBUG=fips140=only`, a source scan for caller-supplied GCM nonces).
- **Secret value reads refused by the secret's own state now answer a client error with a stable code, not 500 / Internal.** On every value-read route (REST `GET /api/v1/secrets/{id}?include_value=true`, `GET /api/v1/secrets/value?ref=`, `POST /api/v1/projects/{id}/secrets/render`; gRPC `GetSecretValue`), for human and machine callers: a read outside the secret's access schedule is 403 `SecretAccessOutsideSchedule` (gRPC `PermissionDenied`); an expired, suspended or max-reads-exhausted secret is 409 `SecretExpired` / `SecretSuspended` / `SecretMaxReadsExhausted` (gRPC `FailedPrecondition`), with a fixed message and, on gRPC, an `ErrorInfo` detail carrying the code. 409 rather than 410 because each state is reversible. A caller who cannot read the secret still gets exactly the 403/404 it got before (no existence oracle), and refused reads still write no audit row. The human `GET /secrets/{id}` answer for a schedule denial keeps its 403 but its `error` changes from `Forbidden` to `SecretAccessOutsideSchedule`; a metadata `GET /secrets/{id}` of an expired secret is now 409 `SecretExpired` instead of 500. OpenAPI documents the new `SecretReadRefused` response.
- **Clients say why.** The CLI prints the reason and the command that lifts it (`secret resume`, `secret update --expires/--clear-expiration/--max-reads`, `secret get-schedule`); `keyorix run` and `secret export` warnings carry the reason instead of "could not fetch value". The web Reveal and copy actions show the server's reason, and a schedule refusal no longer raises the generic "no permission" error. The Kubernetes operator and the k8s sync agent never delete a synced Secret for a suspended or expired source and keep it for a schedule or max-reads refusal (see the source-state entry below); the MCP server names the refusal instead of "not authorized".
- **Stricter validation of responses from external backends.** Responses that do not have the expected shape are now errors instead of being accepted. Vault connector: the mount-info reply must carry `data.path`; a null, absent or empty `options`, or an empty `options.version`, is KV v1 (as in Vault's own KV preflight), and any other `options.version` must be `"1"` or `"2"` (a refused reply is not cached); an empty or non-object KV payload is not a successful read, so reading a KV v2 secret whose data map is empty is now an error; the token lookup must carry a numeric `data.ttl` (an explicit `0`, as reported for root tokens, is unchanged). Kubernetes dynamic engine: only 2xx statuses are success for TokenRequest, Secret create and Secret delete, and `Issue` requires a parsable, future `expirationTimestamp`. k8ssync Keyorix fetcher: only 2xx statuses are accepted, an empty or missing secret value is an error (a legacy secret with an empty value makes each sync cycle report an error and keeps the previously synced copy), an environment or secret id of 0 is refused, and server-supplied error text is stripped of control characters, truncated and quoted before it is logged.
- **Bounded redirect handling.** The JWKS, OIDC discovery, evidence webhook, SIEM forwarder and notification webhook clients refuse a redirect after three requests, compare the full host (port included) instead of the hostname, and still refuse an https to http downgrade.
- **Azure Key Vault connector error bodies.** Non-success responses reach the Azure SDK with a short fixed body (status code, headers and a plain `error.code` are kept), so the SDK no longer parses attacker-sized nested error JSON. The server's error message text is no longer included in connector errors.
- **First-run messages lead a new user through the real steps.** The server's generated-bootstrap-token log line no longer says to "retrieve the full token from KEYORIX_BOOTSTRAP_TOKEN" (a variable the user never set; the token is only logged masked) and names `KEYORIX_BOOTSTRAP_TOKEN_FILE` and `admin generate-secrets` instead. `keyorix system init` prints the MFA enrolment steps and the `--username` to log in with (secrets stay locked until the admin has a second factor). `keyorix-server admin init` lists its next commands in the order that works (keys, schema, validate) and adds the recovery key. `keyorix login` says where credentials are stored and that `KEYORIX_PASSWORD[_FILE]` exists, and its no-input error names the file form. `keyorix mfa enroll` no longer says "scan" when it prints no QR code. No default or security check changed.
- **A webhook signing secret or audit checkpoint key under 14 bytes now warns outside `GODEBUG=fips140=only`.** With the webhook channel enabled and a shorter `notifications.webhook.signing_secret` (or `KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET`), the server logs a `WARNING` at boot. `admin verify-audit` prints a `WARNING` to stderr for a `--checkpoint-key-file` or `--previous-checkpoint-key-file` under 14 bytes. Both keep working as before, and the warnings name only the length. Under `GODEBUG=fips140=only` these keys are still refused.
- **Server builds use profile-guided optimisation.** `server/default.pgo` is a merged CPU profile of the server under the benchmark workload; `go build ./server` (Makefile, release and the server Dockerfile) applies it automatically. Refresh it each release with `scripts/pgo/refresh.sh` (`docs/pgo.md`).
- **`scripts/ci/guard-inputs.tsv` is now a dual-read ledger: a new guard test adds one fragment under `scripts/ci/guard-inputs.d/` instead of a line in the shared file.** The file was touched by 22 PRs in 14 days and sat in 48 overlapping-PR pairs, the most of any file, and every new guard test had to add a row. `guardinputs.LoadMap` reads the legacy file plus every `*.tsv` fragment (exactly one row each, sorted by file name, a duplicate key between the legacy file and a fragment or between two fragments is an error naming both places), so `guardinputs select`, `TestGuardInputsCoverSkippedPaths` and `TestGuardInputsMapIsLive` see fragment rows unchanged. The "no row" failure of `TestGuardInputsCoverSkippedPaths` now names the fragment file to create. `scripts/ledgers/migrate-to-fragments.sh` lists the ledger; the existing rows move in a later quiet-window run.
- **Schema compatibility floor 3: a v0.96.x binary refuses to start against a database this release has migrated; rollback is a restore** (UPGRADING.md §6q; the schema epoch is 7 in this release, the floor stays 3). Rolling upgrades with several replicas: see SELF_HOSTING.md, "Running more than one replica" (upgrade order, what is shared, what to avoid while old and new replicas run).
- **The chart refuses `server.replicas > 1` without Secret mode, and with a ReadWriteMany keys volume.** Moving an existing install: export its keys with `key-secret export`, create the Secret, set `server.keysSecret.*` and `server.keysPersistence.enabled=false` (the old PVC is kept). Back up the key Secret apart from the database backups.
- **Helm web pod is Ready only when the backend answers.** The chart's web nginx answered `/health` with a static `200`, and both the readiness and liveness probes used it, so the web pod stayed Ready while the server Service was down. `/health` is now proxied to the server Service (2s connect / 3s read timeout) and is the readiness probe; a new static `/nginx-health` is the liveness probe, so a backend outage takes the web pod out of the Service endpoints without restarting it. Upgrade note: a load balancer or monitor that probes the web Service's `/health` now sees 502/504 while the backend is down; probe `/nginx-health` to check the web container alone. kube-score's `pod-probes-identical` ignore on the web Deployment is removed. Guarded by `deploy/helm_web_probes_test.go`. Container check of the real nginx: pending e2e VM.
- **The backend's HSTS header no longer includes `preload` by default.** The value is now `max-age=31536000; includeSubDomains`, the same as the web nginx's default. Preload-list submission covers the whole registrable domain, so only the domain's owner should opt in. If your domain is on the browser preload lists and the backend serves TLS directly, set `server.http.hsts_preload: true` to keep sending `preload`.
- **`keyorix status` prints the credential file it reads** (`Credentials file: <path>`, also when no server is configured yet), and `keyorix status --help` explains that the file is per OS user and how `XDG_CONFIG_HOME` (Linux) or `HOME` (macOS) separates two installs. QUICK_START.md documents the same.
- **Shared ledger rows moved into one-row fragments.** The 280 existing rows of `docs/adr-conformance-enforced.tsv` (49), `docs/review-coverage.tsv` (68), `docs/check-then-act-lock-exempt.tsv` (31) and `scripts/ci/guard-inputs.tsv` (132) now live as one file each in the sibling `<name>.d/` directories (`scripts/ledgers/migrate-to-fragments.sh`, rows moved byte-for-byte). The flat files keep only their header comments, so two PRs that add or edit ledger rows no longer conflict on one shared file.
- **Breaking:** the legacy roles `admin`, `editor`, `viewer`, `auditor` and `super_admin` are install-wide only and can no longer be granted on a project, to users, groups, machine identities or through invitations (#3605, #3588). The refusal names the replacement (`project_admin`, `project_developer`, `project_viewer`, `project_auditor`). Grants already held on a project are not changed and keep working; `keyorix-server admin validate --posture` and the startup log list each one with the commands to replace it. See `docs/UPGRADING.md`.
- **The start that tightens the legacy roles to install-wide now says so.** When `admin`, `editor`, `viewer`, `auditor` or `super_admin` is moved from `any` to `global` (#3605), the server logs one line, `storage: tightened assignable_scope of N legacy role row(s) from any to global`, with the number of role rows changed. It is a log line only, not an audit event, and a start with nothing to tighten (including a fresh install and every later start) logs nothing.
- **The upgrade check also lists pending access requests that suggest a legacy role.** `keyorix-server admin validate --posture` (a `WARN`, not a deviation) and the startup `WARNING` now name each pending project access request whose suggested role is `admin`, `editor`, `viewer`, `auditor` or `super_admin`, with the request id, the requester, the project and the project role to approve it as. Approving with the legacy role is refused since #3605; the check changes no request. Expired, approved and rejected requests are not listed.
- The break-glass list response carries an additive `username` per activation (omitted when the user cannot be read); the `break_glass.activated` and `break_glass.revoked` audit descriptions already name the user like `role.assigned` does (#3741). The OpenAPI description of the audit-search `actor` filter now matches its behaviour: user or machine-identity name, case-insensitive, partial.
- **List endpoints no longer issue a query per row for names, shares and tags.** The secrets list (and the dashboard counts built on it), the audit log and search views and the shares list resolved usernames, share records, shared secrets, ACL grants and tags with one statement per row or per distinct actor; they now use one batched lookup per kind. A 1000-secret project list went from about 1180 statements to 15 with an identical response. Responses, ordering and pagination are unchanged.
- **More list endpoints no longer query per row.** The users list (project counts), the project access review, the secrets inventory CSV and the machine audit report now use one batched lookup per kind instead of per user, secret, owner or identity: a 100-user page went from 305 statements to about 15, a 1000-secret access review from 1690 to a few dozen, the machine audit report from 204 to 5. Responses and pagination are unchanged.
- **`single_writer` emergency SQL: the server now restarts.** After `SELECT pg_terminate_backend(holder_pid) FROM keyorix_sole_writer` the server exits 1 instead of running on with confirming caches; its supervisor starts it again, which closes the write fence again. Run the terminate and the change in one `psql` call (`docs/single-writer.md`, "Emergency SQL").
- CI merge-queue test selection: a `_test.go` file under `internal/testutil/` no longer forces the full suite, and rule-3 literals are read with a Go-aware scanner (comments and import paths ignored; rune literals no longer hide real literals).
- **Fewer statements per audited request on PostgreSQL.** The audit group commit now inserts the batch's audit events and checks that they chain onto the current head, in id order, in one statement instead of three (the head check, the INSERT and the link check). The checks are unchanged and still run inside the transaction under the KEYAUDIT lock, before COMMIT. Statement counts per audited read/write are pinned by `TestAuditStatementsPerRequest_Postgres`.
- **Anomaly detection checks each alert key once per pass.** A detection pass used to run the duplicate-alert check (a count over `anomaly_alerts` in its own transaction) for every access-log row in its window, so under a steady read load it cost one database transaction per read. It now runs once per alert key (secret, type, principal, IP) per pass and records the same alerts. Per-access alerts now carry the pass's start time as `detected_at`, like the per-secret and ML alerts already did (a difference of at most the pass's own runtime).
- **A human secret read decides its permission once.** A session or user-token read of `GET /api/v1/secrets/{id}` (and the gRPC `GetSecret`/`GetSecretValue`) evaluated the per-secret decision twice, in the route gate and again in core, and read the access schedule twice. The core read check now reuses the gate's allow for the same user and secret, kept on a request-scoped memo that is used once and never outlives the request, and the value step reuses the schedule/version snapshot the read check took. Fewer round trips per read; the allow/deny decisions, responses and audit rows are unchanged (before/after equivalence over a generated matrix of grants, secret, account and project states: `TestHumanReadGateReuse_Equivalence`).
- **Fewer round trips per audit group commit on PostgreSQL.** The audit flusher now sends its transaction in two pipelined network flights (BEGIN, the audit lock, the chain-head read and the id allocation; then the INSERTs and COMMIT) instead of waiting for each statement in turn. Durability is unchanged: in the default mode every audit row is still durably committed before the request that produced it returns, and the fast audit mode still only skips the wait for the disk sync. The hash chain is byte-identical, a failed or interrupted batch still commits nothing, and `keyorix audit verify` is unaffected. SQLite is unchanged. Guarded by `INV-STORE-audit-pipelined-commit`.
- **Fewer database round trips on the machine-token secret read path.** The statement that confirms the
  cached secret now also returns the machine's roles at its scope and, for a value read, the schedule and
  version state, so the permission and schedule/version reads no longer run as separate statements.
  Authorization decisions, per-request freshness (a revoked role is seen on the next request) and the
  per-read check that the cache trigger is present are unchanged.
- **Audited reads at high concurrency with `single_writer`: the audit flusher keeps two batches in flight on PostgreSQL.** While one batch of audit rows commits, the next is already built and queued behind it on the same database connection (pipeline mode, one transaction per batch), so PostgreSQL starts it the moment the first commits. Each batch is chained onto the last row of the batch before it and checked inside its own transaction, so it commits only after that batch committed and while it is still the chain head; every read is still answered only after its own audit row committed (audit before disclosure). A failed batch fails closed for its own readers and the batches after it are retried in order. Without `single_writer` (where every read also runs its credential statement and the flusher is not the bottleneck), at low concurrency, on SQLite, behind a non-pgx pool and with a configured `audit_flusher_linger_window`, the flusher commits serially as before. New metric `keyorix_audit_flusher_pipelined_batches_total`. Design: `docs/specs/audit-pipelined-commits.md`.
- **Fewer indexes on the audited-read path (PERF-INDEX-1).** Dropped the unused audit_events (machine_identity_id, event_time) index. secret_access_logs: (secret_node_id, access_time) and (secret_node_id, action) are replaced by one (secret_node_id, access_time, action) index (total_reads is still answered from the index alone), and on PostgreSQL the (access_time, secret_node_id) btree is replaced by a BRIN on access_time (SQLite keeps the btree). On PostgreSQL the new indexes are built and the old ones dropped with CONCURRENTLY after the migration, so audited reads keep writing; SQLite does it inside its migration. No query changes. Older binaries recreate their own indexes and ignore the new ones, so there is no schema-epoch bump; the epoch-5 schema snapshots were re-recorded because the indexes are no longer created by migrateDatabase.
- **Startup refuses an audit id sequence with `CACHE` > 1 on Postgres.** The pipelined audit commit needs `audit_events` ids handed out in lock order; the boot-time check fails with `ALTER SEQUENCE ... CACHE 1` as the fix instead of failing every audit write later.
- **Less CPU per machine-token request.** The credential lookup scans its time columns through `sql.NullTime`, which avoids a per-row reflection check of `time.Time`'s method set in the Postgres driver. Results are identical; `TestCredentialLookupRaw_TimesMatchDirectScan` compares with the previous scan on SQLite and Postgres.
- **Less CPU per machine secret read.** The combined node-stamp/roles/schedule statement on the read path is scanned into named variables instead of through gorm's reflection scan, which also re-rendered the statement text (regexp) on every call. Results are identical; `TestReadPathPrefetchScan_MatchesGormScan` compares both scans row for row on SQLite and Postgres.
- **Access log no longer serialises requests on the global logger lock.** The per-request access line keeps the same fields, format, destination and redaction, but is written through a writer whose lock covers only an in-memory append; lines are still written whole and in order.
- **New `server.access_log.on_sink_stall` (`block` | `drop`, default `block`).** When the log sink stalls and the 1 MiB queue is full, `block` makes requests wait (no line is ever lost); `drop` keeps serving, and drops, counts and reports the overflow: `access_log_dropped` and `access_log_on_sink_stall` in `GET /api/v1/system/info`, a warning at most every 10 s, a recovery line, and the mode at startup and in `admin validate`. The audit trail is unaffected. Helm: `server.accessLog.onSinkStall`.
- **Less CPU per machine secret read on PostgreSQL.** The credential re-check and the secret's node read now run on a native pgx connection pool owned by the storage layer, with the same statements, binds and results. The pool uses the same connection settings as the main pool (DSN, password, TLS), holds at most 8 connections (never more than `storage.database.max_open_conns`), and is counted in the start-up connection headroom warning. SQLite is unchanged.
- **`admin backup` refused on a key-rotation staging file exits 4 and prints a structured line.** A leftover `kek.salt.pending` (or a DEK `.pending`) refuses every backup; that refusal now exits with status 4 instead of 1 and prints one stderr line `keyorix-backup-refused reason=key-rotation-staging-file exit_code=4 files="<files>"`, so cron can tell "backups are blocked until someone acts" from any other failure (still exit 1). The refusal itself, its remedy text and the rule that a DEK `.pending` is never removed are unchanged; `admin validate --posture` keeps reporting it. Upgrade note: a wrapper that tested for exit status 1 specifically should test for non-zero, or for 4 (#4105).
- **The SSO-only-administrator posture warning says how to fix it, and says it louder without a recovery key.** When every administrator is managed by an identity provider, `admin validate --posture` now names the remedy (create a local break-glass administrator with `keyorix user create` and `keyorix rbac assign-role`, keep its credentials offline) and, when no recovery key has been generated, says that `admin recover-admin` cannot help either and to run `admin recovery-key rotate`. Still a WARN: the posture exit code is unchanged (#2914).
- Helm chart: the server container now has a startup probe (`/health`, 3 minutes for a first boot) in front of liveness (`/health`) and readiness (`/readyz`), all with explicit period, timeout and failure thresholds instead of fixed initial delays. Tune with `server.probes.{startup,liveness,readiness}`.
- Helm chart: the built-in fallback resources of the server and web containers (used when `server.resources` / `web.resources` are unset) now equal the `values.yaml` defaults, ephemeral-storage limits included, so GOMEMLIMIT and pod sizing no longer depend on how the chart was installed.
- Helm chart: the pod-hardening guard now also covers init containers and the `helm test` pod (drop ALL capabilities, no privilege escalation, read-only root filesystem, non-root, RuntimeDefault seccomp), not just the Deployment containers.
- **Project-name uniqueness is the same on SQLite and PostgreSQL.** The partial unique index on live
  project names was on SQL `LOWER(name)`, which folds ASCII only on SQLite but follows the database
  locale on PostgreSQL, so the two backends accepted different sets of names (for example `ÄÖ` and
  `äö` as two projects on SQLite only). Projects now carry a `name_folded` column (NFC plus case
  folding, computed in Go like `username_folded`), the same index name `uniq_projects_name_active`
  is built on it, and `GetProjectByName` looks up by it. On upgrade the column is added and
  backfilled; if two live projects fold to the same name the upgrade stops with an error that names
  the folded value and the project ids, and changes no row: with the server stopped, rename one
  project of each group (the error gives the `UPDATE projects SET name = ...` statement) and restart. Soft-deleted projects are not checked. Project names created through the API, CLI or
  gRPC were already limited to letters, digits, spaces, `-` and `_`, so existing installs are
  unlikely to be affected.
- **Database reads now name their columns.** GORM `QueryFields` is on for both backends, and the few raw `alias.*` queries list their columns. A column added by the next release no longer makes this release's replicas fail (Postgres "cached plan must not change result type", HTTP 500) during a rolling upgrade. This protects upgrades from this release onward; see `docs/rolling-upgrade-columns.md`.
- **The last `alias.*` read is gone.** The GORM fallback of the machine-credential lookup now lists the credential columns explicitly, and `TestNoStarSelectInProductionSQL` no longer has an allowlist entry for it, so the guard covers every production query.
- **RELEASING.md "What the tag publishes" matches the workflows.** It now lists all six images (adds `keyorix-k8s-sync`, `keyorix-operator`, `keyorix-mcp`), all three signed Helm charts, the 32 release assets, the SLSA provenance and the nightly `main` image build.
- **DEK `created_at` in the crypto inventory** is read from a `dek.created_at` system_metadata row (PostgreSQL), written when the DEK epoch is seeded and in the transaction that makes a rotated DEK current, and used only when it names the epoch's current DEK (a failed or interrupted rotation does not re-date the old DEK). Otherwise it falls back to the key file's mtime and is flagged `created_at_estimated` (CBOM property `keyorix:created-at-estimated`).
- **Backup archive asset fails closed with Shamir share files.** When `shamir_share_files` are configured (primary or fallback provider), `admin backup` archives those plaintext shares, so the inventory no longer credits the archive as AES-256-GCM: the asset is scored unknown (medium) and a warning suggests `shamir_share_env`.
- **SAML and database TLS inventory scope.** SAML signing certificates are only those Keyorix trusts: the IdP descriptor of the entity the SAML provider selects (the root entity, or the first with an IDPSSODescriptor in a federation file); SP, role and other entities' keys are no longer listed. A CA bundle over 16 certificates or an IdP with more than 8 signing certificates is still capped, now with a warning. With `sslmode=disable` the database TLS files are not listed as in use (a note says so).
- **"Last used" in access recertification is bounded to the review period.** The per-user last-activity lookups behind the project access review, campaign items and the dormant-grant count no longer scan the whole audit log: they read `event_time >= now - N days` on the existing `(project_id, event_time)` index, where N is `recertification.cadence_days` (default 90, at most 366; the dormant-grant count uses its 90-day threshold). "No activity" now means "no activity within the last N days", not "ever": the API (`activity_window_days`), the web UI, the campaign CSV (`last_used_window_days`, `all_history` for older campaigns) and the `dormant-access` control state the window. New default-0 column `access_review_campaigns.activity_window_days`, added automatically. See `docs/UPGRADING.md` §6w and `docs/recertification-activity-window.md`.
- **Key operations refuse while an interrupted restore is unresolved.** `admin encryption rotate`, `rotate-kek`, `upgrade-aad`, `migrate-provider` and `init` now refuse with the restore journal's message (`run keyorix-server admin restore --recover`) instead of writing key files the recovery is about to replace. Without `--overwrite-existing`, `admin restore` also refuses an existing `keyset.manifest.json`, like an existing key file.
- **Upgrade: the first start adopts the existing key files.** An install without a manifest (every install before this version) or with an unparseable one starts normally: the current files are recorded once, with a WARN and an `encryption.keyset_manifest_adopted` audit event. An incomplete key set is still refused. Run every key operation with the same `keyorix-server` version as the server: an N-1 admin binary does not maintain the manifest, and the next start refuses the keys it wrote (docs/UPGRADING.md §6za).
- **The access-review campaign warning in the CLI prints the server's `degraded_reasons`** instead of
  claiming that shares could not be read: a campaign can also be degraded by a grant on an
  environment with no project. It says so when the server gave no reason.
- **The user role editor (Admin page) no longer offers project-tier roles.** It replaces a user's
  roles at the global scope, where the server refuses them; they are shown read-only and left out of
  the submitted `role_ids`. Assign them from the project.
- **The Edit Role modal disables "Can be granted" for built-in roles** (the server refuses every
  update of one) and says why. The web's built-in list now matches the server's, so the `system_*`
  and `project_*` roles are marked Built-in too.
- Restore runbook (`docs/operator/restore-failure-modes.md`): recovering from a PostgreSQL restore killed during the load is `admin restore --recover` followed by `admin restore --input ... --overwrite-existing`, with what each step checks.
- **A changed `*_FILE` secret needs a restart.** Secrets resolved through the server config (DB password, SIEM/SMTP/webhook/SCIM tokens, SSO client secrets, rotation DSNs) are read once when the config is loaded, not on every use.
- **A start-up warning for connection parameters PgBouncer refuses.** With `storage.database.pooler` set to `pgbouncer-session` or `pgbouncer-transaction`, the server now logs a warning when the DSN or connection fields carry a startup parameter such as `search_path` or `options`, naming it and pointing at `ALTER ROLE ... SET`. Nothing is refused: PgBouncer's `ignore_startup_parameters` may be set. See `docs/postgresql-poolers.md`.
- **The shares list decides secret readability for the whole page at once.** `GET /shares` (and the owned-shares list) used to run `AuthorizeSecret(secrets.read)` once per secret to decide which secret names to show, a handful of statements per row. `AuthorizeSecretsBatch` decides the page from a fixed number of statements with the same rules (PAT restriction, ACL including folder ancestors, role, direct and group shares, expiry, project membership at access time) and records the same share-elevation audit. Guarded by `TestAuthorizeSecretsBatch_EqualsPerRow` (per-row and batch over a generated principal x secret x state matrix) and `TestAuthorizeSecretsBatch_QueryCountDoesNotGrowWithRows`.
- **`admin verify-audit --pg-dsn` help now says not to point it at a live database.** The
  flag takes no lock, and a purge running during the walk can make a valid chain read
  BROKEN; use a detached copy. Pinned by `TestVerifyAudit_PGDSNHelp_WarnsAgainstALiveDatabase`.
- **Removed the unused `UpdateDynamicSecretLease` storage method.** Nothing has called it since lease renew and revoke moved to column-scoped writes (#2825). The full-row write ledger rows for break-glass, legal hold and users now say whether a stale write could affect access.
- **A refused clear-synced-copies suspend now says what to do next.** When `POST /secrets/{id}/suspend` or `POST /projects/{id}/secrets/suspend-all` with `clear_synced_copies` is refused because its audit event cannot be recorded, the 500 now carries the stable error code `SuspendAuditUnavailable` (it was a generic `InternalError`) and a fixed message: suspend without clearing synced copies to cut access immediately; clearing needs the audit log back. `keyorix secret suspend` and `keyorix project suspend-secrets` print the command to run next, and the web suspend and freeze dialogs offer the plain suspend one click away. The refusal itself is unchanged (fail closed, nothing is modified).
- **A refused clear-synced-copies suspend now has a drift guard on its message.** The refusal tells the person how to cut access right away ("suspend without clearing synced copies to cut access immediately"). The API, CLI, web and journey tests already carried that text; a new server test fails if the CLI or web test fixtures stop matching the text the server sends. No behaviour change.
- **`storage.database.single_writer`: warm machine-token secret reads skip the confirming statement.** While the single-writer guard vouches for it (holder lock held, write fence intact, lease fresh, no write to a security table in flight or finished since), the server answers a warm machine-token secret read from the last result of its confirming statement instead of running it again. Every check (revocation, expiry against the current time, identity state, roles, schedule) is still made on every request, and any write this server makes to a security table takes effect on the next request. Sessions and personal access tokens are unchanged. Off by default; with it off nothing changes.
- **A failed read of the source or destination environment in an environment clone is a storage fault, not a validation refusal.** It used to be worded "Validation error: source environment: <driver text>" whatever the cause; a missing environment keeps its text and its 404 and now matches `storage.ErrEnvironmentNotFound`, any other failure is the retry class.
- **A refused new password also matches `ErrValidation`** (in addition to `ErrPasswordPolicy` / `ErrPasswordReused`), so a transport classifying by `ErrValidation` answers it 400 / InvalidArgument.
- **In-app confirmations replace native `window.confirm`.** Transfer ownership, secret version rollback, machine-identity suspend/revoke, machine-token revoke, dynamic-secret lease revoke (single, retry and all) and project-member removal now ask through the app's own dialog (`components/ui/useConfirm`) with the same wording, instead of a browser dialog (#3153). A structure test (`noNativeConfirm.test.ts`, INV-WEB-no-native-confirm) fails on any new native `confirm`.
- **Sharing page: Edit and Revoke are disabled on shares you do not own.** The server only lets a secret's owner (who is still a project member) change or revoke its shares, and refuses admins and recipients; the page now says so on the row ("Only the secret's owner can change or revoke its shares") instead of offering an action that ends in a 403. The bulk-select checkbox follows the same rule. Server enforcement is unchanged.
- **Inactive-user filter documented by its real rule.** The `filter=inactive` description of `GET /api/v1/admin/users` in the OpenAPI spec now says a user is inactive when the last login, or for an account that never logged in its creation date, is 30+ days old (the rule since #3740). Description only, no schema change.
- **Web session-token guard scans for opaque tokens.** `sessionTokenNeverPersisted.test.ts` (INV-WEB-03) now also fails on a 32+ char hex or base64 run written to `localStorage`/`sessionStorage`, with a calibration case and a UUID allow-list.

### Deprecated
- **`storage.database.insecure_audit_skip_durable_sync`** is an alias of `audit_durability` for one minor release (`true` = `standard`, explicit `false` = `strict`) and logs a deprecation line; setting both keys to conflicting levels refuses to start.
- **`--format` on those six commands** keeps working as a hidden alias of `--output` and prints a deprecation notice on stderr. `project stats` and `project health` now print indented JSON instead of one compact line (same content).
- **`--by` on `keyorix user delete`, `suspend`, `reactivate`, `force-password-reset`, `revoke-sessions` and `resend-setup-link` is deprecated and no longer required.** It was never sent to the server (the acting admin is always your session). Passing it still works and prints a deprecation notice, as for `user create --by`; drop it from scripts. The flag is deleted after one minor release.
- **`secrets.chunking.*` and `secrets.limits.max_secrets_per_user` are deprecated.** No code ever read them: there is no secret chunking and no per-user secret cap. A config that still sets them loads as before but logs a start-up warning; they will be rejected after the next minor release.
- **`keyorix user create --by` is deprecated.** It never had an effect, because the acting admin is always the session behind your token. Passing it now prints a warning, and it will be removed in the next minor release.
- **`server.http.keepalive.*` is deprecated and ignored.** Only `server.grpc.keepalive` was ever read; the eight keys under `server.http.keepalive` parsed and did nothing. Setting the block now prints a start-up warning. Remove it from `keyorix.yaml`: it is deleted after one minor release. No configuration that `keyorix-server admin init` writes contains it.

### Removed
- The unused `RevertAccessReviewItemClaim` storage method (no caller, and no campaign-is-open condition) is deleted (#2803).

### Fixed
- **The demo image, `keyorix system info` and the web footer report the real build.**
  `scripts/demo/up.sh` (and `check.sh --postgres`) now pass `VERSION`, `GIT_COMMIT` and
  `BUILD_DATE` (from `git describe`, `rev-parse` and the commit date) to `docker build`, so the
  image is no longer `dev` / `none`. `GET /system/info` reports the injected build date as
  `build_time` instead of a hard-coded `unknown`. `keyorix system info` prints the server's
  version, commit and build time plus the CLI's own version, and shows an unstamped value as
  `dev (not stamped)` / `n/a`, never raw `none` or an empty field. The web footer shows the
  server version from the API (the web bundle's own version only as a secondary detail when it
  differs). On the dashboard the Security tile reads "No anomaly or expiry alerts" (it does not
  cover Compliance gaps), and a DB connection count of 0 is shown as `n/a`.
- **`scripts/demo/up.sh` no longer reuses a stale demo image.** The `keyorix-demo:airgap` image is
  labelled with a fingerprint of the source it was built from (HEAD commit, plus a hash of any
  uncommitted changes); a run reuses it only when that matches the checkout, and otherwise says so
  ("image is stale: built from X, this checkout is Y") and rebuilds, instead of starting an old
  server that dies with `unknown flag: --dev`. New `--no-build` fails fast with the fix when the
  image is missing or stale. A rebuild is refused while another container runs from the same tag
  (set `KEYORIX_DEMO_IMAGE` on a shared host), and a startup failure on a mismatched image names
  the mismatch. (#3149)
- **`scripts/demo/down.sh --wipe` refuses the default-named volume** (`keyorix-demo-data`) unless
  `--force-default` is also given, and always prints exactly what it will remove first, so a wipe
  without your `KEYORIX_DEMO_*` overrides can no longer delete another session's demo. (#3149)
- **The Kubernetes operator rejects duplicate `spec.data[].secretKey` entries.** Two entries with the same `secretKey` let a readable entry overwrite a key that another entry held (expired or suspended). The CRD now declares `spec.data` as a map list keyed by `secretKey` (`x-kubernetes-list-type: map`), so new or updated CRs with a duplicate are refused by the API server (apply the updated CRD; Helm does not upgrade `crds/` automatically). A CR stored earlier that still carries a duplicate is refused by the controller: `Ready=False`, reason `InvalidSpec`, one Warning Event, nothing read or written (the target Secret is left as it is) until the spec is fixed. k8s-sync already rejected duplicates.
- **`GET /api/v1/secrets/{id}/certificate` maps secret-state refusals like the value routes.** A suspended secret was 400 and an expired one 500; both are now 409 `SecretSuspended` / `SecretExpired`, and a read outside the access schedule is 403 `SecretAccessOutsideSchedule`, with the same fixed messages. The caller is authorized before the state is revealed, as on the value routes.
- **`keyorix secret update --max-reads 0` no longer fails with a bare 400; the read limit can now be removed.** The flag help said "0 = unlimited", but the API has always required `max_reads >= 1` (OpenAPI `minimum: 1`), so there was no way to clear a limit. The API contract for `max_reads` is unchanged; `PUT /api/v1/secrets/{id}` gains an additive `clear_max_reads: true` (like `clear_expiration`; mutually exclusive with `max_reads`, audited as a `max_reads` change, and a lifecycle-permission action when it removes an existing limit), and the CLI gets `keyorix secret update --clear-max-reads`. `--max-reads 0` is now refused client-side with a pointer to it, and the help text is corrected (#3172).
- **`keyorix secret clear-schedule` no longer reports success as an error.** The server answers `DELETE /api/v1/secrets/{id}/schedule` with 200 and a `{deleted: true}` envelope; the CLI (and the OpenAPI document) expected 204, so the CLI printed `Error: clear secret schedule: schedule removed (HTTP 200)` and exited 1 although the schedule was removed. The CLI now accepts 200 and 204, and OpenAPI documents the real 200 response; the wire behaviour is unchanged (#3173).
- **`scripts/e2e/web-real-smoke.sh` no longer picks a port another session is using.** Its free-port probe only asked `127.0.0.1`, so a Vite listening on `[::1]` only looked free and the next group failed with `http://localhost:NNNN is already used`. The probe now checks both loopback families, port ranges start from a random high base per run (so concurrent runs stop walking the same ports), the base can be pinned with `KEYORIX_E2E_PORT_BASE`, and the script now fails loudly if its own server process died (a lost bind race) instead of continuing against a stranger's `/health`. The selection logic lives in `scripts/e2e/lib/free-port.sh` with a test run by `go test ./scripts/e2e/lib` (#3174).
- The HTTP access log now follows `log.SetOutput`/`SetPrefix`/`SetFlags` at write time instead of snapshotting them when the router is built (regression from #3231). This also restores the canary log-leak fuzzers' view of access-log lines.
- Operational drills (`scripts/drills`) no longer report a valid `verify-audit` (or other matched output) as a failure at random: `echo "$out" | grep -q` under `pipefail` died of SIGPIPE (exit 141); all such sites now use here-strings. `totp_fresh` keeps the last consumed code per account, so two accounts no longer replay a code. `scripts/drills/selftest.sh` (run by `go test ./internal/statemap`) proves both and fails on any new `echo | grep -q`.
- **Restoring a secret no longer runs without its environment lock when the first read fails.**
  `RestoreSecret` reads the secret to learn its environment, takes that environment's lock and
  then opens the restore transaction. If the read failed, it carried on with no lock, and the
  storage restore took the lock inside the transaction instead: the lock-inside-transaction
  order that can stall writers on SQLite and pin a request connection on Postgres. A failed read
  now fails the restore and changes nothing; a missing secret still reports "not found". (#2694)
- **The gRPC failed-authentication limiter no longer scans its whole table on every failed
  token.** It now clears idle source IPs once every 1000 failures, like its HTTP twin and the
  per-principal gRPC limiter. Limits and idle timeout are unchanged. (#3429)
- **`POST /api/v1/compliance/evidence/verify` documents its `filename` field.** The OpenAPI request schema listed only `data_b64` and `signature`, but the evidence signature is bound to the pack's canonical filename, so a client built from the spec could never get a valid verdict. `filename` is now declared and required, and the generated web types and CLI client carry it. Guarded by `TestContract_EvidenceVerifyRequest_RequiresFilename`.
- **The `keyorix-web` image build no longer breaks when Alpine publishes a newer revision of a security-pinned package.** `web/Dockerfile` pinned `libuuid`, `libexpat`, `pcre2` and `tiff` to exact revisions; on 2026-10-19 Alpine 3.24 replaced `libexpat-2.8.5-r0` with `2.9.0-r0` and the `release-dry-run` multi-arch build (and with it `docker-publish` and `release` at tag time) failed with `unable to select packages`. The pins are now minimum versions (`libexpat>=2.8.5-r0`, etc.), so the fixed versions are still enforced but a later revision satisfies them.
- **Web: the New Role and Edit Role forms work again.** They sent an empty permission list, which the server refuses, so every Create and Save failed with a generic error. The forms now carry a permission checklist (at least one on create), require a description, and show the server's error message instead of a generic one (for a validation failure that is the server's "Invalid request data"; a refusal such as a permission the admin does not hold names the reason). On edit the name is read-only (the server has no rename), and the permissions and "Can be granted" are sent only when changed, so saving a description does not undo a scope change another admin made in the meantime. A permission change applies only the admin's own ticks and unticks to the role's permissions as the server holds them at Save, so it does not re-grant a permission another admin revoked while the dialog was open.
- **Web: Edit Role no longer offers a change the server refuses.** The server refuses every update to a built-in role, so its Edit dialog is now read-only: name, description, "Can be granted", the permission checklist and Save are disabled, with the line "Built-in roles cannot be edited.". The web's built-in role list now matches the server's, so the named project and system roles (such as `project_viewer`) are treated as built-in too.
- **Web: dark theme text contrast.** `--text-muted` is now `#92929d` (4.5:1 or better on every dark surface; it was 2.7 to 3.8:1). Status badges and messages on the System Health, Authentication, Notification Channels, Roadmap and Dashboard pages, the token revoke control and the share dialog use the `--success`, `--warning` and `--danger` tokens instead of fixed hex colours, so they follow the theme. A structure test (`hardcodedTextColours.test.ts`) fails when one of those hex colours returns or a new hard-coded text colour is added.
- **A failed invitation accept is undone completely and says what happened.** Accepting an invitation creates the account, spends the setup link, grants the invitation's roles (a global invite grants each one in its own step), marks the invitation accepted and signs the user in. When a step after the account creation failed, the accept was left half-done: a failed link spend kept the new account (the same link then reported "an account already exists"), a global invite whose system role was granted before a later grant failed kept that role on the removed account (a user restore brought it back), a failed "mark accepted" write left the account and its roles live behind a still-pending invitation, and an audit-log refusal was reported as "nothing was changed, retry" although the account had been created and the link spent. Now every such failure reverts the roles already granted, removes the account, leaves the invitation pending, and the error (and an `invitation.accept_failed` audit row) names the failed step, what was undone and what to do next: retry the link if it was not spent, otherwise ask the inviter to resend the invitation. A failed automatic sign-in after everything committed now says the invitation was accepted and to log in with the new password. The web answer is unchanged (the generic setup-link message).
- **An older admin binary can no longer rotate a database newer servers use.** The database records the DEK rotation protocol of the servers that used it (`system_metadata` `dek.rotation_protocol`); `admin encryption rotate` from a binary with an older protocol refuses before writing anything. **Upgrade note:** never run `admin encryption rotate` with an admin binary or image older than the servers. v0.96.x binaries predate the record and are not stopped by it: a v0.96.x rotation against a database a newer server has used leaves the DEK epoch naming the old DEK, so replicas with the new key set refuse to start. Recovery: `docs/operator/key-rotation-runbook.md` section 6.2.
- **`scripts/mutation-testing/run-mutation.sh` measures packages again.** Since #3733 the comment lines inside the double-quoted `PACKAGES` string quoted code in backticks, which bash ran as command substitutions, so under `set -euo pipefail` the script exited 127 before measuring any package. `PACKAGES` is now a quoted heredoc. Guard: `scripts/mutation-testing/run_mutation_packages_test.py`.
- **Air-gapped web UI served entirely from the binary.** `/fonts/*` and `/favicon.svg` were not routed, so the UI's self-hosted Inter and JetBrains Mono fonts fell through to the SPA shell and the browser silently used system fonts; they are now served with the right Content-Type. The `/swagger/` page loaded swagger-ui from `unpkg.com` (it failed offline and sent the operator's browser to a third party); swagger-ui-dist 4.15.5 (about 1.45 MB, Apache-2.0) is now vendored into the binary, pinned by SHA-256, with the online validator off. `TestWebUIServesEveryDistFile` and `TestAirgapServedMarkupNamesNoExternalHost` guard both (the second is report-only until its first green nightly on main).
- **A fault in the admin notice no longer turns a committed MFA reset step into a 500.** The recipient lookup after an approval, request or cancellation could panic past the best-effort notice; for an approval that lost the one-time password, which exists only in that response. It is now logged like any other notice failure (`TestMFAReset_RecipientFaultAfterCommit_IsBestEffort`).
- **gRPC error codes follow typed errors, not message text.** The project, role, user, share, secret and secret-ACL error mappers classified `not found` / `already exists` / `permission denied` by matching the error string, so a locale change or an unrelated error that happened to contain those words changed the status code. They now use `errors.Is` on the storage and core sentinels, like the group mapper. Revoking an ACL that does not belong to the secret now matches `storage.ErrSecretACLNotFound`. `CreateSecret` with an environment that belongs to another project now answers `NotFound`, like a missing environment (was `Internal`). A raw error that merely contains "not found" is `Internal`. Messages that still have no sentinel (role-name unique index, user field validation, share expiry, rotation validation, dynamic-secret and machine-identity errors) keep their text match until core types them.
- **SQLite upgrades: hand-written timestamp columns get a type the driver can read back
  (#3440).** The ten `ALTER TABLE ... ADD COLUMN ... TIMESTAMP WITH TIME ZONE` statements
  (users, sessions, secret_nodes) and the user_roles/group_roles primary-key rebuild now
  declare `DATETIME` on SQLite (PostgreSQL DDL is unchanged). None of them runs on a
  database from a supported upgrade source: v0.93.0, v0.94.0 and v0.95.0 databases already
  have these columns. A database from before v0.93 that still reached them got a column
  whose values failed to load ("unsupported Scan ... into type *time.Time"). Guarded by
  `TestNoHandWrittenTimestampColumnDDL`.
- **A v0.95.x backup restores into the current release (#3452).** `admin restore` refused every archive taken by v0.95.0–v0.95.3 that held a notification channel: its plaintext `url` column was replaced by the encrypted `url_enc`/`url_meta` pair in #2468, and restore's schema check treated the old column as unknown. Restore now carries the value into the legacy column and, once the keys are installed, runs the same encrypting backfill the server runs at startup, so no plaintext URL is left in the restored database. Works on SQLite and PostgreSQL; see docs/UPGRADING.md §4. Guarded by `TestAdminRestore_V0953Archive` (a checked-in v0.95.3 archive) and `TestLegacyColumns_AreUnmappedFieldsOfTheirModel`.
- **Restore no longer holds a whole table in memory (#3462).** `admin restore` read each archive entry (a whole table's NDJSON) into memory before checking and staging it, so its peak memory grew with the largest table, typically `audit_events`. Entries are now streamed through the checksum straight to the staging file; size and checksum refusals are unchanged and a refused entry leaves no staged file. Restoring PostgreSQL archives into SQLite works and is covered by `scripts/release-qa/scenario_restore_scale.sh`. Guarded by `TestExtractArchive_StreamsTableEntries` (bounds allocations against the entry size).
- `verify-audit --previous-checkpoint-key-file` now also authenticates an `--anchor` exported before rotate-kek / migrate-provider.
- `verify-audit` no longer reports deleted checkpoints as "never written", and states in "what this run does not prove" when no signed checkpoint was found.
- `admin restore` of an archive written on a host with a non-UTC offset (for example a v0.95.x archive with `+01:00` times) no longer leaves a database that a UTC host cannot read back ("unsupported Scan, storing driver.Value type string into type *time.Time"); restored times are stored in UTC.
- **A concurrent rename to a taken username answers AlreadyExists / 409.** `UpdateUser` and `UpdateUserIfActiveStateMatches` now map a collision on the users username index to `storage.ErrDuplicateUsername` (SQLite and PostgreSQL), as `CreateUser` does, and `core.UpdateUser` turns it, and the email twin, into `ErrUserAlreadyExists` (REST 409, gRPC `AlreadyExists`) instead of a storage failure (500 / `Internal`) carrying the constraint text. SCIM provisioning answers 409 `uniqueness`, SSO JIT provisioning and the first-admin bootstrap answer "already exists"; the loser leaves no user row, grant or audit event.
- **Session-revocation failure text names the personal access tokens.** When the PAT listing fails during an account-state change, the `SECURITY:` log line and the `auth.session_revocation_failed` audit row said "could not list the sessions of user N"; they now say "the personal access tokens".
- **The evidence signing key and the audit checkpoint key are described as KEK-derived, which is what they are.** A config comment and the air-gap design note called them DEK-derived. The same wording remains in generated or CLI-owned text (`keyorix compliance verify` help and `docs/cli-reference.md`, the OpenAPI and gRPC comments) and is left for the owners of those files.
- `audit search --actor <name>` (`GET /api/v1/audit/search?actor=`) now also matches machine identities: a partial, case-insensitive name such as `payments-ci`, `PAYMENTS` or `ci` finds the rows the ACTOR column shows under that name, not only user names (#3736).
- The `break_glass.activated` and `break_glass.revoked` audit descriptions name the user the way `role.assigned` does (`user 2 ("dana")`), not only `user 2`; when the name cannot be read they keep the bare id (#3741).
- **Copying a restricted secret now says why it was refused (#3804).** `POST /api/v1/secrets/{id}/copy` answered a restricted-classification gate refusal (missing `secrets.read.restricted`, approval or recent step-up) with 404 "Secret not found". It is now 403 with the gate's reason; a caller who cannot read the secret at all still gets not-found.
- **A user who has not logged in yet is no longer counted as "inactive" on day zero** (#3740). The dashboard "Inactive Users" tile and the `?filter=inactive` user list (HTTP and gRPC) matched `last_login_at IS NULL`, so an account created a minute ago showed up as "no login in 30 days". They now judge a user by `COALESCE(last_login_at, created_at)`: a never-logged-in account counts only once it is itself more than 30 days old. The inactivity sweep (`suspend-inactive-users`) already used this rule and is unchanged. The tile hint now reads "not logged in for 30+ days".
- **Rolling upgrade: an older replica saving the audit verification state no longer leaves
  `audit verify` permanently BROKEN (#3708).** During a Helm `RollingUpdate` (replicas > 1),
  a replica from before the audit verification state was placed against the chain re-signs
  the state without those fields. The new version used to read that as a sticky
  "before a recorded break" discontinuity that no command could clear over an intact chain.
  Now the `system.audit_verification_state_initialized` event names the state generation
  that placed the state, and a row an older replica re-signed after it is restarted instead:
  the status reads `not_proven` (the `KeyorixAuditVerifyStateRejected` alert can fire during
  the rollout) until a full verification passes, which a rolling cycle does on its own, or
  run `keyorix audit verify --full` once every replica runs the new version. A row from
  before the upgrade, a replayed row, a row saved before a recorded break and a re-sign that
  dropped a discontinuity still latch, and so does an older replica's save after its load
  rejected the row (deleted, put back, garbled), whatever generation that replica last read,
  which would otherwise launder the deletion. An older replica's re-sign of a row that still
  carries a rejection no full verification has cleared yet latches too (fail closed).
  While an accepted loss (`admin audit accept-loss`) or a key transition exists, an older
  replica's save still latches (kind `seal` / `key transition`: it drops `seals` and
  `key_epoch`), so such deployments still read BROKEN during a rolling update: stop older
  replicas before upgrading them. A deployment whose marker event predates this change
  gets a named one with its next state save; an older replica's save before that still
  latches, so finish that first rollout before rolling back.
- A refused secret-ownership transfer by a non-owner now matches `core.ErrPermissionDenied` at its call site, so the nightly `rollout` guard `TestEveryErrorPermissionDeniedRefusalIsTyped` is green in enforce mode. The refusal text and its HTTP/gRPC mapping are unchanged.
- **A storage outage no longer reads as "not found" on revoke paths.** Revoking or suspending a machine identity, revoking a machine token, deleting an OIDC binding, transitioning a project membership, revoking or resending an invitation, resolving or withdrawing an access request, revoking a dynamic-secret lease, and attesting an access-review grant used to turn ANY storage read error into "... not found" (HTTP 404, gRPC NotFound), so during a database outage an operator concluded the principal was already gone while the revoke had never been applied. A read fault is now `core.ErrStorageReadUnavailable`: REST answers 503 with `Retry-After` and code `storage_unavailable`, gRPC `Unavailable` (reason `storage_unavailable`); bulk delete, bulk rename and attestation report a distinct "storage temporarily unavailable, please retry". A true not-found and a cross-project mismatch still give one identical "not found" answer. Guarded by `TestNoStorageReadErrorFoldedIntoNotFound` (report-only on its first day). Not yet covered: the REST dynamic-secret lease routes (`POST /dynamic-secrets/leases/{leaseID}/revoke` and `/renew`) resolve the lease's scope in the authorization middleware before the handler runs, and that resolver still answers a lease-read fault with 404 (global permission holders) or 403 (everyone else); the gRPC lease revoke and the core `RevokeLease` are fixed.
- **Updating a role that was deleted concurrently answers 404, not 500.** `PUT /api/v1/roles/{id}` now maps `ErrRoleNotFound` from the update itself (the role vanished between the handler's read and the write) to the same `404 Role not found` the read branches return. The gRPC `UpdateRole` already answered `NotFound` through `mapRoleError`. Guarded by `TestUpdateRole_RoleDeletedConcurrentlyAnswers404`.
- **A storage outage no longer reads as "not found" when a REST route resolves its target.** The authorization middleware reads the target of a route (environment, secret, deleted secret, share, rotation policy, dynamic-secret config, and the secret of the per-secret routes) before it authorizes, and used to turn ANY failed read into "no such target": a caller who holds the permission globally got 404 "Resource not found" for a target that may well exist, and the operation was never applied. A read fault now answers that caller 503 `storage_unavailable` with `Retry-After`; every other caller keeps the exact 403 an absent target gets, so a fault adds no existence signal for them, and a transient fault (connection refused, a driver timeout) answers every caller alike with 503 "authorization temporarily unavailable". A target that does not exist keeps its 404 / 403 and body. `DELETE /api/v1/folders/{id}` and the dynamic-secret config routes, which read the target again in the handler, answer a fault there 503 too instead of 404.
- **Bulk secret delete no longer returns storage error text.** A secret that `POST /api/v1/projects/{id}/secrets/bulk-delete` could not delete reported the raw error in `failed[].error`, which for a storage failure named database tables and columns. It now reports one fixed reason: `permission denied`, `secret not found`, `storage temporarily unavailable, please retry` or `internal error`; the detail goes to the server log.
- **The web `Audit dependencies` CI step passes again.** `follow-redirects` 1.16.1 (pulled in by `axios`) is flagged by GHSA-mrwp-f3q8-3g9p (custom credentials can follow redirects), patched in 1.16.2. `web/pnpm-workspace.yaml` now overrides the vulnerable range to `^1.16.2` and the lockfile resolves to the patched version.
- **A panic while building an audit event no longer replaces the request's answer.** The failure-event writer behind ~22 deny-path audits, and six other best-effort audit writers (secret-read denial rows, anomaly business-hours, retention policy, license state, security-posture changes), now recover a panic themselves, log it and count it in `keyorix_best_effort_failures_total{step="audit.<writer>"}`.
- **Audit events emitted without a time are stamped with the emit time.** An event whose emitter left `EventTime` unset was stored as `0001-01-01`; core now sets it to the current UTC time (microsecond precision) before the row is hashed, so `verify-audit` still passes.
- **Web build no longer leaks `tailwindcss.com` into air-gapped deployments.** Tailwind v4's generated CSS carries a `/*! tailwindcss v4.3.3 | MIT License | https://tailwindcss.com */` banner, which tripped the air-gap guard (`TestAirgapServedMarkupNamesNoExternalHost`) on any PR that triggered a web build check. A small PostCSS plugin now strips that banner comment from generated CSS only; license banners for other JS dependencies are untouched.
- **Impersonation answers a database read outage with "retry", not with a verdict.** A
  failed read of the impersonating admin (re-checked on every request made with an
  impersonation session) answered 401 and the session's token was cached as invalid; it now
  answers 503 with `Retry-After` (gRPC `Unavailable`), and a failure to re-check the admin's
  authority is no longer remembered for 60 seconds as a refusal. `POST
  /api/v1/admin/impersonate` and `POST /api/v1/auth/end-impersonation` answer a failed
  read with 503 `storage_unavailable` instead of 404 / 500. A deleted admin, target or
  session is still refused as before.
- **MFA and passkey account endpoints answer a database read outage with "retry".** Enrolling,
  activating or disabling MFA, regenerating or counting recovery codes, registering or
  deleting a passkey and the passkey re-check answered a failed read of the caller's own
  account with 400 "user not found"; they now answer 503 with `Retry-After` and the code
  `storage_unavailable`, and the attempt does not count against the IP's login budget.
- **Setup links, session refresh and passkey sign-in answer a database read outage with
  "retry".** `POST /auth/setup/consume` answers a failed look-up of the link with 503 and
  `Retry-After` instead of "this setup link could not be completed" (a failure after the link
  was found valid still gets that answer, so the response never confirms a link).
  `POST /auth/refresh` answers a failed read of the session or its owner with 503 instead of
  401, so the web app no longer signs the user out during an outage. `POST
  /auth/webauthn/login/finish` answers a failed read of the account's roles or permissions
  after the passkey was accepted with 503 instead of 401; the attempt still counts like a
  failed one.
- **Machine callers can issue machine tokens.** A machine identity holding `roles.assign` at a project can now issue a token for another machine in that project over REST and gRPC. Before, the privilege ceiling was checked as user 0, so the call was always refused, and REST answered 500. A ceiling refusal now answers 403 (gRPC `PermissionDenied`).
- Adding a user to a group no longer skips the grant ceiling for a group role whose definition could not be read because of a storage fault: the join is refused with a retryable "storage temporarily unavailable" error. A role that was really deleted is still skipped. The same fix applies to the group-join separation-of-duties check, the invitation scope check and the report of pending invitations outside their role's assignable scope (#3988).
- Updating a role's assignable scope on a multi-replica Postgres deployment now locks the role row while it decides whether the change widens the scope, so a concurrent narrowing on another replica can no longer turn a widening into a "narrowing" that skips the fail-closed audit path or records the wrong scope change (#3919).
- `GET /api/v1/secrets` and gRPC `ListSecrets` no longer fail for a user with a role who has received 10,000 or more shares. Past that cap some rows may not show the user's share permission. The share-list endpoints still refuse at the cap (#3943).
- **Nine user and group store writers now store their times in UTC.** `UpdateLastLogin`, `UpdateLoginLockoutState` (`last_failed_login_at`, `login_locked_until`), `SetPasswordHash`, `SetOneTimePasswordExpiry`, `SetAccountState`, `SetAccountStateIfMatches`, `ClaimUserExternalIDIfUnset`, `UpdateUserIfActiveStateMatches` and `UpdateGroupFields` wrote the caller's time through `UpdateColumn` or a map `Updates`, which run no model hook and no GORM `NowFunc`. Core hands them its clock in the host zone, so on a SQLite deployment on a non-UTC host the column held text with the host offset (for example `2026-11-06T19:13:09+05:30`) instead of the UTC text every other writer stores; the inactive-account sweep compares `last_login_at` in SQL against a UTC cutoff, and SQLite orders that text by wall clock. PostgreSQL stores an instant and was not affected. The store now normalises each value itself, like `TouchSession` and `UpdateProjectFields` already did. New guards `TestEveryStoreTimeColumnWriteIsUTC` (every time-column write in `internal/storage/store`) and `TestEveryServerExpiryWriteIsUTC` (expiry and cutoff hand-offs in the HTTP handlers and gRPC services) keep it that way; both are report-only until their first green nightly on main.
- **OpenAPI: `POST /api/v1/folders` (createFolder) declares `201`.** The spec declared only `200` but the handler returns `201 Created`; `201` is now declared next to `200`, and the generated web types and CLI client follow.
- **A pilot SDK now sees the right status for the last text-matched error families.** `GET /api/v1/projects/{id}`, `GET /api/v1/groups/{id}`, `GET /api/v1/secret-templates/{id}` and `GET /api/v1/secrets/{id}/sharing-status` answered 404 whenever the error text contained "not found", so a storage read fault with those words read as a missing target, and a plain fault was a 500. Core now returns the existing not-found sentinel, the handler reads it with `errors.Is`, and a storage fault is the family's 503 `storage_unavailable` with `Retry-After`. A caller with no access to a secret's sharing status is a 403 by sentinel, not by the word "permission". `DELETE /auth/sessions/{id}` answers 404 only for a session that is missing or not the caller's (or a machine principal, which owns none). Every other, untyped error from `RevokeOwnSession` (a failed delete included) is now a 500 `InternalError` (it was a 404), and an audit outage (the owed audit event cannot be written) is a 503 `audit_unavailable` (it was a 404); a client that treated any non-204 as "already gone" should retry on 500/503.
- **The grant ceiling is classified by sentinel.** `POST /api/v1/users` and `POST /api/v1/groups/{id}/members` read the refusal as `core.ErrPermissionDenied` instead of the words "cannot grant this role". A guard fails any handler that spells the phrase and any untyped `fmt.Errorf`/`errors.New` with that text in `internal/core`; a family test drives eight grant routes as an actor who lacks the granted role's permissions and requires 403 from each. `POST /api/v1/projects/{id}/machine-identities/{machineId}/roles` answered such a refusal 500; it is 403 now.
- **The machine-identity, OIDC-binding and dynamic-secret routes classify core's refusals by sentinel.** A read fault while resolving the environment or role of a machine role binding is 503 (it was 404 or 500); a missing environment or role is 404, an environment of another project 400, an already-assigned or not-assigned role and an already-bound OIDC subject 409. `POST .../machine-identities/{machineId}/oidc-bindings` by an actor without install-wide admin authority is 403 (it was 400). A dynamic-secret config or lease that is gone is 404 and a refused input 400 (both were 502).
- **OpenAPI.** Documents the 403 of `POST /api/v1/groups/{id}/roles`, the 503 of `POST /api/v1/users`, `POST /api/v1/invitations` and `POST /api/v1/rotation-policies`, and the rule behind the dashboard's `inactiveUsers` (last login, or creation time for a user who never logged in, more than 30 days ago). `web/src/types/api-generated.ts` is regenerated.
- `PUT /api/v1/users/{id}/roles` now lets a directly authenticated machine actor replace roles as itself when it holds the needed permissions; before, the grant ceiling refused every machine actor.
- **A storage panic during session refresh no longer costs the caller's login budget.** `POST /auth/refresh` used to answer a storage panic with a 500 and keep the per-IP login-attempt slot, even when the panic hit the session lookup, before any token was checked. Each storage call in the refresh now handles a panic exactly like its error: a lookup panic hands the slot back and answers 503, and a panic after the token matched keeps the slot (503 for the owner read, the wrong-token 401 for a write). A panic while listing the session family on a replayed token no longer skips the family revocation (#3968).
- **OpenAPI: `POST /api/v1/secret-templates` and `POST /api/v1/folders` declare the 201 they return, and `PATHygieneRow.last_used_at` is nullable** (#4132 OPENAPI-STATEFUL-4/6/9; the handlers are unchanged).
- **`admin backup` no longer silently drops webhook URLs from a database upgraded in place from v0.95.x.** A database upgraded in place and backed up before the new server's first start still keeps each webhook URL only in the plaintext legacy `notification_channels.url` column, which the backup does not archive, so the restored channels had no destination. The backup now refuses, before it writes anything, naming the channels and the remedy: start the server once to finish the upgrade migrations, then back up. A restore of a v0.95.x archive is unchanged (it already encrypts the URL). Guarded by `TestAdminBackup_InPlaceUpgradeBeforeFirstStart_NeverDropsTheURL` and `INV-ADMIN-backup-refuses-unmigrated-legacy-url`.
- **`admin backup` refuses a key directory behind the database's DEK (#4104).** With `storage.encryption.key_dir_lock: database`, a backup from a replica whose key directory still held the old `dek.key` after another key directory's DEK rotation committed its sweep wrote an archive that restored but could not start (`ErrDEKEpochMismatch`) and did not decrypt. On PostgreSQL the backup now checks its DEK against the database's `dek.epoch` (read through the backup's own snapshot) and refuses with no archive written and no key file changed: finish the rotation in the key directory that holds `dek.key.pending`, distribute the new key set, then back up. A failed read of the epoch refuses as well. SQLite is unchanged.
- **A backup refused on a key-rotation staging file is visible (#4105).** The refusal message names the file and, for a leftover `kek.salt.pending` that a successful server start left in place, says the start proved the active key set opens without it and how to remove it safely; `admin validate --posture` reports `backups are refused: key-rotation staging file present` (non-zero exit) until the file is gone. Boot behaviour is unchanged, and a DEK's `.pending` file is never suggested for removal.
- **`keyorix-server admin` output no longer cites internal design notes or issue numbers.** Progress lines such as "Loading data into the staged database (design §3.4)...", errors from `admin restore`, `admin backup` and `admin encryption migrate-provider`, and the `--help` text of `restore`, `backup`, `recover-admin`, `verify-audit` and `audit export-checkpoint` carried references like "design §7.4", "design-b3-backup-v2.md §5" or "(#429)" that mean nothing to an operator. The sentences stay; the references are gone. A test now fails when such a reference is added to a string in these packages, and another checks that every "run `keyorix-server admin ...`" hint names a command and flag that exist.
- **A change refused because the audit log was down now answers a retryable 503, not a bare 500.** When a security-relevant mutation cannot record its audit row, its transaction rolls back and nothing is changed (that was already so). REST handlers that reach such a mutation (role and permission grants, group and project membership, project and environment create/update/restore, shares, machine identities, user create/update/restore/unlock, invitations and access requests, policies, legal hold, rotation, notification channels, ...) now answer `503` with a `Retry-After: 5` header and the stable error code `audit_unavailable` and the fixed message "could not record the change in the audit log; nothing was changed, retry". It is documented as the shared `AuditUnavailable` response in `openapi.yaml` and in `docs/API_REFERENCE.md`. The suspend endpoints keep their dedicated `SuspendAuditUnavailable` code and body and stay `500`, because that code and status are part of the published contract the CLI, web and k8s operator read. A guard test (`TestEveryAuditUnavailableReachingHandlerMapsTheOutage`) fails when a handler calling an audited core method does not map the refusal.
- **gRPC answers the same refusal with `Unavailable`.** The group, project, user, role, share, machine-identity, secret-ACL and break-glass RPCs map a change refused for lack of its audit row to `codes.Unavailable` with the same fixed message and a `google.rpc.ErrorInfo` (reason `audit_unavailable`, domain `keyorix.audit`, metadata `retry_after_seconds`), instead of `Internal`. `TestEveryAuditUnavailableReachingRPCMapsTheOutage` guards every RPC that calls an audited core method.
- **gRPC group RPCs classify errors by type, not by text.** `groupError` matched the substring "not found", so the last-administrator refusal (removing a member or deleting a group that holds the install's last admin grant) answered `Internal` instead of `FailedPrecondition`, a missing user answered "group not found", and any raw "record not found" from another row answered `NotFound`. It now uses `errors.Is` on `ErrGroupNotFound`, `ErrUserNotFound`, `ErrDuplicateGroupName`, `ErrLastAdminGroupGuard` and `ErrWouldStrandLastAdmin`; the two core paths that returned an untyped not-found (an `UpdateGroup` that matched no row, and the storage `RestoreGroup`) now wrap `ErrGroupNotFound`, so the text fallback is gone.
- **A lost invitation-accept race no longer leaves an orphan account.** Accepting an invitation creates the invitee's account, spends the setup link and grants the invitation's roles before it marks the invitation accepted. When an admin revoked the invitation (or it expired) in that window, the grants were reverted and the accept refused, but the new account stayed active: no grant, no invitation, a link that cannot be replayed, yet a password that logs in and an entry in the user list. The account is now removed like on every other failed step; the `invitation.accept_race_reverted` audit row says the account was removed (or that it could not be, with `invitation.accept_orphaned_account_cleanup_failed` for manual cleanup). The invitation stays revoked and is not put back to pending.
- **With `storage.database.pooler: pgbouncer-transaction`, the advisory locks held across statements no longer hold back the database's xmin.** The transaction each lock lives in (including the server-presence lock, held for the server's lifetime) is sent over the simple query protocol, so it keeps no snapshot: VACUUM is no longer held back while a server runs, and `CREATE INDEX CONCURRENTLY` (the audit index build) no longer waits for it. The audit index build's own lock is transaction-scoped under that pooler, like every other lock held across statements.
- **A retention purge after a checkpoint no longer breaks audit verification.** Closes #3257. A sanctioned audit purge (`POST /api/v1/admin/jobs/purge-audit-logs`) that removed more events than had been appended since the last signed checkpoint made `GET /audit/verify` report "truncated below the certified high-water mark" and `POST /audit/checkpoint` refuse with 409 until enough new events arrived — on a deployment that purges regularly, possibly forever. The purge now signs the cumulative number of chained events it removed into the retention anchor (same transaction as the delete, same HMAC key); checkpoints certify chained + purged, and the checkpoint, high-water and offline `admin audit verify` checks (including an external `--anchor`) compare that sum. A raw `DELETE`, a forged or inflated count, or an anchor rewritten without the key still reads as truncation. Upgrade notes: the anchor gains a `v2` layout (`v1` anchors read as 0 purged, the old behaviour); a checkpoint written after a purge reports a larger `chained_events` than `audit verify` (the difference is the signed purged count); do not downgrade after a purge (older versions cannot read the `v2` anchor). See `docs/CONFIGURATION.md` § audit_checkpoints.
- **The recover-admin alert job no longer re-reads the whole audit table on every run.** It
  runs at start-up and every 10 minutes and filters on the unindexed `event_type`; its stored
  high-water mark only moved when an event matched, so an install that never used
  `recover-admin` scanned all of `audit_events` each time (seconds at a million rows, and on
  SQLite the open read snapshot kept the WAL from checkpointing, slowing every concurrent
  write). The mark is now the highest audit id examined, and each run scans only the primary-key
  range added since the previous one. Every recover-admin use still alerts exactly once. No
  schema change.
- **An unfinished `admin audit accept-loss` can be resumed after a key change (#3814).** Before, a re-run on the new key after `rotate-kek` or `migrate-provider` was refused ("the latest checkpoint ... authenticates neither under seal #1 nor before it") and the chain stayed broken. The key change's record, signed by both keys, now names the checkpoint and high-water mark the acceptance had not rewritten yet, with the seal binding each was signed under, so the resume completes over them and the next server start completes the key change. Anything the record does not name and the current key does not authenticate is still refused.
- **Audit search `resource_type` is now case-sensitive on SQLite, as it already was on PostgreSQL (#4090).** Event types are lower-case, so `resource_type=secret` matches `secret.*` on both databases and a differently cased value (`SECRET`, `Secret`) matches nothing on both. Behaviour change on SQLite only, and only for callers that sent an upper- or mixed-case value: they got results before and now get an empty list; send the lower-case resource kind.
- **Revoking or creating a share no longer answers 500 when its notification panics** (#3350). The share change and its audit row had already committed; the post-commit notification panic escaped as an error response. The share notifiers now recover it (logged at SECURITY level), so the committed change keeps its success response. Pinned by `TestShareNotificationFailure_IsNotReportedAsFailure` (REST and gRPC revoke and create, panic and error).
- **A retention purge landing just after the audit walk no longer reports a valid chain as broken.** The row count that follows the online verification walk now fails only when the table holds more rows than the walk accounted for, so a purge that lowers the count is not reported as tampering. Rows with id 0, a NULL id or a duplicated id still read broken (#3944).
- **A retention purge during a checkpoint write or an `admin audit accept-loss` re-seal no longer refuses a valid audit chain.** Like `audit verify` since #3944, both walks now re-read the signed retention anchor when a purge removed rows ahead of them and walk once more from the moved anchor, counting its purged events. A delete outside a purge is still refused. A new guard test fails on any other walk from the chain start that skips this.
- **The audit checkpoint error says the signing key is derived from the KEK.** When encryption is off, the checkpoint endpoint (HTTP 412 and the gRPC `FailedPrecondition`) said the signing key was derived from the DEK. The key is derived from the KEK. Only the message text changed. Three code and test comments carried the same wording.
- **Failure audit events are stored with `success = false`** (#3363). `mfa.failed`, `mfa.error`, `webauthn.failed` and every other event whose name records a failure (`*.failed`, `*_failed`, `*_error`, `*_panicked`, …: 23 call sites) were written through the success writer, so failed second factors were missing from `success = false` queries, SIEM rules and exports. A source guard (`TestFailureNamedAuditEvents_AreWrittenWithSuccessFalse`) now fails on any such event written as a success. Existing rows keep their old value (docs/UPGRADING.md §6u).
- **Auth endpoints answer a database read outage with "retry", not with a verdict.**
  `GET /api/v1/auth/profile` answered a failed read of the caller's own account with
  404 "User not found"; it now answers 503 with `Retry-After` and the code
  `storage_unavailable` (a deleted account and a machine credential still get 404).
  `POST /api/v1/auth/mfa/stepup` answered the same read failure, which happens before any
  code is checked, with 401 "user not found"; it is now 503 with `Retry-After`, and the
  failed attempt no longer counts against the IP's login budget.
  `POST /auth/setup/consume` with an invitation link still answers a storage fault with the
  same response an invalid link gets (a different status would confirm the link), but the
  audit log now records it as `setup_token.consume_error` (a fault; the link still works)
  instead of `setup_token.consume_failed` (an invalid-link attempt).
- **A used MFA recovery code's `used_at` is stored in UTC on a server whose clock is not UTC
  (SQLite).** It was stored in the host zone. PostgreSQL was not affected; existing rows are
  not rewritten.
- **A machine-identity token on a user-only route now gets 403, not 500.** `GET /api/v1/auth/sessions`, `GET /api/v1/auth/tokens`, `GET` and `DELETE /api/v1/auth/tokens/expired`, `POST /api/v1/auth/end-impersonation` and `DELETE /api/v1/secrets/{id}/self-share` act on the caller's own user record; a machine has none (user ID 0), and the handlers mapped the core's validation error to `500 InternalError`, which paged operators and polluted error metrics. They now answer `403 Forbidden` ("This endpoint is only available to user accounts"). Nothing was disclosed before and nothing changes for human users. The OpenAPI spec lists the 403 on these operations. Guarded by `TestEveryRoute_MachineToken_NoServerError` (every route, every method, real machine token, no 5xx).
- **A CreateUser race on one username answers AlreadyExists / 409.** The loser of two concurrent creates of the same username hit the users username unique index, which was not mapped to a sentinel, and got gRPC `Internal` / HTTP 500. The store now returns `storage.ErrDuplicateUsername` (SQLite and PostgreSQL) and core answers `ErrUserAlreadyExists`.
- While PostgreSQL was down or a request hit its deadline, a caller's request failed in the permission lookup behind a middleware gate and the client got `403 Forbidden` ("you are not allowed"), which clients do not retry (#3458). A failed permission lookup at those gates now answers `503 Service Unavailable` with `Retry-After` over REST and `Unavailable` over gRPC, the same as a failed credential lookup. REST routes that check the permission inside the handler (for example `POST /api/v1/secrets`, `GET /api/v1/secrets`, folder create, secret copy) still answer `403` on an outage until a follow-up; the request is still refused and nothing is cached. A real denial is unchanged (`403` / `PermissionDenied`, same body), and a lookup error that is not an outage stays a fail-closed denial. Alert on a rise in `503` during a database outage, not on `403`.
- While PostgreSQL was down or a request hit its deadline, the REST routes that check the permission inside the handler (`POST /api/v1/secrets`, `GET /api/v1/secrets` for a machine token, secret copy, folder create, the dynamic-secrets routes) still answered `403 Forbidden` for a failed permission lookup, although the middleware gates and gRPC answered `503` / `Unavailable` (#3857). They now answer `503 Service Unavailable` with `Retry-After` and the same fixed message, so a client retries instead of being told it is not allowed. The request is still refused; a real denial keeps its `403` and body, and a lookup error that is not an outage stays a fail-closed `403`. A new guard fails when an `err != nil || !allowed` branch refuses with `403` / `PermissionDenied` without the transient check (report-only on pull requests for its first day). Three other in-handler checks (project MFA-requirement change, invitations with a role, rotation-policy create) still answer `403` during an outage and are tracked in a follow-up.
- **Permission-lookup outage is visible at three more places.** `CreateRole` / `UpdateRole` over gRPC answer `Unavailable` (retry) instead of `Internal` when the check that the caller holds each permission it bundles into a role cannot be made because storage is down. The template-render route (`POST /api/v1/projects/{id}/secrets/render`) answers `503` + `Retry-After` instead of `403` when the global-scope probe that decides 404 versus 403 for a missing referenced secret fails. `GET /api/v1/system/info` keeps answering `200` and still omits the admin-only fields on such a failure (a cosmetic flag is not worth a 503), and now logs a warning with the error. Fail-closed before and after: only a status code changes.
- **Clearing the login-failure counter after a successful step-up or re-authentication can no longer turn into a 500 (#3712).** `clearLoginFailures` already recovered a panic in its storage write; a panic anywhere else in it (the in-memory budget fallback clear) could still reach the caller after the step-up grant committed. It now recovers across its whole body, so `requireReauth`, `VerifyMFAStepUp` and `FinishWebAuthnReauth` no longer need allowlist rows in the best-effort call-site guard. The step-up recovery-code consume itself became panic-safe in #3557.
- **A machine-identity token on `POST /api/v1/notifications/read-all` and `POST /api/v1/notifications/{id}/read` now gets 403.** The routes act on the caller's own notifications and a machine has none; `read-all` answered 200 `{"all_read":true}` and `{id}/read` answered 404. Nothing was disclosed or changed. Found by the new write walk.
- `POST /api/v1/user-roles`, `POST /api/v1/projects/{id}/invitations`, `PUT /api/v1/projects/{id}/access-requests/{requestId}` (approve) and `POST /api/v1/projects/{projectId}/environments/{id}/restore` now answer 403 when the caller passes the route's permission check but core refuses the request: the caller does not hold every permission of the role it grants, or, for the restore, lacks the authority to reinstate the project's administrative role assignments. They answered 500 before. Nothing was written in either case.
- **Name and user search now ignore case the same way on SQLite and PostgreSQL.** Searching secrets by name on SQLite only matched upper and lower case for ASCII letters, so `äö` did not find `ÄÖ` (PostgreSQL did). The `username` and `email` filters of the user list were case-insensitive on SQLite but case-sensitive on PostgreSQL. All three are now case-insensitive for any script (search term and stored value both NFC-normalized, so a name stored in decomposed form is found too; per-character lower-casing; Greek final sigma treated as sigma) on both backends. PostgreSQL needs a UTF8 database encoding for these filters. On PostgreSQL both the column and the search term are folded by the same SQL expression, so on a database or column with C/POSIX collation (where `LOWER()` leaves non-ASCII letters unchanged) an exact-case search still finds its own value; a different-case non-ASCII search matches only as far as that collation lowers it. No schema change; SQLite gets a small `keyorix_fold` SQL function registered on its connections. `%`, `_` and `\` in a search term are still matched literally.
- **An expired secret suspended with "also clear synced copies" now says so on every read path.** `GET /secrets/{id}?include_value=true` (and the other callers of the core read check, including the by-name lookup) answered the `SecretExpired` refusal without `details.clear_synced_copies: true`, although the value-fetch path already carried it (#3215), so a client reading through that route could not tell that the synced copies should be cleared. The refusal still never returns the value, and a caller who cannot read the secret sees the same 403/404 as before. Guarded on every value-read route and principal by `TestSecretValueReadRefusals_MapToClientErrorsOnEveryRoute`.
- **`admin backup` is refused while a key rotation is pending.** After a killed `rotate` or `rotate-kek`, the backup exited 0 and archived the `.pending` staging file, and `admin restore` then refused that archive on any clean host (#4058). The backup now fails with no archive written and names the fix: start the server once so boot recovery completes the rotation, then back up again. A `kek.salt.pending` still present after a successful start is unused and can be deleted, as the start's log says. Backup scripts see a non-zero exit in this state.
- **Crypto inventory CBOM: a certificate's `signatureAlgorithmRef` now points at the algorithm it was signed with.** It used to reference the algorithm of the certified key (for example `ECDSA-P256`). The document now carries a signature-algorithm component per distinct certificate signature algorithm (`ECDSA-SHA256`, `SHA256-RSA`); the ref is omitted when the algorithm is unknown. The certified key's algorithm stays linked through a `keyorix:key-algorithm-ref` property.
- **Crypto inventory CBOM: the recovery-key verifier's SHA-256 component carries `parameterSetIdentifier` `256` instead of `260`.** For a hash the identifier is the digest length, not the size of the secret it verifies.
- **The crypto inventory no longer hangs on a certificate path that is a FIFO or device.** `tls.cert_file` and the database `ssl_root_cert` / client certificate are opened non-blocking and refused unless they are regular files (symlinks to regular files still work).
- **`crypto_inventory.migration_years: 0` now means zero years instead of silently becoming 3.** Only an absent key keeps the default of 3; the key name and the configuration surface are unchanged. (`docs/CONFIGURATION.md` still describes the default as 3, which is correct for an absent key.)
- **CI: `server/faultops` no longer hits the 30-minute `go test` timeout in the `test-suite` matrix.** The package had grown from 1305s to 1805s inside root-4's catch-all, so main and merge-queue groups failed at random. It now runs in two dedicated legs (`faultops-1`, `faultops-2`) split by test name, root-4 excludes it, and both legs upload coverage into the floor. No test, fuzz corpus or seed was skipped or reduced; `assert_faultops_shards_complete` fails CI if any test would run in no shard or in two.
- `keyorix-server admin` commands now check for an undeclared transaction-mode connection pooler (PgBouncer `pool_mode=transaction` without `storage.database.pooler: pgbouncer-transaction`) before taking the exclusive database lock, as the server does. Previously the lock was taken first and a refusal could not release it on the pooler's shared server connection. `--force` does not override this refusal.
- **The SonarCloud analysis no longer fails intermittently with `NoSuchFileException: .git/.probe-<uuid>`.** The scanner's JGit timestamp probe (a transient file in `.git`) raced SonarPython's unfiltered walk of the project directory; the workflow now makes `.git` read-only for the duration of the scan so JGit does not probe. Analysis scope, coverage and blame are unchanged.
- **`keyorix login`, `mfa activate`, `mfa step-up` and the delete/revoke confirmations lost every piped line after the first.** Each prompt built its own buffered reader over stdin, which swallowed the rest of the pipe, so `printf 'user\npass\n' | keyorix login` failed with `read password: EOF` (#3448). All prompts now share one reader. Terminal password entry (no echo) is unchanged.
- **Operator messages named commands that do not exist** (`keyorix encryption rotate --confirm`, `keyorix system init --database`, `keyorix encryption migrate-provider`, `keyorix encryption shamir-split`). They now name `keyorix-server admin ...`; `TestEveryCommandNamedInAMessageExists` (CLI) and `TestEveryServerCommandNamedInAMessageExists` (server) fail for any quoted command in a Go string literal that is not in the command tree.
- **`printf %s pw | keyorix login` no longer fails with EOF.** A final piped line without a trailing newline is now accepted by every prompt (username, password, confirmations); EOF is reported only when nothing at all was read. CRLF line endings are still stripped.
- **A mistyped subcommand of a group now fails.** `keyorix secret lst` printed the group's help and exited 0; it now says `unknown command "lst" for "keyorix secret"`, suggests `list` and exits 2. A stray positional argument on a command that takes none (`keyorix secret get 42`) is refused instead of silently ignored.
- **Bootstrap and Vault tokens now come from the `*_FILE` boot snapshot.** `KEYORIX_BOOTSTRAP_TOKEN_FILE` and a Vault connector's `token_env` `*_FILE` were re-read from disk after the startup permission check had judged them, so a file replaced between the two reads supplied the token. Both are now answered from the bytes `config.Load` read and judged (`config.LookupSecretEnv`); a file changed after boot is picked up on restart. A new guard (`TestNoLiveSecretenvLookupOfFileCapableVars`, report-only at first) fails when server code calls `secretenv.Lookup` outside the snapshot (#3830).
- **`admin encryption init` no longer blames a live server for a missing key directory.** When the key directory does not exist it now says `key directory <dir> does not exist: run `keyorix-server admin init` (or create it with mode 0700)`; the live-server hint stays for real lock contention (#3742).
- **Web e2e: the secrets CRUD smoke finds the environment tab again.** It matched the tab by its raw, lower-case name, but the page capitalises the label, so every test timed out on any PR that runs web e2e (regression from #3293). The test now matches the capitalised label exactly, without building a RegExp from runtime input. Test-only change (#3351).
- **A user with 10000 or more received shares (the cap) now gets a typed refusal from the secrets list, not a 500.** `GET /api/v1/secrets` answers `422 ShareListOverCap` (the body `GET /shares` already used) and gRPC `ListSecrets` answers `FailedPrecondition`, instead of `500 InternalError` / `Internal`. The list is still never shortened; `show_owned_only` avoids the refusal only for a caller with no role covering the listed scope. The 422 is documented on the operation.
- **Template render no longer answers "no such secret" when the permission check itself failed.** A storage fault in the per-reference permission check of `POST /api/v1/projects/{id}/secrets/render` (a share or ACL read, or a transient role lookup) was folded into the not-found refusal, so a caller holding `secrets.read` at global scope got 404 for a secret that exists, and the refusal was audited as `forbidden`. That caller now gets 503 `storage_unavailable` (+ `Retry-After`) and the refusal is audited `internal_error`. Every other caller keeps the identical 403 a missing or forbidden reference gets (and the identical 503 during a permission-lookup outage), so the fault is no existence oracle (#181).
- **A role grant beyond the actor's ceiling on a group is a 403, not a 500.** `POST /api/v1/groups/{id}/roles` answered the grant-ceiling refusal "Failed to assign role to group" (500); it is now 403 like the user, project-member and group-member paths.
- **A storage outage during an in-handler permission check is a 503, not a 403.** `PUT /api/v1/projects/{id}` (changing `require_mfa`), `POST /api/v1/invitations` (system role and project assignments), `POST /api/v1/rotation-policies` and `POST /api/v1/users` (with `role` / `project_assignments`) now answer 503 + `Retry-After` when the permission lookup itself fails, so a client retries instead of reading "forbidden". A genuine denial keeps its 403.
- Verified already fixed on main and now pinned: `PUT /api/v1/users/{id}/roles` ceiling refusal is 403 (#3840) and the SCIM `GET /scim/v2/Groups` member-read error is a 500 SCIM error, not an empty member list (#3775).
- **`pending_steps` now lists `enroll_mfa` for a user who owes MFA enrolment after an administrator MFA reset.** The login and `GET /auth/profile` responses omitted the step although the setup gate's 403 listed it, so the user was confined but the informational field said nothing was owed. `core.PendingSetupStepsFor` takes the owed flag (`core.MFAEnrolmentOwed(user)` at login, `userCtx.MFAEnrolmentOwed` at profile); users who owe nothing see no change.
- **The gRPC role RPCs (`AssignRole`, `RemoveRole`) answer `PermissionDenied`, not `Internal`, for a role grant-ceiling refusal.** The refusal (`core.ErrPermissionDenied`) fell through `mapRoleError` to `Internal`; it now maps to `PermissionDenied` with a fixed message that names no permission or role. Nothing was ever over-granted: the request was refused before any change.
- **`keyorix secret restore --id N` on a secret that is not deleted answers 409 "secret N is not deleted; nothing to restore" (#3737)** instead of "Storage operation failed: Secret not found (HTTP 404)". A missing secret is still 404; no `secret.restored` row is written for the refusal.
- **An impersonation attempt refused because the target user could not be read now writes its `impersonation.start_failed` audit row (#3786)**, like every other impersonation refusal.
- **Replacing your own roles no longer leaves you with none and a retry that can never succeed (#3684)**; see Security.
- **Machine tokens with a corrupted IP allowlist are refused instead of accepted from anywhere (#3396)**; see Security.
- **Deactivating a user no longer stalls on SQLite when credential cleanup fails.** `UpdateUser`'s
  deactivation wrote the `user.deactivation_cleanup_failed` audit event from inside its own
  transaction, a second writer behind the SQLite write gate that transaction holds. The event is now
  written after the commit; the deactivation itself still succeeds. Guarded by
  `TestNoOuterStorageInTransactionClosure` (INV-CORE-no-outer-storage-in-transaction-closure).
- **DEK rotation sweep now invalidates the read-path latest-version cache.** `admin encryption rotate` rewrites `secret_versions.encrypted_value` in place, which moved none of the terms the cache validates against, so a replica with a warm entry kept serving the pre-sweep ciphertext for up to five minutes: the same plaintext while it still held the old DEK, a decrypt error once it held only the new one. The sweep now raises a new `secret_versions.cache_epoch` column (added by the normal migration, `DEFAULT 0`, no backfill) in the same transaction, and the cache's generation sums it, so every replica misses on its next read. No extra statement on the read path (one more term in the aggregate each hit already issues). A decrypt failure is still an error; nothing falls back. Run `admin encryption rotate` from the same release as the servers: an older CLI does not raise the epoch (entries then expire by TTL, as before). Supersedes the "documented as safe" note of the earlier DEK-sweep test, which is removed. Guarded by `TestDEKSweepCache_*` (SQLite and Postgres, two replicas), `TestSingleWriter_DEKSweepVsLatestVersionCache` and `TestSecretVersionCiphertextWriters_AreOnlyTheSweep`.
- **CLI: the right next step after `admin recover-admin`.** A one-time-password session that must change its password (and enrol MFA) now gets "set your own password with `keyorix change-password` ... `keyorix mfa enroll`" instead of the generic "ask a project admin, or request access" hint. `TestEveryAccountSetupCodeHasItsOwnNextStep` reads the server's account-setup codes, so a new one without a hint fails (#3744).
- **CLI help: `user create` and `logout`.** `user create --help` names the hidden prompt and `KEYORIX_INITIAL_PASSWORD[_FILE]` instead of the refused `--password` flag; `logout --help` says what it deletes, including `ca_file` (#3735, #3744).
- **`admin verify-audit` explains a tampered row in plain words.** The reason for a row whose recorded
  hash no longer matches its contents now reads "the recorded entry_hash does not match the row's
  contents — the row was changed after it was written" instead of naming internal encodings. Text
  only: the result fields, exit codes, JSON keys and the hash chain are unchanged. The same wording
  is used by the chain-encoding migration when it refuses to re-hash a modified row.
- **`keyorix secret versions` no longer prints an internal note** about size/algorithm columns.
- **A wrong bootstrap token on `keyorix system init` gets its own hint:** check that
  `KEYORIX_BOOTSTRAP_TOKEN` / `KEYORIX_BOOTSTRAP_TOKEN_FILE` matches the token the server was started
  with, instead of "ask a project admin, or request access". The exit code is unchanged.
- **`scripts/demo/scenario-k8s-sync.sh` is SKIPPED (exit 2), not FAILED,** when `KEYORIX_SERVER`,
  `KEYORIX_TOKEN` or `KX_SECRET_ID` is not set, so `scripts/demo/catalogue-check.sh` no longer reports
  a failure for a scenario it cannot supply.
- **Audit trail no longer opens with boot noise and `unknown` actors (#3155).** Events written by `keyorix-server admin` commands (`admin init`, `encryption init`, `migrate`, ...) now show actor `admin_cli` instead of `unknown`, so a host-admin action (restore, key rotation, checkpoint export, ...) is never attributed to `system`; `system` stays for server-internal events, and `actor_type=admin_cli` finds these rows (the stored actor type, part of the hash chain, is unchanged). The very first start records one `security.posture_baseline_recorded` event holding every security-relevant setting's initial value instead of ~35 `"" -> "false"` rows; a setting that does not read as off still gets its own `security.posture_setting_changed` event, and every later start diffs against the stored snapshot exactly as before.
- **Dashboard "Audit (30d)" panel for users without `audit.read`** shows "Not visible to you" instead of zero counts that read as "nothing happened".
- **`keyorix secret create --project N`** without `--environment` now uses that project's development environment instead of environment 1, and when the project has no `development` environment it refuses and lists the environments, requiring `--environment` (it never falls back to the first one, which may be production); a refusal "environment X does not belong to project N" names the project's real environments, and the absolute-path refusal for `--from-file` says to use a relative path.
- **No dashboard flash or background 403s before the MFA enrolment page (#3155).** The login response and `GET /auth/profile` now carry an additive `pending_steps` list (`change_password`, `enroll_mfa`; omitted when nothing is owed), so the web app routes an MFA-pending session straight to enrolment without rendering protected pages or firing their queries. What such a session may access is unchanged: the server-side confinement (`EnforceAccountSetup`) is untouched and still answers everything else with 403.
- **System info reports the live database pool (#3037).** `GET /api/v1/system/info` (Settings > System Health, the dashboard DB-connections card, `keyorix system info`) echoed the raw `max_open_conns`/`max_idle_conns` config values, which are 0 on every install that leaves them unset (all compose and Helm installs), and a hard-coded "2 active connections". It now reports the pool the server is running: the cap actually applied (config value or the dialect default), connections in use, and idle. A backend with no local pool still reports 0, which the web UI renders as "not reported".
- **A second "Request emergency access" while one is active now answers 409 with the reason, not 500.** `POST /api/v1/projects/{id}/break-glass` (and `BreakGlassService.ActivateBreakGlass`, now `AlreadyExists`) returned `500 "an internal error occurred"` when the caller already held an active break-glass grant on the project, although the server log had the clean message; the web UI showed "Something went wrong". It is now `409` with "you already have an active break-glass grant on this project; revoke it before activating again" (a conflict with current state, so without the "Validation error:" prefix that input errors carry), which the UI shows. Guarded by `TestActivateBreakGlass_SecondActivationWhileActiveIs409`.
- **Helm `NOTES.txt` no longer says "No admin password was set" when the existing Secret carries one.** Step 3 now uses the chart's own `keyorix.hasAdminPassword` check (values, `auth.existingSecretKeys.adminPassword`, or a live `lookup`) and says to log in. When the render cannot see the Secret (`helm template`, `--dry-run`, GitOps renderers), the text says so and covers both cases: log in if the Secret has `KEYORIX_ADMIN_PASSWORD`, otherwise initialise manually; the bootstrap-token command now reads the Secret the release actually uses (`auth.existingSecret`), not the chart-managed one. Guarded by `TestHelmNotesAdminStep`.
- **`docs/operations/quickstart-60s.md` pins `V=v0.96.3`** (was `v0.96.1`), and the release pin checker `scripts/release/check-docs-version.sh` now covers that file, so the pin is verified at every release instead of rotting.
- **The demo footer no longer says `-dirty` on a pristine checkout.** `scripts/demo/up.sh` and `check.sh` ran `make populate-webui-dist` (which replaces the committed placeholder `server/webui/dist/index.html`) before stamping the build with `git describe --dirty`, so every demo image was `vX-N-gSHA-dirty`. The stamp now ignores the generated `server/webui/dist`; an edited source file still says `-dirty`. Guarded by `TestUp_BuildStampIgnoresTheGeneratedWebUIDist`.
- **The Helm `NOTES.txt` manual-init command now works as printed.** It used `http://localhost:8080` against the chart-default TLS-only server (HTTP 400) and omitted `--admin-email` (init rejected with `Validation error: Email`). It now prints `https://` when `secureBaseline.enabled` (and `http://` otherwise), the `chmod 600` + `keyorix config set ca_file` steps the CLI needs to trust the self-signed certificate (the CLI has no skip-verify flag) before the init command, a port-forward to the server service, and `--admin-username`/`--admin-email`. Guarded by `TestHelmNotesAdminStep`.
- **Every `--role developer` help example is now a role that exists.** The examples for `rbac assign-role`, `rbac assign-role-to-group`, `rbac remove-role`, `rbac remove-role-from-group`, `machine grant-role`, `machine revoke-role`, `invite send` and `request access` (and `docs/cli-reference.md` and the man page generated from them) used `--role developer`, which failed with `role "developer" not found` when pasted; they now use the built-in `project_developer`. `TestHelpExamples_RoleValuesAreBuiltinRoles` checks every `--role` value in every help example against the server's built-in role names.
- **`audit verify` no longer reads NOT PROVEN for a day after a v0.96.x upgrade.** v0.96.x left
  a fresh signed checkpoint but no record of a full re-walk, and the new server held its first
  verification tick back until that checkpoint was 24 h old. The first tick now runs at start
  whenever no full verification is on record, so a chain of up to 100,000 events reads `VALID`
  within seconds of the first start (the log says `first tick in 0s`). A longer chain is still
  re-walked over 7 daily ticks; `keyorix audit verify --full` proves it at once. What `VALID`,
  `NOT PROVEN` and `BROKEN` mean is unchanged. Upgrade note:
  `docs/upgrading.d/audit-verify-after-v096-upgrade.md` (#3743).
- **`keyorix run --var` read every secret in the environment.** It fetched (and audited as `secret.read`) the value of all secrets in the project and environment and then filtered, so a CI identity injecting one secret looked like it had read the whole project and tripped the `principal_breadth` anomaly rule. It now reads only the secrets named by `--var`; `--derive-names` is unchanged.
- **`keyorix compliance verify` rejected every genuine evidence pack.** The server binds the signature to the pack's canonical filename (carried in the `.sig`), but the CLI never sent it, so verification always failed with "presented under the wrong filename". The CLI now sends it.
- **Demo seed no longer leaves a red `principal_breadth` alert.** The seed's own setup calls (13 secrets) are acknowledged with the other first-observation alerts.
- **Demo readiness check asserted a stale rotation total.** `scripts/demo/check.sh` hard-coded "2 of 3 secrets covered" although the seed now has 13 secrets, failing `demo-up-smoke` in the merge queue. It now asserts exactly one secret uncovered ("N-1 of N", N >= 3) on the secret-rotation gap; the real-backend Compliance spec does the same.
- **`scripts/demo/check.sh --postgres` now comes up on any Linux host, not only a uid-1001 CI runner.**
  The server refuses secret files owned by another user, and the check's throwaway Postgres stack
  creates them as the host user, so on a normal dev box (uid 1000) the backend exited at startup and
  the check never ran. The files are now handed to root (passwordless `sudo`, else a throwaway
  `docker run --user 0`) on every non-root Linux host.
- **`scripts/demo/check.sh` latency step has a baseline** (`scripts/demo/latency-baseline.txt`), so the
  p50 secret-read time prints next to a recorded number and fails only at 10x it.
- **`scripts/demo/check.sh --url` can check the native demo.** It read only `./.demo-2-state`, so against a `native-up.sh` demo every authenticated step failed with `401 missing authorization header`. It now finds `.demo-native/state.env` (the file whose `DEMO_URL` matches `--url`) or takes `--state FILE`, and says which file it used. New `--used` for a demo that has already been read from: open `new_user`/`new_ip` alerts make "no open anomalies" and "exactly one compliance gap" a printed WARN instead of a FAIL; any other alert still fails, and without `--used` a fresh demo stays strict. Guarded by `scripts/demo/check_state_test.go`.
- **`scripts/demo/native-up.sh` builds the scenario helpers.** It built only the server, CLI, TOTP helper and `demo-dbexec`, so the MCP, OIDC-federation and Vault-import scenarios stopped at "bin/... missing: go build ...". It now also builds `bin/keyorix-mcp`, `bin/demo-oidcissuer`, `bin/demo-fakevault` and `bin/keyorix-migrate` when missing (also on a re-run against a demo that is already up). New flags: `--with-helpers` (default), `--no-helpers`, `--build-only`. A helper that fails to build is reported and the demo carries on. Guarded by `scripts/demo/native_up_helpers_test.go`.
- **Light-theme secondary text is readable.** `--text-muted` (gray-400 on white, about 2.5:1) and the light `--danger`, `--error`, `--success` and `--warning` tokens now reach 4.5:1 as text on every light surface; the dark theme is unchanged. A unit test computes the ratio of every token pair so it cannot regress (DEMO-WALK-4 finding 5).
- **Admin tables usable on a phone.** The Groups table no longer clips its Actions column and the Secrets table keeps its row actions on screen at 390 px: the Actions column is pinned to the right edge of the sideways-scrolling card (DEMO-WALK-4 finding 3).
- **`scripts/demo/check.sh` "no open anomalies after 6 minutes" step works on the Postgres demo stack again.**
  It read the server uptime from `GET /health`, but behind the compose stack nginx answers `/health` itself
  with a static `healthy`, so the step failed with "could not read the server uptime" on every nightly run
  since the step was added (#3152). `demo_uptime_seconds` now reads `data.uptime` from the authenticated
  `GET /api/v1/system/info` (admin token); `/health` is unchanged and still exposes no new fields. When the
  uptime cannot be read, the helper now prints the HTTP status and the head of the response body to stderr
  instead of failing silently.
- **`docs/operator/startup-refusals.md`: the "Wrong master passphrase" entry now says
  what the key-file state looks like when you reach it.** Start-up checks the key set
  (`keys/dek.key`, `keys/kek.salt`, `keyset.manifest.json`) before it tries the passphrase,
  so a missing or mixed file is refused earlier with `key file consistency: ...` or the
  file-permission audit; the entry now links to those two and says that this message means
  the files are present and consistent.
- **Server, CLI and `migrate` did not compile for 32-bit ARM (`linux/arm`).** Three untyped constants above 2^31 were used as `int`: the dynamic-secret TTL bound (`internal/core`), the bundle component size limit in the error message (`pkg/bundleverify`) and a project-id range check (`migrate`). The checks keep their meaning (on a 32-bit `int` the bound cannot be exceeded, so it is clamped to `MaxInt`; messages still print the real limit). Nothing changes on 64-bit targets.
- **`--passphrase-fd` was silently ignored.** The server binary and the `admin diagnose` / `backup` / `restore` / `audit export-checkpoint-key` commands declared `--passphrase-fd` so that it never marked the descriptor as given, so the master passphrase was not read from it and the command failed with "no master passphrase available" (fail-closed). This is the descriptor form ADR-099 recommends for systemd `LoadCredential=`. The flag now works, and a non-numeric value is refused with a clear error.
- **A storage fault no longer reads as "not found" for dynamic-secret configs, leases and machine tokens.** `ClassifyDynamicSecretConfig`, `SetDynamicSecretConfigEnabled`, `IssueLease`, `RenewLease` and the lease project/environment liveness check folded any read error into "config/lease not found"; a database outage now answers the retryable storage-unavailable class (HTTP 503, gRPC `Unavailable`) and a true not-found stays 404 / `NotFound`.
- **A driver message can no longer pick a gRPC status class.** The gRPC machine-identity, dynamic-secret and user mappers classify core's refusals by typed sentinel (`ErrMachineIdentityNotFound`, `ErrMachineTransitionInvalid`, `ErrMachineIdentityNotActive`, `ErrDynamicSecretNotFound`, `ErrValidation`) instead of words in the error text; a backend or driver error that says "permission denied" or "required" is a backend failure, not a caller refusal.
- **`POST /api/v1/audit/checkpoint` shows a checkpoint refusal reason by sentinel, not by text.** An unrelated storage error that happens to contain "refusing to checkpoint" is no longer echoed to the client (it stays in the log).
- **Storage read faults no longer answer "not found" on more endpoints.** A database
  outage used to look like "does not exist" on `GET /secret-access-requests/{id}`,
  `POST /secret-access-requests`, `POST /anomalies/{id}/acknowledge`, the by-reference
  secret read (`?ref=`), the access-review campaign endpoints (and the CSV export),
  access-review revoke/attest, `POST /folders` (parent folder), membership transitions
  and `POST /secrets/{id}/copy`. They now answer `503 storage_unavailable` with
  `Retry-After` (or 500 where the endpoint has no 503 mapping yet), and a true
  not-found keeps its 404. The by-reference gate keeps the 403 for callers without the
  permission, exactly like the by-ID gate.
- **Not-found is matched by typed error, not by message text.** Notification mark-read,
  secret-ACL, risk-exception approve, group-member, project-member, folder and membership
  handlers, the access-review status mapping, the rotation-state read and the secret
  read-denial audit classification no longer treat any error whose text contains
  "not found" as a missing target; a driver error worded that way was a 404 or an idle
  rotation state. New sentinels: `ErrAccessReviewNotFound`, `ErrMembershipTargetNotFound`,
  `ErrAnomalyAlertNotFound`, `storage.ErrNotificationNotFound`.
- **Per-secret ACL check no longer reads a storage outage as "no grant".** `GetSecretACL` wrapped every error (DB outage, cancelled context) as "Resource not found", and the authorization check matched that text: in English an outage silently became "no ACL grant" (a plain denial, or an ACL holder silently missing from the secret access report), while in de/es/fr/ru the same outage was an error. Only a missing row (`storage.ErrSecretACLNotFound`) now means "no grant"; any other failure is an authorization error in every locale. Effects: the secret access report marks the outage as `degraded` instead of leaving the holder out; in-core per-secret checks (`CheckSecretPermission`, sharing status, dependency create/delete) return a retrieval error instead of "insufficient permissions"; a bulk suspend that clears synced copies counts the secret as failed instead of skipping it as denied. The per-secret route gates still answer any authorization error with a denial (HTTP 403, gRPC PermissionDenied), unchanged. `POST /secrets/{id}/acl` reports a failed target lookup as a 500 instead of "node not found". The last-admin guard drops a holder only when the account is positively gone (`storage.IsUserNotFound`). An outage never grants access, before or after.
- **Environment lookups on the role scope guard, the machine-role environment check and the environment-without-project grants report classify by sentinel.** A storage error worded "environment not found" was taken for a missing environment (a 400 refusal instead of a 500, and in the access-review report a live grant described as "environment no longer exists"). It is now reported as the storage failure it is.
- Core authorization refusals (the "permission denied" and "not authorized" family, plus the SoD, risk-exception, machine privilege ceiling and share-management refusals) now match a single sentinel, `core.ErrPermissionDenied`, so a caller can map them to 403 with `errors.Is` instead of matching translated text. The refusal text is unchanged. The bulk-suspend skip check uses the sentinel instead of the translated text.
- **Role and permission routes now answer 404 / 403 / 409 / 5xx by what failed, not by the wording of the error.** The RBAC handlers (`/roles`, `/permissions`, `/user-roles`, `/groups/{id}/roles`) decided "not found", "already assigned", "built-in role" and "you do not hold it yourself" by looking for English text in the error. Under a translated server locale a real missing role, a duplicate grant or a refused built-in edit became a 500, and a database failure while looking up a group or permission was reported as a 404 (its error text carried "not found" around the driver message), hiding the outage. They now use typed errors (`ErrRoleNotFound`, `ErrPermissionNotFound`, `ErrGroupNotFound`, `ErrUserNotFound`, `ErrRoleNotAssigned`, plus the new `ErrRoleAlreadyAssigned`, `ErrRolePermissionNotAssigned`, `ErrBuiltinRole`, `ErrActorLacksPermission`, `ErrRoleNameReserved`), so the status follows the failure in every language. Message texts are unchanged.
- **Secret read, create, update, delete, classify, auto-rotate, rotate and rollback routes now answer 404 / 403 / 409 / 422 / 5xx by what failed, not by the wording of the error.** The secret handlers decided "not found", "permission denied", "already exists" and "environment ... does not belong to project" by looking for English text in the error. Under a translated server locale a real missing secret or a refused read became a 500, and a database failure on the secret lookup (core wraps the driver error under the "not found" text) was reported as a 404 even in English, hiding the outage. They now use typed errors (`ErrSecretNotFound`, `ErrSecretVersionNotFound`, `ErrPermissionDenied`, plus the new `ErrSecretAlreadyExists`, `ErrSecretTargetInvalid`, `ErrAlreadyCurrentVersion`), so the status follows the failure in every language. Message texts are unchanged.
- The secret dependency (list, add, remove, impact, impact preview), certificate inspection, rotation dry-run, version diff and version comment routes now answer from the kind of failure (`errors.Is` on a sentinel) instead of matching the translated error text. Under a non-English locale a real 404, 400 or 403 on these routes is no longer a 500. A storage failure while reading a secret, a dependency edge or a version is now a 5xx instead of a 404 (add-dependency used to answer it 400). Error texts are unchanged (ERRLOSS-SENTINELS-1).
- A dependency-graph cycle found while computing rotation order or plan is a server-side data fault and is now a 500, no longer a 400 (it matched the word "cycle").
- A restricted-classification gate refusal (missing `secrets.read.restricted`, no approved access request, no recent MFA step-up, or a read with no identifiable user) now matches the permission-denied sentinel, so certificate inspection and the value routes answer it 403 instead of 500 (copy answers it with its usual not-found refusal). A storage failure while checking a gate is still a 5xx. A version-comment call on a secret that no longer exists is now a 404 instead of a 500.
- **Secret tag, description, move and copy routes now answer 404 / 403 / 400 / 5xx by what failed, not by the wording of the error.** These handlers looked for "not found", "permission" and "exceeds" in the error text. Under a translated server locale a real missing secret or refused write became a 500, and a database failure on the secret lookup was reported as a 404 (copy also answered 404 for any failure of its source read), hiding the outage. They now use typed errors (`ErrSecretNotFound`, `ErrPermissionDenied`, plus the new `ErrSecretInvalidInput`), so the status follows the failure in every language. Server errors on describe, move and copy no longer echo the raw storage error text. Copying into an environment that does not exist is now a 400 (it was a 404 from the driver's "record not found" text). Message texts are unchanged.
- The secret access-list, access-history, access-stats, audit-trail, access-log-export, read-summary and risk routes now answer from the kind of failure (`errors.Is` on a sentinel) instead of matching the translated error text. Under a non-English locale a real 404 or 403 on these routes is no longer a 500, and an unrelated error that says "permission denied" is no longer a 403. A storage failure while reading the secret on the export and risk routes is now a 5xx instead of a 404. An unsupported export format is a typed 400. Error texts are unchanged (ERRLOSS-SENTINELS-1).
- The secret suspend, resume, ownership-transfer, ownership-history, bulk-reassign-owner and template-render routes now answer from the kind of failure (`errors.Is` on a sentinel) instead of matching the translated error text. Under a non-English locale a real 404, 403 or 400 on these routes is no longer a 500, a storage failure while reading the secret, the new owner or a referenced secret's latest version is a 5xx instead of a 404, and an unrelated error that says "permission denied" is no longer a 403. Error texts are unchanged (ERRLOSS-SENTINELS-1).
- Copying a secret whose source is suspended, has used all its reads or is outside its access schedule now answers that refusal's status and stable code (409/409/403) instead of a 500. The "environment not found" refusal of a copy names the environment instead of echoing the storage error.
- Storage getters for notification channels, machine credentials, OIDC bindings, connector project bindings, secret templates, shares, SSO login state, permissions, alert escalation policies and rotation policies now return typed not-found sentinels (`storage.Err…NotFound`) for a missing row, so callers can classify with `errors.Is` instead of matching the translated error text. The error text is unchanged and a driver error never matches a sentinel. Handler migration follows in a separate change (ERRLOSS-SENTINELS-1).
- **User routes now answer 404 / 5xx by what failed, not by the wording of the error.** The user, impersonation and user-role handlers decided "no such user" by looking for the text "not found" in the error. Under a translated server locale (de, es, fr, ru) a real missing user became a 500; and because core prefixes every storage error with "user not found", a database failure on a lookup was reported as a 404 (for example on `GET /users/{id}`, the by-email, by-username and by-external-id lookups, update and start-impersonation), hiding the outage from the admin and from monitoring. The handlers now use the typed `ErrUserNotFound`, so a missing user is a 404 and a storage failure is a 5xx in every language. `POST /users/{id}/resend-setup-link` no longer returns the raw storage error text to the client on a 500. Review follow-ups for the storage not-found sentinels: the remaining `fmt.Errorf` sentinel sites keep the database cause, and `CheckSharePermission` and the by-secret rotation-policy lookup are covered by tests.
- **gRPC group, share, ACL, user and connect errors are classified by typed error, not by the words in the message.** A Postgres `permission denied for table groups` (a database-role fault) used to answer `PermissionDenied`, and any storage or driver text containing `invalid`, `required` or `exceeds` answered `InvalidArgument`; a name a user controls could steer the class. Untyped errors now answer `Internal` (`Unavailable` for a transient authorization-storage outage); real refusals keep their class. The `roles.assign` ceiling and group-restore authority refusals now match `core.ErrPermissionDenied` (text unchanged), so restoring a group that holds an administrative role as a non-administrator answers `PermissionDenied` instead of `Internal`. The user-service message for these refusals is now `insufficient privileges for this operation`.
- **Connect errors that merely echo a safe phrase are no longer forwarded to the client.** The gRPC connect service matched five phrases inside the error text, so an upstream connector or storage error that echoed a caller-controlled ref could be passed through verbatim; it now matches the core sentinels, as REST already did.
- **A storage fault no longer reads as "first boot" for a connector.** Boot-time connector ownership re-pinned a connector's project by name on any storage error whose text contained `not found`; it now requires the typed not-found.
- **Vault token TTL check reports a failed body read.** `CheckTokenTTL` discarded the read error, so a connection that died after a complete root-token reply returned a TTL of 0 with no error, which looks like a healthy never-expiring token. It now returns the (wrapped, body-free) error (#4063).
- **TOTP under `GODEBUG=fips140=only` is refused with a clear error, not a panic.** Keyorix TOTP is HMAC-SHA-1, which Go's FIPS 140-only mode refuses. In that mode MFA enrolment, activation, the login second factor, step-up and re-authentication with a six-digit code now return 503 `TOTP is not available in FIPS mode; use a recovery code or a passkey`. The refusal happens before any code is checked: nothing is consumed, nothing counts toward the account lockout or the login budget, and the attempt is audited as `mfa.error`. Recovery codes and passkeys keep working. Outside that mode nothing changes. Whether FIPS mode should offer TOTP with another algorithm is still open.
- **A webhook signing secret under 14 bytes is refused under `GODEBUG=fips140=only`, not a panic on delivery.** Go's FIPS 140-only mode refuses an HMAC key under 112 bits, and the notification webhook's delivery worker panicked on one. In that mode the server now refuses to start when `notifications.webhook.signing_secret` (or `KEYORIX_NOTIFY_WEBHOOK_SIGNING_SECRET`) is set and shorter than 14 bytes, and the error names the minimum. As a second check, a delivery with such a secret fails with an error and posts nothing. Outside that mode nothing changes.
- **Azure Key Vault: a wrong-length unwrap result is refused before the envelope MAC check.** `Decrypt` keyed the version-pinning MAC with the unwrapped key before checking that it is a 32-byte KEK, so a short result panicked under `GODEBUG=fips140=only`. It is now refused first with the provider's `KEK must be 32 bytes` error and wiped, in every mode. Real KEKs are 32 bytes, so stored keys decrypt as before.
- **`verify-audit` refuses a checkpoint key under 14 bytes under `GODEBUG=fips140=only` with a usage error, not a panic.** A `--checkpoint-key-file` or `--previous-checkpoint-key-file` of 1 to 13 bytes made the verifier panic in `crypto/hmac` in that mode. It now exits 3 with a message naming `MinKEKLen` (14 bytes); real checkpoint keys are 32 bytes. Outside that mode such a key is still reported as not authenticated, as before.
- **A wrong Postgres password now fails startup with one clear message instead of the driver's `connection reset by peer`.** When Postgres rejects the credentials (SQLSTATE `28P01` / `28000`), or the server or a proxy in front of it closes the connection during the login exchange, the server and the admin commands report `postgres authentication failed for user "..." at host:port` and name what to check (the database user and the password source: `KEYORIX_DB_PASSWORD`, `KEYORIX_DB_PASSWORD_FILE`, `storage.database.password`, or the DSN). The message never contains the password or the DSN; the server logs the driver's text with both redacted on a second line. Documented in `docs/CONFIGURATION.md`.
- **Storage tests no longer leak the role-permission integrity check.** Tests in `internal/storage` and `internal/storage/store` that built a Postgres storage without closing it left the integrity-check goroutine running and logging for the rest of the test binary, which raced with a later test that captures log output (`-race` merge-group failure). Each such storage is now closed at test cleanup, and both packages' `TestMain` fail the run if any storage background job is still running after the last test (`store.LiveBackgroundJobs`).
- **The fault-ops test world now closes its SQLite connection pool on cleanup (FLAKE-4).** `openWorldDBTB` (`server/faultops`) already closed the Postgres pool when the test finished but left each SQLite in-memory database open, so a fuzz run leaked two databases per iteration until the process exited. Guarded by `TestOpenWorldDB_ClosesPoolOnCleanup`, which pings the pool after its owning subtest ends.
- **single_writer canary no longer counts the server's own write as unattributed.** The poller read the write tracker's commit count after the poll's answer, while the epoch it compares is as of the statement's snapshot; a commit landing in between could raise a false "epoch moved without a write" alarm, and a second one left the authoritative state until restart (fail closed, caches stopped working). The tracker is now read before the poll is sent. Guard: `TestPoll_CanaryCountsACommitInThePollThatSeesItsMove`.
- **A secret you just deleted now shows up in the project's recycle bin without a page reload.**
  Deleting a secret (single or bulk) did not refresh the project settings "Recycle bin" list, which
  could stay stale for up to five minutes after in-app navigation; both delete actions now invalidate it.
- **`POST /api/v1/projects/{id}/memberships` answers 403 for a role the caller may not grant.** It answered 500. The response is documented in the OpenAPI document, as it now is for `POST /api/v1/projects/{id}/members`.
- **Cancelled scheduler ticks stop cleanly.** When a scheduler lock is lost or the server shuts down mid-tick, auto-rotation no longer reports the secrets it had not reached as failed, and evidence delivery no longer publishes a signed pack that is incomplete only because the tick was cancelled. Both are picked up by the next tick.
- `DELETE /api/v1/groups/{id}/roles/{roleId}` for a grant the group does not hold at that scope answers 404 "Role not assigned to group" (as `DELETE /api/v1/user-roles` does), not 500.
- **gRPC `RemoveRole` of a grant the subject does not hold answers `NotFound`, and `AssignRole` of one it already holds answers `AlreadyExists`, instead of `Internal` (#4020).** They match REST's 404 and 409. A real storage fault on the same call still answers `Internal` (an audit-log outage still `Unavailable`). The `O-S:known-other-4020` tolerance is gone from the authzdiff sequence harness.
- **gRPC share mutations (`UpdateSharePermission`, `RevokeShare`) answer `Unavailable` when the share or its secret cannot be READ, instead of `NotFound` (#3911).** `NotFound` is now only for a row that is really absent, as REST's 503 since STORAGE-ERR-CLASS-3. The dynamic-secret scope resolver already did this; a test now guards it.
- **A bulk secret delete marks the items an outage left undeleted as retryable (#3912).** Each such item in `failed[]` carries `code` (`audit_unavailable` or `storage_unavailable`, the single delete's words) and `retryable: true`; the result has a `retryable` count and the response message says how many to retry. A real not-found, a refusal or an unclassified error is never marked. The two new fields and the count are documented on `BulkOpError` / `BulkDeleteResult`.
- **SCIM `PUT /Groups/{id}` answers 200 with the group when a member removal committed and only its read-back failed (#3773).** It used to answer a SCIM error for a change that had already been applied, which tells the IdP the revocation did not happen. The body is built from the group row and the members the new set kept; the cause is logged.
- **Rolling upgrade: an older replica's audit purge could drop the purged-event count for good (#3359).** A pre-#3258 binary rewrote the v2 retention anchor as v1, after which `/audit/verify` reported truncation and checkpoints answered 409. On PostgreSQL a trigger now refuses that write, so such a purge rolls back whole; the epoch floor stops older binaries from starting.
- **Rolling upgrade: an older replica's resume left the "clear synced copies" marker set, and its next plain suspend emptied the Kubernetes copies (#3362).** On PostgreSQL a trigger clears the marker on every status change away from `suspended`, whoever writes it, and the migration clears rows already left stale.
- **gRPC: removed a message-size option that never took effect.** A `MaxRecvMsgSize` derived from `secrets.limits.max_secret_size` was always replaced by the later `server.grpc.max_request_body_bytes` option; the comment claiming wire-level parity with the HTTP secret routes was wrong. Oversized secret values over gRPC are still refused by core (`ResourceExhausted`).
- **TLS 1.2 with ECDSA certificates.** The default TLS 1.2 cipher list held only `ECDHE_RSA` suites, so a server with an ECDSA certificate failed every TLS 1.2 handshake (only TLS 1.3 clients could connect). The default now includes the matching `ECDHE_ECDSA` AEAD suites on both listeners.
- The web "SDKs & CLI" page and `docs/MIGRATION.md` no longer teach `keyorix connect`, `keyorix auth login`, `--password` or `--value`; they show `keyorix login --server …` (password prompted) and `keyorix secret create --from-file`. A new vitest guard fails on any `keyorix <unknown subcommand>` or `--password`/`--value`/`--mfa-code` in web string literals, with the command list derived from `cli/cmd`.
- `docs/state-map/entrypoints.tsv` no longer carries a line-number column, which went stale on every unrelated edit (102 rows had drifted unnoticed). A new `cmd/statemapgen` test regenerates both state-map TSVs into a temp dir and fails on any differing row.
- **Machine-token lifetime is bounded on both transports.** `expires_in_days` below 0 used to mint a token that never expires, and a huge value overflowed the expiry computation. HTTP and gRPC `IssueMachineToken` now share one core check (`core.MachineTokenExpiresAt`): 0 or omitted still means never expires, a negative value or one above 36500 days is `400` / `InvalidArgument` and mints nothing.
- **A personal access token cannot be created already expired.** `POST /api/v1/auth/tokens` accepted an `expires_at` in the past and issued (and showed once) a token that could never be used. Core `CreateOwnPAT` now refuses an expiry at or before now with a validation error (`400`), so every caller is covered; an omitted `expires_at` still creates a non-expiring token.
- **README and `docs/SELF_HOSTING.md` §2 clone the release tag, and `docker-compose.yml` pins the matching images.** `git clone` of `main` followed by `docker compose up -d` left the backend unhealthy (`field ssl_root_cert not found in type config.DatabaseConfig`: `main`'s `keyorix.docker.yaml` was ahead of the pinned `0.96.0` image). Both docs now use `git clone --branch v0.96.3`, and the compose pins are `0.96.3`. `scripts/release/check-docs-version.sh` now also checks `git clone --branch vX.Y.Z` pins, so a stale clone tag fails the release check; `TestComposeImagePinsMatchLatestRelease` accepts pins ahead of `main`'s newest CHANGELOG heading (patch releases are cut from a release branch) but still rejects older or mismatched pins.
- **Install docs: five wrong or stale statements found by the INSTALL-CLEANROOM-2 re-walk.** `QUICK_START.md` pins `V=v0.96.3` and says what a release CLI lacks (`KEYORIX_PASSWORD_FILE`, `KEYORIX_MFA_CODE[_FILE]`, `keyorix doctor`) and what to use instead (password on stdin plus `--mfa-code`), and how to script `mfa activate`; `INSTALL-WITH-AI.md` step 15 lists `secrets/metrics_token` among the files to back up and to put in a restore directory (without it the restored install does not start); `docs/SELF_HOSTING.md` §5 streams the backup out of the container's tmpfs instead of `docker compose cp` and runs `chmod` before `chown` on the restore archive.
- **The evidence-pack and audit-checkpoint signing keys are called KEK-derived everywhere users read about them.** The OpenAPI and gRPC text, `keyorix compliance verify --help`, `docs/cli-reference.md`, the man page and the generated web API types said DEK-derived (the code comments were fixed in #3885). The OpenAPI text for evidence verify also promised that a signature made under a superseded DEK version (after a key rotation) is unverifiable. That is not what happens: a DEK rotation does not change the key. A pack signed before a KEK change (`rotate-kek` or a KEK-provider migration) is reported as `valid: false` with a "superseded key version" reason, `key_version` and `current_version`, not as tampered. The checkpoint endpoint text no longer tells operators to re-baseline after a key rotation: a DEK rotation does not change the key, and `rotate-kek` / a KEK-provider migration carry the audit verification state over and write a fresh checkpoint themselves (`docs/operator/key-rotation-runbook.md` section 5). `TestEvidenceVerify_PackSignedBeforeKEKChangeIsUnverifiable` derives the keys from two real KEKs and asserts the described behaviour.
- Restoring a secret that is not deleted now answers 409 Conflict with "secret N is not deleted; nothing to restore" instead of a 404 "Storage operation failed: Secret not found" that read like a storage fault (#3737). A secret that does not exist still answers the same 404, and the route's permission check still runs first.
- **Paginated user, group and secret lists have a stable order.** `ListUsers` and
  `ListSecrets` had no `ORDER BY` on the paged query and `ListGroupsPage` ordered by name
  only, so on PostgreSQL the row order could change between pages when the planner's
  statistics changed, repeating some rows and skipping others in a page-by-page walk. The
  queries now end in an `id` tiebreak (existing primary sort keys are unchanged). Regression
  tests walk the pages on SQLite and, with `KEYORIX_TEST_PG_DSN` set, on PostgreSQL with an
  `ANALYZE` between pages.
- **A lost advisory lock is detected on direct and `pgbouncer-session` connections too.** On the most common install (PostgreSQL direct, or PgBouncer in session mode) the locks are session locks, and a `pg_terminate_backend`, a PostgreSQL restart or failover or a network partition ended them silently: the holder kept running while another replica took the lock, so two scheduler jobs or two single-writer servers could run at once. Every advisory lock held across statements is now checked in every pooler mode (the same 5-second ping as `pgbouncer-transaction`, one log line for every kind of lock). A named, scheduler, bootstrap, audit-checkpoint or audit-index-build lock holder's context is cancelled with `ErrAdvisoryLockLost`, so its work stops, and the call returns that error. A server whose presence lock or `single_writer` holder lock is lost shuts down gracefully and exits with status 1. Guarded by `TestSessionAdvisoryLock_KilledLockBackend_StopsTheHolder`, `TestPostgres_ServerGuard_LostSessionPresenceLockIsReported`, `TestGuard_KilledHolderBackend_ClosesLost` and `TestLockLoss_Postgres` (a real server, `pg_terminate_backend`, exit status 1).
- **The web footer no longer requests `GET /api/v1/system/info` while the session is MFA-pending.** The footer's system-info query now runs only for a fully authenticated session that owes no setup step, so an enrolment-confined session fires no refused request (restores `web-e2e-real-smoke` shard 1/2 on main). The server-side confinement is unchanged.
- **MFA reset tails (REVIEW-3838-DEEP-1 L1-L3).** Registering a passkey now clears the
  enrolment an administrator MFA reset demanded, in the same transaction as the credential,
  so removing that passkey later no longer confines the user to enrolment again. An MFA
  reset approval refused because the request expired or was decided, the requester or the
  target changed, or the approver has no second factor now leaves a DENIED
  `mfa.reset_approved` audit row, whether the refusal is decided before or inside the
  approval transaction (before, only some of these refusals were audited). An MFA reset
  request refused because the requester has no second factor now leaves a DENIED
  `mfa.reset_requested` row. An audit-log outage on the MFA reset routes now answers
  like every other audited mutation: 503 with `Retry-After` and error code
  `audit_unavailable` (was `AuditUnavailable`, without `Retry-After`).
- `keyorix-migrate` printed every error twice (cobra, then `main`); it now prints one `Error:` line. The exit code is unchanged.
- `migrate/healthscan-policy.hcl`, the documented Vault token policy, now lets `vault plan-access` / `apply-access` / `audit-access` list a KV v1 mount (`list` on `kv1/*`: replace `kv1` with your v1 mount) and read userpass users (`auth/+/users`, `auth/+/users/+`). `+/metadata/*` never matched a v1 mount, so with the documented policy `plan-access` could not list one and reported every default-convention policy it could hold as unmappable (`cross-mount-scope`). The "could not list" warning now names the stanza for KV v1 as well as KV v2.
- **`admin restore` reported INDETERMINATE for every database that had ever been through an audit retention purge.** Its automatic `verify-audit` was not given the checkpoint signing key it had just unwrapped, so the purge's signed re-anchor could not be authenticated, although `admin verify-audit --checkpoint-key-file` on the same data said VALID. Restore now derives the key from the restored key files and passes it (SQLite and PostgreSQL). Guarded by `TestAdminRestore_PurgedAuditChain_ReportsValid_SQLite` / `_Postgres`.
- **A restore turned SQL NULL in JSON columns into the text `null`.** The backup archive writes NULL as JSON null and `models.JSON` kept the four bytes, so e.g. `secret_nodes.metadata` came back as `'null'` after a SQLite to PostgreSQL move. The restore codec now gives null back as NULL. Guarded by `TestRowCodec_NullJSONColumnRestoresAsNull`.
- **Signing out once, even when several things end the session at the same moment.** The inactivity timeout, the absolute-lifetime banner and a request whose session was just revoked could each start their own sign-out. The second one sent `POST /auth/logout` with the already-revoked session, got a 401 and redirected to `/login?logout_error=1`, telling the user their session might still be valid when it was not, and cutting off the first redirect (the web-e2e session-timeout spec failed on this with `net::ERR_ABORTED`). A sign-out that is already running is now joined, and a failed token refresh no longer signs out a session that has already ended.
- **Key-directory lock refusals blame a live server only when another process really holds the lock (#3742).** `admin encryption rotate`, `rotate-kek`, `migrate-provider`, the auth-encryption commands, the migrate-backup cleanup, `admin diagnose`, `admin backup`, `admin audit export-checkpoint-key`, `admin audit accept-loss` and the notification-URL step of `admin restore` no longer say "stop the running server" for a missing key directory or a permission error; they report the real cause.
- **Bulk secret delete classifies an in-transaction audit-log outage per item as "could not record the change in the audit log; nothing was changed, retry" instead of "internal error" (#3912).** This applies to callers that write the audit row inside each delete's transaction; such an item is not deleted. `POST /api/v1/projects/{id}/secrets/bulk-delete` is unchanged: it still writes its audit row after the delete commits, best effort, so an audit outage there does not stop the delete.
- **`POST /auth/end-impersonation` with a personal access token answers 403 instead of 500 "session not found" (#3465).**
- **Concurrent writes on a small Postgres pool no longer hang the server.** Operations that take a
  cross-replica named lock (creating secrets per environment, membership and role changes, ...)
  held that lock on a request-pool connection and then waited for a second one, so with as many
  different environments/projects being written at once as `storage.database.max_open_conns`, every
  connection could end up waiting and all requests timed out until restart. Named locks now use
  their own small pool (at most 8 extra Postgres connections per process, closed when idle), and the
  startup headroom warning counts it. Locking behaviour across replicas is unchanged.
- **`TestWebNginxHSTS_ComposeImage` no longer runs under `go test -short`.** The quick tier (`test-quick-root`) died with `panic: test timed out after 8m0s` in `deploy/` on every PR whose affected set included that package. The test starts one real nginx container per case, so it now skips under `-short` and runs only in the non-short tiers. Its HTTP requests also get a 10 s timeout so a stalled connection fails the case instead of hanging the package. Both HSTS tests now probe readiness and assert HSTS on the static `/nginx-health` instead of the backend-aware `/health` (which has no backend in these tests); the Helm test keeps asserting `/health` (its 502 response), and the Compose test no longer asserts `/health`.
- **Every route that takes a new password now says which password rule it broke, the same way `POST /auth/change-password` does (#3543).** `POST /system/init` answered a weak initial admin password with 403 (it reads as a bad bootstrap token); it is now 400 with the rule text, and a wrong token still gets 403 before the policy is consulted. Accepting a project invitation checked the password without the invitee's email, so a password embedding it was refused later inside account creation and answered as "This setup link could not be completed" (a dead link) while the link was in fact still good; it is now checked up front against the identity the account will get and answered 400 with the rule text. gRPC `CreateUser` answered a policy violation with the blanket `InvalidArgument: invalid request parameters`; it now carries the rule text (fixed policy wording, never derived from the password). Other validation failures keep their generic gRPC text. Guarded by `TestPasswordPolicyFamily_RefusalIsA400NamingTheRule` and `TestPasswordPolicyFamily_EveryPasswordOperationIsListed` (fails when an `openapi.yaml` operation with a password field is missing from the table) and, for gRPC, `TestGRPCPasswordPolicyRefusalIsInvalidArgument` and `TestGRPCPasswordPolicyRPCsAreAllListed`.
- **A personal access token whose stored scope list is whitespace only no longer authenticates with its owner's full rights.** Keyorix stores an empty value for "no scope list" and never writes whitespace, so such a row is corrupted or hand-edited; it was read as unscoped. It is now refused everywhere, like a scope list stored as `null` or `[]`. A token created without scopes (an empty value, or a token from before scopes existed) still inherits its owner's permissions.
- **`PUT /api/v1/users/{id}/roles` and `PUT /api/v1/projects/{id}/members/{userId}` answer 403 when the caller asks for a role they cannot grant** (the grant ceiling), instead of 500 "Failed to update user roles".
- **A storage fault while re-checking the caller's own authority in the second half of a role-set replacement is reported as retry-safe** (`retry_safe: true`), instead of "you no longer hold the authority to complete the change".
- **A secret read can no longer stall for its whole audit deadline when it lands on the audit flusher's idle exit.**
  The batching flusher stopped after 200 ms without work if its queue was empty, even when a read had already picked
  up the queue and was about to hand over its audit row; that row then waited in a queue nobody read until its 10 s
  deadline and the read failed with "Failed to record audit trail". Rows now register before they are handed over,
  and the flusher stops only when none is on its way. Guarded by `TestAuditFlusher_SlowSendIsNotStrandedByIdleExit`.
- **`POST /auth/change-password` says which password rule the new password broke.** A new password that broke the password policy (length, character classes, the username/email, the common-password list) was answered with "an internal error occurred; please try again or contact support" (HTTP 400) and the real reason only reached the server log, so a user logging in with a one-time password could not tell what to change. The policy message ("password must not contain your username, email, or display name") is now returned, and only after the current password has been verified: a wrong current password still gets the generic 401 with no policy text. Re-submitting the current password is named ("must differ from the current password"). A new password found in the account's password history is refused with generic wording ("this password cannot be used") and is charged like a wrong current password: it counts toward the account lockout and keeps the per-IP login-budget slot, so the refusal cannot be used to test candidates against the password history for free. Other failures keep the generic text. Guarded by `TestChangePassword_PolicyRefusalNamesTheRule`, `TestChangePassword_EachPolicyRuleIsNamed` and `TestChangePassword_HistoryReuseSpendsTheLoginBudget`. The refusal text is assembled from fixed wording per rule (never from the validator's returned error), and the server log carries a fixed line for it, so CodeQL's `go/clear-text-logging` no longer sees password-check output reach a log call.
- **`admin init` leaves a PostgreSQL database alone until `admin migrate`.** With `storage.type: postgres` and a DSN, init used to open storage for its own audit event, which migrated the whole schema before `admin migrate` ran. It now creates no table and no SQLite file (`keyorix.db*`); it records itself in the audit chain only when the schema already exists, and says so otherwise. Its closing hints are now the last thing it prints, after the SQLite files it creates, and the "Using PostgreSQL instead?" hint names every SQLite file to delete (#3523).
- **`init-secrets.sh` no longer half-initialises when run as uid 1001 (#3522).** A user whose uid is the server container's uid now gets the refusal before anything is written (no secrets, no `.env` edit), instead of the files being created and the script then exiting 1.
- **Admin commands refused because a server is running no longer tell a binary install to run `docker compose` (#3524).** The refusal (`admin encryption rotate` and every other admin command that needs the database to itself) now says "stop the server, run this command again, then start the server" on a host install, and names the Docker Compose sequence only when it runs inside a container.
- **`keyorix-server admin encryption init` no longer blames a live server for a missing key directory (#3742).** The "a live server or an in-progress key operation is using this key directory" hint is now added only when another process really holds the key lock. A missing key directory says `key directory <path> does not exist: run `keyorix-server admin init` (or create it with mode 0700)`; permission denied reports the permission error alone.
- **`keyorix logout` no longer deletes your `ca_file` and server URL (#3735).** Logout revokes the session on the server and removes only the token (and the active project) from the CLI credentials file, rewriting it at 0600 (if that rewrite fails, for example on a full disk, the whole file is removed as before and logout warns that the settings went with it); the next `keyorix login` against a private-CA server works without running `keyorix config set ca_file` again, and `--server` can be omitted. `keyorix login` also checks the server's TLS certificate before it asks for the password, and a certificate failure now says to set `ca_file`.
- **A TLS certificate replaced with its old file time is now served (#4146).** The HTTP and gRPC listeners detected a rotated certificate by file modification time only, so `cp -p`, `rsync -t` or a restore from backup replaced the files and the server kept serving the previous certificate. `internal/tlsreload` now compares a SHA-256 over the certificate and key contents on each `CheckInterval` tick (about 30 seconds); an unchanged pair is not reloaded, and a pair that does not load (mismatched key, half-written rotation) is still never served. No configuration change. Guarded by `TestReloader_PicksUpReplacementWithPreservedMtime`, `TestReloader_UnchangedPairIsNotReloaded` and `FuzzReloaderFailClosed` (now run with fixed file times).
- **Compose `web` `/health` now reflects the backend (#3460).** The web container's nginx answered `/health` with a static `200 healthy`, so the compose healthcheck and any load balancer on port 8088 reported healthy while the backend was down. `/health` is now proxied to the backend's `/health` (502/504 when it is unreachable); a static `/nginx-health` answers for the web container alone. The compose `web` healthcheck keeps probing `/health`; the image-level `HEALTHCHECK` in `web/Dockerfile` moves to `/nginx-health`. If you probe the web port from a load balancer and want it to keep working through a backend outage, point it at `/nginx-health`. Guarded by `internal/config/web_nginx_health_guard_test.go`. Container-level check: pending e2e VM. The Helm chart's web nginx (`web-config.yaml`) is unchanged.
- **A small Postgres pool no longer hangs the server under load at startup.** Background
  scheduler jobs took their cross-replica lock on a connection from the request pool and then
  waited for a second one, so with a small `storage.database.max_open_conns` (e.g. 5) and
  traffic right after boot every connection could end up held by a waiting job, and all
  requests timed out until restart. The scheduler lock now uses its own small pool (at most 4
  extra Postgres connections per process, closed when idle), and the startup headroom warning
  counts them. Single-runner-per-replica behaviour is unchanged.
- **A lost admin-command or key-initialisation lock now fails closed.** The exclusive database lock every `keyorix-server admin` command holds was not watched: if its PostgreSQL backend ended (failover, `pg_terminate_backend`, a PgBouncer restart), a server could start beside a running rotation or restore unnoticed. The command now stops with exit status 1, as after a crash. With `storage.encryption.key_dir_lock: database`, a replica whose key-initialisation lock is lost while it writes the key files now refuses to start instead of serving with keys that may not match the files. Every advisory-lock loss is also counted in the new metric `keyorix_advisory_lock_lost_total{lock}`. See docs/postgresql-poolers.md ("When a lock is lost") and docs/design/pooler-lock-loss.md.
- Revoking or creating a share no longer answers 500 when the follow-up "access revoked/shared" notification panics after the change has already committed. The panic is now recovered and logged at `SECURITY: WARN`, and the committed result is reported as success (#3350).
- `scripts/check-closures.sh` prints each closure row's own verdict even when another test in the same package fails (a failing package used to hide the `ok` line of every healthy row sharing it), and `scripts/gen-security-closures-tsv.sh` now also refuses a fragment whose embedded newline is followed by `#` text.
- **A FIFO can no longer hang `admin validate --posture`.** The integrity checks open `checksums.txt`, the running binary and the `/sys` and `/proc` sources through `secretenv.OpenRegular`; a FIFO at one of those paths reports `unknown` instead of blocking.
- **A database outage no longer looks like a bad token.** With PostgreSQL unreachable, every valid machine token, PAT and session answered 401 (gRPC `Unauthenticated`), was negative-cached for the invalid-token window (so the 401s outlived the outage) and counted as a brute-force strike against the caller's IP. A credential, account or machine-identity lookup that fails now returns a retryable 503 (gRPC `Unavailable`) with nothing cached and no strike; a lookup that positively finds nothing is still a 401. Found by the new disaster drill (`scripts/drills/disaster.sh`). Recovery after the database returned dropped from the cache window to one second.
- Retention purge on PostgreSQL: a failing step (for example the environments delete) no longer aborts the whole purge transaction and rolls back the steps that had succeeded. Each step now runs in its own savepoint, a failed step reports 0 rows for itself, and the `data.purged` audit event counts only what was actually removed.
- Secret share and revoke notifications that fail or panic after the share has committed are now recorded as `notification.failed` audit events (as the access-request notifications already were) instead of only being logged; a failed group-member lookup is recorded too. The share or revoke itself is still never reported as failed.
- **`keyorix-server admin` commands refuse a too-open secret file.** A `*_FILE` secret (for example `KEYORIX_DB_PASSWORD_FILE`) with mode 0644 was accepted by every admin command and then refused by the server at start. The admin commands now apply the server's check (`config.Config.EnforceSecretFilePermissions`) and fail early with the same `secret file security: ...` message. Guarded by `TestLoadConfig_RefusesTooOpenSecretFile`.
- **`keyorix-server admin recover-admin` no longer leaves a passkey admin locked out.** It removed every WebAuthn credential but left `WebAuthnEnabled` set, so the next login asked for a passkey the account no longer had. The flag is now cleared in the same transaction (`TestPerformRecoverAdmin_ClearsWebAuthnFlag`).
- **The frontend SBOM no longer records the build machine's directory.** `keyorix-server_frontend_sbom.cdx.json` carried cdxgen's `LocalNodeModulesPath` (an absolute path such as `/home/runner/work/...`) on two components. `web/scripts/build-frontend-sbom.mjs` now drops those properties and refuses to write an SBOM that still contains the repository path.
- **Nested named locks no longer stall every named lock on a replica (#3358).** A nested `WithNamedLock` call waited in the in-process queue while holding one of the 8 named-lock pool sessions; with enough concurrent role changes for one user across projects, every named lock in the process (secret creation's included) waited until the request contexts ended. A nested call on PostgreSQL now waits in PostgreSQL on the session it already holds.
- **The admin-init config template no longer documents settings that do nothing.** `secrets.limits.max_secrets_per_user` and `secrets.chunking.*` were never read by the server: there is no per-user secret quota and no chunking setting. The template now documents the limit that is enforced, `secrets.limits.max_secret_size` (default 64 KiB), and its session comment no longer claims the 30-minute `access_ttl` is the default (the default is 24h under the 12h `absolute_ttl` ceiling). Existing configs that set the old keys still load; the keys stay ignored. Guarded by `TestShippedConfigKeysAreRead`.
- **A rotation that loses a race with a delete says what it stored (#2873).** When a backend-bound secret is deleted while it is being rotated, the rotated value is still kept as a new version (it may be the only record of the rotated upstream credential), and a restore serves it. The rotate call used to answer a bare "secret not found", and auto-rotation audited it as DRIFT ("storing the new value failed"). The error now names the stored version (still HTTP 404), and the auto-rotation audit says the new value was stored but the secret was deleted during the rotation. Rotations with no backend, rollbacks and value updates already stored nothing in this race; the new two-replica Postgres test covers all of them (`internal/core/rotate_delete_interleaving_test.go`).
- **`admin restore` checks free space where it stages, and its size-limit errors say how to raise the limit.** The pre-flight check measured the filesystem of the archive, but the archive is unpacked into a directory under `$TMPDIR`, which is often a smaller filesystem (or memory-backed); a large restore could pass the check and then fill the staging disk. The check now runs on the staging directory and names `$TMPDIR` when it fails. An archive with a table over the per-entry limit (default 1 GiB uncompressed) or over the total limit (default 2 GiB) was refused with a message that did not mention that `--max-entry-bytes` and `--max-total-bytes` exist; the message now names them.
- **A user created inactive is now stored inactive.** SCIM provisioning with `active: false`, and the admin create paths (REST/gRPC/CLI) with `is_active: false`, wrote `is_active = true`: the column's `default:true` made GORM drop the false value from the INSERT. Login was already refused for a SCIM user (its `account_state` is `deprovisioned`), but `is_active` was wrong in every user list, export and SCIM GET/list. The create now writes the column explicitly in the same transaction as the insert; the model default is unchanged. Existing rows created this way are not rewritten: a SCIM `PATCH active=false` (or an admin deactivate) corrects one. The SCIM provisioning journey now also drives Entra's PATCH body (`"op":"Replace"`, `"value":"False"`) and a POST with `"active": false`.
- **SCIM Groups no longer report a failed write as "not found" or "bad request" (#3620).** `GET`, `PUT`, `PATCH` and `DELETE /scim/v2/Groups/{id}` answered every error with `404`, and `POST /scim/v2/Groups` with `400`; an IdP does not retry either, so a group change that a storage failure rolled back was lost for good (a member removal or a group delete that never happened). A `404` now means the group does not exist; a storage failure, deadlock or cancelled request is `500` with a generic detail (the real error is in the server log), and SQLite write contention is `503` with `Retry-After`, as for SCIM Users. Upgrade note for IdP integrations: a duplicate `displayName` (create, or a rename onto another group's name) is `409` with `scimType: uniqueness`; a member that is not a SCIM-managed user is `400` with `scimType: invalidValue` (PUT and PATCH used to answer `404`); adding members to a group that grants an administrative role is `403`; deleting or emptying the group that holds the install's last administrator is `409`. A storage failure while the server checks a member or the group's roles used to be reported as one of those refusals and is now a `500` the IdP retries (the add is still not made).
- **A SCIM-provisioned user's first SSO login is no longer stuck in change-password-only.** SCIM creates the account in `pending_first_login` with a random, discarded password, so the restricted session could never be cleared (the change needs a current password nobody knows) and only an admin `reactivate` freed the user. The first successful SSO/SAML sign-in now moves a SCIM-owned account to `active` and writes a `scim.first_login_completed` audit event. Local-password accounts keep the first-login restriction, including ones an SSO login claimed by email; suspended, deprovisioned and locked accounts stay blocked (#3655).
- **SCIM group reads no longer hide a storage fault as "no members".** `GET /scim/v2/Groups`, `GET /scim/v2/Groups/{id}` and the POST/PUT/PATCH responses discarded the member-list error, so a storage fault answered 200/201 with an empty `members` array, which an IdP reads as "remove every member". They now answer 500 with the SCIM error body (#3620).
- **A SCIM group write that committed is no longer reported as failed.** `ReplaceSCIMGroup`, `PatchSCIMGroup` and `ProvisionSCIMGroup` re-read the group after the commit, and the handler read its members after that, so a fault in either answered 500 for a write that was applied. A write that can widen access (a create, an add, a rename) now reads the group and its members inside its own transaction and returns them (`SCIMGroupState`): for a single-commit write a failed read rolls it back, so its error is a true "not applied". A pure member removal is a revocation and is never rolled back by its read-back: it reads after its commit, and if that read fails the removal stands and PATCH answers 204 No Content (PUT, which must return the resource, answers 500 and the IdP's retry is a no-op). In a request that both removes and adds, the removals commit first and stand; a failed read in the second commit is reported as a partial mutation (503).
- **A lock error after a committed SCIM user deactivation no longer skips the revocation steps.** In `UpdateSCIMUser` and `DeprovisionSCIMUser`, an error from `WithNamedLock` after the deactivation transaction had committed returned early, skipping the session and cache eviction and the owed audit row, and the IdP's retry would not redo them (#3774). The post-commit steps now run and the lock error is logged.
- **Drill scripts: the last `cmd | grep -q` under `set -o pipefail`.** `scripts/drills/disaster.sh` checked `list_names | grep -qx ...`, which could report a false failure (grep exits early, the left side gets SIGPIPE) and also passed silently when listing failed. It now captures the listing first and greps a here-string. `scripts/drills/selftest.sh` now fails on any `<command> | grep -q`, not only `echo`/`printf`.
- **`scripts/demo/vault-migration-demo.sh` runs again.** It stopped at `project create` ("requires multi-factor authentication") since `security.require_mfa` became the default; it now enrols the demo admin's MFA through `scripts/demo/lib.sh`. `lib.sh`'s `demo_api` also reads the bearer token from a 0600 header file, and its login/activate JSON builders read the password from the environment instead of `python3`'s argv.
- `keyorix user create` now reads `KEYORIX_INITIAL_PASSWORD_FILE`. The refusal of `--password` already told users to set it, but the command ignored it and prompted instead.
- **A killed lock connection behind `pgbouncer-transaction` is no longer silent.** Advisory locks held in a pinned transaction (named, scheduler, bootstrap, audit-checkpoint and audit-index-build locks, and the server-presence lock) are now pinged every 5 seconds. A lock holder whose connection died gets its context cancelled with `ErrAdvisoryLockLost` and an error from the call; a server whose presence lock was lost logs it and shuts down with a failure status instead of running beside a possible admin command. Guarded by `TestWithNamedLock_TransactionPooling_KilledLockBackendIsReported` and `TestPgBouncer_ServerGuard_LostPresenceLockIsReported` (`pg_terminate_backend`). The check never pings a connection while a nested lock waits on it, so a nested `WithNamedLock` that waits longer than the ping timeout is no longer reported as (and turned into) a lost lock (`TestWithNamedLock_TransactionPooling_NestedWaitIsNotALoss`). Direct and `pgbouncer-session` connections are unchanged. See `docs/postgresql-poolers.md`.
- **Refused-secret-read summary rows open at shutdown are no longer lost.** A graceful
  stop (SIGTERM) now writes the audit summary row of every refusal-aggregation window
  still open, so the count of refusals after each window's first row is recorded
  instead of dropped (#3377). The flush is bounded to 10 s so a slow database
  cannot hold shutdown; rows not written in time are counted in a `SECURITY:` log line.
- **Dashboard: failed logins and refused secret reads are counted apart.** The "failed auth attempts (24h)" figure counted every failed audit event, so since #3274 refused secret reads inflated it. `failedAuthAttempts24h` now counts failed logins (`auth.login_failed`) only, a new `refusedSecretReads24h` counts refused `secret.read` events, and the UI labels read "Failed Logins (24h)" and "Refused Secret Reads (24h)". The first dashboard snapshot after upgrade compares against an older, broader count, so its trend arrow for failed logins can read as a one-day drop.
- **Accurate `tls: none` SMTP wording and a clear auth-failure log.** The `KEYORIX_ALLOW_INSECURE_SMTP` refusal (credential delivery and the notification email channel), the env flag description and `docs/CONFIGURATION.md` no longer say relay credentials are sent in cleartext: go-mail never sends a PLAIN or LOGIN password without TLS. They now say the message and username travel unencrypted and that a relay offering only PLAIN or LOGIN will fail to authenticate. When that happens, the send failure now names the cause ("server offers only PLAIN/LOGIN and TLS is disabled") instead of go-mail's generic autodiscover error; credential delivery still hands the admin the setup link. No change to what is sent.
- On SQLite, a risk exception or a Connect per-reference grant created with an `expires_at` that carries a UTC offset other than the server's own (for example `2027-01-01T10:00:00+02:00` on a UTC server) was stored with that offset as text, and every later listing of risk exceptions or Connect reference grants failed with a 500. The expiry is now stored as the same instant in UTC, as on PostgreSQL.
- On SQLite, an invitation, its setup link and an access request created on a server whose host time zone is not UTC stored their expiry and creation time in the host zone, so a project invitation's expiry did not order against the UTC clock the expiry checks use. They are now stored in UTC.
- **A server on a host with a non-UTC time zone no longer stores zoned timestamps on SQLite that it cannot read back.** GORM's `created_at` / `updated_at` stamp now uses UTC (`NowFunc` in the storage factory), and a machine identity's `updated_at` (assigned from the host-zone clock in core) is converted to UTC on save. Before, such a host stored `machine_identities.updated_at` as `2026-10-31 12:44:58.849121 +1400 OT m=+0.45…`, `GetMachineIdentity` failed to scan it, and `POST …/machine-identities/{id}/tokens` answered 404. `last_used_at` written when a personal access token or machine credential is used, and a web session's `last_seen_at`, are now stored in UTC too (a used credential or session could not be read back on such a host), the hygiene stale-PAT and stale-machine counts compare them with a UTC threshold, as are the session `absolute_expires_at` copied on refresh, the SSO/SAML login-state expiry and a new user's one-time-password expiry. Existing rows already stored with a zone suffix are not rewritten.
- **Start-up refusals say why (BOOT-REFUSALS-1 report, items 1, 2, 4).** The file-permission audit refusal now lists each file and what is wrong with it, with the `file permission validation failed:` prefix printed once (the cause used to be only in an untimestamped `[WARN]` line above it). An explicit `security.enable_file_permission_check: true` on a brand-new install still refuses, but says that nothing exists yet and what to do (remove the key for the first start, or restore the key files) instead of three `Cannot open file` lines. The secret-file refusal offers `security.insecure_allow_unsafe_file_permissions` only for files the override actually helps: for the master passphrase, env KEK and Shamir share files it says the override does not apply. It no longer says "refusing" twice.
- **Clearer start-up messages (BOOT-REFUSALS-1 report, items 3, 5-9).** An unknown config key is reported with its YAML section (`unknown key "webauthn" under security`), not a Go type. A misspelled or weak `tls.allowed_ciphers` is refused by config validation, before the start-up lines that read as readiness. Schema-epoch and compatibility-floor refusals say `database schema check failed (checked before migrating; nothing was migrated)` instead of `failed to migrate database:`. A wrong master passphrase is reported once (no doubled `failed to unwrap DEK`) and names the source it was read from (`--passphrase-file`, `KEYORIX_MASTER_PASSWORD_FILE`, ...). The `insecure_*` start-up warning says when its name is a registry name rather than a config key and which key controls it (for `security.insecure_allow_cleartext_transport`: `security.require_transport_tls` is false or not set). A logger set-up failure is no longer printed as `Configuration is invalid:`.
- **A storage outage no longer reads as "not found" or "unknown role" on the grant, create and own-revoke paths.** Revoking your own session or personal access token, creating a user with a system role or project assignments, validating a role grant, creating an environment, copying secrets between environments, approving a secret access request or a project access request, and inviting a project member used to turn ANY failed storage read of the session, token, role, project, environment or secret into the verdict for an absent one (404 "not found", 400 "unknown role", 409 "no longer exists"), so a database outage looked like a mistake in the request and the revoke of a still-valid credential looked already done. A read fault is now `core.ErrStorageReadUnavailable`: REST answers 503 with `Retry-After` and code `storage_unavailable`, gRPC user create answers `Unavailable`. An absent session, token, role, project or environment keeps its existing text and status. The REST dynamic-secret lease routes (`POST /dynamic-secrets/leases/{leaseID}/revoke` and `/renew`), which resolve the lease's scope in the authorization middleware, now answer a lease-read fault 503 `storage_unavailable` to a caller who holds the permission globally; everyone else keeps the 403 they get for an absent lease, so a fault adds no existence signal for them. A transient fault (connection refused, a driver timeout) answers every caller alike with 503 "authorization temporarily unavailable", as every other authorization lookup already does during an outage. Not yet covered: the setup-link accept path (`completeInvitationAccept`) and the grant/create paths of machine tokens and dynamic-secret configs and leases, which stay listed as exceptions in `TestNoStorageReadErrorFoldedIntoNotFound`.
- **More storage read faults no longer read as "not found", "denied" or "invalid".** A read fault now answers 503 + `Retry-After` (code `storage_unavailable`) over REST and `Unavailable` over gRPC, while a true not-found keeps its 404 / `NotFound`. Fixed: a secret access request whose secret cannot be read (`RequestSecretAccess`); gRPC `UpdateSecret`/`DeleteSecret` when the permission lookup is down and every gRPC scoped-target fetch (secret, dynamic-secret config) for a caller who holds the permission globally (closes the two gRPC rows of #3873); template rendering of a referenced secret; the handler pre-checks of project access requests, secret sharing, share listing, leaving a share, and migrating a user to a machine identity; and `core.GetSecret` itself, which no longer reports a read fault as "secret not found". A caller without global standing keeps the uniform denial for an unreadable target, so a fault adds no existence signal. A gRPC `GetSecretValue` refused by such a fault is audited as `internal_error`, not `not_found`, for every caller (as REST already does). Bulk delete's `failed[].error` was already a fixed message: unchanged.
- **Access-review reads answer a storage fault with 503 `storage_unavailable` (+ `Retry-After`), not a 500 or a 400 policy refusal.** The campaign and item listings, the project access report, the role-assignment and share scans behind an attest or revoke, and the group-membership lookup behind the reviewer-independence check (decide and force-close) used to answer 500 with a raw retrieval text; the membership lookup read a fault as "you belong to that group" (400). Still fails closed: nothing is claimed or closed. A campaign, item or grant that does not exist stays 404 (`ErrAccessReviewNotFound`, sentinel not text).
- **`DELETE /api/v1/auth/tokens/{id}` no longer answers 404 for a failed revoke.** Every error after the token read used to read as "Token not found", so a revoke whose write failed told the caller the token was gone while it still authenticated. Only a token that is absent or not the caller's is 404 now (`core.ErrPATNotFound`); a storage-read or audit-unavailable refusal is 503 and a failed write is 500.
- **Alert-escalation policies, notification channels and rotation policies no longer answer a storage fault as 404.** Their Get/Update/Delete handlers (and the channel retry-policy get/set) matched the word "not found" in the error text, so a storage read fault whose driver message contained it read as a missing policy or channel. They now classify by the typed not-found (404) and answer a read fault 503 `storage_unavailable`; validation refusals are typed (`core.ErrInvalidInput`) instead of prefix-matched. Fifteen rows leave the error-text guard's exception list.
- **Audit verification no longer reads a valid chain as broken when a retention purge runs during the walk.** On chains longer than 1000 events, a purge that removed rows past the walk's position reported "prev_hash does not link to the preceding event" (#3944). On that failure the verifier now re-reads the signed retention anchor and, only if a sanctioned purge moved it, verifies the chain once more from the new anchor. A delete outside a purge and a tampered row are still reported broken.
- **Upgrade: PostgreSQL and SQLite databases installed before v0.96 get `idx_break_glass_activations_reviewed_by`.** The migration creates it if missing (idempotent), so upgraded databases match a fresh install (#4091).
- **Nineteen more column-scoped writes store UTC on a non-UTC host.** Writes that update a single column or a set of columns skip the model hooks and GORM's UTC clock, so they stored the server's local time zone: share, project, secret, template, rotation-policy, escalation-policy and dynamic-secret-config `updated_at`, break-glass `revoked_at`/`reviewed_at`, lease `revoked_at`, setup-token `consumed_at`, session `rotated_at`, secret `last_rotated_at`/`cert_not_after`, machine-identity reactivation `updated_at`, the scheduler lock's `expires_at` and anomaly-alert `acknowledged_at`. On SQLite those values did not sort against the UTC timestamps written everywhere else. They are now stored in UTC. Guarded by `TestHookBypassTimeWriters_StoreUTCOnNonUTCHost`, which runs under `TZ=Asia/Kolkata` on SQLite and Postgres.
- **Server integration tests no longer need port 8080 (or 8099) to be free.** The tests that boot the built `keyorix-server` binary from an `admin init` config (`TestAdminGuard_RefusesWhileServerRunning_ThenForceOverrides`, the `recover-admin`, audit-durability and `insecure_audit_skip_reads` end-to-end tests, and the PostgreSQL audit-durability test) now rewrite the config's HTTP port to a free ephemeral one before the first boot, so they pass while another server holds the default port. Test-only change; the product default port is unchanged.
- **Audit full-verification job status.** `GET /api/v1/audit/verify/jobs/{id}` could report a job that had just finished as `interrupted`: the dead-process check ran after the job cleared its local id but against the state read before it saved its result. The status is now re-read before a job is declared interrupted.
- `docs/UPGRADING.md` 6j: the recover-admin alerting first pass is described correctly. An install with no stored `recover_admin_alert_last_notified_id` mark scans the audit table from the first row once; an install with a stored mark resumes from it.
- **A rolling upgrade to a release that changes a trigger function no longer makes old and new replicas revert each other every 30 seconds (PostgreSQL, #3717).** Each checked trigger function now carries a version marker comment with a digest of its definition. A replica leaves a newer release's self-consistent definition (at most one version ahead) in place, on its checks and its boots. It logs a non-`SECURITY` warning, invalidates the cache once and increments the tamper counter under the new `reason="newer_definition"` label. Before, each side logged `SECURITY:` and re-installed its own definition every tick, with fleet-wide cache flushes, and older replicas could undo a security fix. `keyorix_role_permission_generation_tamper_total` and `keyorix_secret_node_cache_epoch_tamper_total` now carry a `reason` label (`tamper` or `newer_definition`), so alert on `reason="tamper"`, and on `newer_definition` outside a deploy. A missing, malformed or inconsistent marker is still tampering. A newer definition is left in place for at most 24 hours from when a replica first reads it: after that the replica logs `SECURITY:`, counts it as `reason="tamper"` and restores its own definition, so a forged marker cannot switch the check off indefinitely. Finish a rolling upgrade that changes a trigger definition within 24 hours. Design and residual risk: `docs/design/trigger-rowdigest.md`.
- **Residual host-zone time handling on SQLite (#3913, #3914).** On a host whose zone is not UTC, an impersonation session now stamps `last_seen_at` and `impersonation_started_at` in UTC, so the last-seen touch is no longer skipped east of UTC. The unreviewed break-glass posture query, the soft-delete purge helpers, the role-expiry listing and several usage/billing/secret/user readers now bind their time argument as UTC in the store, so a host-zone cutoff no longer drops overdue rows (west of UTC) or includes not-yet-due ones (east of UTC). `RestoreProject` now compares each child's `deleted_at` as an instant, tolerating both the pre-upgrade host-zone text and the current UTC text, so a secret deleted independently before the UTC upgrade is no longer resurrected (and its frozen purge date no longer cleared) when its project is restored. No data migration is performed; existing host-zone rows are read correctly as they are.
- **User search and the audit-log actor filter match case-insensitively in the Unicode sense on both backends.**
  `GET /users` `search` (username, email and display name) and the audit-log actor filter used
  `LIKE` / `ILIKE` / `LOWER()`, which fold ASCII only on SQLite and are case-sensitive or
  locale-dependent on PostgreSQL, so the same search returned different rows per backend
  (for example `ünal` versus `ÜNAL`). Both now use the shared fold already applied to the
  username and email filters and to secret search; `%`, `_` and `\` stay literal.
- **single_writer: the trigger-integrity check no longer flushes every memo every 30 seconds (#3978).** The tracker that counts the server's own writes to fenced tables treated any statement with a `;` in it as several statements, and so as a fenced write. The check's healthy tick is a read rolled back at once, but its text holds `concat_ws('; ', ...)`, so each tick raised the in-flight count and moved the generation: memo caches were flushed and bypassed on that cadence. The tracker now reads statements as PostgreSQL's lexer does (string literals with `''` and E'' escapes, dollar quotes, quoted identifiers, `--` and nested `/* */` comments) and counts a statement as a read only when it has read the whole text with certainty; an unterminated quote or comment, a backslash right before a quote in a non-E string, a U& identifier or a real second statement is still a fenced write. The same change closes older misreadings in the unsafe direction, none of which the server's own SQL uses: a verb followed directly by a comment, a form feed or a carriage return (`DELETE/**/FROM ...`), a leading `--` comment ended by a carriage return and a nested leading block comment were read as reads; a table named through a `U&"..."` identifier, or a string literal inside a bookkeeping-only `SET` list, as a write of no fenced table; a comment inside `ROLLBACK TO` or `COMMIT AND CHAIN` turned it into a plain end.
- **Times written in the host's zone into SQLite store columns that are compared as UTC.** On a non-UTC server, project-invitation and access-request transitions (`expires_at`, `accepted_at`, `revoked_at`, `resolved_at`), machine-identity revocation (`revoked_at`), the system-metadata and recovery-key upserts (`updated_at`, `rotated_at`) and secret-ACL grants (`updated_at`) stored the caller's clock with its offset, so the text did not order against the UTC values written everywhere else (a wrong expiry or retention window). These writers now store UTC. Guarded by `TestHookBypassTimeWriters_StoreUTCOnNonUTCHost`, which runs under `TZ=Asia/Kolkata`. Postgres (`timestamptz`) was never affected.
- **Session lifetime ceilings and a passkey's last-used time are stored in UTC on a server whose clock is not UTC (SQLite).**
  On SQLite a timestamp is stored as text in the zone it carries. A new session's
  last-seen time and absolute lifetime ceiling (at login, for a setup-only session, and when
  the session is refreshed) and a passkey's last-used time were stored in the host zone,
  inconsistent with every other expiry column; they are now written in UTC, and the bounds
  of the stale-token and stale-machine-credential counts are normalised to UTC as well.
  Expiry checks compare instants in the server, so nothing expired early or late.
  PostgreSQL stores an instant and was never affected. Rows already stored in the host
  zone are not rewritten by the upgrade: a session ceiling becomes UTC at its next refresh.
- **Ordinary validation refusals in the users, versions, break-glass, account, env-clone and access-review families answer 400, not 500.** Deleting or restoring user id 0, listing the versions of secret id 0, activating break-glass with an install-wide-admin or role-assigning emergency role, deciding an access-review item that is already decided, an unknown access-review source and a machine caller deciding an item answered `500 InternalError` because core built these refusals as bare "Validation error: ..." errors that the handlers could only classify by text. They are typed now (`ErrValidation`, `ErrBreakGlassInvalidRequest`) and the handlers classify by `errors.Is`, so REST and gRPC agree and the status no longer depends on the language. The refusal text is unchanged.
- Web: the Projects page no longer shows **New Project**, edit and delete to a session that lacks `secrets.write` / `secrets.delete` (for example a `project_viewer`), instead of offering actions the server refuses (#3739).
- Web: the two-factor setup dialog, including the forced first-login enrolment, now shows the `otpauth://` URI as a QR code drawn in the browser (no network request); the text setup key and the "Open in authenticator app" link remain as fallbacks (#3738).
- Dashboard: "Inactive users" no longer counts an account created within the last 30 days that has not logged in yet, so a fresh install reads 0 instead of 1 (#3740).
- Web: controls the server would refuse for a read-only role are no longer offered. The project **Settings** tab hides Save (General needs `secrets.write`, the MFA setting needs `roles.assign`), Add environment, Promote, Freeze/Resume all, the bulk Extend and Apply renames, Restore secret (`secrets.write`), Delete environment and Delete Project (`secrets.delete`), and Restore environment and Reassign owner (`roles.assign`). The project page **Edit** button needs `secrets.write`. The Access Review campaign controls (Open, Attest, Revoke, Close) and the per-grant Revoke need `roles.assign`. Rotation policy Edit/Delete need `secrets.write`. The Projects page gating and the dependency Add form landed earlier (#3739, #3142); this adds the per-control tests and a `project_viewer` case in the real-backend permission spec.
- Web: three more controls now follow the permission the server checks. The per-grant **Attest** button on the project Access Review tab is offered only with `roles.read` (it was shown to every role and ended in a refusal). **Transfer ownership** on an open secret follows `secrets.write` like its route, instead of `secrets.delete`, so a writer who may transfer a secret sees it and a user who can only delete does not. **New Policy** on Rotation Policies (header and empty state) needs `secrets.write`, which the create handler checks. The real-backend permission spec gains the Attest and Transfer cases for a `project_viewer`, with admin positive controls.
- Web: the project Settings "Require MFA" Save is offered only to a session that holds both `roles.assign` and `secrets.write` (the server needs both: the route checks `secrets.write`, the handler `roles.assign`), so a custom role with only `roles.assign` no longer sees a Save that ends in a refusal.
- Web: the Dynamic Secrets page offers New config, the classification picker and lease management to a session with `secrets.write` (what the server routes require) instead of to install administrators only.
- **Roles modal: the permission group headings are readable.** They used the muted text colour (2.5:1 in the light theme, 3.5:1 in the dark one); they now use the secondary text colour.

### Documentation
- **Golden path: break-glass on the web.** `docs/demo/GOLDEN-PATH.md` describes the web path next to the CLI commands.
- `docs/UPGRADING.md` §6j: the first `recover_admin_alert` run after the upgrade reads the audit history once, in 100,000-id windows, resumably. `docs/PERFORMANCE.md`: SQLite long readers, and what not to run against a live database file.
- **Start-up refusals:** entries for the weak SCIM token and the unneeded KMS context fallback (`docs/operator/startup-refusals.md`), an upgrade note (`docs/UPGRADING.md` §6i) and a generation hint for the SCIM token in `docs/CONFIGURATION.md`.
- **Design note for hybrid post-quantum key wrapping.** `docs/design/pq-key-wrapping.md` inventories which at-rest key hops are exposed to a quantum attacker (the Azure Key Vault RSA-OAEP KEK wrap and classical recipients for recovery-key delivery) and proposes a hybrid X25519 + ML-KEM envelope inside a KEK-authenticated keyset with optional escrow/DR recipient slots. Draft awaiting approval; nothing changes at runtime.
- ADR-121 (Accepted): how `internal/core` is split — tests move first, the kernel stays, production code leaves only as pure leaves (`docs/adr-121-core-package-split.md`).
- **Key rotation runbook: exact recovery paths** for a DEK rotation that failed midway (refused, killed, commit outcome unknown) and one that succeeded but was wrong (key set not distributed, new `dek.key` lost, older admin binary), with what each loses; rehearsed with the real admin commands on SQLite. `encryption validate` does not prove the DEK opens the data; `encryption rotate --dry-run` does.
- `docs/operator/startup-refusals.md`: the "Wrong master passphrase" entry shows the extra line the error carries when an interrupted `rotate-kek` or `migrate-provider` left a file in the key directory, and names the key files by their config keys (`dek_path`, `salt_path`).
- **Rolling upgrade from v0.96.x: don't suspend with "also clear synced Kubernetes copies"
  until the rollout has finished.** A v0.96.x replica ignores the option. See UPGRADING §6q,
  which now also names the refusal v0.93 to v0.95.x binaries print. The schema-epoch refusal
  transcripts in `docs/operator/startup-refusals.md` were re-captured at schema epoch 9, with
  a real v0.96.3 rollback added.
- **Sharing guides match the web UI.** `docs/SECRET_SHARING_USER_GUIDE.md` and `docs/SECRET_SHARING_WORKFLOWS.md` no longer describe web screens that do not exist (bulk share, group recipient in the Share dialog, a shared-secrets filter, "Leave share", share notifications, the 👥 icon, "Share Secret"); button and field labels now match the UI. `web/scripts/check-sharing-guide-ui-strings.mjs` (`pnpm check:sharing-guide-strings`) lists quoted phrases in the two guides that are missing from `web/src`; it is advisory and not part of CI.
- **Threat-model GAP rows now cite their pinning tests.** In `docs/security/threat-models/`, SHARE-13 (sharing lifecycle: #2794, #2796, #2797, #2798, #2801, #2802, #2887 and the purge half of #2795), RL-5 (#3429), DYN-3/DYN-4 (#3424) and BG-6 (#3420) name the tests on `main` that pin each fix, and the README's GAP index says which issues can close. The read side of #2795 (`GetUserRoleIDsAt` and its siblings still `LEFT JOIN projects`) stays a GAP.
- **Docs no longer cite files and commands that do not exist.** `migrations/README.md` pointed at the deleted `internal/cli/migrate/migrate.go` (the user-to-machine migration is `keyorix machine migrate-from-user`); two other pages named `deploy/docker` and `internal/cli/bundle`. New report-only guards `TestDocsCitedRepoPathsExist` (backticked repo paths) and `TestDocsOnlyUseExistingKeyorixCommands` (`keyorix` / `keyorix-server admin` commands in QUICK_START, SELF_HOSTING and `docs/operator/`) keep them true.
- **First login after `mfa activate`.** The 60-second quick start and the pilot install guide now say an authenticator code works once, so the next `keyorix login` needs the app's next code (QUICK_START already did).
- **Recovery-options design doc: recorded the decision on the audit seal's `unpinned` field.** The accept-loss seal record's optional `unpinned` span field (AUDIT-SEAL-TAILS-3, #3852) is accepted as a backward-compatible addition to the existing seal-record format constraints, not a new ADR; the residual gap it does not close (deletion of older checkpoint rows) is noted as tracked separately.
- **Air-gap runbook and start-up refusals:** a table of what the air-gapped build refuses at startup (cloud KMS key providers, `auto_cert`) in `docs/AIRGAP_RUNBOOK.md`, plus an `auto_cert` entry in `docs/operator/startup-refusals.md` and its inventory.
- **Upgrade note for the config keys the next minor release rejects (#3743).** `secrets.chunking`, `secrets.limits.max_secrets_per_user` and `server.http.keepalive` are ignored today and each logs a deprecation warning; the note says how to remove them and that `audit verify` reads `NOT PROVEN` until the first full re-walk (`audit verify --full`). A test now fails when a key in the ignored list is not named in an upgrade note.
- **The rate-limit matrix lists change-password and profile as bounded.** `docs/security/production-hardening-matrix.d/rate-limits.md` still reported `POST /auth/change-password` and `PUT /auth/profile` (email change) as an unbounded current-password check; since #3365 both spend the `/auth/login` per-IP budget and feed the account lockout. The row moves from "Gaps" to the authenticated-routes table.
- **OpenAPI declares the permission-lookup `503`.** New shared `AuthorizeUnavailable` response (`Retry-After`, fixed message) on `POST|GET /api/v1/secrets`, `GET /api/v1/secrets/{id}`, `POST /api/v1/secrets/{id}/copy`, `POST /api/v1/folders`, `GET|POST /api/v1/dynamic-secrets/configs` and the template-render route. Web types and the Go CLI client are regenerated.
- **Hardware sizing guide.** `docs/SIZING.md` lists what decides server size (backend, audit writes, audit durability, pool, disk), small/medium/larger tiers for SQLite and PostgreSQL, and a procedure for measuring them on your own hardware. It publishes no benchmark figures: tier values that would need one say "not measured". Linked from `docs/README.md`.
- **Start-up refusals page.** `docs/operator/startup-refusals.md` lists what an operator sees when `keyorix-server` refuses to start or an `admin` command stops (configuration, TLS, key and secret files, schema epoch and rollback, locks, single_writer, backup/restore): the message, the cause, the fix, and whether the fix is safe in place. Linked from the troubleshooting page, SELF_HOSTING and UPGRADING. `docs/operator/startup-refusals-inventory.md` records how the list was built and what the search could not see. The troubleshooting page's "known gap" about a server that fails to bind its port staying alive is corrected: it exits with status 1.
- **`docs/REMOTE_CLI_TROUBLESHOOTING.md`** now starts with `keyorix doctor` and no longer lists `keyorix config status` / `keyorix auth status`, which do not exist.
- **fdatasync section completed.** `docs/CONFIGURATION.md` now says the gain scales with how expensive a sync is on the storage in use and that `fsync` stays the default. `internal/storage` pins that the default SQLite DSN carries no `journal_size_limit`, with an in-test case showing the check fails on a DSN that sets one.
- `docs/CONFIGURATION.md` documents 56 more config keys, each read against the code for default, unit and effect: `storage.database.host/port/name/user`, the listener keys that parse under both `server.http` and `server.grpc` but only one listener reads, SAML provider keys, `oidc.issuers[].max_token_age_seconds`, `membership.domain_allowlist`, `secret_value_policy`, `secret_name_policy`, the three `classification` gates, `audit.siem.token/spool_dir`, `notifications.email.broadcast_to`, `notifications.webhook.signing_secret`, `expiry_reminders`, `license_expiry`, `read_quota_alerts`, `anomaly_alerts.business_hours/baseline_quarantine`, `license.*`, `minimum_cli_version` and `kms_encryption_context`. Security-relevant defaults (off, unsigned, no restriction) are stated plainly.
- `docs/CONFIGURATION.md` no longer says `server.grpc.tls.allowed_ciphers` applies to HTTP only (gRPC reads it too), and the notifications intro now says that webhook, Slack and Teams receive only the deployment-wide broadcasts (compliance digest, auto-rotation failure); per-user notifications go to the email channel only.
- `docs/CONFIGURATION.md` no longer calls the audit checkpoint scheduler opt-in: it is on by default whenever encryption is configured, and `insecure_disable_audit_checkpoints: true` is the only way to turn it off.
- **`POST /api/v1/projects/{id}/members` documents its 403**, including the privilege ceiling that also applies to machine-identity tokens.
- **docs/PERFORMANCE.md: a production PostgreSQL profile** (memory, WAL compression, checkpoint spacing; durability left on), with what it measurably changes (WAL volume) and what it does not (read throughput, `commit_delay`). The SQLite advice now says the server's own settings are complete: the cache/mmap/temp_store PRAGMAs it used to recommend made no measurable difference.
- **The release-binary golden path.** `docs/demo/GOLDEN-PATH.md` has a ~20-minute demo script from the two release binaries (SQLite or PostgreSQL, TLS and MFA on, upgrade, backup/restore, recovery), walked end to end, and a known-rough-edges list linking #3735-#3744.
- **UPGRADING: v0.96.x -> next.** `audit verify` says `NOT PROVEN` until `audit verify --full` after the first start, and the two deprecated keys v0.96's `admin init` wrote must be deleted before the next minor (#3743). QUICK_START: TOTP codes are single-use, `logout` forgets `ca_file`, and the stale #2941 and example-password lines are gone (#3744).
- **Hosted demo README: cost advice and first-boot checklist.** Idle power-off saves nothing on most providers, so the README now recommends destroying and recreating the VM between calls (`install.sh` is idempotent) and points at the current UpCloud/Hetzner price lists instead of quoting a figure. The first-boot checklist matches the scripts again (staging certificate, gate user, MFA enrolment, the seed placeholder); the seed section explains why `scripts/demo/seed-demo.sh` is not wired as the default yet.
- **The Helm quick start no longer crash-loops the server pod.** The chart README's "Quick start" and `docs/operator/j8-kubernetes.md` built `auth.existingSecret` with an admin password but no `KEYORIX_BOOTSTRAP_TOKEN`; the server then exits at first boot ("KEYORIX_ADMIN_PASSWORD is set but KEYORIX_BOOTSTRAP_TOKEN ... is not") and `helm install --wait` times out with no hint. Both recipes now write the token file (generated into the file, never on a command line), and j8 no longer calls the token optional. A deploy test keeps every such recipe carrying it.
- **The GOLDEN-PATH break-glass example now works as written (#3202).** It used `--project-id 1` (`default`), where the seeded user alice has no role, so the first command was refused with `break-glass is available only to members of the project`. The example uses project 2 (backend-api, alice's `project_viewer` grant), says who runs what (alice activates; `admin` or `security-officer` lists and revokes), and the stale "published images do not embed the web UI" note (#2752) is corrected.
- **The `inactive` users filter is described as the server applies it.** The OpenAPI `filter` parameter of `GET /api/v1/users` and the `ListUsersRequest.filter` comment now say: no login in the last 30+ days, and an account that has never logged in counts as inactive only once it is 30+ days old (judged by its creation date). Text only, no behaviour change; the web types and the pb files are regenerated.
- **Audit checkpoint signing key is KEK-derived.** `docs/CONFIGURATION.md` called it DEK-derived; the code (`deriveAuditCheckpointKey`, `internal/encryption/keymanager_lifecycle.go`) and the key rotation runbook derive it from the KEK, so it survives a DEK rotation and changes only with the KEK.
- **Key rotation docs say `rotate-kek` and `migrate-provider` need the database.** Both open it for the exclusive presence lock (#3513) and fail with `cannot connect to the database to check for a running server` when it is unreachable, even though only key files change (`docs/operator/j6-key-rotation.md`, `docs/operator/key-rotation-runbook.md`).
- **`docs/SELF_HOSTING.md` upgrade section** says which compose image tags are pinned to an exact release (the two Keyorix images) and which follow a major version (`postgres:15-alpine`, `caddy:2-alpine`), and states when the MFA grace period after an upgrade ends.
- **Backup threat model matches `admin backup` on PostgreSQL.** `docs/security/threat-models/backup-restore.md` (diagram, BAK-4, residual risks) and `docs/security/threat-model.md` still said `admin backup` refuses on PostgreSQL and that Postgres has no Keyorix-native backup. Both backends are supported, as the hardening guide, `SELF_HOSTING.md` §5 and `AIRGAP_RUNBOOK.md` already state.
- **Docs are now machine-checked against the code.** `go test ./internal/docsdrift ./server/admin` fails when CONFIGURATION.md, SELF_HOSTING.md, QUICK_START.md, AIRGAP_RUNBOOK.md or docs/operator/*.md name a config key the loader rejects, a `keyorix-server` subcommand or flag the binary does not have, a `KEYORIX_*` variable no source reads, or a relative link or `#anchor` that does not resolve; every security-weakening setting in the insecure-settings registry must be documented. It also fails on a doc that passes a secret as a flag value or opens a secret-bearing file to group/other.
- **Fixed what the checks found.** The restore walkthrough no longer tells the operator to `chmod 644` the backup archive (it holds the database and the wrapped key files) or `mkdir -m 777` the backup directory; `server.{http,grpc}.max_request_body_bytes` is documented; the KEK `env` provider example no longer names a variable (`KEYORIX_KEK`) that nothing reads; a Helm value is no longer written as a config key.
- **UPGRADING.md: the first run scans the audit history once.** New section 6j states the real bound of the recover-admin alert catch-up (windows of 100,000 audit ids, saved after every window, resumable, background) and that the recertification "last used" lookups have no such pass.
- **Edge guide, "Unattended operation" (§7a):** states, per topic, what the server does today and what the operator must do. It covers start after a reboot (there is no unseal step; what each key provider needs at start), the `-wal` file left behind by `kill -9`, self-update and rollback (the server never swaps binaries; pointers to UPGRADING.md §7), where the clock matters in the code when there is no NTP, and which configured dependencies need a network. Anything the code does not do is written as a limit.
- **`docs/CONFIGURATION.md`:** two `require_existing_path` paragraphs that had slipped under "Committing with fdatasync" are back in their own section.
- New config keys are documented in their own file `docs/configuration.d/<key, dots as __>.md` and upgrade notes in `docs/upgrading.d/<slug>.md`, instead of editing `docs/CONFIGURATION.md` and `docs/UPGRADING.md` (the two most conflicted docs). `TestEveryConfigKeyIsDocumented` and the other readers of `CONFIGURATION.md` read the flat file plus the fragments; existing text is untouched. Each directory's `README.md` has the naming and how upgrade notes are folded into `UPGRADING.md` at release time.
- **Hardening guide: `admin backup` supports PostgreSQL.** Section 6 of `docs/security/hardening-guide.md` said the command refuses on Postgres; it does not (SQLite and Postgres are both supported, as `SELF_HOSTING.md` §5 and `AIRGAP_RUNBOOK.md` already state).
- **Broken links and stale file references in `docs/`.** `docs/README.md` no longer links the missing `DEPLOYMENT_GUIDE.md` (now `SELF_HOSTING.md`) and `COMPREHENSIVE_TEST_RESULTS.md`, and its API anchor works; `DAST.md` and `security/architecture.md` name the files that exist now.
- **Audit durability spec: current SQLite refusal.** `docs/specs/fast-audit-mode.md` S7 quoted the removed `insecure_audit_skip_durable_sync` refusal message and test names; it now matches `storage.database.audit_durability` and the tests that exist. The other docs already agree with `config_surface_leaves.txt` (`audit_durability`, deprecated alias, `security.audit_durability` / `audit_reads_skipped` in `/system/info`, `security.one_time_password_ttl` / `recovery_one_time_password_ttl`).
- **UPGRADING.md covers the post-v0.96.0 audit and single-writer changes.** New sections 6d (refused secret-value reads are audited), 6e (`insecure_audit_skip_reads`, default off) and 6f (`single_writer`, opt-in), each pointing at the existing detail docs.
- `changelog.d/migrate-vault-tails-1.md`: the `--path-map` examples use numeric project and environment IDs, as `keyorix-migrate` requires. `docs/releases/v0.97.0-draft.md`: the roles row says "added in schema epoch 7", and the rebase note names the current schema epoch (9).
- `scripts/check-doc-links.py --refs` resolves a backticked path against the referencing file's own directory as well as the repo root (no more false positives on `operator/...` links in `docs/`); `--self-test` checks it. The `POST /api/v1/audit/checkpoint` handler comment now says the checkpoint key is KEK-derived, so a DEK rotation does not need a re-baseline.
- **`docs/CONFIGURATION.md` documents `auto_rotation`.** `auto_rotation.enabled`, `schedule` (default `1h`) and the `backends[]` keys `name`, `type`, `region` and `allowed_refs` now have a section: the backend types, that `allowed_refs` is required (a backend without it is not registered: a warning is logged, the server still starts, and its rotations fail) and how its prefix match works. `connect.connectors[].environment` is documented as reserved and not enforced.
- **The four legacy `client.*` keys are listed as exempt, with a reason.** The server ignores `client.endpoint`, `timeout`, `auth.type` and `auth.api_key` (the pre-ADR-108 CLI's connection settings). `internal/docsdrift/testdata/undocumented_config_leaves.txt` now requires `<key> <reason>` on every line that stays on it.
- **DEK rotation has no revert, and the docs now say it where operators look.** `docs/security/hardening-guide.md` gains a "DEK rotation has no revert" row: no command reverses `admin encryption rotate`; the two ways out are to roll forward or to restore the pre-rotation backup (`admin backup` before, `admin restore --input <archive> --overwrite-existing`, plus `--allow-rollback` when the restore refuses an archive behind the host's audit trail), and a rotation must never be run with an N-1 admin binary. `docs/operator/key-rotation-runbook.md` section 6 spells out the same two commands, and both documents now link the N-1 rule in `docs/UPGRADING.md`.
- **`devtools/familycheck/README.md` documents the first-marker-line rule.** Only the first `family-check: intentional` (or `new-member-verified`) line in a PR body is read, and it must name the family; a second family confirmed on its own line is ignored, and for `new-member-verified` that keeps the check failing. Put every family name on one marker line. The README gives one example of each outcome, taken from real runs of the tool.
- **`docs/INVARIANTS.md` counts table repaired and guarded.** The index listed `internal/storage`, `internal/storage/store` and `internal/encryption` twice with different counts, and its Total matched neither copy. The table is hand-written (there is no generator), so it was re-counted from each package's `INVARIANTS.md` and `INVARIANTS.d/` fragments, the missing `internal/faultstorage` row was added, and `TestInvariantsIndexHasNoDuplicateRowsAndTotalsAddUp` now fails on a duplicate package row, a row whose Invariants is not Guarded + UNGUARDED, or a Total that is not the column sums (report-only on pull requests until its first green nightly, as `docs/guard-rollout.d/` describes).
- **Bootstrap-token examples now use a generated 64-hex-character token in a 0600 file.** `docs/operator/demo.md`, `QUICK_START.md`, `scripts/demo/vault-migration-demo.sh` and `demo/vault-migration/run.sh` no longer show or use a fixed or guessable `KEYORIX_BOOTSTRAP_TOKEN`; they run `openssl rand -hex 32` into a 0600 file and pass `KEYORIX_BOOTSTRAP_TOKEN_FILE`, so the token is never on a command line. `scripts/smoke.sh`, `scripts/e2e/web-real-smoke.sh` and `scripts/release-qa/*` generate theirs the same way, so they stay valid once the server refuses a token shorter than 32 characters.
- **Operator docs checked against the binaries and the code (DOCS-PILOT-1).** Fixed commands, flags, config keys, defaults and file paths that did not exist or had changed: the 3-hop version-skip restore (`--output-db`, `--db`, `--target-dsn` do not exist; each hop is chosen with `--config`), `keyorix encryption ...` (it is `keyorix-server admin encryption ...`), `keyorix system init --database` (it is `keyorix-server admin init --database`), `keyorix-server --version` (it exists), the C-toolchain requirement (the SQLite driver is pure Go), `auth.password_policy` and `encryption.key_provider` (they are `password_policy` and `storage.encryption.key_provider`), the SQLite `integrity_check` backup description, gRPC being off in a generated config, the MFA step missing from `docs/operator/demo.md`, and the stale CLI "local mode" and `config set-remote` text in `docs/REMOTE_CLI_SETUP.md` and `docs/REMOTE_CLI_TROUBLESHOOTING.md` (both rewritten for the REST-only CLI). `docs/operator/j8-kubernetes.md` drops a "known gap" (a server crash-loop on absolute key paths) that cited internal report files not in the repository, and installs with a 0600 values file instead of secrets on the command line.
- **Removed claims and figures a reader cannot reproduce.** `docs/PERFORMANCE.md` (invented latency, throughput, memory and sizing figures, a Redis cache and server timeout settings that do not exist, scripts that do not exist) is rewritten to the settings that exist; `docs/README.md` no longer reports fabricated "current metrics"; the air-gap runbook's historical Postgres estimate, the SELF_HOSTING timing measurements and the UPGRADING "VERIFIED" narratives are gone.
- **New `docs/operations/pilot-install.md`:** the one supported pilot path (single node, Docker Compose, PostgreSQL over TLS, Caddy TLS, a deliberate `strict`/`standard` audit durability choice, off-host backups, monitoring), step by step, each step pointing at the detailed document.
- **Upgrade note 6j corrected: the first recover-admin alert pass resumes from the stored mark.** An install that has used recover-admin before already has a mark at its last alerted id and reads only the audit rows added since; only an install that never used it walks the whole audit table once (`docs/UPGRADING.md`, section 6j).
- **Restore failure modes: after a PostgreSQL restore killed during the load, restore again with `--overwrite-existing`.** `--recover` rolls the data back, but the migrations had already committed, so the database has tables and a new `admin restore` is refused without the flag (`docs/operator/restore-failure-modes.md`).
- **Versioning and deprecation policy (draft).** New `docs/VERSIONING.md`: SemVer rules before and after 1.0, what counts as breaking (API, CLI, config, schema, audit, key-wrapping and backup formats), the deprecation process (changelog and `UPGRADING.md`, runtime warning, at least two minor releases before removal), the table of current deprecations derived from the code, and the upgrade-path promise versus what is tested. A docsdrift test fails if a deprecated config alias is missing from the table.
- **SDK install lines match what is published.** `README.md` and `docs/sdks.md` no longer show `pip install keyorix`, `npm install @keyorixhq/sdk` or the `com.keyorix:keyorix-sdk` Maven dependency: none of those packages is on PyPI, npm or Maven Central. They now state that, keep the Go install, and give a verified from-source install for Node.js. Python and Java from-source installs are marked not yet verified.
- The air-gap design note and the `RefWithinPrefix` doc comments now say what the code does: the evidence-pack and audit-checkpoint HMAC keys are derived from the KEK (not the DEK), and an empty reference prefix matches an empty or `/`-led reference rather than "nothing" (callers skip it first). The hardening guide's backup section now lists the refusal of `admin backup` on a database upgraded in place from v0.95.x until the new server has started once, on both SQLite and PostgreSQL.
- **Pilot upgrade notes match the code (DOCS-UPGRADING-TRUTH-6).** `docs/UPGRADING.md` 6o now says a mutation refused because its audit row cannot be recorded answers `503 audit_unavailable` with `Retry-After: 5` (it said 500); 6l no longer says `system init --bootstrap-token` has a prompt; 6w says the dormant-access wording follows `cadence_days`; 6r notes the 60 s flush backoff ceiling. `docs/SELF_HOSTING.md` describes the status-only `/health`.
- **UPGRADING.md sections 6n, 6u, 6y and 6z checked claim by claim against the code** (DOCS-UPGRADING-TRUTH-7). 6y: `--path-map` takes numeric IDs, `<vault-prefix>=<project-id>:<environment-id>`, not names (the old `<team-a>:<dev>` form is rejected by `keyorix-migrate`); `audit-access` can also report a finding as `POSSIBLY WIDER THAN VAULT` (`"status": "unconfirmed"` in `--json`), and an unreadable Vault userpass user list makes the audit incomplete too. 6u: the failure-event family is every `internal/core` event whose name ends in `failed`, `error`, `rejected` or `panicked` (changed by #3363) plus `denied`, `refused` and `unresolved` (already `success = false`). 6z: the startup `WARNING` also lists SSO settings that would create out-of-scope grants and grants at `project_id=0` with an `environment_id`; the mixed-version note is about an epoch-6 binary, and the section names schema epoch 7 as the epoch the column arrived in. 6n: the evidence paragraph now says the Postgres tests need a superuser role and skip without one.
- **The PostgreSQL-outage drill matches how the server behaves.** `docs/operator/drill-disaster.md` said the server keeps serving `503` while PostgreSQL is down; the server instead shuts itself down gracefully when its advisory-lock connection is lost (`INV-STORAGE-session-advisory-lock-loss`) and must be restarted once the database is back. The page, the `pgdown` drill and a new covered-backends table (kept equal to the drills README by a test) now say that.
- **Edge guide: crash testing.** `docs/edge-deployment.md` §4 says what the soak covers (process crash, not a power cut) and states the mutation-audit gap.
- **Edge guide: no-NTP behaviour.** New §5a in `docs/edge-deployment.md`: what each kind of clock error does and the operator rule (set the clock before the service starts; restart it after stepping the clock backward).
- **Edge guide: unattended operation.** New §7a in `docs/edge-deployment.md`: start at boot, what each stuck state does, and what an operator must still monitor.
- **Footprint and architectures.** The edge guide has a short section naming the four scripts that guard cgo-freedom, ARM cross-builds and footprint ceilings, what each checks, and how to run them.
- **Edge deployment guide.** New `docs/edge-deployment.md` for edge and industrial devices: SQLite as the edge backend (strict audit durability only), the `audit_durability` levels and the advice to set `strict` on PostgreSQL edge installs, power-loss behaviour, qualitative sizing, backup/restore, air-gapped updates, physical-access hardening and the `insecure_` settings that must stay off. Linked from `README.md` and `docs/README.md`.
- `docs/edge-deployment.md` §4 records the 2026-10-23 `kill -9` soak on SQLite (222 cycles, no lost acknowledged write, chain valid after every kill) and what it does not show: `kill -9` cannot distinguish `synchronous=NORMAL` from FULL, and a real power-cut run is still open.
- **`docs/operator/startup-refusals.md` lists the `GODEBUG=fips140=only` refusals:** the boot self-test failure (`fips140 self-test failed on <path>`) and the short webhook signing secret, with cause and fix. The boot refusal is now also exercised by a default-mode test, since no CI job runs in that mode.
- **Added `docs/operations/quickstart-60s.md`:** the shortest path from the release download to reading back a first secret (one node, SQLite, no Docker), with the times measured on one Apple silicon Mac and what they exclude.
- **A machine token's privilege ceiling is checked at mint time only, by design.** If the user who issued a machine token later loses the authority to issue it, tokens already minted stay valid until revoked or expired (a personal access token whose owner lost the ceiling is refused at use time). Recorded in ADR-042 and `INV-CORE-machine-token-issue-cannot-widen-caller`; re-checking the issuer at use time is noted as an open idea, not planned work.
- **Advisory-lock overlap window.** `docs/design/pooler-lock-loss.md` records the accepted window for separation-of-duties grants and dual-control approvals, and what a double run does for each scheduler job.
- **Production-hardening matrix: rate limits.** `docs/security/production-hardening-matrix.d/rate-limits.md` lists every unauthenticated or credential-checking endpoint with the limiter that bounds it and the test behind it, and the gaps still open.
- **Production-hardening matrix: request limits.** `docs/security/production-hardening-matrix.d/request-limits.md`.
- **Production-hardening matrix: response hygiene.** `docs/security/production-hardening-matrix.d/response-hygiene.md`.
- **Production-hardening matrix.** `docs/security/production-hardening-matrix.md` lists what each network listener enforces, with setting, default and the test that proves it; `TestHardeningMatrixRowsNameExistingTests` fails when a row names a test that does not exist.
- **Production-hardening matrix: TLS.** `docs/security/production-hardening-matrix.d/tls.md`.
- Install docs, from a clean-VM walk of the v0.96.3 release binaries: INSTALL-WITH-AI.md gains a release-binary variant of step 1 (server and CLI assets, checksum check), a recipient-key hint for the recovery key, and a single-archive backup and restore recipe; the README compose quick start now says to clone the repo first; QUICK_START.md notes that `--interactive` needs a terminal.
- Install guides, from the INSTALL-CLEANROOM-1 walk: INSTALL-WITH-AI.md step 2 says the install directory is arbitrary (and that the CLI credential file is per OS user), step 15 says to keep the admin password in a password manager for later logins, and QUICK_START.md states the prompt order of a scripted `keyorix login` (password, then authenticator code) and of `keyorix mfa activate` (code, then password), with the environment variables to use instead of piping.
- **PostgreSQL with the single binary is documented.** New `docs/operations/postgres-single-binary.md`: the config keys (`dsn` or fields, `ssl_mode`, `ssl_root_cert`), the password through `KEYORIX_DB_PASSWORD_FILE`, `admin init --storage-type postgres` (no empty SQLite file), the database-TLS requirement of the secure baseline and the errors you meet. `SELF_HOSTING.md` section 10 and `pilot-install.md` no longer say that `--storage-type` does not exist.
- **INSTALL-WITH-AI.md covers PostgreSQL and Docker Compose.** The secret-blind install procedure now has a single-binary PostgreSQL variant (the database password is written by the user to `secrets/db_password` and passed as `KEYORIX_DB_PASSWORD_FILE`) and a Docker Compose path (C1 to C9, ending with `admin validate --posture`), an offline checklist, and maintainer notes with the transcript test that is still pending on the e2e VM. README links it. `mfa activate` in the HUMAN STEP reads the password through `KEYORIX_PASSWORD_FILE` instead of a prompt.
- **`docs/install/offline-install.sh setup --postgres-dsn`.** The offline script installs against PostgreSQL. It refuses a DSN that contains a password, and it requires `secrets/db_password` to exist first. A relative `--bin-dir` now works. The closing backup list names `secrets/metrics_token`.
- **Open-issue audit, 2026-11 (ISSUE-AUDIT-NOV-1).** `docs/design/issue-audit-2026-11.md` gives each of 24 old open issues a verdict (FIXED / OPEN / OBSOLETE / NEEDS DECISION) with the file:line or test name that proves it, and copies the rows PLANNER-11140103 verified. No code change.
- **Open-issue audit, 2026-11, second batch (ISSUE-AUDIT-NOV-3).** `docs/design/issue-audit-2026-11-b.md` gives each of 13 storage, perf, security-test and policy issues a verdict (FIXED / OPEN / NEEDS DECISION) with the file:line or test name that proves it. It records that #3427, #3612 and the tightening of #3605 are already on `main`, that the INV-PQWRAP keyset is not wired yet (#3758), and what the perf issues measured and did not. No code change.
- **Only PgBouncer is a supported pooler.** `docs/postgresql-poolers.md` and `docs/CONFIGURATION.md` now say that other poolers and proxies (PgCat, Odyssey, RDS Proxy, Supavisor, pgpool-II) are not tested and not supported, and describe what each lock holder does when its lock is lost.
- **ADR-112 is Accepted** (Andrei, 2026-10-17; Amendments 1, 3 and 4 shipped). Amendment 5 records the `require_mfa` grace end condition.
- `docs/vault-health-scan.md`: the same policy file is the token policy of the access-migration commands; a table of what they need beyond the scan, and why a KV v1 mount needs its own `list` stanza. A test over the policy parser checks that the file grants exactly the Vault calls the commands make.
- **Moving from SQLite to PostgreSQL: the verified procedure** in `docs/SELF_HOSTING.md` (steps, what was checked, what is deliberately not carried over, what an interrupted restore leaves behind and how to restart it, rollback), plus `docs/operator/drill-sqlite-to-postgres.md`. Corrected the recovery-point text: the `admin.backup_created` event is written to the source after the archive, it is not in it.
- **Threat model row NW-2 (notification-channel URL on read, #3425) is closed.** The notifications-webhooks threat model now records the contract change that already shipped: the channel URL is a create-only secret (full URL in the `POST` response only), `GET` list/get and `PUT` return scheme+host with the path elided plus `url_set`, and an explicit `url` on `PUT` replaces it. Operators who read the URL back from list or get must keep the value from the create response.
- **Prometheus metrics reference.** `docs/operations/metrics.md` lists every metric the server and operator define (name, type, labels, meaning, endpoint), generated from the Go definitions. `internal/metricsdoc` fails CI if a metric is added or relabelled without regenerating it, and if any label is not on a bounded-label allowlist (no secret names, paths or user ids as labels).
- **Backup and restore on PostgreSQL: what `--overwrite-existing` really does, and what needs the server stopped.** The hardening guide said the flag moves any existing target aside; on PostgreSQL it moves only the key files, loads the rows into the tables that are already there and, over a database with data, stops on a duplicate key with the database unchanged. `hardening-guide.md` §6 and `SELF_HOSTING.md` §5 now say so and tell the operator to drop and recreate the database first. They also state that the checkpoint-anchor export and `admin verify-audit` are refused beside a running server on PostgreSQL too, give the binary-install form of `admin backup`/`admin restore`, and `AIRGAP_RUNBOOK.md` and the threat-model index no longer describe the PostgreSQL drill as missing or "operator-driven".
- **`docs/CONFIGURATION.md` states exactly when `PGSSLMODE` applies.** It replaces the `prefer` default only for a `dsn` with no `sslmode` and no `ssl_mode`; it is ignored when the dsn names a mode and when no `dsn` is set.
- **`docs/testing/postgres-tests.md` says why the Postgres-backed packages need a database each, or `-p 1`.**
- **The j5 lost-admin runbook shows the CLI's real refusal text.** The 403 a setup-only session gets and the 401 after setup is complete are now quoted exactly as `keyorix` prints them (server message, HTTP status and the CLI's "Next step" hint), and two tests keep them true: one checks the doc lines against the CLI's formatter, one checks the quoted messages against the middleware's.
- **Pilot install guide corrected after a clean-VM run on v0.96.2.** `pilot-install.md` now says it lives on `main` (not in the tags), adds the missing `chown root:<gid> secrets/*` step and a binary-only PostgreSQL variant for tags without published images; `SELF_HOSTING.md` §10 no longer documents the non-existent `admin init --storage-type`; `AIRGAP_RUNBOOK.md` names the `keyorix-server-airgap` release asset and shows how to prove a host makes no outbound connection; `drill-backup-restore.md` lists the drill's prerequisites (checkout of `main`, Go, current CLI).
- **Restoring a v0.95.x backup on a current release is supported directly, no intermediate hop (#3452).** The failure on `notification_channels.url` (the plaintext column dropped by at-rest encryption, #2468) was fixed earlier: `admin restore` carries the legacy column and encrypts each webhook URL under the restored keys. Verified natively on 2026-10-31 with `scripts/release-qa/scenario_restore_compat.sh`: a v0.95.3 server (built from the tag) seeded with an admin with TOTP, a second user, a secret, a share and a webhook channel, then `admin backup`; restored by current main (`ad272b323`) on SQLite and on PostgreSQL. Restore succeeded, `admin verify-audit` reported VALID, per-table row counts matched the old archive (78 tables), password + TOTP login worked, the secret value was byte-identical and the channel URL decrypted. Only v0.95.3 was tested; other 0.95.x archives share the same schema but were not run. Restore with the same `KEYORIX_MASTER_PASSWORD` as the backup.
- "Committing with fdatasync" in `docs/CONFIGURATION.md` now explains why the option helps (after a complete checkpoint SQLite overwrites the WAL in place, and only a commit that grows the file pays for the size update, which `fdatasync` does not skip), warns that `journal_size_limit` or truncating the WAL after checkpoints makes commits extend the file again and removes most of the gain, and tells tests that want fail-fast behaviour to give `BeginTx` a context with a short deadline. A DSN test pins that `journal_size_limit` is not set by default and that an operator-supplied value passes through untouched.
- **Backup/restore docs match the commands.** `admin restore --help` no longer says restoring into PostgreSQL is unsupported; `UPGRADING.md` §3 uses the real `--config` flags instead of `--output-db`/`--db`/`--target-dsn`; `SELF_HOSTING.md` §5 states the recovery point.
- **QUICK_START, README, pilot-install and quickstart-60s corrected** after a native first-run walk: release downloads for macOS and all four platforms, the generated bootstrap token cannot be exported (use `KEYORIX_BOOTSTRAP_TOKEN_FILE` / `admin generate-secrets`), the audit event is `share_revoked`, there is no `keyorix doctor` (use `keyorix status` / `admin diagnose`), the credentials path per OS, and the Sharing example now creates the recipient first.
- **Attenuating agent tokens: design (R&D, not implemented).** ADR-120 (Proposed) adopts draft-niyikiza-oauth-attenuating-agent-tokens-02. Keyorix would issue a root token when an agent session starts (aligned with ADR-118, the agent evidence ledger design, PR #3668). Agents derive narrower tokens offline, and a verified chain only narrows the agent's roles and the delegator's current permissions at the `Authorize` chokepoint. Design note `docs/design-rd-aat.md`: the profile, the SMT encoding that proves the attenuation rules sound (each rule shown to be needed), the prototype results against the draft's published vectors, and the implementation plan. Threat rows: `docs/security/threat-models/agent-delegation-tokens.md`, all GAP. Demo script (future CLI): `docs/demo/attenuating-agent-tokens.md`.
- **ADR-120 realigned to the published draft-02.** The ADR was written against a pre-publication working copy of `draft-niyikiza-oauth-attenuating-agent-tokens-02` (2026-10-21); the author revised -02 in place before it was published on the IETF datatracker (2026-10-26). Two Section 4.5 attenuation rules changed: the constraint-map omitted-key rule no longer applies to `"*"`, and the `any` rule now says explicitly that splitting a parent clause is valid while a derived clause covered only by the union of several parent clauses is not. The vector suite grew from 224 to 229; the 224 already run are byte-identical, and the five new ones (`J.9.6`, `J.16.7`, `J.16.8`, `J.21.22`, `J.21.23`) have not been run because the prototype and SMT model were throwaway. ADR-120 now claims 224/229 rather than full conformance, records the multi-anchor `iss` binding at step 3k, and pins the draft by published text plus vector-suite hash instead of by revision number.
- **ADR-116 (Proposed): signed audit checkpoints and a standalone verifier.** Design for hybrid Ed25519 + ML-DSA-65 checkpoint statements over the audit hash chain, commitments to the owed-audit set, a chain-exact export and an offline `keyorix-verify` binary; answers RUNBOOKS-1 gap 5 (older checkpoints after a key change) offline. Design only, nothing implemented: `docs/adr-116-signed-audit-checkpoints.md`, `docs/design-rd-audit-ckpt.md`, demo script `docs/demo/rd-audit-ckpt.md`, threat-model rows AUDIT-6 to AUDIT-10 (GAP).
- `docs/post-quantum-transport.md`: the Java SDK negotiates X25519MLKEM768 on JDK 25.0.5 (checked by hand against a Go test server); Caddy and nginx front-proxy checks are marked pending e2e VM. The RD-CBOM design note's coverage-gap list is updated.
- **RD-KEYLIME-SPIKE-1 design note and ADR-119 (Proposed).** Keylime comparison for attestation-gated secret release (Keyorix as RATS relying party): build-vs-adopt table, failure modes, lab plan (pending e2e VM), demo script (not implemented). Docs only; no behaviour change.
- **Attenuating agent tokens: SMT model of the I4 rules rebuilt against the published draft-02 (R&D, not run by CI).** `docs/formal/rd-aat-smt/` holds an SMT-LIB model (z3; the runner also takes cvc5) of the core subsumption table, the `all`/`any` matching rules and the constraint-map key rules, with the published `"*"` carve-out. Each rule is proved sound and shown to be needed by a weakened copy that the solver refutes. The key rules are still five load-bearing rules. `docs/design-rd-aat.md` records the re-run and corrects its claim that the 224 earlier vectors are byte-identical in the current suite.
- **ADR-117 Amendment A (Proposed): prefer a signed PCR policy over raw PCR binding.** Design only, no behaviour change. It ranks a UKI PCR 11 signed policy (`signed-uki`) and systemd-pcrlock (`pcrlock`) above raw PCR 7, and compares them with raw PCR 0/2/4/7 on updates, rollback, dual-boot, Secure Boot db/dbx changes and root on the host. `signed-uki` also requires Secure Boot on, enforced by the TPM (PCR 7 is bound alongside the PolicyAuthorize term over PCR 11): with Secure Boot off, systemd-stub accepts a kernel command-line override measured into PCR 12, so an offline attacker could otherwise boot the genuine UKI into a debug shell and still unseal. A host with a signed UKI but Secure Boot off falls through to `pcrlock` or `secure-boot`; the mode is chosen once, at `init`, and `reseal`/`recover` use the recorded mode. It also defines the planned-update and unplanned-refusal procedures, Shamir custody of the recovery code, and fail-closed rules. It states that Keyorix never claims to detect a compromised OS, and adds a claims-vs-evidence table. New: `docs/design/tpm-signed-pcr-policy.md`.
- **TLA+ model of the owed-audit design (R&D).** `docs/formal/owed-audit/` models revocations, grants, the mixed-request split, break-glass (normal and degraded), audit and owed-ledger outages, a crash and the multi-replica backfill. TLC checks within bounds that a revocation is never blocked by an audit outage, that widening is fail closed, that no effect goes unrecorded, and that the hash chain is valid after the backfill. Four seeded bugs, each found by TLC, show the properties are not vacuous. `run-tlc.sh` fetches the pinned TLA+ tools and checks every verdict; it is not a CI job. Design note: `docs/design-rd-tla-owed-audit.md`; demo: `docs/demo/tla-owed-audit.md`.
- **ADR-117 (Proposed): TPM-sealed KEK with PCR policy and off-TPM recovery.** Design only, no behaviour change. It is a gap analysis of the existing `tpm` key provider (no boot-state binding, no recovery after TPM loss, a new KEK minted when the blob file is missing, no parameter encryption), plus the proposed fix. New: `docs/design-rd-tpm-seal.md`, the threat model `docs/security/threat-models/tpm-sealed-kek.md`, and a 5-minute demo script written against the future CLI (`docs/demo/tpm-sealed-kek.md`, marked not implemented).
- **Release checklist.** `docs/releases/RELEASE-CHECKLIST.md` gives the order of work and the exact commands for cutting a release, including a local rehearsal of `make release` and the post-tag verification. `scripts/changelog-dedupe.sh` finds the changelog fragments a side-branch patch release already published, so they are not printed twice in the next minor.
- **v0.97.0 upgrade documentation.** `docs/UPGRADING.md` §6k to §6p list the breaking changes (CLI secret flags refused, CLI exit codes 2 to 6, PostgreSQL `session_replication_role`, fail-closed grants and break-glass, API and client-visible changes) with exact steps; `docs/operator/upgrade-checklist-v0.97.md` gives the pre-checks, step order for one node and for several replicas, rollback limits and post-checks; `docs/CONFIGURATION.md` documents `server.grpc.keepalive` including the new `max_connection_idle` and `handshake_timeout`.
- **Repository documents agree with the code.** The threat model, hardening guide and two component threat models no longer call CLI local mode open (it was removed by ADR-108) and no longer say `admin backup` refuses PostgreSQL; the security FAQ and the compliance controls say the retention purge scheduler is wired and opt-in (`purge.enabled`); the FAQ gives the published 48-hour acknowledgement time; `SECURITY.md` says session, personal access and machine tokens are stored as SHA-256 hashes.
- **The v0.97.0 upgrade pages are re-checked against the merged code.** `docs/UPGRADING.md` §6l to §6o, §6q, §6t and §6u, the upgrade checklist and the release draft no longer carry "pending" entries. Corrections: 15 CLI flags are refused (notification `--url` included); a grant refused for want of its audit row answers a generic HTTP 500 on the REST API (the sentence is in the server log), and only a mixed narrow-and-widen request is a 503; the schema epoch is 7 with compatibility floor 3. Section numbers are unique (the recertification window is §6w, the CLI webhook section §6x), `docs/CONFIGURATION.md` names the gRPC TLS files, `server.grpc.trusted_proxies`, `server.grpc.hsts_preload` and the `server.http.keepalive.*` keys, and `internal/storage/INVARIANTS.md` INV-STORAGE-02 states the real epoch and floor.
- **Helm quick start keeps secrets off the command line.** The chart README now creates the Secret from owner-only files and installs with `auth.existingSecret` (values file or `--set-file` as alternatives), and the install NOTES warn when the passwords came from Helm values. `docs/operator/j8-kubernetes.md` follows the same steps.
- **Pilot operator runbooks.** New `docs/operator/audit-chain-break-runbook.md` (what the online and
  offline verifiers report, benign causes, tampering versus truncation, evidence to keep, and that no
  re-seal command exists), `lost-totp-runbook.md` (recovery paths per account type, with the gap for
  a non-admin without a recovery code) and `key-rotation-runbook.md` (preflight, verification,
  rollback, what not to do, the audit-checkpoint key change after `rotate-kek`). Linked from the
  docs index next to the break-glass runbook.
- **SSO/JIT accounts cannot be offboarded through SCIM or an IdP disable.** `docs/CONFIGURATION.md` ("Offboarding an SSO / JIT account") and the SCIM/SSO threat model now say plainly that the PATs and sessions of an `sso:`-scheme account survive until an administrator suspends or deletes the user (or the PAT expires or the session lifetime ends), that the inactivity sweep (`keyorix user suspend-inactive`) is not scheduled, and give the CLI and API steps. The JIT paragraph no longer claims a later SCIM push reconciles to the JIT account (false since #3493).
- **`docs/UPGRADING.md` section 6v:** a check query, identical on SQLite and PostgreSQL, that lists the SCIM-created rows whose `externalId` starts with `sso:` and so stopped being SCIM-managed in #3493.
- **`docs/CONFIGURATION.md` no longer says `migrate-provider` takes "no DB lock".** The command holds the exclusive database-presence lock for its whole run and refuses to run next to a live server or another `admin` command; the paragraph now says so. The Makefile comment on release stripping no longer quotes binary sizes.
- **CONFIGURATION.md key derivation.** The audit-checkpoint and evidence-pack signing keys are described as KEK-derived (as in the code), not DEK-derived.
- `docs/CONFIGURATION.md`, "Committing with fdatasync": says that the server's only WAL truncation is the one-off `wal_checkpoint(TRUNCATE)` in `admin restore`, and tells operators to measure on their own hardware before enabling the option, with the limits of the evidence (ext4 only, dropped-writes fault model only).
- `docs/operator/startup-refusals.md` now covers the key-material and key-initialisation refusals (no wrapped DEK over encrypted data, a lost key-initialisation lock, a DEK rotation under `--force`, `migrate-provider cleanup`, the `key-secret` `--out`/`--dir` refusals), the restore-journal recovery refusals, the rollback refusal after an accepted audit loss, `accept-loss` under `--force`, and a `secret_name_policy` pattern that does not compile. The messages without an entry fell from 37 to 10 in the page's own report. The three key-file entries that still named `dek.enc` / `salt.bin`, the secret-file-too-open block and the admin-command-while-running block were re-captured from the current binary, and the schema-epoch blocks were re-run at schema epoch 9.
- **Other connection poolers.** `docs/postgresql-poolers.md` now compares what PgCat, Odyssey and RDS Proxy document (pool modes, advisory locks, timeouts that can end an open lock transaction, prepared statements, `SET`) with Keyorix's lock model and start-up check. Documentation only; none of these poolers is tested or supported.
- **Removed docs for commands and features that do not exist.**
  - The sharing guide's CLI examples used `keyorix shares …`, `keyorix secret share` and `keyorix shared-secrets list`; they now point to the real `keyorix share` group.
  - Its claims of end-to-end, per-recipient encryption and of storage quotas are removed. A share is an access-control row, not a separate encrypted copy.
  - MIGRATION.md no longer documents `keyorix secret import --source vault|aws|azure|gcp`, which the CLI no longer has; live sources go through `keyorix-migrate` (migrate-from-vault.md, migrate-from-cloud.md).
  - Three command spellings are corrected: `request secret-access`/`request review` flags, `keyorix-server admin encryption migrate-provider`, and `keyorix access-review`.
- **The keys above are gone from the shipped config template, the sample configs and CONFIGURATION.md.** That section now documents the real `secrets.limits.max_secret_size`.
- **Docs no longer name commands and files that do not exist.** The examples READMEs used `keyorix system validate|audit`, `keyorix encryption ...`, `system init --interactive|--force` and `--format json`; they now name the real `keyorix-server admin validate`, `keyorix-server admin encryption ...` and `--output json`. Also fixed: `keyorix admin validate --posture` (it is `keyorix-server admin`), the `keyorix-core.md` layout (no `internal/cli`, `internal/client`), the nonexistent `keyorix_template.yaml`, the "chunked encryption" claim (never built), and 13 refactor-worklist rows for deleted functions.
- **Pre-1.0 security support is now stated by severity.** `SECURITY.md` has a table: every severity is fixed on the current minor, and Critical and High are also backported to the previous minor for a stated window (the later of the next-but-one minor, or 30 days after the immediate successor). Medium and Low on the previous minor need an upgrade. `SUPPORT.md` points to it, and ADR-104 records the decision in a dated amendment that supersedes its "latest release only" scoping.
- **Closure row for #4025** (`ADMIN-RANK-CEILING-SNAPSHOT`) and a corrected `GetUserRoleScopes` doc comment: the admin-rank ceiling takes the target's role set from one read.
- **Six new per-component threat models** in `docs/security/threat-models/`, in the existing format (DFD, trust boundaries, threat table with Evidence and Residual-or-GAP columns): sharing and secret ACLs, break-glass, SCIM and SSO-managed accounts, dynamic secrets and leases, notifications and webhooks, and rate limits and login lockout. Every mitigation names a function and a test that exists on `main`; where none does, the row is a GAP with an issue number. The README indexes them and lists the eleven gaps filed (#3418, #3419, #3420, #3422–#3429).
- **ADR-117 addendum (Proposed): signed-policy distribution, recovery authority and no fallback.** Design only, no behaviour change. It defines how a new signed PCR policy reaches a host and when the old one stops being accepted, who may authorise a TPM recovery and that the audit event is written before the blob is replaced. A policy-bound `tpm` provider must be the only provider in its chain, and `insecure_allow_weaker_kek_fallback` does not lift that. It also corrects ADR-117 D9: a DEK sweep alone does not cut off an old sealed blob; that takes a new KEK first, and the default-yes prompt on entering PCR mode now plans both.
- **Upgrade drill (`docs/operator/drill-upgrade.md`): step 5 re-run against main.** An old v0.96.x binary on a database that main has upgraded refuses to start with `database declares a minimum compatible schema epoch of 3 (database schema epoch 5), above this binary's schema epoch 2 ... Refusing to start (ADR-101)` and exits 1, and nothing in the database or key files changes. The step description named the other (no-floor) message. The "Last run" section now has the result, and what the old binary's `admin` commands do on that database.
- **Upgrade and rollback runbook, verified with the published images.** New `docs/operator/upgrade-rollback.md`: 0.96.1 → 0.96.3 on Docker Compose (PostgreSQL) and on SQLite and PostgreSQL binaries. It covers which binary runs on which schema, a concrete backup-first checklist, rollback by image/binary swap within v0.96.x, and rollback by restoring the pre-upgrade backup in place. Also covers measured timings and what not to do.
- **SELF_HOSTING.md §5: the documented live-backup copy-out could not work.** `docker compose cp backend:/tmp/backup.tar.gz` fails because `/tmp` is a tmpfs. The archive is now streamed out with `docker compose exec -T backend cat`.
- **SELF_HOSTING.md §5 and UPGRADING.md §7: PostgreSQL in-place restore.** "Drop and recreate the database, then restore without the flag" was refused, because the key files still exist. The docs now say to empty the database and restore with `--overwrite-existing` (plus `--allow-rollback` on the same host). They also warn that a failed `--overwrite-existing` over a populated database has already replaced the key files, and give the recovery.
- **UPGRADING.md §7** names both rollback refusals (the floor message for v0.97 → v0.96.x, and the epoch message) and the binary-only rollback within one schema floor. Stale v0.96.2 and epoch-3 references in the operator drills are fixed.
- **The "migrate off Vault" demo works again** (#3638). `demo/vault-migration/run.sh` ran `keyorix secret import --source vault`, which the CLI no longer has; it now runs `keyorix-migrate vault --apply` with both tokens passed through files, and stops with a clear message when `keyorix-migrate` is not installed. The demo README and `docs/specs/vault-migration-fidelity.md` point to `docs/migrate-from-vault.md`, which now notes that `--force` needs `--apply`.

### Testing
- **No-leak coverage past the route gate.** New handler-level tests call each value-disclosing handler (by id, by ref, certificate, render) as a caller that passes the route gate but fails the per-secret permission check, against suspended, expired and out-of-schedule secrets, and assert it sees exactly what it saw before the state applied (for render, also exactly what a missing secret answers). A reorder of the state guard ahead of the permission check inside core is now caught.
- **Security closures can now be verified in the `cli` module.** `scripts/check-closures.sh` (and `scripts/gen-security-closures-tsv.sh --check`) resolve each row's package to the Go module that owns it: `./internal/...` runs from the repo root as before, `./cli/...` runs `go test` inside `cli/` (own `go.mod`, `GOWORK=off`). A bare path, a wildcard or `..` segment, a missing directory or a module the checker cannot run fails the check instead of being skipped; `--self-test` covers a passing and several failing cli rows. New closure rows `cli-ca-file-fifo-refused-001` and `cli-input-fifo-refused-001`..`004` record the CLI FIFO fixes (#3182, #3186).
- **Host-TZ backup/restore tests no longer write `time.Local`.** The SQLite and Postgres
  `RoundTripAcrossHostTZ` tests now run each zone in a subprocess of the test binary started with
  `TZ=<zone>`, and the `backupfmt` codec test passes zone-located times explicitly. Assigning the
  `time.Local` global raced with timer goroutines (`-race` failure that removed #3168 from the merge
  queue). `TestNoTestAssignsTimeLocal` fails if any `_test.go` assigns it again.
- `scripts/demo/check.sh --postgres` generates the Postgres certificate with the real
  `init-secrets.sh`, and its compose project, published port and image names are overridable
  (`KEYORIX_DEMO_CHECK_PG_PROJECT`, `_PORT`, `_WEB_IMAGE`, `KEYORIX_DEMO_IMAGE`) so a shared Docker
  host can run it without touching another run's resources.
- **Real-backend spec for break-glass.** `web/e2e/real/break-glass.spec.ts` drives activate, admin sees it, admin revokes, member sees revoked, and an outsider is refused. `scripts/e2e/web-real-smoke.sh` boots the group of a spec carrying `// e2e-server: break_glass=true` with break-glass enabled.
- **The outsider test asserts exactly what an outsider sees.** An outsider's project fetch is a 403, so the page shows "Failed to load project." and the break-glass tab never mounts; the spec (and a `ProjectDetailPage` unit test on a direct break-glass link) now require that and reject the tab's own "Not allowed", the tab link and any activation data.
- PostgreSQL tests that need the full production schema now clone a migrated template database (`pgdsn.MigratedDatabase`, one template per schema fingerprint, built once under an advisory lock) instead of migrating an empty one every time. `KEYORIX_TEST_PG_TEMPLATE=0` restores create-empty-and-migrate.
- **Long audit readers never hold one snapshot across a walk (AUDIT-READER-HYGIENE-1).** Measured on a 300k-row audit table with a concurrent writer, on SQLite (production storage settings) and PostgreSQL: the audit_checkpoint rolling re-walk and `admin verify-audit` already read in 1000-row statements, so neither pins the SQLite WAL nor the PostgreSQL xmin horizon. No code change was needed; `internal/core/audit_long_reader_snapshot_test.go` now fails if a walk starts holding one snapshot (or the write lock), and `audit_chunked_walk_differential_test.go` pins that every chunked walk (statement batches, rolling segments, offline batch sizes) gives the verdict, first broken row and head of one whole-chain walk, including on retention-purged chains with v1 and v2 anchors.
- **Scheduler jobs that read audit-sized tables must declare their bound.** `server/scheduler_audit_read_registry_test.go` derives, from the code, every scheduler job that can reach a read of `audit_events` or `secret_access_logs` and fails on one without a registry entry (one file per job, `server/REGISTRY-ENTRIES.md`) naming its bound: high-water mark, time window, id window, or a named conditional full walk.
- **One declared lock order, checked statically over every call site.** A new test in
  `internal/core` follows `internal/core`, `internal/core/storage` and `internal/storage/store`
  call by call. It covers in-process mutexes, `sync.Once`/singleflight waits, named-lock
  families, transactions and the scheduler, bootstrap and checkpoint locks, and fails on any
  acquisition that goes against the declared table, including a mutex/named-lock ABBA. The
  named-lock runtime order check now also runs in the `server/http`, `server/http/handlers`,
  `server/grpc` and `server/grpc/services` suites. A parity test keeps the gRPC limiters' sweep
  interval and idle timeout equal to the HTTP limiters'. (#2694, #2685, #3429)
- **FLAKES-4 test hygiene.** The web-e2e real-smoke port base now stays outside the OS ephemeral ranges (#3353); `activateMFAForStepUpTest` retries when a TOTP step boundary passes mid-activation (#3352); the secrets-crud History spec waits on the server's rotate and audit responses instead of a timer (#3276); five more handler tests moved to `sqlitetest` (two wait for #3365) and the shared-cache guard now requires each pending entry to name its PR.
- **`internal/core` test doubles share one `hookStore`.** 123 per-test `struct{ storage.Storage }` doubles each cost ~2.6 MB of method wrappers; the `[internal/core.test]` archive is now ~50 MB instead of 326 MB and compiles several times faster. No product code changed and no test assertion changed. `TestNoWholeStorageEmbeddingInCoreTests` keeps a second whole-`Storage` embedding out of the package.
- **Flaky-test fixes (TEST-HYGIENE-3).** The SQLite write-gate pair forces its contention with a held write lock instead of relying on host speed (the ungated control saw no SQLITE_BUSY on fast machines); `free-port_test.sh` draws its test base below every OS ephemeral range and reports a listener that cannot bind instead of exiting silently (#3353); the server/faultops owed-audit calibrations drive each case in its own subtest so a Postgres run no longer holds ~77 connections at once (SQLSTATE 53300), and a per-test world budget (`world_db_budget_test.go`) fails any test that piles up worlds again.
- **Repo-wide guards no longer read the calendar or go blocking on day one.** Expiry dates on exemption rows (full-row write and child-parent liveness pending rows, fault-injection tolerances, the named-lock pending family, ADR open decisions) are checked for format on PRs and evaluated only by the nightly job on main (`scripts/guard-expiry-report.sh`, 7 days' warning). New guards report through `guardrules.Rollout` and stay report-only on PR and queue runs while listed in `docs/guard-rollout.d/`; `scripts/guard-meets-open-prs.sh` runs a guard over main plus open PRs' merge results. Contract: `docs/guard-rollout-contract.md`; enforced by `TestGuardTestsDoNotReadTheCalendar`.
- **`(*KeyorixCore).StorageForTesting()` gives tests outside package core the raw storage handle** (ADR-121 decision 2), next to `SetClockForTesting`. `clock_seam_guard_test.go` now fails on any non-`_test.go` use of it, including a method value. Six in-package test files read `c.storage` through it, which makes seven files black-box with their helper closure (81 to 88). No product behaviour and no test assertion changed.
- **SCIM Groups: the "storage failure is not a 404" guarantee is now pinned end to end (#3620).** The status change itself shipped in #3734; this adds the tests that keep it from regressing: a missing or soft-deleted group is the typed `ErrGroupNotFound` and a database failure never is (SQLite and Postgres), `core.GetGroup` keeps the storage error chain, and each group write (`POST`, `PUT`, `PATCH`, `DELETE`) answers write contention `503` with `Retry-After` and leaves the group unchanged. No behaviour change. The fault sweep over the group routes found a separate, pre-existing effect-then-error (`PUT`/`PATCH` answer `500` when the re-read after commit fails); it is tracked in #3773.
- **The solewriter own-table lock test runs on a non-superuser PostgreSQL and covers every covered table.** `TestPoll_OwnTableLockKeepsTheHolderLock` grants its test role to the current user (it failed on a NOSUPERUSER CREATEROLE role before taking any lock), holds the lock until the test releases it, and loops over every fenced and own table: where the lock blocks the poll (the own tables and the fenced tables with a `WHEN` trigger) the lease must lapse and stay lapsed, elsewhere a poll must succeed, and on every table a write under the lock is refused. `TestCheckOff` also runs with `storage.type: postgresql`, killing the fence.go negation mutants for that spelling.
- **Proof side of the administrator MFA reset (#3751).** A cross-replica test (two administrators approve one request at once, on Postgres and SQLite): exactly one wins, the other gets the typed already-decided error, and the user ends with one cleared second factor, one one-time password and one `mfa.reset` audit row. A report-only guard (`TestEverySecondFactorClearerCallerIsAllowlisted`) allowlists the callers of `DeleteMFAForUser` and `DeleteWebAuthnCredential`, so a new call site that clears a second factor outside the reset flow fails the build once promoted. The three MFA reset routes are now fault-injected (faultops `StatusFuzzed`) with a new oracle: never a cleared second factor beside a working old password, a live session or a live personal access token.
- **No released binary starts on a database this release migrated (#3359, #3362).** A test
  replays the start-up checks of v0.93 to v0.95.x and v0.96.x against a fresh database, the
  v0.95.0 upgrade fixture and a database v0.96.x left behind. All of those binaries predate
  the v2 audit retention anchor and the suspend clear-copies marker.
- **Two regression pins and a familycheck doc note (TEST-HYGIENE-4).** `TestCaptureLogBuf_ConcurrentLoggerWritesAndReads` (`server/http/handlers`) pins the capture-log buffer against concurrent writes and reads under `-race`. `TestInvalidateUserTokenCache_UserBothImpersonationTargetAndImpersonator` (`server/middleware`) pins cache eviction for a user who is both an impersonation target and an impersonator. `devtools/familycheck/README.md` now says that only the first marker line of each kind is read.
- **New guard `TestNoDiscardedStorageReadErrorOnDecisionPath`** (`internal/core/guards`, report-only on its first day): fails on a storage read (`List*`/`Get*`/`Find*`/`Count*`/`Resolve*`/`Lookup*`) whose error is discarded (`x, _ :=`) in a revocation-, authorization- or account-state-named function or file of the core family. Calibrated by `TestDiscardedReadScanner_Calibration` (4 hit shapes, 5 safe shapes, a floor of 3 candidates); its doc comment lists what it does not catch. One registered exception: `authz_secret_batch.go`'s group-membership read, which fails closed.
- **Two-replica PostgreSQL race for a duplicate username**: two independent connections both pass `CreateUser`'s username pre-check; exactly one row is written and the loser gets `ErrUserAlreadyExists` (409 / AlreadyExists), not the raw unique-index error.
- **Suspend's session delete is proven retried and reported**: a one-off fault is retried and the session rows are gone; a persistent failure keeps the state change, is logged, audited (`auth.session_revocation_failed`) and evicted per user, and the leftover session is refused while the account is blocked. Covers the session half of the fix in AUTHZ-ORACLE-1, which only tested the PAT half.
- **MFA-reset race tests now force the interleaving they claim (#3801).** A Postgres cross-replica test holds two create-requests for one target inside their transactions so only the target's row lock decides (with a no-lock calibration), the two-approver race holds both past the pre-transaction read and checks the loser is refused inside its transaction, and the second-factor-clearer guard also sees `SetUserMFAEnabled(false)` / `SetUserWebAuthnEnabled(false)` and cleared `MFAEnabled` / `WebAuthnEnabled` fields.
- **Rolling-upgrade compatibility, with the older binary's exact writes (#3362, #3359, #3708).**
  A PostgreSQL test plays v0.96.3's `TransitionSecretStatus` statement (resume, then a plain
  suspend) between this version's clear-copies suspend and its read, which must not carry
  the clear-copies marker. Audit verify state tests play the row an older replica's save
  writes (the fields its struct knows, the next generation, the current checkpoint trail).
- **Postgres tests that set `session_replication_role` skip on a role that may not, and fail in CI.**
  `internal/testutil/pgpriv.RequireReplicationRolePrivilege` probes the connected role once and
  skips (naming the missing privilege) unless `CI=true` or `KEYORIX_REQUIRE_PG_SUPERUSER=1`, where
  it fails. Ten tests use it, and `TestEveryReplicationRoleTestRequiresThePrivilege` (report-only
  rollout row) flags a test file that sets the role without calling it. Test-only change.
- **A wording guard fails when a non-ADR doc or a Go comment calls a checkpoint or evidence key DEK-derived.** `TestNoDEKDerivedWordingForKEKDerivedKeys` (`internal/docsdrift`) is report-only until its first green nightly on main.
- **A relative `KEYORIX_TOKEN_FILE` has a CLI journey.** `TestJourney_TokenFileRelativePath` drives `./token` (0600, in the CLI's working directory) against a real server, and checks that a relative path to a missing file fails with exit 3 without echoing the path (#3564).
- **The "variable unset" env-expansion test really unsets the variable.** `t.Setenv(name, "")` leaves it set-but-empty; `TestLoadExpandsEnvVarFallsBackToDefaultWhenUnset` now unsets it and both it and the set-but-empty test assert which state they are in.
- **`scripts/ci/tz-sweep.sh`** runs time-sensitive Go packages one at a time under non-UTC zones (default Asia/Kolkata and America/Los_Angeles) and lists every failing zone/package pair; a zone Go cannot load is refused (exit 2). Not wired into CI.
- **Renew-side dynamic-secret guards are pinned.** `TestDynamicSecrets_RenewRefusesNoNativeExpiryBackendWithoutSweeper` checks that `RenewLease` refuses a backend without native expiry while the lease sweeper is off, and `TestDynamicSecrets_RenewRevalidatesAdminDSN` checks that renew refuses a stored admin DSN pointing at a private or link-local address once private targets are disallowed, without calling the engine or moving the expiry.
- **Resuming a secret in a soft-deleted project is refused.** `TestResumeSecret_RefusedInDeletedProject` (SQLite) asserts `ErrProjectNotFound` and that the secret stays `suspended`.
- **The machine credential lookup's GORM fallback is now tested (#3464).** `TestCredentialLookup_GORMFallbackAnswersAsTheRawPath` forces both fallback branches (a transaction-scoped store and a failed prepare), proves the fallback query ran and compares its answer with the raw path on SQLite and PostgreSQL.
- **A report-only guard flags an `addr`/`address` value that is parsed as a URL and then formatted into a log or error.** `TestNoConfiguredAddrURLFormattedIntoLogsOrErrors` (`internal/urlleakguard`) exempts values the same function uses as a host:port dial address, and is report-only until its first green nightly on main.
- **GUARD-PROMOTE-2 guard promotion and widening.** The URL-leak guard (`TestNoConfiguredURLFormattedIntoLogsOrErrors`) is blocking on every run now; the KEK-derived wording guard also scans `_test.go` comments (two wording fixes); a new report-only guard, `TestEveryExpiryAssignmentAndColumnWriteInCoreIsUTC`, covers assignments and `Update`/`UpdateColumn`/`Updates(map)` writes of expiry, `last_used_at` and `last_seen_at` in core (#3961).
- **Fourteen guard promotions and three test-hygiene fixes (TEST-HYGIENE-5).** These guards now block on every run: `TestAuditEventWritersRecoverTheirOwnPanic`, `TestDemoScriptsOnlyUseDocumentedKeyorixCommands`, `TestDocsCitedRepoPathsExist`, `TestDocsOnlyUseExistingKeyorixCommands`, `TestEveryProjectsJoinRequiresTheRow`, `TestEveryRefusingPermissionCheckMapsAStorageOutage`, `TestEveryReplicationRoleTestRequiresThePrivilege`, `TestEveryStoreTimeBindIsUTC`, `TestInvariantDocs_IndexListsEveryFragmentArea`, `TestInvariantsIndexHasNoDuplicateRowsAndTotalsAddUp`, `TestKeyLockRefusalsBlameAHolderOnlyOnContention`, `TestNoDEKDerivedWordingForKEKDerivedKeys`, `TestNoErrorTextClassification` and `TestShareListFetchCallersRefuseAtTheCap`. The `internal/encryptionops` failed-write restore test now lowers `RLIMIT_FSIZE` through a `limitFileSize` helper, which restores the limit in `t.Cleanup`. A new `internal/core` test covers self-replacement of a role set when `roles.assign` stays available through a direct `project_admin` grant. `scripts/guard-meets-open-prs.sh` has a new `-f FILE|-` option that reads the open-PR list from a file or stdin.
- **Five surviving `internal/core` mutants killed, found by fuzzing each survivor against its mutated copy.** New `scripts/mutation-testing/survivor-fuzz/` runs one gremlins `LIVED` mutant's original and mutated function side by side under `go test -fuzz` and reports `killed-by-input`, `likely-equivalent`, `harness-missing`, `no-node` or `error`. The pilot's inputs became plain unit tests (`internal/core/survivor_fuzz_regression_test.go`): an unknown action is not reported as the highest secrets action, a password exactly at its maximum age is not expired, a lower-ranked actor cannot revoke an admin's sessions, the force-closing actor's own pending item blocks a force-close, and the smallest escalation delay is returned.
- **Stateful authz sequence fuzzing.** `server/authzdiff` gains `FuzzAuthzSeq` and an opt-in sweep (`AUTHZSEQ_SWEEP=1`) that run random sequences of grants, revokes, group changes, suspensions and permission toggles on the core, REST and gRPC legs, and compare every step and every probe with the reference model. A transport allowing what the model denies, an allowed step whose effect is missing (a revoke that did not revoke, a suspension or membership change that did not happen), a denied step that changed state, and a step on which a transport answers a server error (5xx, gRPC `Internal`) always fail; they are never treated as single-step noise. The fuzz target and the sweep share one triage, and the planted-defect tests assert that it fails. One known-open gRPC error-mapping gap (#4020: `RemoveRole`/`AssignRole` answer `Internal` where REST answers 404/409) is tolerated by its exact signatures only, and only when the revoked grant was absent (or the granted one already held) before the step, with the state still required unchanged. The default `go test` runs the baseline, one benign sequence and three planted defects (`revoke-noop`, `revoke-noop-held-grant`, `revoke-noop-held-grant-4020`); `AUTHZSEQ_SELFTEST=1` runs the rest. The reference model's group-role resolution now treats a project-scoped group membership as conferring the group's roles only in that project, which matches the store's group-role resolution.
- `FuzzStorageBackendDifferentialV2` runs the same operation sequence against SQLite and PostgreSQL and compares storage error classes, edge-string handling, updates, filtered page walks and secret value bytes. Companion tests compare `ORDER BY` lists and concurrent unique-key races. All of them skip without `KEYORIX_TEST_PG_DSN`. The pre-registration and the outcome of the first campaign are in `docs/fuzzing/pg-sqlite-differential.md`.
- **Secret-leak canary oracle.** A sweep over every HTTP route and unary gRPC method, plus a CLI test that builds the real binary, plants secret-class canaries and fails if one appears on a response, log, stdout, stderr, metrics, DB cell, raw DB file or temp file. Allowed hits are an exact route, label and surface list that fails when a row goes unused.
- Added `internal/verifierflip`, a bit-flip, truncate, extend and reorder mutation harness over the integrity and authenticity verifiers, with planted-defect self-tests and the `FuzzVerifierMutationChain` fuzz target.
- **Process-level crash-recovery fuzzer.** `TestCrashRecoveryFuzz_SQLite` kills `admin encryption rotate`, `rotate-kek`, `backup` and `restore` with SIGKILL at fuzzed points, recovers with the documented commands only, and checks whole-install invariants. Rules and results are in `server/CRASH_RECOVERY_FUZZ.md`; the first campaign did not meet its pre-registered bar (R2).
- Add an upgrade-path fuzzer (`TestUpgradePathFuzz`, opt-in via `KX_UPGRADE_BINDIR`) that installs and populates released tags, then upgrades with the current tree through a clean migrate, a repeated migrate, SIGKILLed migrates and the old release's own backup. It found that backups taken by v0.95.2 and v0.95.3 with soft-deleted secrets cannot be restored (fixed from v0.96.0); see `server/UPGRADE_PATH_FUZZ.md`.
- **Fake-clock fuzzers for extreme instants and DST schedules.** `FuzzFakeClockExtremes` mints sessions, PATs and leases from the zero time through 2106 and runs multi-step clock programs against model-based oracles, and `FuzzEnforceScheduleDST` compares `enforceSchedule` with an independent computation across 14 time zones. `TestSeamGap_*` pins two expiry and schedule decisions that the injected clock cannot reach yet. Rules, oracles and results: `internal/core/FAKE_CLOCK_FUZZ.md`.
- **Opt-in input-to-sink taint fuzz harnesses.** New `Fuzz*Taint*` targets in internal/backupfmt, internal/config, internal/connect and internal/dynamic, built only with the `taintoverlay` tag and run through the overlay wrapper from fuzz-corpus. They fail an iteration when fuzz input reaches a file path, command, query or unexpected host sink. internal/fuzzutil/taint is a vendored copy of the oracle; default builds and CI are unaffected.
- **Cross-SDK differential fuzzer (`scripts/e2e/sdkdiff`).** Runs one scenario through the Go, Node, Python and Java client SDKs behind a recording proxy and compares the wire requests, results and error classes. Test tooling only: nothing ships in the server or a release. A run that executed nothing fails instead of passing, and the proxy forwards request targets byte for byte.
- **`FuzzSAMLXMLTransitive`** fuzzes the SAML XML stack and fails on `crewjam/saml` v0.5.1, so a dependency downgrade or regression is caught.
- **Wycheproof vectors and mutations for the crypto wrappers.** `internal/wycheproof` runs the pinned C2SP/wycheproof `testvectors_v1` files (fetched and SHA-256-checked by `scripts/wycheproof/fetch.sh`, not vendored) against `internal/encryption/aead` (AES-256-GCM), `pkg/trust` (Ed25519), JWT ES256/ES384/RS256/PS256 verification after `rules.ParseJWK`, crewjam/saml `xmlenc` AES128GCM, HKDF-SHA256 and PBKDF2-SHA256, mutates every valid vector, and checks planted defects are caught. Without the vectors the suites skip (`WYCHEPROOF_REQUIRE=1` makes that a failure). Three differential fuzz targets are registered, and `TestMACComparisonsAreConstantTime` (report-only on PRs until its first green nightly) flags `==`/`bytes.Equal` comparisons of MAC, signature and tag values in the crypto packages.
- **Live-server authorization replay harness.** `scripts/e2e/livereplay` (build tag `e2e`) boots a throwaway `keyorix-server`, records a legitimate project-admin session and replays it and every `/api/v1/*` OpenAPI operation as other principals (another tenant's admin, a lower role, no grant, machine tokens, no or bad credentials), with swapped and mutated object ids. Three deny-direction oracles (status, cross-tenant leak, observable state change) are judged against a small authorization model. The state oracle calibrates its own snapshots for self-induced drift and requires a change to persist. Planted-defect self-tests run in the default `go test` (fake API) and against the real server (`TestLiveReplay_PlantedDefects`).
- **Configuration-space fuzzer (`scripts/fuzzing/configspace`).** Exercises `keyorix-server`'s YAML options, flags, secret-source environment variables and deprecated aliases as a combinatorial space (single-fault rows, pairwise covering arrays, seeded mutations, precedence and alias cases), in process through `config.Load` and `Validate` and against the real binary on loopback, checking a registered rule set: no crash, invalid values refused by name, insecure postures warned about, no secret in logs or responses, aliases and precedence honoured, clean start and shutdown. The process-stage probe pins the case's own TLS certificate (TLS 1.2 floor) instead of skipping verification. Planted-defect self-test in `planted/`; Go fuzz target `FuzzConfigLoadValidate`. Test tooling only: nothing ships in the server or a release.
- **`FuzzConfigLoadValidate` secret oracle no longer flags echoed key names.** The loader repeats an unknown key name in its error by design; the oracle now fails only when the canary appears as a value, and a self-test plants value leaks to show it still does.
- **Configspace known-findings table (`known.tsv`).** Triaged findings of class HARDENING or lower are tagged with a stable `CSK-` id (never dropped); `TestKnownFindingsReproduce` goes red when a listed finding stops reproducing. Configuration findings are triaged privately.
- New AST guard `TestEveryDirectMachineGrantEntryTagsSelfGranter` (report-only on pull requests for now): every HTTP handler and gRPC method that reaches the role-grant ceiling must tag the context with `WithSelfMachineGranter` on the machine-actor branch.
- New guard `TestMigrateDatabase_ExistenceSnapshotPrecedesEveryTableCreation`: every `tableExists` call written directly in `migrateDatabase` (not those inside the migration steps) runs before any table-creating `AutoMigrate`.
- Invariant index recounted; stale gRPC "Ledger gap" note removed.
- **Schema-driven stateful OpenAPI fuzzer (`FuzzOpenAPIStateful`, `server/http`).** Enumerates
  all 307 operations straight from `openapi.yaml` (kin-openapi), generates request arguments from
  the schemas (valid / boundary / schema-violating), binds ids returned by one call into later
  calls' path params and `*_id` body fields (a successful DELETE feeds the use-after-delete
  shapes), and drives 1–12 operation sequences against the real in-process `NewRouter` stack over
  a seeded SQLite store with eight fixed principals (no-token, garbage, no-role, viewer,
  project-admin, global-admin, machine-token, expired-grant). Five oracles — no undeclared 5xx,
  response conformance, unauthenticated-layer authorization monotonicity, canary non-leakage, and
  idempotent reads — each documenting what it does NOT verify. Added its
  `scripts/fuzzing/targets.d/` entry. Oracle 1 (undeclared 5xx) is not yet a strict gate: a
  well-formed request that returns an undeclared 5xx is only logged as a candidate unless
  `KEYORIX_OSF_STRICT=1`, and the known instances (OPENAPI-STATEFUL-1..8, real unfixed bugs)
  are waived via an exception list tracked in #4132. Oracles 2-5 are always fatal.
- authzdiff cross-layer differential harness now covers the bulk secret-owner
  reassignment route (`POST /api/v1/projects/{id}/secrets/reassign-owner`,
  core `ReassignOwnedSecrets`). Its single project-scope `roles.assign` gate
  (the #G10 fix) is checked on the core and REST legs against the independent
  reference model. A permanent planted-defect self-test
  (`reassign-owner-core-gate-removed`) proves the harness still records a
  dropped core gate, as the known-04 waiver ("core allows, every transport
  denies"): REST keeps its router gate, so a strict sweep does not fail on it.
- authzdiff now also covers self-service break-glass activation
  (`POST /api/v1/projects/{id}/break-glass` and the gRPC RPC
  `BreakGlassService.ActivateBreakGlass`, core `ActivateBreakGlass`). Neither
  transport carries a permission gate of its own — the entire authorization is
  core's — so all three legs are checked against a new independent model rule
  (`memberOnly`): only a USER who is a member of the project NOW (a role scoped
  to that project, direct or via a live group — never a global/install-wide
  role, the #284-era fix), and never a restricted PAT. A machine actor
  (reaching core as `userID==0`) is refused with a validation error and
  absorbed by the partition's existing machine mapping-gap waiver, never a
  disagreement. A permanent planted-defect self-test
  (`breakglass-activate-membership-gate-removed`) proves a strict sweep fails
  when that membership gate is dropped.
- authzdiff coverage rises from 89 to 91 of 211 in-scope REST operations and
  from 34 to 35 of 46 in-scope gRPC operations.
- **Derived guard over every handler that can hit the grant ceiling.** `internal/core` derives which exported methods can refuse with the grant ceiling (`testdata/grant_ceiling_reaching_methods.txt`), and `TestEveryGrantingHandlerMapsTheCeilingRefusal` requires every HTTP handler calling one to classify `core.ErrPermissionDenied`. Two handlers that still answer it 500 (`CreateGlobalInvitation`, `TransitionMembership`) are exempted naming #4154, and an exemption whose handler maps the refusal is reported as stale.
- **Family guards for the status-mapping class.** `TestEveryGrantingServiceMapsPermissionDenied` (gRPC) checks every service that calls a granting core method (derived from internal/core's grant-ceiling checks) maps `core.ErrPermissionDenied` to `PermissionDenied`, following one-hop helpers; report-only on pull requests until its first green nightly. The REST twin lands with #4165 (`TestEveryGrantingHandlerMapsTheCeilingRefusal`). The classifier's table is driven through both adapters (REST/gRPC parity on every sentinel), and `TestErrMap_StatefulFindingsAnswerDeclaredStatus` pins the #4132 findings under English and a translated pseudo-locale.
- **Disk-full edge test asserts the real audit-before-disclosure invariant.** `TestEdgeUnattended_DiskFullThenFreed` failed on macOS: it expected every value read to be refused while writes fail, but a file-size limit only refuses file growth, so a small audit commit can still land in WAL space a failed write left behind, and that read is then served and audited (the row survives a restart). The test now requires every value disclosed while the disk is full to have its own `secret.read` audit row after a restart, reads until the audit write fails and the read is refused, and measures `/bin/sh`'s `ulimit -f` unit (512 bytes on dash, 1024 on macOS) instead of assuming 512. No server change: the read path already failed closed.
- **The PostgreSQL long-reader probe counts only the walk's own connections.** `TestAuditLongReaders_*` tagged nothing and read every backend of the database, so a snapshot held by another package's test (CI runs `internal/core` and `internal/storage` in parallel on one database) or by autovacuum was reported as the audit_checkpoint rolling re-walk's own and failed the nightly "Cross-replica race tests (Postgres)" on an unchanged chunked walk. Each env's connections now carry their own `application_name`; the verdict is that no one transaction was seen holding a snapshot in half of the walk's probes (a count, not wall time). New guards: a snapshot held by a foreign backend is not attributed to the walk, and the same tick run inside one REPEATABLE READ transaction is reported pinned. Test-only; no production change.
- **The change-password / profile budget is now tested through the real router.** `TestChangePassword_CurrentPasswordBudgetThroughRouter` and `TestUpdateProfile_CurrentPasswordBudgetThroughRouter` send a real session bearer token through `NewRouter`: ten wrong current passwords answer `401`, the next request from that IP answers `429` even with the right password and changes nothing, each wrong password left an `auth.login_failed` row with `success=false` and the client IP, another IP is not throttled, and a display-name edit (no `current_password`) never is.
- **Cross-layer authz operation matrix.** `devtools/authzmatrix` derives every mutating and secret-value-reading operation from type-checked SSA. For each one it records the core entry point, REST route and gRPC method, and whether core itself refuses or leaves authorization to the transport. It is calibrated against the FIX-1 grant guards, with a red self-test. Output: `server/authzdiff/MATRIX.md` and `matrix.json`.
- **Cross-layer authz differential harness.** `server/authzdiff` runs each operation for the same principal and inputs on three layers: core called directly, the real REST router and the real gRPC server, each leg on its own copy of a seeded SQLite template (synthetic fixtures only). Two oracles: the layers agree, and each layer matches a reference model over the role's actual permissions. Principals are fixed named ones plus permission sets generated per operation, held directly, through a group or by a machine. Coverage over every in-scope operation is derived from `matrix.json` (`COVERAGE.md`, `COVERAGE-ALL.md`). The default `go test` run (smoke, coverage freshness, route and universe checks) fails on any case no known waiver covers, as does `FuzzAuthzDiff`; the exhaustive sweep (`AUTHZDIFF_SWEEP=1`) is opt-in.
- **Planted-defect self-test.** `TestPlantsAreDetected` applies five planted authorization defects with `go test -overlay`, so the tree is never edited, and fails if the harness stops naming the planted operation. Opt-in (`AUTHZDIFF_PLANTS=1`); CI job `authzdiff-plants` runs it nightly, on manual dispatch and on `ci:full` PRs.
- **Harness self-checks.** A full strict sweep fails on a waiver that matched no case (so a waiver cannot outlive the condition it was written for) and on any case whose admin positive control failed. `TestMatrixKeysAreCurrent` fails when `matrix.json` no longer matches the REST route inventory (keys and gates) or the registered gRPC methods, and `authzmatrix` writes its output only after its calibration passes.
- **Authorization guards that no test used to defend.** Removing any of these now fails a test: the re-check of the decrypted dynamic-secret admin DSN at lease issue and revoke, the refusal to issue from a MySQL, MongoDB or Redis backend while `dynamic_secrets.sweep_enabled` is off, and the refusal to issue from a disabled config (#3424). A new source-scan test fails when any caller of the core secret-ACL grant, revoke or list methods is not behind `secrets.manage` (#3423), another when a caller of `ShareSecret` passes a group (#3422), and a table test names the gate of each neighbouring grant primitive (role assignment, project membership, machine-identity role grant, break-glass activation, connect ref-grants).
- **`audit search --actor` is pinned over REST for users and machine identities (#3736).** A real machine-token read and a real session read are each found by `GET /api/v1/audit/search?actor=` under the name the ACTOR column shows. The storage fix landed in #3836.
- **The RBAC test fixture seeds the ADR-021 project roles and keeps the legacy roles install-wide (LEGACY-ROLES-GLOBAL-1 leftover).** `internal/testhelper`'s fixture kept `admin`/`editor`/`viewer`/`auditor` assignable at any scope after real installs made them install-wide only (#3605, #4089); tests that granted them on a project through core now use `project_admin`/`project_developer`/`project_viewer`/`project_auditor` (`testhelper.RoleProject*`), and five tests that passed only because of the old scope now assert the reason they refuse. Test-only, no product change.
- **A fault-injection seed covers the admin-rank ceiling's new grant read (REVOKE-AUTHORITY-TAILS-1 leftover).** `4025_grpc_updateuser_listuserrolegrants_error` faults gRPC `UpdateUser`'s ceiling read of the target's grants and must fail closed with no exemption row; the existing `3093_grpc_updateuser_getuserrolescopes_nth2_error` seed still targets the call it was written for and is unchanged. Test-only, no product change.
- **gRPC low-privilege method walk.** Every registered RPC (unary and streaming, read from `GetServiceInfo`) is now called as a zero-grant machine token, a project viewer user and a project-restricted PAT with canary ids bound; each must be refused or return an empty result, never leak canary data, and never change table content (`server/grpc/authz_walk_lowpriv_test.go`, `INV-GRPC-lowpriv-method-walk`).
- **gRPC dead-credential method walk.** Every registered RPC is now called with a credential in each dead state (revoked/expired session, PAT and machine token; suspended/deleted/deactivated user or revoked/suspended machine identity), cold and warm; each must answer Unauthenticated with no state change (`server/grpc/authz_walk_dead_credential_test.go`, `INV-GRPC-dead-credential-walk`).
- **gRPC/REST walk parity table.** Every registered RPC must map to a REST route (or carry a reason it has none) and every REST route family must be reachable over gRPC or be listed REST-only with a reason, so a new RPC or REST family cannot slip past one set of authorization walks (`server/grpc/authz_walk_rest_parity_test.go`, `INV-GRPC-rest-walk-parity`).
- **Route-wide authorization walks for writes and for dead credentials.** `TestEveryWriteRouteRefusesAndChangesNothing` calls every POST/PUT/PATCH/DELETE route as a zero-grant machine token, a viewer and three restricted PATs, with every path parameter bound to the real canary objects, and requires a 4xx plus an unchanged hash of every table. `TestEveryRouteRefusesADeadCredential` calls every route with each dead credential state (suspended or deleted user, expired or revoked session, revoked or expired PAT, revoked or suspended machine identity, machine token of a deleted project), cold and cache-warm, and requires a 401 and no state change. Public routes and self-service writes are explicit, commented allowlists, so a new route has to be classified.
- **Real-backend spec for suspend + clear synced copies + expired.** `web/e2e/real/suspend-clear-synced-copies-expired.spec.ts` covers the case #3215 left out: a secret suspended with the clear choice that then expires keeps the `clear_synced_copies` marker on its `SecretExpired` refusal, never returns the value, and the suspend stays in the audit log.
- **Lever-2 fold follow-ups.** The folded machine-credential cross-replica test gains a classification-change case (a secret turning `restricted` under the restricted-read gate is refused on a warm folded replica exactly as on a cold one), and `credential_read_fold.go` documents that the fold also needs the secret in the replica's node cache (REVIEW-LEVER2, accepted). No behaviour change.
- **Refusal docs guard.** `internal/refusaldocs` fails when a message text documented on the start-up refusals page no longer exists in the Go sources, and logs (does not fail) the refusals in the boot path that the page does not cover yet.
- `TestAuthorizeSecretsBatch_EqualsPerRow` runs its read-only comparison sweeps on four workers and pins the size of its matrix, so it is faster in CI and cannot shrink silently.
- **Static ACL-gate guards moved to `server/httpguards`.** The three go/ast guards
  `secret_acl_gate_guard_test.go`, `grant_primitive_gate_table_test.go` and
  `share_secret_isgroup_guard_test.go` moved unchanged out of `server/http` into a
  test-only package. Their path literals (`internal/core/`, `internal/storage`, ...)
  made the merge queue's selector run all six `server/http` legs for any
  `internal/core` or `internal/storage` change; a core test-file edit now runs 7 legs
  instead of 13. Closure row `AUTHZ-GUARDS-3423` names the new package.
- **`TestOwedAuditOracle_SweepEveryScopedOp` reuses one world pair per op instead of two fresh worlds per case.** Same cases, same assertions; `TestOwedAuditOracle_SweepReuseMatchesFreshWorlds` checks case by case that the reused worlds reach the same verdict as fresh ones. Two soundness gaps in the shared world reuse (also used by `FuzzStorageFaultOperations`) are fixed on the way: reused worlds had no SCIM routes, and a reset kept the previous iteration's `LocalStorage` caches (audit-chain head, row-id caches) across the table wipe.
- A static guard (`TestNoDirectBufioOverStdin`) fails on `bufio.NewReader(os.Stdin)` / `bufio.NewScanner(os.Stdin)` anywhere in `cli/cmd` but `stdin_reader.go`, so a new prompt cannot bring back the lost-buffered-input bug (#3448, #4126).
- The CLI MFA login journey covers a piped login (username and password on stdin, code in `KEYORIX_MFA_CODE`).
- **OpenAPI drift exemptions are narrowed to (path, message kind) (#2868).** An `ALLOW` entry used to silence every check on its path; it now silences only the one message kind it names, and an exemption that matched nothing, or matched a different message, fails the test.
- **Membership and grant routes must pass the request's machine actor to core.** A new guard in `internal/core/guards` fails when a REST handler calls a core method that takes `actorIsMachine` (or a machine identity ID) with anything other than the request's own actor kind.
- gRPC group RPCs: a test now pins that a storage fault whose text says "not found" still answers `Internal` with the static message, never `NotFound`, through the real handlers (GetGroup, UpdateGroup, DeleteGroup, AddGroupMember). The missing-group `NotFound` case, the SCIM Groups member-read 500 and the lost invitation-accept race (account removed) were already fixed and tested on main.
- **The MFA-reset cross-replica, login-budget and project MFA toggle tests run on the production SQLite dialect.** `mfa_reset_cross_replica_test.go`, `login_budget_count_failures_test.go` and `project_mfa_toggle_http_test.go` use `internal/storage/sqlitedialect` and are removed from the `TestNoNewDriverSqliteTestImports` allowlist. No assertion needed changing.
- **Storage-fault oracle (h): a lookup fault is never answered with a verdict (#3457).** The fault fuzzer now classifies a 401/403 (gRPC Unauthenticated/PermissionDenied) answer to an injected fault on a credential or permission lookup as a misclassification; the #3326 bug (a database outage answered valid credentials with 401) is red against the commit before its fix. Faults on those lookups are armed with an outage-shaped error, since the permission classifier deliberately keeps an unrecognised error a denial. Only the reviewed post-verdict login rows are exempt.
- **Folded credential re-check in the auth-cache differential (#3454).** `FuzzAuthCacheDifferential` compares a machine-token secret read served from the token cache with the credential-read fold, without it, and with the cache entry forced out; the HTTP fold test gains a credential-relabel case. No behaviour change.
- **The credential-lookup GORM fallback is reached by a test (#3464).** `TestCredentialLookup_TxScopedFallback` runs the lookup on a transaction-scoped store, under `-tags nplus1` too.
- **Journey 24: the release-binary golden path on the secure baseline.** `TestJourney_ReleaseBinaryGoldenPath` installs the way a customer does, with no `--dev`: `admin generate-secrets`, TLS with the generated certificate, `keyorix system init`, TOTP MFA through the CLI. It then walks teams and projects, least privilege through group roles, the secret lifecycle, a CI machine identity (CLI, `keyorix run`, HTTP), audit search/export/verify, and backup plus restore onto a fresh host directory. SQLite on every PR (`make e2e-journeys`), PostgreSQL when `KEYORIX_TEST_PG_DSN` is set. The only CLI journey on the TLS baseline (DEMO-1).
- **`check.sh` no longer reports NOT READY on a healthy demo.** The real-backend Compliance spec hardcoded `0 / 3` for the "Unclassified secrets" tile; the seed has 13 secrets, so the pre-demo readiness check failed (and skipped the rest of the UI walk) on a correct install. It now asserts zero unclassified whatever the seed total is.
- **`scripts/demo/check.sh` runs the documented break-glass commands.** `scripts/demo/golden-path-breakglass.sh` extracts them from `docs/demo/GOLDEN-PATH.md` (like the section 7 backup/restore guard), runs them with the CLI as the right user, and requires the list to show the activation, the revoke to end it, and the audit trail to record `break_glass.activated`, `break_glass.revoked`, `role.assigned` and `role.removed`, so the doc and the test cannot drift. It fails if the section drops the commands or goes back to project 1.
- **Request-side MFA-reset audit outage test.** `TestRequestMFAReset_AuditOutage_SharedAuditUnavailable503` joins the approve one: a request whose audit row the audit log refuses answers 503 `audit_unavailable` and records no request.
- **The renamed-settings table in `docs/CONFIGURATION.md` is now checked in both directions.** A row for an alias that is no longer in the registry fails `TestConfigurationDoc_AliasTableHasNoStaleRows`, in addition to the existing check that every registry alias has a row.
- **The recovery drills now run on PostgreSQL, and say so when a leg is skipped.** `accept-loss.sh` (never run with `DRILL_BACKEND=postgres` before) and every other drill under `scripts/drills/` were run against a real PostgreSQL database. Without a `psql` client the drills use `scripts/drills/tools/pgsql.go`. A leg a backend does not cover prints `SKIP <backend>: <reason>` and the drill goes on; `DRILL_BACKEND=postgres` with no database file prints `SKIP postgres: ...` and exits 0; a failed check exits non-zero. `scripts/drills/README.md` lists each drill, its backends, run time and what it proves. `TestDrillScripts_BackendSwitchHasPostgresBranch` fails on a drill with a SQLite switch and no PostgreSQL branch or SKIP line, on a hand-written "skipped" message, and on a drill missing from the README.
- **ARM cross-build.** `scripts/edge/cross-build.sh` builds every shipped component (server full and air-gapped, CLI, `migrate`, operator, `keyorix-k8s-sync`, `keyorix-mcp`) for `linux/arm64` and `linux/arm` (GOARM=7) with `CGO_ENABLED=0`; `deploy/edge/arm_build_test.go` keeps the three packages above compiling for those targets. Compile and link only: running on ARM is pending. The footprint budget gained `linux/arm` binary-size rows.
- **Edge crash soak.** `scripts/edge/crash-soak.sh` and `server/edge_crash_soak_integration_test.go` run the built server on SQLite under mixed writes, `kill -9` it at random points (including during start-up), restart it unattended, and check that it recovers with no manual step, no acknowledged write is lost, `admin verify-audit` stays valid and every acknowledged value disclosure has its audit row. It also reports that the audit row of an acknowledged create/update/delete can be missing after a crash (written after the commit); `--strict-mutation-audit` turns that into a failure.
- **Edge footprint guard.** `server/edge_footprint_test.go` and `scripts/edge/footprint.sh` measure the release server binary (full and air-gapped profiles, per platform) and the peak memory of a started, idle SQLite server, and fail above a budget kept in `scripts/edge/footprint-budget.tsv` (about 20% over the value when the guard was added). `--print` emits current values as budget rows; platforms without a measured memory baseline are skipped with a message.
- **Clock-skew tests for the edge.** Injected-clock tests pin how TOTP, the second-factor challenge guard, secret value reads, sessions, PATs and leases behave across forward and backward clock steps (including the limits an operator must know about), and an audit-chain test pins that timestamps going backwards do not affect verification while a rewritten timestamp still does.
- **Stuck-state tests for unattended devices.** `server/edge_unattended_integration_test.go` drives the built binary through stale (and corrupted) lock files after `kill -9`, `admin migrate` and server start-up killed mid-migration at random points, and a full data volume then freed (writes and value reads fail with an error, nothing acknowledged is lost, restart recovers).
- **ARM static-binary guard.** `scripts/edge/crossbuild-check.sh` builds the server and the CLI for `linux/arm64` and `linux/arm` (armv7) with `CGO_ENABLED=0` and fails if a non-stdlib dependency imports `"C"` or the result is not a static pure-Go build. `--self-test` proves it fails on a cgo package. Cross-compile only; running on ARM hardware is not covered.
- **Footprint tripwire for the CLI and idle memory.** `scripts/ci/footprint-check.sh` compares the release server and CLI binary sizes and the idle peak RSS of a secure-baseline SQLite server (3 runs after 30 s idle, maximum compared) with `scripts/ci/footprint-budget.json`, exits non-zero with current vs budget on a breach, and ships a red/green `--self-test`. It complements `scripts/edge/footprint.sh`.
- **Webhook delivery log regression test.** A failed delivery to a generic webhook whose URL carries a path token never logs the token, for a transport error, a retried 5xx and a permanent 4xx. The leak itself (#3426) was already fixed on main.
- `TestFakeClockExtremes_Cross` derives its encryption key once instead of once per program, and now fails if any program of the cross product does not run.
- `TestMFAResetOpsFaultSweep` keeps each world's encryption key across resets instead of deriving a new one for every input, and its input set is pinned by a committed manifest.
- **`GODEBUG=fips140=only` results for the main packages** are recorded in `docs/design/fips140-only-observations.md`, with the date and commit they were observed at. Tests that only fail under that mode because of their fixtures skip there and give the reason. Production refusals are listed as open items, not fixed or hidden.
- **Handler and operator tests are safe under `-count>1`; the journeys target has timeout headroom.** The shared in-memory core the `server/http/handlers` auth tests use now starts every test with an empty `login_attempts` table, so repeated runs no longer fill the per-IP login budget and answer 429 (24 tests failed at `-count=3`); `TestCloseAccessReviewCampaign_HappyPath` uses a campaign id no other test creates, and the secret-template unit tests no longer write a stray `stunit` SQLite file into the package directory once their counter passes 9. The production login limit and window are untouched. The operator's `TestSetupController_SetsMaxConcurrentReconciles` skips controller-name validation on its own test manager only, so building the `keyorixsecret` controller twice no longer fails. `make e2e-journeys` runs with `-timeout 600s` instead of 300s: the suite takes about 285s on CI, which left 15s of headroom (a timeout detects hangs, it is not a test tolerance).
- **Config-space campaign tool is unit-tested.** `scripts/fuzzing/configspace` had 31% statement coverage because only an opt-in campaign (`CONFIGSPACE_RUN=1`, needs a built server) exercised its checks; the invariant checks, case rendering, process stage (against a stand-in server script) and the campaign loop now run in plain `go test`, which brings the main coverage floor back above 80%.
- **The storage-fault harness captures logs in a locked buffer.** `TestUndeliveredSessionSweep` failed under `-race`: the access-log writer and a detached `log.Printf` wrote to the same unsynchronized `bytes.Buffer` that `runOneFuzzIterationReporting` installed as the log output.
- **FuzzCrossReplicaOps oracle (c) now uses the real commit order.** It used to sort successful role grant/revoke and rotate writes by client Return time, but a grant commits before its audit write and advisory-lock release. So a grant that committed first could return after a revoke on the other replica, and the oracle flagged the correct final state (FLAKE-CROSSREPLICA-1). Role-grant now replays the forced grant/revoke alternation, plus a porcupine compare-and-set check over successes, refusals and the final read. Rotate now orders by `version_number` and checks no lost update, no phantom version, real-time order and the final value. `cross_replica_ops_oracle_test.go` runs without Postgres: it shows the CI history is accepted and planted lost updates and stale reads are rejected.
- **A fixed known finding no longer ejects an unrelated PR from the merge queue.** New
  `guardrules.KnownFindingClosed`: the four tests that pin "bug X still exists" (backend
  differential A, `knownWipeGaps`, `machineGranterTagExempt`, `knownUnauditedOperations`)
  log `FINDING CLOSED` on pull_request and merge-queue runs and fail only under
  `KEYORIX_GUARD_ROLLOUT=enforce` (main push, nightly). Behaviour while the bug is present
  is unchanged.
- The invariants-index guard now quotes the duplicate or second **Total** row and the
  column sums to keep; the edge unattended tests print the server log tail with an
  unexpected status.
- The crash-recovery fuzz harness no longer loses a directory change made just before the child exits, and `TestRunChild_RecordsChangeWindow` no longer depends on poller scheduling.
- **`TestLease_AnchoredAtPollSend` no longer depends on a wall-clock window.** It holds the lock until released and checks the anchor with an injected clock moved during the poll's lock wait (it flaked in the merge queue on loaded runners).
- **Postgres tests that take a database-wide advisory lock run on their own database.** The audit list plan test (#3295), core's audit page test and the KEYAUDIT purge test used schemas of the shared CI database, where another package's test could hold the same lock. Lock-holder counts on `pg_locks` are scoped to the test's database. `TestSharedDatabaseLockGuard` keeps both from coming back.
- **The Postgres savepoint tests no longer lose log lines to each other** (#2870): their capture of the global logger is serialized.
- **The solewriter one-fenced-write tests wait for the trigger-integrity check's first pass to end.** `TestTracker_GrantWithItsAuditRowIsOneFencedWrite` failed on main's push CI with "expected 4, actual 5": the check's first pass runs in the background right after the store is built, and its rolled-back catalog read was misclassified by the tracker as a fenced write (a `;` inside a string literal, #3978), so one could land inside the transaction under test. It reproduced 40 of 40 runs with `-cpu 1` on real Postgres. `LocalStorage.WaitTriggerIntegrityFirstPass` now reports when that pass has ended (or the check was stopped) and the fixture waits for it; the assertions are unchanged.
- **Metamorphic backup/restore round-trip fuzzer.** New `FuzzBackupRestoreRoundTrip`
  (`server/admin`) drives a bounded, fuzz-byte-driven sequence of real core mutations
  (projects, secrets, versions, roles, machine identities, deletes) onto a seeded,
  encrypted store, then exercises the ordinary `admin backup` → `admin restore`
  (fresh-dir, real startup path) → re-backup cycle on the resulting arbitrary state and
  asserts six oracles: logical-state equality `restore(backup(S)) == S` (minus documented
  exclusions), every secret version still decrypts to its original plaintext under the
  restored key files, the restore's verify-audit reports VALID, idempotence
  `backup(restore(backup(S))) == backup(S)`, and that any refusal is an explicit error
  rather than silent corruption. Runs on SQLite always and on PostgreSQL when
  `KEYORIX_TEST_PG_DSN` is set (isolated `bk_<pid>_<n>` databases, dropped on cleanup).
  Complements the malformed-archive reader fuzzers and the crash-point/killed-rotation
  tests, which never fuzzed the ordinary cycle on arbitrary states. Guards
  `INV-ADMIN-backup-restore-roundtrip-preserves-logical-state`.
- **Canary leak fuzz targets for PostgreSQL.** Plant a canary secret and assert it never appears in errors, logs, stdout/stderr, metrics, DB error DETAIL, gRPC status or HTTP bodies/headers, across core, HTTP, gRPC, panic-dump and CLI paths. The PostgreSQL-backed targets skip without `KEYORIX_TEST_PG_DSN`, or when the role may not `SET session_replication_role` (they fail under `CI=true`); the SQLite-backed targets run in the default test run.
- **PostgreSQL leg of the process-death crash fuzzer.** `FuzzProcessCrashRecoveryPG` kills the process (and cuts the connection) at fuzzed points during encryption rotation, backup and restore against real PostgreSQL, recovers with documented commands only and checks whole-install invariants; red-proofs cover the migration schema oracle. Registered in `scripts/fuzzing/targets.conf`.
- Pre-registered a grammar-vs-byte-level fuzzing measurement (coverage growth and
  time-to-planted-defect across the DER, PKCS7 and SAML-XML target pairs); see the
  campaign report for the fixed rule and results.
- **Fuzz coverage for the Kubernetes operator & `internal/k8ssync` authorization
  boundary.** New fuzz targets exercise the controls that keep a namespace-scoped
  tenant — who can only create a `KeyorixSecret` custom resource or a sync config —
  from reading or writing secrets outside its scope: `FuzzValidateServer` and
  `FuzzValidateClientBaseURL` (operator confused-deputy / cleartext-token gates),
  `FuzzReconcileAuthzBoundary` (full reconcile against a controller-runtime fake API —
  namespace-scope, cross-tenant Secret integrity, and a secret-value canary that must
  never reach `.status`/Events/errors), `FuzzReconcileHostileK8sAPI` (the same reconcile
  under adversarial apiserver responses — injected Conflict/NotFound/ServerTimeout and an
  oversized token-sharing peer set — asserting no panic, bounded upstream fan-out, and no
  cross-tenant write or canary leak), and `FuzzValidateKeyorixURL` / `FuzzConfigValidate`
  (the `internal/k8ssync` sync-config transport & scope gates). Test-only; no production
  behaviour change.
- **FuzzStorageFaultOperations seeds now use the stable v2 encoding.** All 88 committed seeds address their operation and storage method by name hash instead of list index, so adding a storage method or an operation no longer silently re-points them (83 of 88 legacy seeds already decoded to a different method). Each seed was re-encoded to the target it was written for, recovered from git history and pinned by `TestSeedMigration_V2TargetsSameOperationAsLegacyUnderOriginalLists`; `TestSeedV2_AppendingToInterfaceOrCatalogDoesNotChangeDecoding` guards the stability property.
- **Storage-interface differential fuzzer.** `FuzzStorageIfaceDifferential` drives the same operation sequences through SQLite and PostgreSQL storage and compares results; `FuzzStorageIfaceMetamorphicSQLite` checks metamorphic relations on SQLite. Both are registered in `scripts/fuzzing/targets.conf`. Chunk runs found no divergence; one finding (audit resource-type LIKE case) is recorded in docs.
- **Deeper hostile-SERVER fuzz coverage of the third-party database drivers used against
  operator-configured targets.** New loopback harnesses drive the real pgx/v5,
  go-sql-driver/mysql and go-redis/v9 clients — exactly as the dynamic-secrets and
  rotation engines do — against a fuzzer-controlled server, with sound oracles: no panic
  escapes the driver's documented error path, bounded time/memory per hostile reply, and
  no credential reaches a host other than the configured one. Adds MySQL handshake/auth,
  COM_QUERY and prepared-statement response coverage plus a LOCAL INFILE refusal oracle
  (red/green); pgx COPY-subprotocol, NoticeResponse-flood and TLS-negotiation coverage;
  and go-redis ASK- and Sentinel-redirect egress red proofs alongside the existing MOVED
  one. All new targets are registered under `scripts/fuzzing/targets.d/`.
- **Skip-version upgrade fuzzers for SQLite and PostgreSQL.** `FuzzUpgradeFromOldSchema` and `FuzzUpgradeInterrupted` (and their `PG` variants, PG-gated) start from real snapshots of releases v0.91.0 to v0.96.3, apply the migrations (also interrupted midway), and check that secrets still decrypt, authorization is unchanged, the audit chain is intact and the schema matches a fresh install. Findings are in `docs/findings/`; the v0.91.0 interrupted-upgrade artifact is reproducible only on the unlocked path.
- **Wire-protocol fuzzing of the server transport (B1).** New `server/wirefuzz`
  package stands the real stack (router + auth middleware + handlers + core +
  storage, and the real gRPC server with its full interceptor chain) up in-process
  on loopback listeners and feeds RAW bytes to the production HTTP/1.1 parser, the
  HTTP/2 framers (grpc-go's and net/http's own, the latter over TLS with ALPN
  "h2") and the gRPC message framing — surface no existing fuzzer reached (they all
  drive `router.ServeHTTP` via `httptest`, bypassing the wire). Targets:
  `FuzzWireHTTP1` (a structured lane of fixed framing variants with a body-embedded
  smuggling canary, plus a raw lane where fuzz bytes become Content-Length deltas
  and odd forms, chunk-size tokens, line terminators, TE values, a raw header and a
  verbatim tail), `FuzzWireHTTP2` (pseudo-header abuse, CONTINUATION chains,
  RST/SETTINGS/PRIORITY/WINDOW_UPDATE abuse, valid gRPC bodies for either secret),
  `FuzzWireGRPCFraming` (length-prefix abuse incl. a 4 GiB pre-alloc probe, plus a
  valid-message shape) and `FuzzWireHTTP2TLS`. Oracles: no panic/hang/bounded
  allocation; handler-count smuggling and a never-dispatched body canary
  (HTTP/1 structured lane); per-request (HTTP/1) and per-stream (HTTP/2) authz/leak
  invariance, so a secret returned to a request or stream that carried no
  authorizing credential is caught even when another request on the same connection
  carried one; no response splitting on encoded CRLF payloads placed in reflectable
  positions; and a post-abuse health probe that makes a fresh connection complete a
  real request. Drivers never half-close before reading (a FIN makes net/http cancel
  the request, so every token-bearing request fails closed with 503 and the leak
  oracle would never see an authorized response). Each target has an anti-vacuity
  test (an admin read of A returns A, the projA reader's read of B is denied) and a
  planted-leak red twin through the same driver; every oracle predicate, the
  allocation oracle and the health probes (including a listener that accepts but
  never serves) have committed red/green proofs in `oracle_redproof_test.go` and
  `anti_vacuity_test.go`. Declared in `scripts/fuzzing/targets.d/`.
- **Six stale UNGUARDED invariants now name the guards that already close them.** INV-CLI-03 and INV-CLI-06 (`cli/internal/depguard`, `cli/internal/clientguard`), INV-GRPC-05 and INV-GRPC-07 (`server/grpc/proto_reserved_fields_test.go`, `auth_interceptor_completeness_test.go`), INV-MW-06 (`cache_hit_fresh_allowlist_test.go`) and INV-CORE-29 (`purge_independence_test.go`) were each guarded on main already; the invariant text and the `docs/INVARIANTS.md` counts now say so. No new tests.
- **Guards for two reports that were already fixed on main: `RevokeShare` with a panicking notifier answers success (#3350, `INV-CORE-34`), and a self-replacement of the actor's own role set whose commit 2 ceiling read faults is a retry-safe partial mutation (#3938).** The second adds a test for the self-replace variant; no production change.
- **Web image floors are checked in PR CI.** `deploy/web_dockerfile_floors_test.go` fails a malformed (unquoted, exact-pinned or release-less) or unsorted floor in `web/Dockerfile`'s `apk add --upgrade` line, instead of the nightly trivy gate finding it a day later.
- **`INSTALL-WITH-AI.md` guards tightened.** The secret-read rule is an allowlist of non-reading commands (an unknown command naming a secret path fails), and the page's pinned release must not be older than the newest release in `CHANGELOG.md`.
- **`TestInstallWithAIIsSecretBlind` (internal/docsdrift).** Checks every assistant-run line of INSTALL-WITH-AI.md. No line reads a secret file. No line runs `mfa enroll`, `mfa activate` or `recovery-key rotate` without `--recipient` outside a HUMAN STEP. No line sets a plain `KEYORIX_*` secret variable. Every `keyorix` and `keyorix-server` line is spelled so the command-tree checks resolve it. Both install paths end with `admin validate --posture`, and the prompt keeps its rules. A calibration test plants each violation. The page is also added to the env-var, secret-flag, chmod, link and `keyorix-server` command checks.
- `go test ./internal/statemap` (`TestInvariantDocs_IndexListsEveryFragmentArea`, report-only on pull requests until its first green nightly on main) now flags when a package has an `INVARIANTS.d/` directory but `docs/INVARIANTS.md` has no row linking its `INVARIANTS.md`, so a new invariant area can no longer be left out of the index.
- **`TestInvariantsIndexHasNoDuplicateRowsAndTotalsAddUp` no longer skips table rows it cannot match.** A line of the `docs/INVARIANTS.md` counts table that is neither the header, the separator, a package row nor the Total row is now reported (it used to be left out of the sums without a word), and the doc comment states what the test does not check. A calibration test plants malformed rows into an in-memory copy of the real table.
- **`familycheck` finds the marker in the original PR body.** Lower-casing the body first shifted byte offsets when a non-ASCII letter preceded the marker, so a valid `family-check: intentional` line was missed or its reason mangled; the `hasMarker` doc comment and README now describe the first-marker-line behaviour accurately, and `devtools/familycheck/marker_test.go` pins both.
- **`docs/INVARIANTS.md` "Highest-priority UNGUARDED gaps" refreshed.** INV-CLI-11 and INV-ENCRYPTION-25 are guarded and re-run green; the RLS layer (INV-STORAGE-31/32) and the `openapi.yaml`-only CI gap (INV-WEB-05) remain.
- `scripts/k8s-e2e/run.sh` gains journey J6 for `secureBaseline.existingSecret` on a real kind cluster: install with a pre-created Secret and two upgrades leave the Secret, certificates and pods unchanged (nothing generated, nothing rolled), and a Secret missing a key fails the upgrade naming it with no PEM in the error. `KEYORIX_K8S_E2E_ONLY=j6` runs it alone; new `scripts/k8s-e2e/README.md`.
- **Dynamic-secret lease: a renewal racing a revoke whose target drop failed keeps the lease `revoke_failed` with its original expiry (#2698).** New `TestCTAReview_RenewLease_vs_RevokeFailed_*` (SQLite and Postgres); the `UpdateDynamicSecretLease` full-row write ledger row moves from UNSAFE-OPEN to FIXED-NO-CALLER (the code fix landed in #2825).
- **`scripts/migrate/sqlite-to-pg-check.sh`**: seeds a SQLite instance (more than 10,000 audit events, a retention purge, MFA users, deleted and suspended secrets, machine tokens, a dynamic-secret config, break-glass history), migrates it with `admin backup` / `admin restore`, compares every table by row count and checksum, and exercises logins, decryption, the audit chain and `kill -9` of a restore at two points.
- **Journeys wait for the server's SQLite write lock (#3683).** The customer journeys that edit the live server's database (a trigger that makes the audit log refuse rows) ran `sqlite3` with its default busy timeout of 0, so a statement that met the server's own write failed at once with "database is locked". Every journey now runs `sqlite3` through one helper that waits as long as the server's own connections do (10 s), and `TestJourneysRunSQLiteOnlyThroughHelper` keeps a bare `sqlite3` out of the journeys.
- **A route the e2e smoke never calls now fails on the pull request.** `TestEveryRouteHasAnE2ESmokeCallOrSkip` (server/http) reads the smoke driver's sources and fails when a route in `router.go` is neither called by `scripts/e2e` nor in its `skipList`, or a `skipList` entry matches no route. Until now only `TestAPISmoke_SQLite`, which runs in the merge queue alone, found this, after a full queue round.
- **Test worlds built through the production storage factory use a SQLite file, not a shared-cache in-memory database.** Two replicas (or one 8-connection pool) on `cache=shared` collide on SQLite's table locks and fail writes with "database table is locked (262)" at once, past any busy timeout; the dead-credential walk failed in the merge queue on this. `sqlitetest.FactoryPath` gives such tests a file (WAL, the production shape), and `TestFactoryConfigsNeverUseSharedCacheDSN` keeps `sqlitetest.DSN` out of a factory `database.path`.
- **internal/crypto mutation efficacy 88.2% to 98.8%.** New boundary tests for the KMS providers, Shamir, the multi-provider chain and the exec/file providers kill 36 of the gremlins survivors from #3612; the rest are listed with reasons in `internal/crypto/mutation_equivalents_test.go`. Test-only, no production change.
- **Mutation testing widened to six more security packages.** `internal/netutil`, `internal/auditverify` (with `anchorbundle`), `internal/serverguard`, `internal/solewriter`, `internal/core/rules` and `internal/identity` are in `scripts/mutation-testing/run-mutation.sh` with an efficacy floor each (100, 99.55, 100, 99.26, 98.06, 100 percent), and the tests that kill every killable surviving mutant are added. The survivors that remain are equivalent mutants, listed in the script. `internal/backupfmt` is not included yet.
- **Pinned the notification-channel SSRF guards (#3427).** `noEscalationRedirect` (a receiver answering 302 to a second host gets refused and the second host receives nothing) and the resolve-and-check loop of `validateWebhookURL` (a hostname resolving to `10.0.0.5` is refused on create and update, a resolve failure is refused) each have a test that goes red when the guard is removed.
- **Stateful OpenAPI fuzzer: record a second known undeclared success status.** `POST /api/v1/folders` returns 201 while `openapi.yaml` declares only 200, the same class as the already-recorded secret-template case. The fuzzer now logs it as a known finding instead of failing unrelated per-PR fuzz shards when it happens to create a folder. The spec fix remains open.
- **Audited five security fuzz oracles with `oraclehealth`** (PAT restriction algebra,
  AEAD tamper, SSRF encoding-parity, backup-archive path safety, bundle path
  containment). Every survivor was explained as an equivalent/defense-in-depth mutant,
  a property the target intentionally does not assert, or one covered by a sibling
  target or unit test — no unguarded defect found. No test behaviour was changed.
- Every way a credential ends (revoked, rotated, expired, owner suspended or deleted, machine
  identity suspended or revoked, session logged out, revoked or rotated) is now tested to be
  refused on another replica from the first request after the change, on the REST reads and
  gRPC, on SQLite and PostgreSQL, including while the audit log refuses every write
  (`server/http/revocation_after_commit_test.go`).
- Commit-time failure of the pipelined audit commit, and a disabled cache-epoch trigger on the combined secret read path, are now covered against real Postgres.
- **Postgres test helpers and tests no longer print the test DSN's password on failure.** `pgdsn.PGReplaceDBName`'s panic on an unparseable URL DSN is a fixed message with no parse-error detail (a `*url.Error` quotes the whole URL, and its inner error can quote a password prefix when the password holds an unescaped `/` or `#`), and the assertions that compared passwords/DSNs derived from `KEYORIX_TEST_PG_DSN` (or printed the DSN in a failure message) now use fixed messages. Guarded by `TestPGReplaceDBName_PanicMessageHasNoPassword`.
- **Postgres tests that read backend state count only their own backends.** `internal/core` and `internal/storage` run in parallel on one database and tests isolate by schema, which does not separate `pg_stat_activity`: the last-used coalescer's lock-wait probe counted another package's waiter (red in 18 of 30 runs beside a store loop), the cross-replica lock-wait gates could be released by a foreign waiter, and the pipelined-batch `pg_sleep` probe could pick, and terminate, a foreign backend. They now tag their connections (`pgdsn.WithApplicationName`) and filter on `application_name`. `TestSharedDatabaseActivityGuard` fails a test file that queries `pg_stat_activity` or `pg_locks` without such a scope (report-only until the long-reader test is fixed by its own PR). Test-only; no production change.
- **Backup/restore drill.** `scripts/drills/backup-restore.sh` backs up a seeded instance, restores into a fresh SQLite directory or an empty PostgreSQL database, and checks decryption, MFA login, shares, machine tokens, `verify-audit` against an off-host anchor, the recovery point and the refusals (tampered archive, populated target, stale backup). Runbook: `docs/operator/drill-backup-restore.md`.
- **Disaster drills.** `scripts/drills/disaster.sh` rehearses SIGKILL under write load (SQLite and PostgreSQL), a PostgreSQL outage and recovery (via a TCP forwarder, `scripts/drills/tools/tcpproxy.go`) and a full SQLite data directory (`ulimit -f`), checking that acknowledged writes survive, the server recovers or fails closed with a clear message, no secret value is disclosed without its audit row, and `admin verify-audit` stays VALID. Runbook: `docs/operator/drill-disaster.md`.
- **Key rotation drill.** `scripts/drills/key-rotation.sh` rehearses DEK rotation (dry run, refusal beside a live server, SIGKILL during the sweep), KEK rotation (old passphrase refused, pre-rotation archive still restores) and `migrate-provider` password to file and back, on SQLite and PostgreSQL, checking data, logins, tokens and the audit chain after each step. Runbook: `docs/operator/j6-key-rotation.md`.
- **Upgrade drill.** `scripts/drills/upgrade.sh` seeds an old release (users with MFA, secrets with versions, a share, a machine token, audit history), swaps in the build under test and checks that data, logins, tokens and `admin verify-audit` survive, on SQLite and PostgreSQL. Runbook: `docs/operator/drill-upgrade.md`.
- **Two more operational drills.** `scripts/drills/rotation-under-load.sh` runs the documented stop, rotate, start procedure for the DEK while a read/write/delete load generator is running, and `scripts/drills/kill9-soak.sh` kills the server with SIGKILL at random points under the same load (SQLite or PostgreSQL). Both check every acknowledged write, the seeded data and `verify-audit` afterwards. Shared load generator: `scripts/drills/load.sh`.
- **Guards for explicit column reads.** `TestNoStarSelectInProductionSQL` rejects a new `SELECT *`; a Postgres test reproduces the cached-plan failure and proves model reads survive an added column; `go test -tags nplus1` runs the storage and core suites against a schema with an extra column on every table.
- Re-auth grant revocation is now pinned against faults: an audit-write failure or a `GetUser` fault no longer
  can stop the step-up grant purge on suspend, `UpdateUser` deactivation, SCIM update and SCIM deprovision, and a
  faulted use-time account re-check counts toward the lockout like a wrong guess.
- A static guard (`internal/besteffort`) fails if `besteffort.Run` is used inside a `WithTransaction` closure
  (directly, or through a same-package helper such as `purgeStepUpGrants`); the package doc now names the one
  sanctioned in-transaction shape, a nested savepoint step.
- Period-boundary, hard-maximum and large-table plan tests for the five `LastUser*Activity` lookups on SQLite and PostgreSQL, and a guard that every such lookup is listed in the inventory.
- **Documentation drift checks.** `internal/docsdrift` now fails when `docs/UPGRADING.md` has two sections with one number, an empty section, or a reference to a section that does not exist, and when a key of `internal/config` is named in no reference document (a list of 68 older gaps may only shrink). `internal/storage` checks that INV-STORAGE-02 quotes the epoch and floor the code has, and that a v0.96.x epoch is refused on a database this build migrated.
- **Old-release backup restore is now proven against what real released binaries wrote.**
  A fixture generator (`scripts/i6-gen`) runs a released tag's own `admin backup` to emit a
  v2 logical archive plus an old-code canonical sidecar; `TestI6RestoreOldVersion`
  (`server/admin`) restores the v0.96.3 fixture into current `main` on SQLite and PostgreSQL
  and asserts every secret decrypts to its original plaintext, the audit chain verifies VALID,
  roles/grants/counts equal the source, and a re-backup round-trips again.
  `TestI6RestoreOldVersion_CorruptFailsClosed` and the new `FuzzI6OldArchiveMutation`
  (`internal/backupfmt`, seeded with the real old-release archive) assert a corrupted or mutated
  archive fails closed and leaves no partial state (no half-restored database, no key material
  written). New invariants `INV-BACKUPFMT-oldrelease-restore-lossless` and
  `INV-BACKUPFMT-corrupt-restore-fail-closed`.
- **A schema change without a schema-epoch bump fails the build** (`internal/storage/schema_epoch_snapshot_test.go`, snapshots in `internal/storage/testdata/schema_epoch/`).
- **The Helm pod-hardening guard checks every container (#3360).** Container-level `runAsUser: 0` / `runAsNonRoot: false` and any `capabilities.add` beyond `NET_BIND_SERVICE` now fail it, and it is calibrated against the opt-in root `postgresql.migrateOwnership` init container.
- **Review-tail test hardening (REVIEW-LOW-TAILS-1).** The weakened-validator SSRF test now drives the weakened validator through `CreateNotificationChannel` and the weakened-redirect harness covers all five redirect targets; the MFA-reset audit-outage tests assert from the fault-storage call log that exactly one audit row precedes the faulted one; `admin audit accept-loss --help` no longer wraps mid-sentence at `--resume-seal` (with a contains test); `TestBufBreakingIsNotRunInCI` fails if `buf breaking` appears in `.github/workflows`, `scripts/ci` or the `Makefile`, so the ADR-105 conformance row's "not run in CI" claim is updated with it.
- **A project member role change is pinned against a storage fault at the grant.** `TestSetProjectMemberRole_GrantStorageFault_NeverStrandsTheProject` (`internal/core`, SQLite and PostgreSQL) fails `AssignRole` itself, not only the grant's audit row: the sole administrator swapping to another admin-tier role keeps the old role and the project keeps its administrator (one transaction), and a co-administrator's demotion answers a partial-mutation error that names both halves while the other administrator still governs the project. Red on the pre-#3488 shape (the project was left with no administrator), green on main. No behaviour change.
- A structural guard (`cache_publish_sites_guard_test.go`) fails when a function publishes into a read-path cache (secret metadata, role-permission, folded-credential memo) without being registered alongside the test that proves its generation stamp is read before the data (the unfinished part of GUARD-6).
- **#3684 is now driven through every transport that can reach it.** `PUT /api/v1/projects/{id}/members/{self}` that would drop the caller's own `roles.assign` answers 403 with nothing changed (it answered 503 `MutationPartiallyApplied` with `retry_safe: true` before #3840); the same replacement made by another admin still applies; and the HTTP body and the gRPC `ErrorInfo` say `retry_safe: false` when the second commit was refused on the caller's own authority, `true` after a fault. gRPC has no role-set replacement RPC.
- **New `FuzzScheduleInterleavings` concurrency/interleaving fuzzer (`internal/core`).**
  Fuzzes the *order* of concurrent operations on the paths whose correctness
  depends on interleaving — PAT revoke vs validate, secret delete/update vs read,
  role grant/revoke vs authorize, and concurrent audit-chain appends — by running
  2–4 operations goroutine-per-op against one seeded `KeyorixCore`, with a
  per-op `runtime.Gosched()` schedule and a happens-before mode decoded from the
  input. Four oracles, each documenting what it does NOT verify: serial
  equivalence (linearizability of result class + final state over every
  HB-constrained permutation), post-return visibility (a revoked token / deleted
  secret / revoked role is never observed live after the mutation returned),
  audit-chain integrity plus one event per successful synchronously-audited
  operation, and no deadlock / panic / data race under `-race`. Oracles 1–3 are
  pure-function-checked with committed red/green self-tests; a companion
  `TestScheduleInterleavings_Postgres` replays the two-writer schedules against a
  real Postgres pool (`KEYORIX_TEST_PG_DSN`) where goroutine-per-op gets genuine
  DB-level write concurrency. Target registered in `scripts/fuzzing/targets.d/`.
- **Oracle 2 soundness fix (schedule-race fuzzer).** The post-return-visibility
  oracle's role branch flagged `authorize=true` whenever group 1 revoked the role
  and group 2 did not re-grant it — but missed the case where group 1 *itself*
  contains a `grantRole` concurrent with the revoke. Such a grant can legally
  commit last, leaving the role held, so `authorize=true` is serializable (oracle 1
  accepts it). The branch now also skips when group 1 contains a grant, mirroring
  the existing group-2 skip. Regression seed
  `testdata/fuzz/FuzzScheduleInterleavings/b78054a10a72fe74` plus a self-test case
  lock it in; red/green-proved (reverting the guard re-fails both). No production
  code changed — this was a false positive in the fuzz oracle, not a Keyorix
  defect.
- **Postgres replay repetition is now configurable (schedule-race fuzzer).**
  `TestScheduleInterleavings_Postgres` reads `KEYORIX_SCHED_PG_REPS` (default 25
  reps/program) so the replay can be soaked at a higher repetition count to widen
  the set of real Postgres interleavings each two-writer/HB program is observed
  under. Confirmed green at 250 reps/program (2250 total replays, all oracles
  green). Test-only; no production code changed.
- `TestUpgrading6vCheckQuery_FindsOnlySCIMCreatedSSORows` runs the query printed in `docs/UPGRADING.md` against SQLite (always) and PostgreSQL (when `KEYORIX_TEST_PG_DSN` is set).
- **SCIM write routes join the storage-fault sweep.** `POST /scim/v2/Groups` and the four `/scim/v2/Users` operations are in the fault catalog (no longer `StatusPending`), and `TestSCIMOpsFaultSweep` sweeps all eight SCIM write operations on every default run. `TestSCIMGroupErrors_*` pins the `errors.Is` typing of the `DeprovisionSCIMGroup` and `PatchSCIMGroup` refusals.
- **Postgres-run mutation survivors in `internal/serverguard` killed, and the terminal-prompt branches of `internal/crypto` get tests.** Against a real PostgreSQL, serverguard's mutation efficacy goes from 88.89% to 98.41%: the presence and exclusive lock release path (a healthy release logs nothing, one whose connection is gone says so, in the session and the pooler-transaction shape) and the error detail of the key-initialisation lock check are now pinned. The one remaining survivor (`keyinit.go:80`) is an equivalent mutant. `internal/crypto` gains pseudo-terminal tests for `readPassphraseStdin`'s terminal-only branches; they skip where no pty can be opened.
- **secretenv: a comment can no longer cite a test that does not exist.** `TestCitedTestsExist` fails when a comment in `internal/secretenv` names a Test function defined nowhere in the repository. It found `describe.go` naming a non-existent `TestDescribeFileCopiesAgree` as the guard for the cli and entrypoint copies of the path formatter; the comments now name the real tests. `TestRefusalPathsCloseTheDescriptor` pins that each refusal after a secret file is opened (directory, FIFO, too open, empty, oversized, snapshot) closes the descriptor.
- **Renamed-settings table cannot drift.** `TestConfigurationDoc_ListsEveryDeprecatedAlias` derives the alias list from `config.DeprecatedSettingAliasPaths()` and requires each pair as a row in docs/CONFIGURATION.md.
- **Security-relevant SQLite tests now run on the production dialect (#3685).** The login-completion identical-response tests and 12 further test files (core rollback, authz, SCIM error typing, suspend races, upgrade migrations, store principal permissions and purge, gRPC machine attribution) open their in-memory or file database through `internal/storage/sqlitedialect` (modernc plus the repo's error translator) instead of `gorm.io/driver/sqlite`. One driver difference surfaced: a non-UTC fixed-zone timestamp scans back as a string on modernc, so `credential_lookup_raw_times_test.go` stays on the other driver until that is decided.
- **New guard `TestNoNewDriverSqliteTestImports`.** A `_test.go` file that imports `gorm.io/driver/sqlite` and is not on `internal/testutil/sqlitetest/driver_import_allowlist.tsv` (one reason per row) fails the test. It starts report-only (`docs/guard-rollout.d/`).
- **DEK sweep vs. read-path value cache.** The named gap (a DEK rotation sweep rewrites `secret_versions.encrypted_value` without moving the latest-version cache generation) is now pinned by a test, including a two-replica case, the retired-DEK case and the TTL bound, and documented as safe (same plaintext for the only holder of the entry; fail closed for a new-key-only holder). No behaviour change.
- **No new hand-written shared-cache SQLite DSNs.** The remaining `cache=shared` literals in the internal/storage, internal/config and internal/core tests, plus the raw `:memory:` pools in three server/http tests, now go through `internal/testutil/sqlitetest`. `TestNoNewSharedCacheLiterals` fails `go test` on any new `cache=shared` literal outside its allowlist, and the allowlist can only shrink.
- **FuzzStorageFaultOperations corpus is v2 only.** `TestCommittedSeeds_AreAllV2` refuses a committed legacy, index-addressed seed, which would re-point with the next storage method.
- **Schema-diff guard for the upgrade path.** `TestSchemaParity_FreshVsUpgrade_{SQLite,Postgres}`
  build a fresh AutoMigrate database and one upgraded from v0.93.0 through the real boot
  path, and compare tables, columns (type, nullability, default), indexes (name, columns,
  uniqueness) and triggers, with a commented allowlist whose stale entries fail. It
  reports the pre-#4100 missing `idx_break_glass_activations_reviewed_by` (#4091).
- **Removed 63 Go tests that duplicated another test in the same package line for line,** plus one test that only skipped, for a reason that no longer holds (SearchUsers on SQLite). The copy that stays is in the descriptively named file or the earlier coverage wave. Tests cited by security closures or INVARIANTS docs were kept even when duplicated.
- **Removed six Go tests that were byte-for-byte copies of another test in the same package** (found by hashing every test body). The original of each stays. No coverage change.
- **RBAC fixtures grant project roles at a project.** The `RBACTestHelper`-based tests in `internal/core` no longer grant the install-wide legacy roles (`admin`, `editor`, `viewer`, `auditor`) at a project, a state a real install cannot reach since #3605; they use `project_admin`, `project_developer` and `project_viewer`. Where a test asserts on a bundle difference (`project_developer` also deletes, `project_auditor` reads secrets) it uses the new `RBACTestHelper.CreateProjectRoleWithPermissions` to keep the legacy bundle as a project-tier role. Assertions are unchanged.
- **Test reliability (TEST-RELIABILITY-2).** The gRPC interceptor tests no longer share the per-IP failed-auth limiter across tests and `-count` repeats (#2945); `fuzzutil.Guard` reuses a runner goroutine and timer per call instead of spawning a goroutine and a 3s timer (#2431).
- Test runs no longer leave temp files behind: `server` removes its ~99 MB shared `keyorix-server` test binary directory and `internal/auditverify` removes its 1M-row bench fixture when the package's tests finish. A new static guard (`TestNoTestLeaksTempResources`) fails when a `*_test.go` declaration calls `os.MkdirTemp`/`os.CreateTemp` without cleanup (TEST-TMP-LEAK-1).
- **Threat-model Evidence cells are machine-checked.** `go test ./internal/threatmodelcheck` fails when a cell cites a file, a `Test`/`Fuzz` function or an identifier that does not exist, when a threat-model document is not indexed in the README, and, for new documents, when a row cites no test. It checks existence only; it does not check that the cited test proves the mitigation.
- **TLS termination & certificate-lifecycle fuzzing.** Added three fuzz harnesses
  covering the HTTP and gRPC TLS listeners: `FuzzReloaderFailClosed`
  (`internal/tlsreload`) drives the certificate reloader through valid/expired/
  not-yet-valid/mismatched/half-rotated/truncated/empty/deleted/symlink-swapped
  cert-key file states and asserts it never serves a cert/key mismatch, never an
  empty config, and always keeps the previous good certificate on a bad reload;
  `FuzzTLSHandshakeHostileClientHello` (`server`) throws hostile ClientHello bytes
  at the real hardened HTTPS listener and asserts no panic, fail-closed connection
  close within the read deadline, and that failed handshakes never reach the HTTP
  handler; `FuzzHTTP2AbusiveFrames` (`server`) plus
  `TestHTTP2Abuse_ServerStaysResponsive` (`server/grpc`) throw abusive HTTP/2
  frames (rapid reset, SETTINGS/PING floods, oversized headers, CONTINUATION
  floods) at the real HTTP and gRPC servers and assert they stay responsive with
  bounded goroutines. Each oracle was red/green-proofed.
- `devtools/familycheck`: extra calibration for the PR-body marker lookup (`marker_lengthshift_test.go`): runes whose lowercase has a different byte length (`İ`, `Ⱥ`) before the marker, including the two fail-open directions, must not move the line that is checked for the family name.
- `server/grpc/proto_reserved_fields_test.go`: the `.proto` source parser behind the reserved-fields guard (INV-GRPC-05) now has a red/green calibration (a removed field number without a `reserved` entry fails, with it passes) and cases for its blind spots. It now ignores block comments and commented-out message headers, understands `reserved N to max;` and field options, errors on an unparseable reserved item, and lists in its doc comment the forms it does not recognise.
- **Test suite is path-independent (`-trimpath` safe).** Tests and test helpers that located source files via `runtime.Caller` now use `internal/testutil/srcpath` (`RepoRoot()`/`PkgDir()`, found from the working directory), so `GOFLAGS=-trimpath go test ./...` passes. A static guard (`TestNoTestOpensFilesViaRuntimeCallerPath`) fails if a new test opens files via a `runtime.Caller` file name.
- **Store time-bind guard and UTC test harness.** `internal/testutil/sqlitetest` now opens databases with the production UTC `NowFunc`. New guard `TestEveryStoreTimeBindIsUTC` (report-only on its first day, `docs/guard-rollout.d/`) fails on a store reader that binds a time argument against a time column without `.UTC()`.
- **Storage-level guard for UTC passkey `last_used_at`, and the default core clock pinned as monotonic.** `TestWebAuthnLastUsedAtStoresUTC` checks that both WebAuthn counter writers store UTC for New York and Kolkata times on SQLite and Postgres (a regression guard for the #3881 fix). Two INV-CORE-09 tests check that `NewKeyorixCore`'s default clock keeps Go's monotonic reading, so the impersonation-ceiling cache TTL is not wall-clock only (UTC-TOUCH-1).
- `TestEveryValidationRefusalIsTyped` now scans the users, versions, env_clone, account, break_glass and access_review files (still report-only through its `docs/guard-rollout.d` row); `TestValidationRefusalStatusCharacterization` pins the REST status and error code of every reachable refusal of these families, in English and under a translated locale.
- **Server-presence polling no longer refuses the server it waits for.** The `server` admin integration tests' `waitForPresence` probed with `serverguard.ProbeRunning`, which takes the presence lock exclusively; on Postgres a probe landing on a starting server's shared try-lock made the server exit with "an admin operation is running", so `TestServerStartup_RefusedWhileAdminHoldsExclusiveLock_Postgres` failed intermittently in the merge queue. On Postgres the poll now reads `pg_locks` and takes no lock; `TestWaitForPresence_Postgres_NeverRefusesAStartingServer` pins it (the old poll refused 116 of 8112 simulated starts).
- **In-process test servers no longer share a spent invalid-token budget.** The per-IP failed-token limiter is process-global and every `server/http` test world dials from the same address, so walks run in one process (a plain `go test ./server/http`, or the merge preflight) could start at 429 "too many invalid token attempts" instead of 401. Each test world now starts with an empty limiter via `middleware.ResetTokenAuthFailureLimiterForTest` (test-only; production burst, refill and call sites unchanged), guarded by `TestNewWorldStartsWithAFreshInvalidTokenBudget`. The `-skip` for `TestEveryRouteRefusesADeadCredential_G[0-3]` in preflight is no longer needed.
- Web: unit cases for the project Settings sections that were hidden but untested (Extend all, Apply renames and the disabled rename inputs, Restore secret, Reassign owner), asserted visible for a permitted session and absent for a viewer.
- Web: test-local `useCan` literals now spread shared `ALL_CAN` / `NO_CAN` defaults (`web/src/test/can.ts`), so they track the `Can` shape.
- Web: a real-backend Playwright spec (`web/e2e/real/permission-gating-surfaces.spec.ts`) for the project Settings tab, the project Access Review tab and the Rotation Policies page: no write control for a project viewer, all of them for the admin.
- **web/src INVARIANTS closed (INV-WEB-01/03/06/07).** INV-WEB-01 (ESLint rule + `eslintGuards.test.ts`), INV-WEB-03 (`sessionTokenNeverPersisted.test.ts`) and INV-WEB-06 (`noNotFoundBranching.test.ts`) were already guarded on main; their invariant text now names the guards and what they do not cover. New `servicesUseApiClient.test.ts` is the INV-WEB-07 sweep: every `web/src/services` file goes through `apiClient`/`authApi`, builds no client of its own, and sends no state-changing call through any other receiver.
- **Web regression tests for #3153, #3142 and #2450.** A contrast guard for the revoke dialog's title in both themes, tests recording that Check Drift, Rotation Plan and the Sharing nav stay offered to a read-only role because the server answers them, and a reveal test showing the secret page never decodes a field the versions endpoint does not return.
- **Dialog contrast guard covers every modal and dialog in the web app.** `dialogContrast.test.tsx` inventories all dialog surfaces (new ones must be registered), renders the shared dialogs, the Sharing revoke dialog, the session-timeout warning and the command palette in both themes, and audits the headings drawn inside modals; planted dialogs (title colour equal to its background, the #3153 fixed dark title) fail it. The per-site confirm tests now assert the API is called exactly once.
- **Reveal and Copy value guard for #2450.** The copy hook test now asserts Copy never reads `/versions` or calls `atob()`, and the real-backend Reveal spec asserts the value comes from `GET /secrets/{id}?include_value=true` with no page error. The Sharing secret names, revoke dialog, transfer-ownership dialog and read-only gating items (#3153, #3142) were re-checked on main and already have unit and real-backend coverage.
- **The split role-change ops are swept with a plain storage fault at the grant.** `TestSplitOps_AssignRoleStorageFault_NeverStrandsAPrincipal` (`server/faultops`) fails `AssignRole` itself, through the real HTTP stack, on `SetUserRoles`, `SetProjectMemberRole` and the membership activation, and reads the database: a project's only administrator keeps the administrator role, a narrowing that stands is answered with the partial-mutation 503 naming both halves, and a membership whose grant failed is put back to its previous state. No behaviour change.

### Internal
- **`scripts/gen-security-closures-tsv.sh` refuses malformed closure fragments.** A fragment in `docs/security-closures.d/` must now be exactly one row on one line: a second row, a field with an embedded newline (a row split across lines) or any carriage return (CRLF) fails `--check` with a message naming the file. The two historical multi-row fragments (`mi-suspend-cachehit`, `ar-revoke-atomic`) were split into one file per claim_id. New `--self-test` (also run by `scripts/check-closures.sh --self-test`) proves each case goes red.
- **CI: the `test-suite` matrix is rebalanced (22 -> 20 legs) and the critical path shortened.** Merge-queue rounds were bounded by `core-1` (tests plus a ~10 min `check-closures.sh` step), `http-3`/`http-7`, `faultops-2` and `root-3` (21-33 min) while `http-1/2/4/5/6` ran 5-7 min on the same round. Packages split by test name (`internal/core`, `server` (new), `server/http`, `server/http/handlers`, `internal/encryption`, `server/faultops`) now share one weighted bin-pack (`weighted_run_filter` in `scripts/ci-test-legs.sh`, per-test CI seconds in `scripts/ci-test-weights.tsv`, regenerated by `scripts/ci/gen-test-weights.py`): `core` is 3 legs, `server` 2 (replacing `root-3`, whose small packages joined `root-2`), `http` 4, `faultops` 3, `storage-store` 1. `check-closures.sh` stays on `core-1` and is counted in that shard's weight. A test the weights file does not know weighs the package average and lands in some shard automatically. `assert-leg-completeness` now proves "every Test/Fuzz name runs in exactly one shard" for every split package (before: only `core` and `faultops`), checks the weights file, and checks that the ci.yml matrix, `all_leg_names` and the coverage merge list name the same legs. Also fixes `assert_leg_completeness` passing vacuously (`grep -v` with no pattern) and a same-named internal/external test pair of `internal/encryption` that could land in two shards. No test was added, skipped or reduced; required check names are unchanged. Floor: `server/http`'s two largest tests (`TestEveryRouteRefusesADeadCredential`, `TestEveryWriteRouteRefusesAndChangesNothing`) take one leg each (~20 min).
- WIRING-SPLIT-1: `server/main.go`, `internal/config/config.go` and `internal/storage/factory.go` keep only ordered lists (background jobs, core wiring steps, boot refusals, config validators, storage backends); each job, wiring step, config section and storage backend lives in its own file, so a feature is a new file plus one list line (CONTRIBUTING.md). No behaviour change; `TestWiringHotFiles_StayThin` keeps the central files thin.
- **go-webauthn out of `internal/core`'s production closure (CORE-DECOUPLE-WEBAUTHN-1).** Core now talks to the WebAuthn relying party through `ports.WebAuthnRelyingParty`; the go-webauthn library (and go-tpm, cbor, msgp under it, 20.5 MB / 23 packages of compiled closure) lives in the new leaf `internal/webauthnrp`, wired in `server/wire_webauthn.go`. No behaviour change: clone detection, lockout gates, user verification (still required on every assertion), counter persistence, step-up grants and audit are unchanged and stay in core; stored credentials and in-flight ceremony rows keep their exact bytes, so a rolling upgrade needs nothing. Guarded by `internal/core/ports/heavy_deps_webauthn_test.go` and new end-to-end proofs with mutant adapters (`internal/core/webauthn_port_proofs_test.go`, `internal/webauthnrp`).
- **`internal/pqwrap` proof of concept.** Hybrid KEM-DEM wrap (X25519 + ML-KEM-768/1024, HKDF-SHA-256 combiner, AES-256-GCM) with known-answer vectors, tamper and FIPS 140-only tests and a `FuzzParseEnvelope` fuzz target. Not wired into any server, CLI or storage path.
- CodeQL gate (`scripts/ci/codeql-gate.sh`): every new high-severity result now prints rule id, security-severity, file:line, the message and the first code-flow step in the log text, and the gate writes a table to the job summary. Tests use a real SARIF excerpt and real alert lists from main.
- CodeQL PR-time gate: on pull_request, `Analyze (server)` now runs for PRs that change non-test Go of the root module (or go.mod/go.sum, the CodeQL query pack, `codeql.yml` or the gate script), analyses without upload and runs the same gate as the merge queue, so a new high-severity finding fails the PR itself instead of a queue group. The merge-queue and PR analyses keep their SARIF as a run artifact (`codeql-sarif-<leg>`, 14 days). A gate-script-only change now runs the gate in the queue too.
- Guardrails for the `internal/core` split (INV-CORE-package-boundaries): extracted packages never import core, core's keyorix dependencies are an exact list and any added after the split are registered leaves, test-only packages stay test-only, every core file has one owner cluster (`internal/core/CLUSTERS.d/`), source-scanning guards walk the whole core family (`srcpath.CoreFamilyGoFiles`, registry in `internal/testutil/srcpath/corefamily.d`), and file names named by guards must exist.
- `scripts/refactor/provemove` proves a refactor only moved declarations (test/non-test/ignored file class, GOOS/GOARCH suffix, `//go:` directives, build constraints and const iota positions included; `-alias leaf=core` checks a leaf extraction's aliases; an empty proof fails); `scripts/refactor/coretestclass` and `measure-core.sh` print the black-box test and build-cache numbers extraction PRs paste.
- **Test legs no longer wait for `go vet`.** `test-suite` now depends on `changes` and `select` only (like `lint`), so its legs start about 4-6 minutes earlier in every full CI round; `preflight` (`go build`, then `go vet ./...`) runs beside them and `build-and-test` fails unless it succeeded. `go vet` is kept: golangci-lint's `govet` is not the same check. Required check names and the ruleset are unchanged.
- **Nightly guard expiry and rollout job.** `.github/workflows/guard-nightly.yml` evaluates every dated guard exemption against today (7 days' warning) and runs report-only guards in enforce mode, keeping one issue per concern. CI sets `KEYORIX_GUARD_ROLLOUT=enforce` on pushes to main and on the schedule only; the CI exclusion-freshness date checks run on the schedule only, no longer on PRs or in the merge queue.
- **Optional fifth field in the mutation `PACKAGES` list: the efficacy floor when `KEYORIX_TEST_PG_DSN` is set.** The PostgreSQL-only tests then cover mutants a run without a DSN reports as not covered. `internal/serverguard` gets its measured Postgres floor; the `internal/solewriter` one follows.
- Removed the unreachable "admin authority is required" / "administrator" 403 branch from the secret access-request resolve handler: core answers a caller without authority "access request not found" (404) before any of those texts can occur.
- **Guard inputs.** `scripts/ci/guard-inputs.tsv` maps the new wording guard to the paths it reads.
- **Recovery-options design doc wording.** The backlog-4 row of `docs/design/recovery-options.md` no longer repeats the DEK-derived phrase for the checkpoint key; it says the key is KEK-derived. The proto, OpenAPI and generated-type wording landed separately with KEK-WORDING-1.
- **Code comments say the audit-checkpoint and evidence signing keys are KEK-derived, not DEK-derived.** Comment-only: `internal/core/service.go`, `internal/notary/notary.go`, `internal/storage/models/models.go`, `internal/storage/store/local_audit_checkpoint.go`, `server/scheduler_audit_checkpoint.go`, `server/wire_encryption.go` and a test comment in `internal/encryption/audit_checkpoint_key_test.go`. No behaviour change. (The checkpoint refusal text fix shipped separately in #3882.)
- **Removed the caller-free full-row `UpdateSecret` storage primitive.** Secret edits already go through column-scoped writers (`UpdateSecretFields`, `TransitionSecretStatus`, `UpdateSecretRotationConfig`); no behaviour change. The fresh-canary leak fault pass for `PUT /api/v1/secrets/{id}` now faults `UpdateSecretFields` and fails if an armed fault never fires.
- **Regenerated `web/src/types/api-generated.ts` against `openapi.yaml`.** The checked-in file was stale relative to `main`, failing the "Generated API types are fresh" Web CI step on every PR.
- **Five core time writes now carry `.UTC()`, and the unhooked-expiry UTC guard tracks LastUsedAt / LastSeenAt literals.** The access-review last-used stamp (both the annotated entry and the campaign item), the dynamic-lease renewal expiry, the extend-expiring-secrets expiry and the secret-update request expiry are normalised to UTC; the four `TestEveryExpiryAssignmentAndColumnWriteInCoreIsUTC` exceptions that covered them are deleted. `TestEveryUnhookedExpiryWriteInCoreIsUTC` now also checks `LastUsedAt` / `LastSeenAt` keyed fields of models composite literals (assignments and column writes stay with the sibling guard); the widening is report-only until its first green nightly on main.
- **CI runner and tool-version pins.** Every workflow job runs on `ubuntu-24.04` rather than the moving `ubuntu-latest` label; the runners already use that image, so this changes nothing today. `scripts/ci/tool-versions.env` now lists every pinned CI tool version (golangci-lint, gosec, gitleaks, trivy, nuclei, actionlint, checkov, kubeconform, kube-score, go-licenses, govulncheck, and the semgrep image tag and digest). `scripts/ci/check-tool-versions.sh` (`TestToolVersionsGuard`) fails when a workflow pin differs from that file or a listed tool is no longer pinned.
- **gRPC logs keep the driver cause of a storage fault.** A core storage read fault renders as the fixed "storage temporarily unavailable, please retry"; its cause is only in the error chain. The gRPC user, share, project and group services answered such a fault Internal from their error mappers' default branch and logged nothing, so the operator never saw why (REST logs it since #4077). Those branches now log the error with the driver cause (`core.StorageReadFaultDetail`, keeping the outer text such as what a partial update already committed); the existing user/share log lines do the same. The answer to the client is unchanged.
- **Architecture-growth guard.** `make check-growth` fails when a package under `internal/` or `server/` has more than 260 non-test `.go` files or more than 44 transitive dependents in the module (today's max: 226 `internal/core`, 38 `internal/core/ports`), naming the package and the overshoot. It also warns, without failing, when a PR only appends more than 50 lines to an existing doc or data file. Baseline and method: `docs/design/architecture-growth-baseline.md`; rule: `docs/ARCHITECTURE.md`, "Growth ceilings". Not yet run by CI.
- The best-effort call-site guard's mutation test now deletes `clearLoginFailures`' recover and requires the three MFA callers to be reported; its "unwrap a `besteffort.Run` call site" case moved to `RecordLogin`, because `clearLoginFailures` now protects itself.
- **Source-scanning guard tests moved out of `internal/core` into `internal/core/guards`.** The 73 tests that only read the repository's `.go` files (AST sweeps, allowlists, scanner calibrations) no longer compile into `internal/core`'s test archive, which embeds hundreds of MB of promoted-method wrappers for the storage test doubles. Names, assertions and ledger rows are unchanged (`./internal/core` becomes `./internal/core/guards` in the rows that cite them); the new `TestGuardsPackageStaysLight` fails if the package imports core or embeds `storage.Storage`. Guards that need core's types, mocks or Postgres stay in `internal/core`. New MFA step-up allowlist rows now go in `internal/core/guards/` (see `internal/core/REGISTRY-ENTRIES.md`).
- **CI: `test-suite` legs restore a `-race -cover` Go build cache.** The new `go-race-cache.yml` workflow compiles every distinct leg command once per UTC day on `main` (`scripts/ci/seed-race-cache.sh`, nothing is run) and saves the build cache; each leg restores the newest entry after `setup-go`, whose own `go.sum` cache held no `-race` objects. Only `main` writes the entry; PR and merge-queue runs only restore it. Go's build cache is content-addressed and `-coverprofile` already disables test-result caching, so a stale or missing entry costs only compile time and never changes what is tested.
- **Faster closure guard self-test.** `scripts/check-closures.sh --self-test` now runs its independent calibration cases through the same bounded pool as the package run (`CHECK_CLOSURES_JOBS`, sequential under a shared Postgres DSN) and prints every verdict in the original order. It also prints per-phase `timing:` lines to stderr.
- **CI: `core` test-suite leg split into `core-1` / `core-2`.** The internal/core leg took ~35 min and was the merge queue's critical path. `core-1` runs the heavy group (`-run` of `core_heavy_regex` in `scripts/ci-test-legs.sh`), `core-2` runs everything else (`-skip` of the same regex); `assert_core_shards_complete` (assert-leg-completeness job) fails if a test would run in neither or both. Required status check `build-and-test` is unchanged.
- **CI: the slowest `test-suite` legs are split with the existing shard mechanism.** `server/faultops` runs in 5 test-name shards instead of 3; `server/admin` leaves `root-4`'s catch-all for two test-name shards of its own (`admin-1`, `admin-2`); `scripts/check-closures.sh` (the pg-gated security-closure proof) moves from a step after `core-1`'s tests to its own `closures-pg` job with the same Postgres service, DSN and selection, and `core-1` loses the matching bin-pack preload. `scripts/ci-test-weights.tsv` is regenerated with `scripts/ci/gen-test-weights.py` from the same verbose run plus `server/admin`'s rows. Every test still runs in exactly one shard (`assert_all_shards_complete`); `build-and-test` stays the required aggregate and now also requires `closures-pg` on the full tier. No test was added, skipped or changed.
- CI: in the merge queue, `docs_only` (and the other change classifiers) are now computed on the whole stack against the target branch instead of only the entry ahead, so the HEADGREEN batch rule cannot let a docs-only head skip jobs for a code entry below it. `docker-boot-smoke`, `helm-boot-smoke` and `demo-up-smoke` now skip on a docs-only change, and the two guard self-test steps of `adr-numbers` (about 9 of its 13 minutes) skip too.
- **Merge-queue rounds stop at their first round-failing failure.** On `merge_group`, the test-suite matrix now uses `fail-fast` (one red leg stops its siblings), and a new `failfast-*` job after each of preflight, static-analysis, repo-guards, e2e-smoke and web-e2e-real-smoke cancels every run still going for that merge-group commit (`.github/workflows/failfast-cancel.yml`, `scripts/ci/failfast-cancel.sh`). `build-and-test` still reports the failure. Required check names, the ruleset and pull_request runs are unchanged.
- **CI: three guard data files no longer force the full suite in the merge queue.** `scripts/ci/select-affected.py` rule 1 treated every file under `scripts/ci/` and `internal/testutil/` as code. `scripts/ci/guard-inputs.tsv`, the one-row `scripts/ci/guard-inputs.d/*.tsv` fragments and `internal/testutil/sqlitetest/driver_import_allowlist.tsv` are data read by guard tests, and each reader is covered another way: `scripts/ci/guardinputs` is selected (a literal names the legacy file; the fragments, found through a computed directory name, get an explicit seed), and `TestNoNewDriverSqliteTestImports` is selected through its package and run by `repo-guards` on every PR. They now select their readers' legs (`root-4`, plus `root-2` for the allowlist) instead of all 27. The exemption is closed: `guard-inputs.d/README.md`, subdirectories, every other `scripts/ci/**` file and the non-test `internal/testutil/**` files stay FULL, and an exempt file next to a FULL trigger is still FULL. Pinned by `scripts/ci/select_affected_test.go`.
- **`scripts/ci/fuzzplan`: fast fuzz-target listing and package-aware shard packing.** New helper for the `fuzz-changed` workflow: `list` reads a package's fuzz targets without compiling test binaries, `pack` lays them out over shards so a package is compiled on as few runners as balance allows. The target set a PR gets does not change. The workflow still has to be switched to it (`.github/**` change, proposed separately).
- **server/grpc runs on three CI legs.** The gRPC dead-credential walk is split into `TestEveryGRPCMethodRejectsDeadCredential_G0..G3` (every state/cold-warm case in exactly one group, proven by `TestDeadWalkGroups_PartitionTheCases`; the checked combinations are unchanged), and `server/grpc` moves out of `root-1` into `grpc-1..3` (`scripts/ci-test-legs.sh`, `scripts/ci-test-weights.tsv`, `ci.yml`).
- **Guard tests run for the changes that can break them.** A docs-only PR (#3616) merged past `TestDocsShowNoLiteralSecretOnCommandLine`, which reads every `*.md`, because every Go job in `ci.yml` skips a docs_only / web_only / go_unaffected / operator_only change; main stayed red for hours. The new `docs-guards` job runs on every pull_request and merge_group run and executes the guards whose inputs the change touched, from `scripts/ci/guard-inputs.tsv` (guard test file -> input globs). `scripts/ci/guardinputs` fails a PR that adds a guard reading such a path without a map row, by running ci.yml's real `changes` step for each path and evaluating the jobs' `if:` conditions. A change to any `.go` file now always runs the Go jobs: scripts/ci, scripts/demo, scripts/metrics and other Go packages under scripts/ were classified go_unaffected and skipped them.
- **CI: server/http's two route walks are split across shards; `test-suite` goes from 20 to 23 legs.** `TestEveryRouteRefusesADeadCredential` and `TestEveryWriteRouteRefusesAndChangesNothing` were one test each (~26 and ~19 min in CI) and set the floor of the merge-queue round, because the matrix shards `server/http` by top-level test name. Each walk is now `_G0`..`_G3`, one top-level test per route group (FNV-1a of `METHOD /path` mod 4, so a new route always lands in exactly one group), plus `TestEveryWriteRouteRefusesAndChangesNothing_Control` for the whole-surface parts (allowlist hygiene, now also for `awKnownOpen`, and the admin positive control). `TestAWRouteGroups_PartitionTheRouter` proves on the real router that the groups partition the route list, and proves from the source that each walk has exactly one `_Gk` test per group calling its walk with its own group number. The dead-credential walk now also covers `POST /auth/refresh` with an expired (not revoked) session, which rotates the session by contract; route order had hidden it before (logout ran first and deleted the row). `http` goes from 4 to 6 legs and `core` from 3 to 4 (`scripts/ci-test-legs.sh` `sharded_legs`, ci.yml matrix, coverage merge); the split tests' weights in `scripts/ci-test-weights.tsv` are estimates until the next `-v` round. No assertion was dropped; required check names are unchanged.
- **CI rejects AI-assistant attribution.** The new `no-attribution` check (`.github/workflows/no-attribution.yml`, `scripts/ci/check-no-attribution.sh`) fails a PR when a commit message in its range (merge commits included), its title or its body carries a co-author or session trailer, a "generated with" footer or the assistant's links; on the merge queue it checks commit messages. The opt-in `.githooks/commit-msg` hook refuses such a commit locally with the same script. Rule text in CLAUDE.md, web/CLAUDE.md and ADR-081 is file content and is not checked. Offline tests: `scripts/ci/check-no-attribution-test.sh`.
- **CI: queue-only jobs also run on PRs that touch their harness; network steps retry.** A pull request now runs docker-boot-smoke, helm-boot-smoke, demo-up-smoke, e2e-smoke or fuzz-targets/fuzz-reach when it changes that job's own harness (ci.yml, `scripts/selfhost/`, compose and Dockerfiles, `deploy/helm/`, `scripts/demo/`, `scripts/e2e/` and the Makefile, `scripts/fuzzing/`), so a change like #3529's no longer passes its PR and fails only in the merge queue. New `scripts/ci/retry-net.sh` retries a command (max 3 attempts) only on proxy or registry network errors, never on a go.sum mismatch; the licenses job pre-fetches both modules with it and now caches the operator module too, and helm-boot-smoke retries kind cluster creation (same pinned action, checksum still verified).
- **CI: FAST pull_request runs skip two guard proofs their paths cannot change.** In `adr-numbers`, the closure and ADR-conformance `--self-test` steps run on a FAST PR only when the guard scripts, the self-test fixture packages' test files, `internal/testutil`, a module file or `ci.yml` changed. Otherwise the plain verify step checks the real ledger (`--self-test` already does this, so each ledger is verified once per run). In `assert-leg-completeness`, the shard-partition step runs only when a test file of a multi-shard package, `scripts/ci-test-legs.sh`, the weights file, a module file or `ci.yml` changed. merge_group, push, schedule, dispatch, `ci:full` and `release/**` runs are unchanged. `scripts/ci/guardinputs/pathgate_test.go` derives the gate inputs from the scripts and replays 14 merged PRs.
- **CI-SELECT-2 lever C in shadow mode.** `scripts/ci/coverage-shadow.py` logs, as JSON lines, whether each package lever A selects as a dependent actually executes the PR's changed lines under `go test -coverpkg` (KEEP or SKIPPABLE). Observation only: it skips and fails no test, is not called from any workflow, and resolves every doubt to KEEP. Unit tests: `scripts/ci/coverage_shadow_unittest.py`, run by `TestCoverageShadowUnit`.
- **CI-SELECT-2 lever C shadow: fewer undetermined lines, one Postgres database per package.** `scripts/ci/coverage-shadow.py` now resolves a changed line that has no coverage block from facts it can prove: its package is not linked into the dependent's test binary, it is a function signature (judged by its body), or it is a const/type/var that no relevant code mentions (`scripts/ci/declrefs`, `go/ast`). Anything unproven stays KEEP. `--pg-dsn-map` gives each dependent its own `KEYORIX_TEST_PG_DSN`, and go test's own timeout is logged as `timeout` rather than `test-failed`. Still logging only; no workflow calls it.
- **CI-SELECT-2 lever C shadow: more undetermined lines resolved, an independent reachability oracle, old-vs-new verdict logged.** `scripts/ci/coverage-shadow.py` now judges a pure-deletion cut that lies strictly inside one function body by that function's blocks, no longer withholds a comment next to replacement code in the same hunk, widens `-coverpkg` to packages that mention a changed declaration (so those mentions can be judged), and logs `legacy` (the previous rules' verdict on the same profile) next to each decision. `scripts/ci/shadowprobe` rewrites a throwaway tree so a real `go test` reports whether a changed statement is reached, as a check of SKIPPABLE verdicts that does not use the cover profile. The strict rule stays the verdict. Still logging only; no workflow calls it.
- **Scheduled govulncheck now runs every 3 hours** (was weekly), so a newly published reachable Go vulnerability is flagged within hours instead of at the next incidental PR (GO-2026-6859 went unnoticed for ~10 h). `scripts/ci/failure-issue.sh` gained an opt-in `FAILURE_ISSUE_MIN_COMMENT_HOURS` so repeated reds comment on the one open alert issue at most once per day.
- **CI: `server/faultops` and `internal/core` shard weights are regenerated from a verbose CI run.** `scripts/ci-test-weights.tsv` rows for those two packages were last measured on 2026-10-24; tests added since weighed the package `*` default and landed on already loaded shards. Regenerated with `scripts/ci/gen-test-weights.py` from the test-suite legs `faultops-1..5` and `core-1..4` of run 42522635702 (main 3168ca1e8, `verbose_tests=true`). Every other package's rows are unchanged. Every test still runs in exactly one shard (`assert_all_shards_complete`); no test was added, skipped or changed.
- **CI: refreshed the `internal/core` and `server/faultops` rows of `scripts/ci-test-weights.tsv` after the fault-sweep speed-ups (#4052, #4053).** Regenerated with `scripts/ci/gen-test-weights.py` from the nine core/faultops leg logs of verbose run 42713304560 on main 07b613d81; every other package's rows are unchanged. The shard packing now expects `TestMFAResetOpsFaultSweep` at 267 s and `TestFakeClockExtremes_Cross` at 694 s instead of 1346 s and 1498 s, so the faultops legs pack to about 9.1 min each instead of one 22 min leg beside four 13.5 min legs.
- **The CodeQL merge-queue gate accepts findings that are dismissed alerts on main.** `scripts/ci/codeql-gate.sh` read only `state=open`, but the analysis still writes dismissed findings (won't fix / false positive) into the SARIF, so since 18 Oct nearly every queue entry failed. It now reads open and dismissed alerts (still matched by rule id and path, still fail-closed on an API error); a new rule or a new path for a dismissed rule still fails.
- **CodeQL no longer fails merge-queue entries on the SARIF upload.** The upload ran after GitHub had deleted the `gh-readonly-queue/*` branch ("ref ... not found in this repository"). In the queue CodeQL now analyses with `upload: never` and `scripts/ci/codeql-gate.sh` fails the entry on a high-severity result that is not already an open alert on main; push to main and the weekly schedule still upload.
- **Merge conflicts: `merge=union` for five append-only exemption ledgers, plus a hotspot ranking.** `docs/atomicity-exempt.tsv`, `besteffort-exempt.tsv`, `full-row-write-exempt.tsv`, `child-parent-liveness-exempt.tsv` and `docs/state-map/class-overrides.tsv` keep both sides' rows when git merges concurrent appends locally; `TestGitattributesUnionLedgers` proves it. GitHub's own merge ignores merge attributes. See `docs/CONFLICT-HOTSPOTS.md`.
- 40 black-box test files moved out of `internal/core` into the new test-only package `internal/core/coretests` (ADR-121 decision 2, wave 1): they use only core's exported API and the `storagetest` kit, so editing them no longer rebuilds the `internal/core` test binary and editing core no longer reruns them in that binary. Test code only; no production file changed.
- 6 more black-box test files moved from `internal/core` into the test-only package `internal/core/coretests` (ADR-121 decision 2, wave 2; possible now that CORE-TEST-SEAMS-2 built their cores through `NewKeyorixCore`). Test code only; no production file changed.
- **`internal/core` no longer links cobra, pflag or yaml.v3.** The unused `securefiles.FilePermsCmd` is gone, and `EscapeYAMLString`/`RenderYAML` moved from `internal/secrettemplate` to the new leaf package `internal/secrettemplate/yamlescape` (no production callers; behaviour and tests unchanged). The core closure drops 4 packages and about 5.6 MB of compiled archive. `TestCoreStaysLeanOfHeavyThirdParty` (`internal/core/ports`) keeps them out and names the importing package if one returns; INV-CORE-no-heavy-third-party-deps.
- **`storage.Storage` is now a composition of per-domain interfaces.** `internal/core/storage/interface.go` holds only the `Storage` composition; the 475 methods live in `iface_<domain>.go` (25 embedded interfaces such as `UserStore`, `SecretStore`, `AuditStore`) and the filter/row/report types in `types_<domain>.go`. The method set is unchanged. The `MockStorage` and `HookStore` test doubles are split the same way (`mock_<domain>.go`, `hook_<domain>.go`), and the fault-storage generator follows embedded interfaces (erroring on unknown or cyclic embeds), so `faulty_storage_generated.go` is byte-identical.
- **Core test seams, part 2 (CORE-TEST-SEAMS-2).** 14 `internal/core` test files no longer touch the unexported `storage` and `now` fields: struct literals and post-construction `c.storage` swaps now go through `NewKeyorixCore`, `c.now = f` goes through `SetClockForTesting` (only in files whose core never wires an `OIDCVerifier`), and two `c.now()` reads use `EffectiveNow()`. Test-only; no production code and no test behaviour changed. Strict black-box files 88 → 104 (see ADR-121).
- The storage test doubles moved out of `internal/core` into the importable test kit `internal/core/storage/storagetest` (ADR-121 decision 2): `HookStore`/`StoreHooks`/`Hooked`, `MockStorage` and the authz stubs. `internal/core`'s tests reach them through one alias file (`storagetest_aliases_test.go`); the seven `core_test` doubles that each embedded the whole `storage.Storage` now use `storagetest.Hooked`, which shrinks the `internal/core_test` build-cache archive. Test code only; no production file changed.
- **`compliance verify` uses the typed API client.** The OpenAPI schema already lists the required `filename` field of `POST /api/v1/compliance/evidence/verify`, so the CLI now sends it through the generated request body instead of hand-built raw JSON.
- **`scripts/check-doc-links.py`**: a manual check for broken relative links, missing heading anchors and (with `--refs`) backticked repo paths that no longer exist in `docs/`. Not wired into CI.
- Deleted the `mapMachineError`, `mapDynamicError`, `isUntypedUserValidation` and `WriteAuditCheckpoint` rows from `errtext_classification_exceptions.tsv`.
- `TestNoErrorTextClassification` (report-only first) fails on a new `strings.Contains`/`HasPrefix` over `err.Error()` text under `internal/core` and `server/`; the 122 functions that still do are listed with a reason in `internal/core/guards/testdata/errtext_classification_exceptions.tsv`.
- **Read-path metadata cache review follow-ups (#2764).** Cached secret versions are deep-copied on store and on hit, so a caller that wipes or decrypts its result in place can no longer corrupt the cached entry; the schedule cache stamp now includes the row id (a delete-then-recreate of an identical policy in one timestamp tick is a miss); the vestigial `hasVersion`/`hasSchedule` entry fields are gone; `GetLatestSecretVersion` has hit/miss benchmarks.
- **Applied Go `modernize` fixes.** One-time mechanical pass of `golang.org/x/tools` v0.52.0 `modernize` (`any`, `for range n`, `min`/`max`, `slices.Contains`/`Sort`/`Backward`, `strings.SplitSeq`/`Cut*`, `maps.Copy`, `errors.AsType`, `sync.WaitGroup.Go`, `reflect.TypeFor`) across the root, `cli`, `operator`, `migrate` and `devtools` modules. No behaviour change.
- **`modernize` linter enforced; modern-Go guidance for agents.** `.golangci.yml` now enables the golangci-lint `modernize` linter (with `embedlit`, `stringsbuilder`, `newexpr` off, matching the one-time pass), and `CLAUDE.md` points sessions at the JetBrains modern-Go guidelines CLI (v0.1.1, Apache-2.0).
- **CI static-analysis unblocked.** `scripts/ci/check-govulncheck.sh` was failing `static-analysis` (and `build-and-test`) for every PR and merge-queue entry on the unfixed stdlib finding.
- **Fewer allocations on JSON responses.** Responses whose times already carry a zero offset skip the reflective UTC copy (the wire bytes are identical), and the version-metadata classifier decodes the metadata once instead of twice. Same classification for every input (differential test + fuzz target).
- `scripts/ci/check-govulncheck.sh`'s own calibration (`check-govulncheck-test.sh`, run from the
  Go suite by `scripts/ci/govulncheck_exceptions_test.go`'s `TestGovulncheckCheckScript`) proves
  it fails on a reachable, non-allowlisted finding (including a near-miss ID and `govulncheck`
  itself failing) and passes on a clean run, a non-reachable-only finding, and a reachable finding
  that is allowlisted. `TestGovulncheckExceptionsMitigationTestsExist` fails if a row names a
  mitigation test that doesn't actually exist; `TestGovulncheckExceptionsNotExpired` is the
  nightly-evaluated expiry half (`docs/guard-rollout-contract.md` rule 1 — no calendar at PR
  time), picked up automatically by `scripts/guard-expiry-report.sh`.
- Handlers split pilot (HANDLERS-SPLIT-PILOT-1): the shared response/request helpers (`SendError`, `SendSuccess`, `MustGetUser`, `ErrorResponse`, the UTC time encoder, ...) now live in `server/http/handlers/httpx`, and the admin usage, admin billing, credential-hygiene trend and rotation-calendar handlers in `server/http/handlers/reports`. Code moved verbatim; routes, request and response shapes are unchanged. The old helper names stay in `handlers` as aliases. The source-scanning guards of `server/http` and `server/http/handlers` now read the handler subpackages too, and `TestHandlerFamilyListsEverySubpackage` fails when a new subpackage is added without being listed.
- **Names in the legacy-grant upgrade check can no longer inject lines or terminal control codes.** A user, group, machine, project, environment or role name that holds a newline, an ESC or another non-printable character is now shown Go-quoted (`"a\nb"`) in the startup `WARNING` and in `admin validate --posture`, and no copy-and-paste replacement command is printed for it (the API hint is given instead). Names without such characters are shown as before.
- **Test coverage:** the machine (`viewer` at a project) and group (`editor` at an environment) legacy grants are now checked through `AuthorizePrincipal`: allowed inside the grant, refused in another project and at install scope.
- `Storage.WithSchedulerLock`, `WithBootstrapLock` and `WithAuditCheckpointLock` pass the lock-watched context to `fn` (`func(ctx context.Context) error`), like `WithNamedLock`.
- **PR CI runs every repo-wide guard.** The `repo-guards` job now runs `scripts/ci/run-guards.sh` on pull requests (merged with main), the same guard set the merge queue runs, and also runs on docs-only PRs. A guard failure now shows on the PR instead of failing a merge-queue round.
- **CI: merge-queue selection logs two new levers in shadow mode (MQ-TEST-SLIM-1).** `scripts/ci/select-affected.py` now asks `scripts/ci/testreach` which tests of a package can observe a changed non-code input when the package was selected only by a path literal (rule 3) or a non-Go file in its directory (rule 2), and computes "server binary unaffected" gates for edge-builds, e2e-smoke and smoke. With `MQ_SLIM_MODE` unset or `shadow` (the default) it only writes `MQ-SHADOW {...}` lines to the select job log and its step summary: mode, legs and every existing gate output are byte-identical (pinned by `TestMQSlim_ShadowNeverChangesTheOutputs`). `scripts/ci/mq-shadow-report.py` turns a week of those lines plus the same runs' job results into the miss count that decides whether a lever may be enforced (a narrowed leg cancelled by the fail-fast matrix, timed out or missing counts as inconclusive, not as clean); enforcing needs a ci.yml change and the repository variable `MQ_SLIM_MODE=enforce`.
- **CI: encryption test shards rebalanced from measured times.** `scripts/ci-test-weights.tsv`'s `internal/encryption` rows are regenerated from a full `-race` run with Postgres; nothing is added to or removed from any leg (assert-leg-completeness proves the partition).
- **Added `tools/oraclehealth`, a stdlib-only fuzz-oracle health harness.** It plants
  small AST mutants (comparison flips, condition negation, dropped error guards,
  moved bound constants, swapped boolean logic, skipped constant-time compares) in the
  code a Go fuzz target exercises, runs the target against each mutant in an isolated
  module copy, and reports KILLED / SURVIVED so a weak oracle is visible instead of
  assumed. Keyorix-import-free, so it runs on any Go module checkout; carries its own
  committed red/green self-proof (`TestOracleHealth_RedProof`). It refuses an
  overlapping `-src`/`-work`, mutates only a copy carrying its own marker file, and
  reports interrupted or non-oracle failures as `ERROR` (excluded from the kill rate,
  non-zero exit) instead of KILLED. Dev tooling only — no production or runtime change.
- The audit commit resolves the audit table name once per store instead of on every batch (less CPU per audited
  read). Design note for the low-concurrency read path: `docs/specs/low-concurrency-read-path.md`.
- **One shared stdin line reader in `server/admin` (#4179).** `admin recover-admin` and the hidden lock-holder test hook each built a `bufio` reader over `os.Stdin`, which loses the bytes it read ahead when input is piped and several prompts read in turn. Both now read through one process-wide reader (`server/admin/stdin_reader.go`), and `scripts/analysis/remote_storage_classify.go` reads its target list with a single `io.ReadAll`. This is the code half of rolling the #4151 stdin guard out to `server/admin` and `scripts/`; the report-only rollout row is removed once #4179 has merged.
- Posture: a test now derives every deprecated setting alias from the alias table and checks that a config file writing only the old name is labelled explicit, not shipped-default (#2925). The SSO-only-administrator warning (#2914) gained a two-local-admins test.
- **Keyset key-file codec for hybrid post-quantum key wrapping (RD-PQWRAP-2).** `internal/pqwrap`
  now has the self-describing keyset that will replace the bare 60-byte `dek.key`
  (docs/design/pq-key-wrapping.md §7): a KEK slot plus optional X25519 + ML-KEM-1024 recipient
  slots, authenticated at boot by a KEK-derived keyset MAC and a DEK key-check value, so a
  key-directory writer holding only recipient public keys cannot substitute the DEK. The legacy-60
  reader is kept indefinitely and guarded by frozen fixtures. Nothing writes the new format yet:
  key files on disk are unchanged by this release.
- **R&D spike: SMT check of Vault policy vs. migrated Keyorix grants.** `docs/formal/smt/` encodes Vault ACL rule selection (exact, `*`, `+`, priority matching, same-path merge, deny) and the grants `keyorix-migrate vault plan-access` proposes in SMT-LIB (`QF_SLIA`, z3 or cvc5), and asks whether Keyorix can allow anything Vault denies, for every secret name. Case models are generated from the real `accessplan` code and seeded policies (`TestSMTModels_MatchAccessplanOnRealPolicies` keeps them in sync). Design note: `docs/design/smt-vault-policy-equivalence.md`. Not wired into the product or CI.
- **gRPC machine-identity `project_id` narrowing no longer goes through `int`.** `machineIdentityToProto` now uses `uintToU32` like the other model-ID call sites, which clears CodeQL `go/incorrect-integer-conversion` (alert 1268). Values are unchanged; an out-of-range ID still saturates to 0.
- **Independent review recorded for three check-then-act lock exemptions.** `ReissueOneTimePassword`, `SetUserRoles` and `completeInvitationAccept` (fragments in `docs/check-then-act-lock-exempt.d/`, each self-classified SERIAL-EQUIV by the session that added it) were re-read against the code by a separate session. All three hold, and each now has a row in `docs/check-then-act-lock-exempt.reviewed.tsv`.
- **SonarCloud coverage run skips `TestWebNginxHSTS_ComposeImage`.** The `Generate coverage report`
  step in `sonarcloud.yml` now passes `-skip '^TestWebNginxHSTS_ComposeImage$'` to both `go test`
  invocations (`./...` on push, changed packages on pull requests). The test builds a docker compose
  image that exceeds the step's timeout and failed the `Analysis` check on PRs touching `./deploy`.
  The skip is name-pinned (not `-short`), so other tests and the coverage numbers are unchanged; the
  test stays covered by the docker-boot/e2e tiers and `ci.yml`.
- **The folded-read guard now reads the handler and gRPC pre-checks.** `TestNoStorageReadErrorFoldedIntoNotFound` (report-only, `docs/guard-rollout.d`) also scans `server/http/handlers` and `server/grpc/services` for a core read whose error is answered 404 / `NotFound` without being classified. Four sites it found are registered as deferred exceptions: the project `GetProject`, groups `GetGroup`, secret templates `Get` and the share-status handlers.
- **`migrateDatabase` split into ordered per-domain steps.** The additive migration blocks of `internal/storage/factory.go` are now functions in `internal/storage/migrate_<domain>.go`, called in their original order from two step lists in `migrateDatabase` (before and after the table snapshot); the fresh-install tail is unchanged. Pool settings and the schema-epoch code moved verbatim to `factory_pool.go` and `factory_schema_epoch.go`. No statement was reordered or edited: the executed-SQL trace of a fresh SQLite, a fresh PostgreSQL and two upgraded fixture databases is byte-identical before and after. A schema change now edits one domain file plus one call in a list.
- **Removed the caller-free full-row `UpdateDynamicSecretConfig` storage primitive.** Dynamic-secret config writes already go through column-scoped writers; no behaviour change. Also fixed a time-of-day flake in the schema-epoch diagnostic test (expected date now formatted in UTC) and clarified stale `UpdateUser` comments.
- **Removed eleven Go functions nothing called** (found by `deadcode -test ./...`): `core.DefaultSecretValuePolicy`, `storage.CheckSchemaEpoch`, `solewriter.ActiveTracker` and its write-only global, `besteffortguard.DistinctPairs`, `fuzzworld.World.Migrate`, `testhelper.IsolateCLIHome` (its callers went with the old CLI), a test-only `String` method, and in the CLI and migrate modules `cliout.Table.Empty`, `cliout.OrNever`, `cliout.OrDash` and `healthscan.Checks`. No behaviour change.
- **Web: removed code nothing imports** (found by knip, each confirmed by grep): six page/service barrel `index.ts` files, nine unused constant groups in `src/constants.ts`, `formatDay`, unused test mocks and form helpers, and `src/test/README.md`, which documented helpers, files and scripts that do not exist. No behaviour change.
- **Web: dropped two redundant dev dependencies.** `@typescript-eslint/eslint-plugin` and `@typescript-eslint/parser` were declared directly but nothing imports them; the flat ESLint config gets both through the `typescript-eslint` package, which still pulls in the same versions.
- **Removed code nothing calls** (found by deadcode and knip, each confirmed by grep): `KeySetState.IsManifestMissing` (internal/keyfiles), the web UI's unused `isRbacEvent` copy, barrel re-exports no file imports, the `sharingApi.selfRemove` client method (no page used it; the endpoint and `keyorix share self-remove` are unchanged) and two unrouted `ROUTES` entries. No behaviour change.
- **Removed `server/tools`**, the dev-only `go run tools/test_runner.go` wrapper around `go test` that nothing called (its own tests were permanently skipped), with its TESTING_GUIDE sections, its CI leg pin and review-coverage row. Also dropped five SonarCloud ignore rules for files that no longer exist.
- **faultops CI legs get the 3300 s per-binary timeout the core legs already have.** faultops-2 ran p90 27.9 min against a 30 min timeout and timed out in 3 merge-group runs on Oct 18–20; rebalancing the two shards is still open.
- **CI: report-only weights-drift check (`scripts/ci/check-weights-drift.py`) and a verbose-log converter (`scripts/ci/logs-to-timings.py`).** From per-test seconds it warns when a sharded package has a test above 60 s with no row in `scripts/ci-test-weights.tsv` (Rule A) or a shard above 1.30 x the median shard (Rule B, or "dominated by <test>: split the test" when one test already weighted above the shard target is the cause). The layout comes from `ci-test-legs.sh` (`sharded_legs`, `weighted_shard_assignment`), not a second packer. Always exits 0; wired into no workflow yet.

## v0.96.0 — 2026-10-13

### Security
- **A crafted passkey user handle no longer counts as a storage error.** On a
  passwordless login, a user handle above the largest possible user id made
  Postgres return an error that was taken for a database failure, so the
  request was audited `auth.login_error` and gave its per-IP login-budget slot
  back: unlimited attempts, each one recorded as an outage. Such handles (and a
  zero handle) are now refused before the lookup, audited `webauthn.failed` and
  counted. The client answer is unchanged.
- **BREAKING: the HTTP and gRPC listeners now bind `127.0.0.1` by default (#2939).** `server.http.host` / `server.grpc.host` select the bind address; when omitted the server listens on loopback only instead of every interface. **Upgrade note:** installs with their own `keyorix.yaml` (or a mounted container config) and no `host:` line that are reached from another machine, a remote reverse proxy or a published container port must add `host: "0.0.0.0"` (or a specific interface address) under `server.http` / `server.grpc`. The shipped docker-compose config, Helm chart, DAST stack config and demo `up.sh` set it explicitly; `server/config/production.yaml` and `server/config/web-enabled.yaml` carry a commented `host:` line. See `docs/UPGRADING.md` §6a.
- **Successful logins no longer use up the per-IP login budget** (#2936). The
  budget (10 attempts per 15 minutes per IP, shared by the password, TOTP,
  passkey and token-refresh endpoints) was charged for every request, success
  or not, so a few ordinary MFA logins from one demo laptop, booth or office
  network locked everyone behind it out with a 429 for 15 minutes, and a
  restart did not help. A request that delivers a session now returns its slot,
  and so does every earlier step of the same login (the password step of an MFA
  login, a passkey `begin`), so a successful MFA or passkey login costs nothing;
  a failed, expired or abandoned one keeps every slot it took. Failures count
  exactly as before, including storage faults after a correct credential
  (#2880), and the slot is still reserved before the credential check, so a
  concurrent burst cannot outrun the budget. The count still survives a
  restart. New audited host-side command
  `keyorix-server admin clear-login-lockout --ip ADDR | --user ID` clears an
  IP's budget and/or an account's login lockout (docs/SELF_HOSTING.md).
- **The shipped compose stack and Helm chart no longer put credentials in any
  container's environment.** Compose uses Docker secrets files under `./secrets`
  (created by `scripts/selfhost/init-secrets.sh`, which also migrates an existing
  `.env` with `--from-env`); the chart mounts its Secret as a read-only 0440
  volume and sets `*_FILE` variables. Requires a server image with `*_FILE`
  support (#2968). **Upgrade notes in `docs/UPGRADING.md` §5.**
- The share lists (`GET /api/v1/shares`, `GET /api/v1/shares/owned`, and the embedded-mode
  core calls) now refuse a list of 10000 or more shares (the storage layer silently cuts
  unpaginated lists off at 10000) instead of running an unbounded number of user/group
  lookups or showing a list that may be missing shares. Over the cap the HTTP answer is a
  typed `422 ShareListOverCap`, not a 500; the list is never truncated. Real pagination is
  a follow-up.
- **The access report shows no more than the routes it summarises.** Project role levels and
  role-only members need `users.read` at the project; per-secret ACL holders and `acl:` grants
  need `secrets.manage` on the secret (the gate of `GET /secrets/{id}/acl`). Without them that
  part is left out and the report is flagged `degraded`. A departed owner is not reported as
  owner. A failed group-membership lookup now degrades the report instead of only being
  logged. Guarded by `internal/core/secret_access_list_test.go`.
- **The per-IP login budget no longer fails open on a database error.** It used
  to stop counting whenever its `login_attempts` storage failed, including when
  only the count query failed while inserts still worked. It now falls back to
  a bounded in-memory limiter with the same limit and window, per server
  process. Each fallback writes an `auth.rate_limit_error` audit event and
  increments `keyorix_auth_rate_limit_fallback_total{budget="login"}`. Clients see the same 429.
  An MFA or passkey login whose slot came from that fallback completes as
  normal: the in-memory slot is never written to the challenge or ceremony row.
- **A storage error before any credential was checked is no longer recorded as
  a failed login.** The username lookup on `/auth/login` and the passwordless
  passkey's user lookup audit it as `auth.login_error` and hand the per-IP slot
  back; MFA activation's anti-replay write audits `mfa.error`. The client answer
  is unchanged.
- **No auth rate limit fails open on a database error any more.** The per-IP
  login, password-reset and SSO/SAML-begin budgets, and the per-account lockout,
  used to stop counting whenever their storage failed, including when only the
  count query failed while inserts still worked. While the database (or
  just its rate-limit table) was failing, brute-force and email-bombing limits
  were off. The per-account lockout is the only bound on MFA step-up and
  recovery-code guessing. Now each budget falls back to a bounded in-memory
  limiter with the same limits, per server process. Each fallback writes an
  `auth.rate_limit_error` audit event and increments
  `keyorix_auth_rate_limit_fallback_total{budget}`, so alert on that metric.
  `/health` also reports `"auth_rate_limit": "degraded"` while a fallback is in use.
  During the outage, password reset is tighter: half the per-IP limit, and a cap on
  reset emails per account. In HA, set the new
  `security.auth_rate_limit_fallback.replicas` to your replica count so each
  replica enforces its share. Clients see the same responses as before.
- **`keyorix-server admin init` writes the secure baseline** (ADR-112 §4):
  `admin validate --posture` reports zero deviations on a fresh install. TLS is
  on and required, with a generated self-signed certificate
  (`certs/server.crt`/`.key`); API rate limiting is on; `/metrics` requires a
  generated token read from the new `server.http/grpc.metrics_token_file`
  (`secrets/metrics_token`). All generated files are `0600` and never printed.
  An existing config is not changed and nothing is generated for it.
  `admin init --dev` writes the previous relaxed config, labelled DEV-ONLY.
  Guarded by `server/admin_init_secure_baseline_test.go`.
- **The CLI can trust a private CA or self-signed server certificate:**
  `keyorix config set ca_file <path>`, `KEYORIX_CA_FILE`, or `--ca-file`. The
  CLI then trusts exactly that file's certificates, the same on macOS and Linux
  (`SSL_CERT_FILE` is ignored on macOS). `login` remembers the CA file it used.
- **One-time passwords expire.** The one-time password `keyorix-server admin recover-admin` issues is valid for 24h and an admin-created one (`keyorix user create --one-time-password`) for 72h (`security.recovery_one_time_password_ttl`, `security.one_time_password_ttl`; Go durations up to `168h`, a set but invalid or out-of-range value is refused at start-up, empty means the default; there is no "never"). After the expiry the correct password is refused exactly like a wrong one (same response and timing, counted toward `login_lockout`) and audited server-side as `auth.one_time_password_expired`. Choosing a new password clears the expiry. Expiry is a login gate: an already-open session is not cut off by it.
- **Upgrade effect: every account in `password_reset_required` gets 24 hours from the upgrade.** Before this change nothing recorded which accounts hold a one-time password, so the one-off migration stamps every live `password_reset_required` account, including accounts an admin forced to reset and accounts held by the password max-age gate. Those users who have not changed their password within 24h of the upgrade are refused at login until an admin re-issues access (`recover-admin`, `user resend-setup-link`). The same rule is applied when a pre-upgrade backup is restored (`admin restore` of an archive without the column). During a rolling upgrade, replicas still on the previous version keep accepting an expired one-time password until they are upgraded (the schema epoch is unchanged).
- **BREAKING: Docker Compose and the Helm chart now run the secure baseline by
  default.** The baseline (`admin validate --posture`: no deviations, file
  permissions included, #2922) is no longer a separate opt-in. What changes for
  operators:
  - **Compose:** the stock `docker-compose.yml` is the secure stack.
    `docker-compose.secure.yml` and `keyorix.docker.secure.yaml` no longer exist
    (drop `-f docker-compose.secure.yml` from your commands). The backend serves
    TLS on 8080 inside the compose network with a generated certificate that
    nginx verifies (the published port 8088 is unchanged), `/metrics` needs the
    generated token, API rate limiting is on, and the server runs from a private
    0600 config copy. New volumes `keyorix_tls` and `keyorix_tls_public`; the
    config is mounted at `/app/config/keyorix.docker.yaml`. Anything that spoke
    plain HTTP to the backend on 8080, or scraped `/metrics` without a token,
    must switch to HTTPS with the generated CA and send the token.
  - **Helm:** `secureBaseline.enabled` now defaults to `true`. `helm upgrade`
    turns on TLS between the pods (Helm-generated certificate, kept across
    upgrades), the `/metrics` token and rate limiting, switches the bundled
    Postgres to TLS, and rolls the server, web and Postgres pods. If you pin an
    older `image.tag` (no secure-baseline support), set
    `secureBaseline.enabled=false`. With the bundled Postgres the data
    directory ownership also changes (uid 999 to 70): see
    `docs/UPGRADING.md` "v0.95.x to v0.96.0".
  - Both need the 0.96.0 server image; they do not work on v0.95.3 or older.

  Also new: `keyorix-server admin init --secure-files` (generate only the files
  an existing config references); the server image's entrypoint is now its
  ENTRYPOINT (`docker run <image> <cmd>` runs `<cmd>` after the config copy).
  The compose backend mounts a small private tmpfs at `/app/data` for the config
  copy (its root filesystem is read-only). In the chart, rotating the generated
  Secret (delete it, `helm upgrade`) rolls the server, web and bundled-Postgres
  pods through their `checksum/secure-baseline` annotation. The compose config
  sets `server.http.host: "0.0.0.0"` (the server's default bind is 127.0.0.1
  since #2939, which left the web container and the health check unable to reach
  the TLS backend).
- **A panic after the credential check keeps the per-IP login slot counted (#3048, #3064).** Previously a panic in a login, MFA or passkey step that ran after the credential had been judged released the per-IP reservation, so a correct-credential request that crashed cost nothing against the budget. Post-verdict panics are now charged like a wrong credential, matching the rule for post-verdict storage errors; pre-verdict panics still release the slot.
- **A storage fault while looking up a session token no longer spends the per-IP
  login budget on `POST /auth/refresh`** (#2880). When the session lookup itself
  fails, no token was found or judged, so nothing was guessed and the request
  returns its slot instead of counting as a failed attempt (a client behind a
  flaky database could lock its own IP out of logging in). The refusal is the
  same 401 as before. Every fault after the token matched a live session (the
  owner read, the rotation, the reuse revocation) still keeps the slot, so a
  valid token is never cheaper than a wrong one; the rotation and owner-read
  cases are pinned by-design in the fault-injection oracle.
- **Root CI-tooling `undici` raised to 7.29.1 and `qs` pinned to 6.16.0** (the ten undici advisories fixed in 7.29.1, and qs GHSA-x5fp-wj9c-mxmx / GHSA-4mjr-xmp4-gh2g). Both arrive transitively through `@cyclonedx/cdxgen` (cheerio, body-parser); the root `package.json` overrides now pin the first patched versions and `npm audit` reports 0 vulnerabilities. CI/release-SBOM tooling only, not shipped in any binary.
- **`keyorix-server admin clear-login-lockout` now writes its audit event before it
  clears anything** (#2956 follow-up). It used to clear the IP budget / account
  lockout first and audit afterwards, so a fault in the audit write left a lifted
  lockout with no record. Now a failed audit write clears nothing and fails the
  command, and a clear that faults after the audit event was written appends an
  `admin.login_lockout_clear_failed` event so the chain never claims a lift that
  did not happen. The per-run counts ("cleared N attempts") are printed to the
  operator and no longer part of the audit text.
- **source-map-js pinned to 1.2.2 in `web/`** (GHSA-68fv-2mgg-jv7q, Dependabot #25). The web build and test toolchain (postcss, tailwind, jsdom) pulled 1.2.1 transitively; `web/pnpm-workspace.yaml` now overrides it to 1.2.2. Dev/build-time dependency only, not shipped in the web bundle.
- **`admin restore` checks secret references against the right table (#3078).** backupfmt classified
  the `secret_id` column of `share_records`, `secret_acls`, `access_requests`,
  `secret_version_comments` and `access_review_items` as a reference to `mfa_secrets`, because there
  is no `Secret` model and the naming convention also matched a model name that merely *ends* in the
  field's name. Restore's mandatory dangling-reference check therefore refused a valid backup holding
  a share, ACL or access request on a real secret (unless an MFA secret had the same id), and accepted
  a reference to a secret that does not exist whenever an MFA secret had that id. The five columns now
  reference `secret_nodes`, and the convention only matches a field that ends with a model's full name;
  anything else must be listed in `referenceOverrides` by hand (the three `ClientID -> APIClient`
  fields now are). Existing backup archives need no conversion.
- **A restricted personal access token is refused on every ungated write.** Writes
  that no permission gate covers (profile, password, MFA and passkey changes, step-up,
  access requests, marking notifications read, leaving a share, break-glass, PAT
  creation) now answer a PAT with any scope, project, environment or CIDR restriction
  with 403 (gRPC `PermissionDenied`). Still allowed: revoking the owner's own tokens
  and sessions, and creating secrets, folders, rotation policies and dynamic-secret
  configs inside the token's restriction. Unrestricted PATs, sessions and machine
  tokens are unchanged. One table for both transports
  (`internal/core/pat_restriction_writes.go`), guarded family-wide (ADR-042).

### Added
- **Owner-scoped share list: a project-only owner can see and revoke their shares.**
  New `GET /api/v1/shares/owned` returns only the shares the caller created, on secrets in
  projects they are a member of now, within the caller's PAT restriction. The Sharing
  Management page falls back to it (labelled "Shares you created") when `GET /api/v1/shares`
  (global `secrets.read`) is refused; a global admin's page is unchanged.
- **Secret access shows each user's effective level and every grant behind it.**
  `GET /secrets/{id}/access` / `keyorix secret access` / the secret's Access panel list each
  user's effective level (max of role, per-secret ACL and active share; owner for a live
  owner) with a `grants` list such as `role:read, direct_share:write` or `owner:owner`.
  Every applying share is listed, so a direct read share and a group write share both appear.
- **An incomplete access list says so.** `keyorix secret access` prints
  `WARNING: this list is incomplete` with the server's reasons, and the web Access panel shows
  a "This list is incomplete" banner, whenever the report is `degraded`. The OpenAPI response
  now declares `total`, `degraded` and `degraded_reasons`.
- **`keyorix user reissue-one-time-password <user id | email>`** (REST `POST /api/v1/users/{id}/reissue-one-time-password`, gRPC `UserService.ReissueOneTimePassword`). An administrator (`users.write`, within the admin-rank ceiling over the target) issues a new one-time password for an existing user whose first one expired or was lost. The password is shown once, expires after `security.one_time_password_ttl`, and is never stored in clear or audited (`user.one_time_password_reissued`). The account returns to `password_reset_required`, all of its sessions end, and an enrolled second factor is kept. Refused for your own account, SSO/SCIM-managed accounts and suspended or inactive accounts, each with a fixed message; a storage failure returns 500 (gRPC `Internal`), never 404.
- **Helm: `secureBaseline.existingSecret`** for ArgoCD and other GitOps tools that
  render with `helm template`. There `lookup` sees no cluster, so the generated
  certificates and `/metrics` token changed on every sync. With the value set to a
  pre-created Secret (keys `server.crt`, `server.key`, `metrics_token`, and
  `postgres.crt`, `postgres.key` for the bundled Postgres) the chart generates
  nothing, renders no `-secure-baseline` Secret and mounts yours; two renders are
  byte-identical. A missing key fails `helm install/upgrade` with its name, and
  setting it without `secureBaseline.enabled=true` fails the render. Unset, the
  render is unchanged. See `deploy/helm/keyorix/README.md`.
- **Helm: `secureBaseline.existingSecretRevision`** (optional, default empty). Under
  ArgoCD the pod annotation `checksum/secure-baseline` is constant, so rotating the
  existing Secret does not restart the pods. Bumping this value in Git feeds that
  annotation and rolls the server, web and bundled-Postgres pods on the next sync.
  Setting it without `existingSecret` fails the render.
- **`keyorix-server --version` and `keyorix-server admin version`.** Print the version, commit, build date (the commit date, so release builds stay reproducible) and Go version from the same `-X` ldflags the Makefile and `server/Dockerfile` use; no config file or database lock needed. The Dockerfile takes a new `BUILD_DATE` build arg (defaults to `unknown`; the docker-publish workflow should pass the commit date).
- **`keyorix-server admin audit export-checkpoint-key`.** Writes the KEK-derived audit-checkpoint verification key (hex, `0600`, never printed, refuses to overwrite) for `admin verify-audit --checkpoint-key-file`, so an air-gapped drill can authenticate an exported checkpoint anchor (`external_anchor.authenticated == true`). Documented in `docs/AIRGAP_RUNBOOK.md`; `scripts/airgap-e2e.sh` now asserts it.
- **`keyorix-server admin generate-secrets`.** Creates the three secrets a host install needs before the server first starts (`master_password`, `bootstrap_token`, `admin_password`) as 0600 files in a 0700 `./secrets` (or `--dir`), never overwriting an existing file and never printing a value: it prints only the `KEYORIX_*_FILE` paths every `keyorix-server` and `keyorix` command already reads. The host-install counterpart of `scripts/selfhost/init-secrets.sh` (whose 0640 compose files the master-passphrase reader refuses on a host), and the first step of the secret-blind "install with an AI assistant" flow. Guarded by `server/admin/generate_secrets_test.go` and the binary-level `TestAdminGenerateSecrets_SecretBlindHostInstall`.

### Changed
- **The access report reads a secret's shares once**, instead of once or twice per listed
  user, and evaluates each user's share grants from that list with the same rules as
  enforcement.
- **Deleting a secret now shows its real purge date (the restore deadline)** in the CLI,
  REST and gRPC responses and in the trash listing. The date is frozen when the secret is
  soft-deleted, so a later change to `soft_delete.retention_days` can neither pull a purge
  earlier than the date already shown nor silently push it out. New nullable column
  `secret_nodes.purge_at`, added automatically on upgrade (schema epoch 2). **The
  compatibility floor rises to 2: binaries from before this release refuse to start against
  an upgraded database** (they would not clear or re-stamp `purge_at` on restore/re-delete,
  and a stale date could purge a secret earlier than shown), so upgrade every replica
  before relying on a rollback. Secrets soft-deleted before the upgrade keep following the
  current window until purged, and the settings page says so.
- **OpenAPI lint uses vacuum instead of Spectral.** CI's `openapi-lint` job now runs vacuum (pinned in `devtools/vacuum/go.mod`, checksum-verified via `go.sum`, ruleset in `.vacuum.yaml`) and `@stoplight/spectral-cli` is removed from the root `package.json`, dropping a CI dependency whose `braces` dependency has an unfixed advisory (GHSA-vfj7-8cjw-p6xm). A canary spec guards against an inert ruleset. `make openapi-lint` runs it locally.
- **An interactive session's auth-cache hit re-checks the account and the session in one database statement.** Every request served from the HTTP auth cache with a session token used to re-read the owning user (active / not suspended, current account state) and the session row (not revoked, rotated or expired) in two statements; they now come from one statement (`storage.GetSessionAuthLiveness`), i.e. one snapshot. Which requests are allowed, refused (401) or restricted (403 for a pending password change), the order of the checks, the degrade-to-cached-snapshot behaviour on a storage error, and the auth-cache invalidation are unchanged. Pinned by `TestSessionCacheHitLiveCheck_*` (SQLite and Postgres, including two Postgres replicas racing a session revoke or a suspension), `TestSessionCacheHitLiveness_*` and `TestGetSessionAuthLiveness_*`.
- **A fresh demo now shows a healthy Compliance posture with exactly one deliberate finding.** `scripts/demo/up.sh` used to leave "6 gaps across 16 controls" in red (recertification, dormant access, second factor, rotation coverage, classification, independent break-glass reviewer). It now enrols alice and a second administrator (`security-officer`) for TOTP, gives alice one real read, classifies every secret, machine identity and machine token, puts two of the three secrets on a 90-day rotation policy, and runs one completed access-review campaign per project (the product's independent-reviewer rule is honoured: the admin's own grants are attested by `security-officer`). The one gap left is Secret-rotation hygiene, "2 of 3 secrets covered": the Production `payments-webhook-secret` has no policy. `docs/demo/GOLDEN-PATH.md` section 1b is the talking point and the one-command live fix. Only demo seed data and docs changed; no detection logic, threshold or compliance rule.
- **Demo alice now has a second factor.** The live-enrolment moment of the demo script (section 2) now uses a brand-new user, since a seeded user that is not enrolled would be a second-factor gap. The state file printed by `up.sh` carries the TOTP keys of alice and `security-officer`.
- `web/scripts/check-api-contract.mjs`: `KNOWN_VIOLATIONS` entries are now keyed by `<file> <METHOD> <path template>` (e.g. `secrets.ts POST /api/v1/secrets/{dyn}/transfer-ownership`) instead of `file:LINE`, so edits above a call in `web/src/services/*` no longer shift the key and conflict with parallel PRs. The same 18 spec gaps are tolerated; a new unlisted call, a second call to a listed key and a stale entry all still fail.
- **Unreleased changelog entries now live in `changelog.d/`, one fragment file per PR**,
  instead of in `CHANGELOG.md`'s `## Unreleased` section, so merging one PR no longer
  conflicts every other open PR. `scripts/changelog-assemble.sh vX.Y.Z` merges them into
  `CHANGELOG.md` at release time (`RELEASING.md`); `--check` validates them in CI.
- **`total_reads` on `GET /api/v1/secrets/{id}` is now opt-in.** It was added two days earlier (#2972) and was computed on every request as an O(reads) count over the secret's access log. By default the field is now absent and the count is not run; request it with `?include=total_reads` (comma-separated or repeated `include` values are accepted). Authorization is unchanged. The gRPC `GetSecret` equivalent takes the new `include_total_reads` request field, and `keyorix secret get` (the view that prints "Total Reads") requests it automatically. `GET /api/v1/secrets/{id}/versions` is unchanged.
- **Audit batches are written with one INSERT per batch.** The audit flusher now inserts a batch's audit events with one multi-row INSERT and its secret access-log rows with another, instead of one INSERT per item. The hash chain, row contents and ids are unchanged, and every caller still returns only after its audit row is committed (same transaction, advisory lock, durability setting and SQLite busy-retry). A row the database rejects still fails only its own caller.
- **A secret value read checks the caller's read permission once.** `GET /api/v1/secrets/{id}?include_value=true` and gRPC `GetSecretValue` evaluated the same per-secret read-permission check twice for a signed-in user and fetched the secret again in between; the value step now reuses the first check (`core.GetSecretForValueRead` / `GetPermittedSecretValue`), and a gRPC machine read reuses the secret it already resolved. Responses, error codes and audit records are unchanged; the read-time guards (expiry, suspension, classification approval, access schedule, read limit) still run on every value read. Pinned by `TestValueReadAuthorizeOnce_*` (REST, SQLite and Postgres, including a two-replica Postgres case) and `TestGRPCValueReadAuthorizeOnce_Equivalence`.
- **A secret value read checks the access schedule and the latest version in one database statement.** Every latest-version value read (REST `GET /api/v1/secrets/{id}?include_value=true`, `GET /api/v1/secrets/value?ref=`, gRPC `GetSecretValue`, machine and human callers) read the secret's access schedule and then probed the latest-version cache in a second statement; both now come from one statement (`storage.GetSecretScheduleAndLatestVersion`). Allow/deny decisions, error codes, the order of the read guards and cache invalidation are unchanged. Pinned by `TestValueReadScheduleVersion_*` (SQLite and Postgres, including a two-replica Postgres case) and `TestGetSecretScheduleAndLatestVersion_*`.
- **A per-secret permission check no longer fetches a secret the request has already read.** For a signed-in user, the per-secret route gate (REST `RequireScopedSecretPermission` / `RequireScopedSecretRefPermission`, gRPC `authorizeSecretScoped`) now passes the secret it resolved to `core.AuthorizeSecretAction`, which used to fetch it again. `GetSecretWithPermissionCheck` now returns the secret its read check fetched instead of fetching it a second time. A human metadata read (`GET /api/v1/secrets/{id}`, gRPC `GetSecret`) fetches the secret twice instead of four times. Decisions, responses, error codes and audit records are unchanged; ownership, shares, ACL grants and roles are still read live. Pinned by `TestResolvedSecretReuse_*` (REST, SQLite and Postgres, including a two-replica Postgres race of a share revoke and a delete against reads), `TestGRPCResolvedSecretReuse_Equivalence` and `TestAuthorizeSecretAction_ReusesOnlyTheSameSecretsResolution`.
- **A role-based authorization decision reads the principal's roles in one database statement.** Every `Authorize` (users) and machine-principal decision used to read the direct role grants, the group role grants, the admin-bypass flag and the role-permission cache generation in separate statements; they now come from one statement (`storage.ResolveUserPermissionAt` / `ResolveMachinePermissionAt`), and the role-permission cache is checked against the generation read in that same statement. Allow/deny decisions, the admin bypass (never for machines), the cache and its invalidation are unchanged. Pinned by `TestAuthorizeRoleResolution_*` (SQLite and Postgres, including two Postgres replicas racing grants and revocations) and `TestResolvePrincipalPermission_*`.

### Fixed
- **Demo `up.sh` fails loudly and heals old volumes.** The `host: "0.0.0.0"` insert now runs on every start (so demo volumes created before the default changed work again), is verified after the sed, and aborts with a clear message if it did not land; `up.sh` also reports a container that exits during startup instead of timing out silently.
- **DAST stack reachable again.** `scripts/dast/keyorix-dast.yaml` sets `server.http.host: "0.0.0.0"` so the scanner containers reach `keyorix:8080` over the compose network.
- **Login-attempt reservations are identifiable, so a storage hiccup can no longer double-count or lose a login slot (#3050).** Each per-IP login reservation now carries a `reservation_key` (new column on `login_attempts` with a unique index; added by an automatic migration on upgrade). The reservation write is retried idempotently (`ON CONFLICT` on that key), so a write that took effect but reported an error is neither counted twice nor left orphaned, and a delivered login releases exactly its own reservation.
- **A failed notification no longer turns a committed access-request decision into an error (#3075).** Approving or rejecting an access request (project or secret, single or bulk) used to answer HTTP 500 if creating the follow-up notification panicked, although the role grant and the approval had already been saved. Now a notification failure (error or panic) is logged at `SECURITY: WARN`, recorded as a `notification.failed` audit event in the request's project, and the request returns success. A notification error used to be dropped silently; it is now audited the same way.
- **`admin restore` no longer refuses a backup taken after a secret purge (#3085).** The retention purge hard-deleted
  the secret and its versions but left rows that still referenced them, and restore's mandatory
  dangling-reference check counted every one. The purge now deletes, in the same transaction, the
  rows of every mutable table that references the secret or a version: access requests (and their
  approvals), shares, tags, access schedules, metadata history, version comments and notifications.
  `audit_events.secret_node_id` (append-only), `anomaly_alerts.secret_node_id` (an unacknowledged alert is a
  live security signal), `secret_access_logs` (append-only, exported) and the `access_review_items`
  snapshot (its own campaign retention) are historical references the purge keeps and restore's check
  skips by name; every other reference stays strictly checked. Rows orphaned by purges that ran before
  this fix are not swept: such a backup is still refused until the orphans are removed by hand. A guard test fails when a new table
  references a secret without being classified as one or the other.
- **A failing name lookup in an audit description no longer turns a committed change into an error (#3090).** Revoking a project access-review grant removed the role assignment and then answered HTTP 500 if reading the role's name for the audit text panicked. The name lookup used by every audit description (`auditObjectName`) now recovers a panic, logs it at `SECURITY` level and leaves the name out, exactly as it already did for a failed read.
- **A failing "you are now the owner" notification no longer turns a committed ownership transfer into an error (#3092).** Transferring a secret's ownership (and the bulk reassignment summary) saved the new owner and the audit event, then answered HTTP 500 if creating the notification panicked. A notification error was already ignored; a panic is now recovered and logged at `SECURITY: WARN` too, and the request returns success.
- **Creating a dynamic-secret config is now all-or-nothing (#3108, #3095).** The config row was inserted and its encrypted admin DSN written in two separate commits, so a failure of the second write (or of the first one's reply) answered an error but left a config row with no DSN behind. Both writes (and the encryption between them) now run in one transaction, over HTTP and gRPC alike.
- **A failed break-glass activation no longer leaves an activation record behind (#3109).** The activation record was committed first and "undone" by a second write when the emergency-role grant failed, so an error response could leave a `revoked` record (and, between the two commits, an `active` record with no role). The record and the grant now run in one transaction under the existing project-admin lock; nothing is visible, audited or notified until it commits, and a failed grant leaves no trace and does not block a retry. Same core path for HTTP and gRPC.
- **`GET /api/v1/audit/search` `success` parameter is a string enum.** The spec declared `enum: [true, false]` (YAML booleans) on a `type: string` parameter, which generated the TypeScript type `true | false`; it is now `"true" | "false"`. The server already parsed the query string, so behaviour is unchanged.
- **A backup restored on a host whose timezone is not UTC no longer corrupts timestamps (#3088).** The backup row encoder wrote times in the host's local zone, and RFC 3339 cannot carry a seconds-level local-mean-time offset (Europe/Berlin +00:53:28), so pre-1900 instants such as the zero time of an audit row written without an `EventTime` came back shifted. The restored audit row failed its `entry_hash` check and `admin restore` reported verify-audit `BROKEN`. The encoder now writes every time column (all models, `*time.Time`, `gorm.DeletedAt`) as UTC, so the round trip is exact on any host TZ and the archive bytes no longer depend on it.
- **`scripts/demo/check.sh` no longer leaves its scratch project and secret behind.** Its cleanup deleted the project while it still held the scratch secret, was refused with 409 and ignored, so every `check.sh --keep` demo carried a never-reviewed project and an unclassified secret. It now deletes the secret first and fails the step if either delete is refused.
- **Audit rows from the secret, version, folder, bulk and copy handlers now store the bare
  client IP.** They used to store `r.RemoteAddr` raw (`172.17.0.1:56508`) in
  `audit_events.ip_address` and `secret_access_logs.ip_address`. A direct request now stores
  `172.17.0.1`; behind a configured trusted proxy the forwarded client IP is stored exactly
  as before, and `X-Forwarded-For` from an untrusted peer is still ignored. Rows written
  before this change keep their `ip:port` value in storage and in exports (nothing is
  rewritten); `GET /api/v1/secrets/{id}/access-log` and the secret detail view show the bare
  IP for those old rows too. Filters or SIEM rules that matched an exact `ip:port` string
  must match the bare IP for new rows.
- **Secret detail "Recent access" lists reads only.** It also listed the `create` row;
  the other events are in History.
- **`machine_identity.*` audit descriptions say what happened.** `token_issued` used to read
  `machine identity "ci-app" (ci) in project 1 → active` (state, not event). It now reads
  e.g. `issued token for machine identity "ci-app" (ci) in project 1 (state: active)`, with
  its own wording for created, token rotated/revoked, role granted/removed, OIDC bound/unbound
  and activated/suspended/revoked. Name, type, project and state are all still in the text.
  Rows written earlier keep the old wording.
- A real-backend Playwright spec proves one Reveal click sends one `include_value` GET and
  writes exactly one `secret.read`.
- `web/pnpm-lock.yaml`: removed a duplicated `source-map-js@1.2.2` block (packages and snapshots) that made `pnpm install` fail with `ERR_PNPM_BROKEN_LOCKFILE`.
- **A write share's Edit and Rotate are offered in the web UI.** The permission-aware UI (#3047) hid Edit / Rotate from a project member whose roles lack `secrets.write`, so the elevation a write share grants on that one secret worked at the API but was unreachable in the Secrets table. A project-scoped `GET /secrets?project_id=N` now also returns the caller's own `user_permission` for rows they hold a share on (it used to look up shares only for an unscoped listing), and the row offers Edit and Rotate when it is `write`. Share, Delete and automated rotation stay role-only. A recipient's row reads "Shared with you" instead of "0 shares".
- **Restore: `knownRemovedColumns` allowance could apply to the wrong table.** `backupfmt.LoadArchive` named each model by indexing the registry-order name list with its restore-order loop index, so a deliberately-removed-column allowance (empty today) would have been applied to a different model's table and the owner's refused. Each model is now looked up by its restore-order name; the schema-delta error also names the model (#3086).
- **Transferring a secret's ownership now moves its shares to the new owner.** Before, `POST /api/v1/secrets/{id}/transfer-ownership` (and `reassign-owner`) changed only the secret's owner, so the previous owner kept listing the secret's shares in `GET /api/v1/shares/owned` and gRPC `ListUserShares` but got `403` on updating or revoking them, and the new owner could revoke them but not see them in the owner list. The shares are now re-owned in the same transaction as the transfer (live, expired and revoked rows; recipients, permissions and expiries are untouched, so nobody gains or loses access). Visible to API clients: after a transfer a share's `createdBy` is the new owner (the original sharer stays in the `share_created` audit event), the previous owner's owned-share list no longer includes the secret's shares, and the `secret.owner_transferred` audit event's diff gains `shares_reassigned`. A share created by the previous owner at the instant of a transfer is now refused instead of committing with the previous owner's stamp. Guarded by `TestTransferSecretOwnership_ReownsShares` and the cross-replica Postgres tests in `internal/core/cta_review_transfer_ownership_shares_postgres_test.go`. (#3102)
- **The secret detail page offers Edit and Rotate to a write-share recipient, like the list row.** #3083 made the Secrets list row show Edit and Rotate on a secret the caller holds a `write` share on, but the detail page still gated them by role only, so a recipient could edit from the list and not from the detail page. The detail header now uses the same rule (the role union, or `user_permission === 'write'` on that one secret). Share, Copy, Suspend, Delete, Transfer ownership and classification stay role-only, and a `read` share stays read-only. Nothing changes server-side: the API already authorizes the update.

### Documentation
- **Install with an AI assistant, secret-blind.** `INSTALL-WITH-AI.md` is one prompt plus guardrails and steps that any AI assistant can follow to install and configure a fresh, secure-by-default server: secrets are generated into 0600 files (`keyorix-server admin generate-secrets`) and passed by path, the assistant never reads them or asks for one, the steps that show a secret (MFA enrolment, an unencrypted recovery key) are the user's own, and the install ends with `keyorix-server admin validate --posture` (which also fails while the admin has no MFA). `docs/install/offline-install.sh` is the same procedure as a script for air-gapped hosts and local models. `llms.txt` and `AGENTS.md` point assistants at both. Every command and flag in the page and the script is checked against the real command trees (`TestInstallWithAICommandsExist`, `TestInstallWithAIAdminCommandsExist`).

### Testing
- `scripts/demo/check.sh` asserts that a fresh seed has exactly one gap (`secret-rotation`, "2 of 3 secrets covered"), no unknown/partial control and a green anomaly-detection control, and `web/e2e/real/pages.spec.ts` asserts the same on the real Compliance page and that the anomaly view lists no high-severity alert (the two UI tests run only when `check.sh` sets `KEYORIX_E2E_DEMO_SEED=1`).
- **Registry tables in `server/faultops` and `internal/core` are now one file per entry.** `knownOpenTolerances`, `opScopedBestEffortTables`, `effectThenErrorExtraExclusions`, `bestEffortTables`, `nonLoadBearingAuthzReadExceptions`, `oracleAByDesignErrors`, `mfaStepUpPurposeAllowlist` and the `FuzzCrossReplicaInvariants` seed list no longer live in one shared literal that every security PR appended to (216 merge conflicts in two days). Each row is its own `*_entry_<slug>_test.go` file registering itself from `init()`, kept in deterministic order, and a duplicate name or key panics at package init. Same entries, byte for byte; see `server/faultops/registry_entries_test.go` and `internal/core/registry_entries_test.go`.
- **`internal/faultstorage/faulty_storage_generated.go`:** the header now says to take main's version and regenerate on a merge conflict, and `.gitattributes` marks it `linguist-generated=true merge=ours` (`TestFaultyStorageGenerated_IsFresh` fails CI on drift).
- **e2e harness: `RewritePort` now really sets `server.http.port`.** Since #2946 the config template has comment lines between `enabled: true` and `port:`, so the harness's regex matched nothing, every e2e server kept the template's 8080 while the harness polled its own free port, and `e2e-smoke` timed out ("never became healthy"). The match is now anchored on the `server:` / `http:` structure, and a no-match is fatal instead of silent. Guarded by `TestRewriteHTTPPort_RealTemplate`.
- **`TestConcurrency_LoginAttempts_NoLostRecords` no longer flakes with SQLITE_BUSY (#3087).** The test now opens its database through `storage.OpenGormDB` (production DSN, pool cap and FIFO write gate) instead of a bare SQLite handle, so 100 concurrent `RecordLoginAttempt` writers are served in arrival order as on the server. The assertion (no writer errors, all 100 attempts counted) is unchanged. No product change: a failed record is already counted in memory by the auth-budget fallback.
- **Storage-fault fuzzer: three by-design tuples no longer turn CI red (#3091, #3093, #3094).** Oracle (d) now accepts an effect-then-error fault on a pure read (`GetUserPermissions`) only when a reviewed error-kind row opts in and the run leaves exactly that row's state (#3091, WebAuthn login finish). gRPC `UserService.CreateUser` `GetUserRoleScopes#1` and `UpdateUser` `GetUserRoleScopes#2` are post-commit project-count enrichment for the target user, so they are now pinned as non-load-bearing authz reads. New gRPC tests prove authorization fails closed before those reads (#3093). The seeds for #3091, #3093, #3094 and #3101 are committed as corpus, each with a counterfactual test showing it fails again without its rule.
- **Fuzz oracle (d) pure-read rule covers `GetUserRoles` (#3106).** REST `POST /auth/webauthn/login/finish` `GetUserRoles#1/effect-then-error` ends in the same reviewed state as its error kind, exactly as #3091 did for `GetUserPermissions`. The row opts in, the seed is committed, and the per-row guard drives both fault kinds and requires the same response and state.

### Internal
- Removed the now-unused `resolveOutboundIP` helper from `server/main.go` and its test.
- **web: js-yaml 4 -> 5.** `web/scripts/check-api-contract.mjs` now uses the named `load` export (v5 has no default export). `load` keeps its safe default schema (no `!!js/*` tags); the OpenAPI spec uses no merge keys, timestamps or binary tags, so parsing is unchanged.


### Security
- **HSTS behind a TLS-terminating load balancer** (#3058): the web nginx (compose
  image and Helm chart) sends `Strict-Transport-Security` only for a request from a
  configured trusted proxy (`KEYORIX_WEB_TRUSTED_PROXIES` / `web.trustedProxies`)
  that carries `X-Forwarded-Proto: https`; never for direct http, never on the say-so
  of an untrusted client. On by default once a trusted proxy is configured, off
  otherwise. See docs/SELF_HOSTING.md §7. Guarded by a real-nginx test
  (`deploy` `TestWebNginxHSTS_*`).
- **A database fault during login no longer reveals that the password, TOTP
  code or passkey was correct.** Every login path (password, TOTP, WebAuthn
  second factor, passwordless, re-authentication, MFA step-up) already answered
  a storage failure *after* the credential matched with the same response a
  wrong credential gets. The account's **lockout state** now matches too: the
  failed-attempt counter is cleared only once the login has actually been
  delivered, and a post-match failure counts as an attempt. Previously the
  counter was reset on the way to the failure, so an attacker at one attempt
  short of the lockout threshold could tell a correct password from a wrong one
  by whether the account locked. Audit logging distinguishes the two for
  operators — `auth.login_error` (the credential was right; a storage fault
  denied the login) versus `auth.login_failed` (a wrong credential) — and
  `/auth/mfa/verify` now writes `auth.login_error` for this case instead of
  nothing at all. Visible effects: a login denied by a transient storage fault
  now counts toward the per-account lockout, so a sustained database problem can
  lock accounts whose owners typed the right password; and the counter is reset a
  few milliseconds later in the request than before. A fault reading the
  account's roles after the password matched now also answers `401 Invalid
  credentials` instead of a distinguishable `500`. (#2894, #2888)
- **The bundled Caddy (`tls` compose profile) no longer runs as root.** It runs as
  uid:gid 65532 with only `NET_BIND_SERVICE`. A one-shot `caddy-init` service
  chowns the existing `caddy_data` / `caddy_config` volumes first, so upgrading
  an install whose Caddy volumes are root-owned needs no manual step and keeps
  its certificates. `caddy-init` runs with `CHOWN` + `DAC_READ_SEARCH` so a
  second run (Caddy's storage directories are `0700`) and an interrupted first
  run succeed; it touches only the two Caddy volumes and only entries not already
  owned by 65532. See `docs/SELF_HOSTING.md` §7.
- **Every `tmpfs` (compose) and `emptyDir` (Helm) now has an explicit size limit**
  (`size=` / `sizeLimit`), so a runaway writer cannot exhaust host memory or node
  ephemeral storage. The backend's `/tmp` (64 MiB) also stages `admin restore`.
- **The bundled PostgreSQL runs as the image's own uid, 70, in both compose and
  the Helm chart** (`postgres:15-alpine`; the Debian-based images use 999). Compose
  volumes were already owned by 70. **Helm upgrade note:** charts since v0.87.0 ran
  the pod as 999 even on the alpine image, so an existing chart-created volume is
  owned by 999 and the pod will not start (Postgres refuses a data directory it
  does not own). Either `--set postgresql.runAsUser=999` to keep the old owner, or
  `--set postgresql.migrateOwnership=true` for a one-time chown to 70 (opt-in: it
  adds a root init container with only `CHOWN` + `DAC_READ_SEARCH`, which a Pod
  Security "restricted" namespace rejects). Guarded by `deploy/hardening`, which
  ties compose user, chart securityContext and image flavour together. See
  `docs/UPGRADING.md` §5.
- **The shipped compose stack and Helm chart run with
  `security.enable_file_permission_check` on** (ADR-112 default): key material and
  the `*_FILE` secret files are checked strictly; the orchestrator-mounted config
  file only warns. Both configs omit the key on purpose, because an explicit `true`
  would also audit that root/host-owned file strictly. A `*_FILE` secret that is not
  key material follows the same upgrade grace period as the key files. Guarded by
  `deploy/hardening` `TestShipped{Compose,Helm}Config_FilePermissionCheckIsOn`.
- **Every secret the server reads from the environment now also accepts
  `<NAME>_FILE`** (Docker secrets, Kubernetes Secret volumes): the master
  password, DB password, bootstrap token, SMTP/SIEM/SCIM/webhook/SSO secrets and
  the operator-named KEK, Shamir-share, rotation-DSN and Vault-token variables.
  Setting both `X` and `X_FILE`, or pointing `X_FILE` at an unreadable or empty
  file, stops the server at startup; the value and the file contents are never
  logged. File permissions: the master password, KEK and Shamir-share files are
  **always refused** unless `0600`/`0400` (the key-material rule) -- the one
  exception is a group-readable file the running user does not own whose group the
  process holds (a Kubernetes Secret volume with `fsGroup`, a Docker secret with
  `group_add`); every other secret file follows
  `security.enable_file_permission_check` (refuse) / warn, and during the ADR-112
  upgrade grace period they only warn. The container
  entrypoint (`KEYORIX_ADMIN_PASSWORD_FILE`, `KEYORIX_BOOTSTRAP_TOKEN_FILE`) and
  `keyorix system init` resolve `_FILE` too, so a `_FILE`-only deployment
  auto-bootstraps; the entrypoint never exports a value read from a file (the
  server gets the `_FILE` path) and sends the bootstrap token in the request body,
  not on wget's command line. A file value has one trailing `\n`, then one `\r`,
  stripped (same bytes as `--passphrase-file`); the plain `KEYORIX_MASTER_PASSWORD` variable keeps
  its whitespace trim. See `docs/CONFIGURATION.md`.
- **New `server.http/grpc.tls_mode: strict` setting** (ADR-112, secure-by-default
  baseline, item 3) switches a listener to TLS 1.3 only, with no fallback to
  1.2. The existing default (TLS 1.2 floor, restricted to forward-secret AEAD
  cipher suites — unchanged by this release) remains compliant, not a
  downgrade to warn about: NIST SP 800-52 Rev. 2 requires servers to support
  both 1.2 and 1.3, and OT/legacy clients often still need 1.2. `tls_mode` is
  the opt-in upgrade for a deployment that can require 1.3-only clients.
  `tls.allowed_ciphers` has no effect under strict mode (TLS 1.3 negotiates
  its own suite set) and now warns if both are set.
- **Every break-glass activation must now be reviewed after the fact**
  (ADR-112, secure-by-default baseline, break-glass review item 5):
  `POST /api/v1/projects/{id}/break-glass/{activationId}/review` records who
  reviewed an activation, when, and a note — exactly once (a second attempt
  is refused, not a silent overwrite). The reviewer must be **someone other
  than the user who activated it**, and must be an attributable human (a
  machine identity cannot review), and the activation must have **concluded**
  first — a still-active grant has to be revoked or allowed to expire before
  it can be reviewed, since a reviewer cannot assess access that is still in
  use. Activation itself remains single-person, by design (an emergency path
  that needs a second person fails exactly when it's needed) — review is the
  separate, after-the-fact check that makes that safe, not a second approver.

  `break_glass.review_window` (default 72h) is how long an activation may go
  unreviewed before it is reported. Past that, it is counted as a deviation
  in the compliance posture report (`emergency_access.unreviewed_activations`,
  with the age of the worst outstanding one), and a recurring check logs a
  `SECURITY:` warning and writes a `break_glass.review_overdue` audit event
  — on startup and every 6h. That visibility is the whole of the
  enforcement: nothing is locked out, no grant is cut short, and no user is
  blocked, because an emergency path that can be disabled by unfiled
  paperwork fails exactly when it is needed.

  **Upgrade note:** break-glass activations recorded before this release have
  no review on file (`reviewed_at` is NULL), so immediately after upgrading
  every one of them older than `break_glass.review_window` is counted as
  unreviewed — the posture report's `emergency_access.unreviewed_activations`
  will jump, the "emergency-access" control will show a Gap, and the 6-hourly
  reminder will log and audit them until each one is reviewed. Retention will
  not clear the backlog for you — an unreviewed activation is never purged, no
  matter how old, deliberately, so retention cannot silently erase the
  deviation. They are also NOT backfilled as "pre-review-era": a synthetic
  review record would assert a second pair of eyes that never looked, which is
  exactly the claim this change exists to make true. Review the pre-upgrade
  activations (any user other than the activator with `roles.assign` at the
  project can) to clear the report. (#2461)
- **The server now refuses to start on an incomplete key-file set** (ADR-112,
  follow-up from #2400). #2400 made a single restore operation atomic (every
  file in a key-material set is either all written or none are); this adds the
  boot-time check for what that cannot cover — a set assembled across multiple
  operations. The encryption key files (salt, wrapped DEK, and any KMS/TPM
  wrapped-key blob or Shamir share files) must either all be present or all be
  absent. A partial set — the salt restored but not the wrapped DEK, say —
  refuses to start, naming every present and missing file.
  A second, **best-effort** check compares ages within each group of files one
  operation writes together (a Shamir provider's share set, in practice) and
  refuses when they differ by more than 24h. It is deliberately *not* presented
  as a mixed-generation guarantee, because mtimes cannot provide one: `cp`,
  `install`, `docker cp` and `kubectl cp` all stamp the destination with the
  current time, so a set hand-assembled from two different backups by the most
  common means shows no gap at all, and mtime is writable by anyone who can
  write the file. Issue #2900 tracks the real fix — a key-set manifest
  (generation id plus per-file hash) written atomically with the keys and
  verified at boot, which also covers the `.pending` rotation-staging files.
  The wrapped DEK is exempt from the timing check (routine DEK rotation
  legitimately rewraps it on its own schedule), and so is any comparison
  *across* groups: `rotate-kek` rewrites only the salt and DEK, so a deployment
  with a KMS/TPM/Shamir fallback keeps that provider's blob at its original
  age, which must not become a refusal to boot after an ordinary rotation.
- **`security.enable_file_permission_check` and `security.require_mfa` now
  default to the secure state** (ADR-112, secure-by-default baseline, item 1).
  A fresh install enforces file-permission/DEK-salt-size/database-reachability
  startup checks and admin MFA from its very first start, with no config
  changes needed; the first admin login asks for MFA enrolment. On the
  default, the encryption key material and database file are checked strictly;
  the config file and TLS cert/key (usually orchestrator-mounted) get a warning
  naming the file and the fix, and an explicit `true` makes those strict too.
  **Upgrade note:** an existing deployment (its database already has users)
  that never set `enable_file_permission_check` keeps booting during a grace
  period: a real file-permission or startup-validation problem logs a loud
  `ADR-112` warning naming the setting and how to comply, instead of refusing
  to start. The grace period ends for good at the first boot whose checks pass
  (or when the key is set explicitly). `require_mfa` on such a deployment is
  also in a grace period: not enforced yet, with a loud start-up warning on
  every boot until the key is set explicitly. On a fresh install a
  session-authenticated user without MFA is confined to the enrolment
  endpoints until they enrol (non-interactive PAT/machine credentials are
  unaffected). An explicit
  `enable_file_permission_check: true` keeps its exact pre-upgrade behavior,
  including refusing to start when the key material is missing.
- **`keyorix mfa enroll` / `keyorix mfa activate`**: the CLI can now enrol a
  TOTP factor (secret + otpauth URI, then confirm with a code and the account
  password; prints one-time recovery codes). With `require_mfa` on, this is
  how a CLI-only operator gets past the first-login enrolment confinement;
  `keyorix login --mfa-code` completes later logins.
- **16 security-weakening settings renamed to an `insecure_` prefix** (ADR-112,
  secure-by-default baseline, item 2, part 3) —
  `security.allow_unsafe_file_permissions`, `security.login_lockout.disabled`,
  `security.recover_admin.keyless_mode`,
  `audit.siem.allow_private_network_target`/`allow_insecure_transport`,
  `evidence_delivery.webhook.allow_private_network_target`/`allow_insecure_transport`,
  `notifications.webhook.allow_private_network_target`/`allow_insecure_transport`,
  `dynamic_secrets.allow_private_network_targets`/`allow_insecure_transport`,
  `storage.encryption.key_provider.kms_allow_context_fallback`/`allow_weaker_fallback`,
  `sso.providers[].trust_asserted_email`,
  `sso.providers[].saml.allow_idp_initiated` and `audit_checkpoints.disabled`.
  **Upgrade note: every old name still works exactly as before.** It is a
  deprecated alias, not a removal — the raw YAML is rewritten before the strict
  decode, so nothing changes except that using an old name now logs a start-up
  warning naming its replacement. Setting both names is not ambiguous: the new
  one wins and a "both set" warning fires. The two key-provider settings are
  also aliased **inside the `fallbacks:` chain**, where a config file using the
  old name previously hit the strict decode's unknown-field check and the
  server refused to start instead of warning.
  Not renamed: the fourteen settings tracked in #2895, each of which needs a
  polarity inversion or a non-boolean field restructured first.
- **Every security-weakening setting is now registered, warned about and
  audited** (ADR-112, secure-by-default baseline, item 2 — the opt-out rule).
  `internal/config.InsecureSettingsRegistry` is the single enumeration of all
  33 of them (32 plus the fast-audit opt-out from ADR-112 Amendment 1); three things read it, so nothing has to be wired up per setting:
  a start-up **warning** for every one currently in effect, a start-to-start
  **settings diff** that writes an audit event (old value → new value) for any
  of them that changed between two starts of the same deployment, and the
  posture report. Nothing is renamed yet and no behaviour changes for an
  existing config file: each entry records the `insecure_`-prefixed name it is
  *heading for* alongside the real key it reads today, and the literal YAML
  renames land as their own small follow-ups, each keeping the old key working
  as a warning-logging deprecated alias.
  A **sweep of the whole config surface** (`insecure_settings_sweep_test.go`)
  is what keeps the registry honest: a setting whose name reads as an opt-out
  and that no entry covers fails CI by name, and a set ratchet over every
  leaf setting fails on *any* config addition, removal or rename — because seven of the registered
  weakenings (`membership.validation_mode`, `storage.database.ssl_mode`,
  `credential_delivery.mode`, the SMTP/email `tls` enums, `metrics_token`,
  `max_request_body_bytes`) have names no pattern list can recognise. Thirteen settings that cannot be renamed
  mechanically — each needing a polarity inversion of a load-bearing flag, or
  a non-boolean field restructured into a real boolean — are recorded as known
  exceptions with an owning tracking issue, and are covered by the warning,
  the audit diff and the posture report under their current names meanwhile.
- **New `keyorix-server admin validate --posture` command** (ADR-112,
  secure-by-default baseline, item 4) reports every secure-baseline deviation
  in one place and exits non-zero if any is found. **Every security-weakening
  setting in effect counts**, whatever stage its `insecure_` naming is at:
  encryption-at-rest disabled, database TLS disabled, unauthenticated
  `/metrics`, log-delivered setup links and the rest are deviations because of
  what they do, not because of what they are called. The report also covers
  `security.enable_file_permission_check` disabled outright, a real
  file-permission / encryption / database problem, an incomplete key-file set
  (item 6), an enabled listener with no TLS while
  `security.require_transport_tls` is set, and an admin-tier holder with
  neither TOTP MFA nor a passkey enrolled. `security.require_mfa: false` is a
  deviation, and so is an upgraded deployment still in `require_mfa`'s ADR-112
  grace period (the server does not enforce MFA there yet, even with every
  admin enrolled). A grace-period setting (item 1)
  still enforcing only via its new secure-by-default value, with the underlying
  condition it covers still non-compliant, is reported as its own deviation
  referencing the detail above it. Each deviation is labelled with whether it
  comes from a **shipped default** or an **explicit** config choice (whether
  the config file literally writes the key), so an
  operator can tell "this install has not been hardened yet" from "someone
  turned this off" — but both count toward the exit code. Only genuinely
  non-judgemental facts are informational: TLS mode, and the KEK salt file's
  age (no rotation-age threshold is defined anywhere in this codebase, so a
  number here would be a guess).

## v0.95.3 — 2026-10-01

### Security
- **Last-admin guard on group deletion is now race-free.** Deleting a group
  concurrently with deleting a user could remove the last administrator; both
  operations now serialize on the same lock (an advisory lock on Postgres, an
  in-process lock on SQLite). Under heavy contention a deletion can now fail
  with a lock timeout instead of racing. (#2348)
- **Deleting an environment can no longer orphan a secret created at the
  same moment.** Secret creation, folder creation and secret restore now take
  the same per-environment lock as environment deletion and re-check that the
  environment still exists. A create against an environment that was just
  deleted returns "not found" (not a server error). (#2353)
- **Machine identity revoke/suspend always takes effect immediately.** If the
  post-revoke cache eviction fails, every machine token in the auth cache is
  now flushed instead of the revoked one staying cached for up to 30s, and
  the call reports success (the revoke had already committed). The flush no
  longer locks out unrelated machine identities. (#2349)
- **`POST /auth/logout` on an already-invalidated session returns 401, not
  500.** (#2337)
- **More operations write audit events:** alert-escalation-policy changes,
  every on-demand admin job (including runs that find nothing to do),
  compliance evidence verification and posture snapshots, and 13 further
  operations found by the audit-completeness fuzzer, including bulk secret
  owner reassignment and bulk rotation. (#2249, #2252)

### Added
- **`keyorix-server admin recovery-key rotate --recipient <age1… key | ssh-ed25519 public
  key file>`** prints (or, with `--output <file>`, writes) the new recovery
  key only encrypted to that recipient; the plaintext key is never shown. The
  recipient is validated before the key is generated. (#2257)
- **New `alerts.write` permission and `alert_operator` built-in role** (ADR-110
  follow-up): notification-channel/escalation-policy management and 5 of the 11
  `/admin/jobs` on-demand triggers (the ones that only emit/dispatch a
  notification AND carry no compliance/audit-derived data — rotation/expiry/
  token-expiry reminders, role-expiry-check, check-read-quotas) moved off
  `system.write` onto this narrower permission. `system.write` remains a
  strict superset: existing holders keep access via a one-time backfill on
  upgrade. `record-hygiene-snapshot`, `suspend-inactive-users`, and
  `purge-audit-logs` stayed on `system.write` (they mutate account/data state,
  not just send a notification); `anomaly-alerts`, `compliance-digest`, and
  `run-alert-escalation` also stayed on `system.write` despite being
  notification-only, because they all dispatch anomaly/compliance-derived
  data and an `alert_operator` could point a notification channel at a URL
  they control to exfiltrate it (an SSRF path from air-gapped hosts too). See
  `docs/adr-110-system-write-scope.md`'s Decision section for the full
  per-route table. (#2244)

### Fixed
- **Deleting a custom role now also removes its user, group and machine
  role assignments, its permissions and its connector ref grants**, in the
  same transaction. Previously these rows were left behind. They granted
  nothing (authorization always checks the live role), but they cluttered
  exports and listings. Break-glass and access-review history keep their
  references by design. (#2357)

### Testing
- End-to-end customer-journey suite (application reads a secret, access
  control, audit trail, Vault/OpenBao migration, Keycloak SSO, disaster
  recovery) runs against the real server and CLI binaries: the fast tier in
  the merge queue, the container tier nightly. (#2338, #2339, #2341–#2344,
  #2355, #2358)

## v0.95.2 — 2026-09-30

### Added
- **`admin backup`/`admin restore` now support Postgres, in addition to
  SQLite** — the same commands, same archive format, on either backend.
  Backup reads through a single `REPEATABLE READ` snapshot transaction by
  default on Postgres (`--exclusive` opts into the same host-level lock a
  SQLite backup always holds). The archive itself is a new backend-neutral
  logical format: a streaming, table-by-table snapshot with an
  HMAC-signed manifest (KEK-derived key), rather than a raw database-file
  copy — checksums catch corruption, the signature catches tampering a
  checksum alone can't. Restore still reads an archive from the previous
  (SQLite-only, physical-copy) format, with a deprecation notice, until
  Keyorix 1.0. Moving a deployment from SQLite to Postgres, and restoring a
  backup taken on a much older release, are both just this same restore
  command pointed at a different target — no new subcommand, no separate
  migration tool. See `docs/SELF_HOSTING.md` §5.
  (#2261, #2263, #2270, #2280, #2284, #2288, #2291, #2293)

### Security
- **`admin restore` now refuses to restore a backup that is behind this host's
  own audit trail, by default.** Restoring an older backup than the host has
  already progressed past could silently undo any revocation recorded since
  (a suspended account, a deleted machine credential, a rotated role grant) —
  the restored database simply doesn't know it happened, and `verify-audit`
  reported the restored (shorter, self-consistent) chain as `VALID` either
  way. Restore now compares the archive's own certified audit-trail progress
  against a host-local witness file before writing anything to disk, and
  refuses if the archive is behind; pass `--allow-rollback` for a genuine
  disaster-recovery restore of an intentionally older backup, which writes an
  explicit audit event recording the override. See `docs/SELF_HOSTING.md` §5.
- **Removed the dead `verify-credentials`/`verify-mfa`/`mfa-challenge` HTTP
  endpoints.** These existed only to serve `storage.type: remote`, removed
  entirely in ADR-108 Phase 6 — the routes had no remaining legitimate caller
  but stayed live, gated only by `users.write`. (`c8bcf9dd`)

### Fixed
- **Seven tables with live handler code were never migrated on any
  install** (secret version comments, notification channels, alert
  escalation policies, secret templates, MFA step-up tokens, hygiene-trend
  snapshots, compliance-posture snapshots) — every fresh install 500'd on
  first use of any of them. Fixed for fresh and upgraded installs alike.
  (`0b6bb65a`)


### Changed
- **The air-gapped build profile ships, and the published air-gapped image
  is renamed** `keyorix-server-lean` → `keyorix-server-airgap`. Operators
  pulling the air-gapped image must update their image reference. (`2bc79ce2`,
  `ddadf47c`)

### Added
- `keyorix-migrate vault scan` — a free, strictly read-only health check for an existing Vault
  (or OpenBao) install: version/EOL, seal configuration, audit devices, auth methods, policy
  sprawl, TTL hygiene, secrets-engine inventory, TLS listener config, and a "migration readiness"
  summary. Ships in the same `keyorix-migrate` binary. See `docs/vault-health-scan.md`.

## v0.95.1 — 2026-09-27

### Security
- **Admin-rank ceiling now fails closed on a storage error.** A transient DB error while
  resolving a target's or actor's roles during a privileged user mutation (delete,
  update, suspend, revoke sessions — over REST and gRPC) used to be treated as
  permission-granted; it now refuses the action. High severity: this let a
  lower-privileged actor act on a higher-privileged user's account during the error
  window. Found by `FuzzStorageFaultOperations`. (#2201)
- **Dynamic-secret lease renewal/sweep now enforces an anti-rollback watermark** against
  clock jumps (NTP correction, VM pause/resume, manual clock changes), closing a window
  where a backwards time step could let an expired lease be renewed or an active lease
  swept early. (#2186)
- **Login-throttle budget is now reserved by `ConsumeSetup` and
  `BeginWebAuthnPasswordlessLogin`**, closing two authentication paths that could be
  hammered without counting against the same per-account throttle every other login path
  already respects. (#2190)
- **SSRF guards now validate every host in a multi-host PostgreSQL admin DSN**, and decode
  6to4/Teredo/NAT64-local-use IPv6 encodings of an embedded IPv4 address (extending the
  existing NAT64/IPv4-compatible decoding already used by the SIEM forwarder and
  notification-channel webhook guards). Previously, a bracket-quoted IPv6 host anywhere in
  a comma-separated failover DSN skipped SSRF validation entirely, even though the
  Postgres driver would still dial it. (#2197)
- **Auth-cache negative tombstones are no longer written on a benign account-state
  transition** (e.g. reactivating a suspended user). Previously, any state transition
  evicted every one of the account's session/PAT hashes from the auth cache via a
  short-lived negative tombstone — including on reactivation, where a credential created
  while suspended (never cached before) could be spuriously rejected as "invalid or
  expired" for up to the tombstone TTL after the account came back. (#2206)
- **Removed the dead `verify-credentials`/`verify-mfa`/`mfa-challenge` HTTP endpoints.**
  These existed only to serve `storage.type: remote`, which was removed entirely in
  ADR-108 Phase 6 — the routes had no remaining legitimate caller but were still live and
  gated only by `users.write`, making them an unnecessary credential/MFA-testing oracle
  for any holder of that permission. (#2212)
- **Installs bootstrapped before v0.95.0's ordering fix now self-repair on first upgrade.**
  See "Fresh-Postgres bootstrap" below (#2188) — that fix only prevents the bug on *new*
  installs. A one-time startup reconcile now grants the missing `system_viewer` baseline
  role to any existing user who never got it, on every backend, the first time a
  pre-v0.95.1 install starts up after upgrading. It runs exactly once (a
  `system_metadata` completion marker prevents any later run), and skips a user whose
  audit trail shows an admin deliberately removed the role, or who was JIT-provisioned via
  SSO with a different configured baseline role — it repairs the ordering bug only, never
  overrides a deliberate choice made since. **Known limitation:** if audit-log retention
  has already purged an admin's `role.removed` event for a given user before this reconcile
  runs, that removal history is no longer visible to it, and the user is re-granted
  `system_viewer` once on this one upgrade despite having been deliberately removed —
  re-remove it if this applies to your install. (#2195)

### Fixed
- **Fresh-Postgres bootstrap no longer logs `"user 1 (admin) created without its baseline
  system_viewer role: Role not found"`.** The bootstrap admin user was created before the
  baseline RBAC role catalog was seeded — on every backend, not just Postgres — so the
  admin silently never got the `system_viewer` grant. Roles are now seeded first. (#2188)

### Added
- **Published `keyorix-server`/`keyorix-web` Docker images now include a `linux/arm64`
  manifest** alongside `linux/amd64`. `docker compose up` previously failed outright on
  Apple Silicon and arm64 servers (e.g. AWS Graviton) with "no matching manifest for
  linux/arm64/v8". (#2187)
- **`keyorix-migrate` is now a published release binary** (linux/darwin × amd64/arm64,
  each with its own SBOM and a `keyorix-migrate version` command), instead of requiring a
  source build to run the Vault/OpenBao migration tool. (#2189, #2200)
- **A CI job dry-runs the full release process** — `make release` plus a no-push
  multi-arch Docker build — on every PR touching release-relevant files, and weekly, so a
  release-day failure like the ones fixed above is caught before tagging. (#2185)

### Documentation
- **`.env.example` and `docs/SELF_HOSTING.md` now document `KEYORIX_BOOTSTRAP_TOKEN`**,
  required alongside `KEYORIX_ADMIN_PASSWORD` for the first-boot admin auto-bootstrap —
  previously, omitting it silently skipped admin creation with no visible error.
  `server/entrypoint.sh` now logs a clear `WARN` when this happens. (#2184)

## v0.95.0 — 2026-09-27

### Added
- **`keyorix machine grant-role` / `revoke-role` / `roles`** — grant, revoke,
  and list a machine identity's project-scoped role grants. The REST
  endpoints (`POST`/`DELETE .../machine-identities/{id}/roles`, and a new
  `GET` for listing) already existed (ADR-030); previously the only way to
  give a machine identity access to anything was a hand-crafted authenticated
  HTTP call. See [`QUICK_START.md`](QUICK_START.md#giving-a-machine-ciapp-access)
  and [`docs/operator/demo.md`](docs/operator/demo.md) step 5.
- **`keyorix change-password`** — self-service password change
  (`POST /auth/change-password`), so the documented lost-admin recovery flow
  (`docs/operator/j5-lost-admin.md`) needs no raw `curl` call to finish
  setting a real password after logging in with `recover-admin`'s printed
  one-time password.

### Changed
- **BREAKING: `keyorix` is now the new, thin, REST-only CLI (ADR-108 Phase 5).**
  The old, thick CLI's **local/embedded mode — opening the database directly,
  with no server involved — is gone from the released `keyorix` binary.**
  Every command now talks to a running `keyorix-server` over the network;
  `keyorix login` replaces `keyorix connect`. Host-side operations that used to
  be `keyorix system init` / `keyorix system audit` / `keyorix system validate`
  / `keyorix encryption ...` are now `keyorix-server admin init` / `admin
  audit` / `admin validate` / `admin encryption ...` — see
  [`docs/cli-migration.md`](docs/cli-migration.md) for the full old-command ->
  new-command table. **The old CLI's source (`internal/cli`, `make
  keyorix-legacy`) is now removed entirely (ADR-108 Phase 6)** — rollback to
  the old CLI means checking out a commit before this removal, not a build
  flag.
- **BREAKING (opt-out available): the `keyorix`, `keyorix-k8s-sync`, and
  `keyorix-operator` Helm charts now default to a deny-by-default egress
  `NetworkPolicy`** on top of the existing ingress restrictions
  (`networkPolicy.egress.enabled`, default `true`). Pods can now only reach
  DNS and their known peers (bundled Postgres, the Kubernetes API server, the
  configured Keyorix server) — a server-side integration that dials out on
  another port (SMTP, syslog/SIEM forwarding, LDAP, a checkpoint notary/TSA,
  a secret-rotation backend, a webhook sink, a non-default external Postgres)
  needs a `networkPolicy.egress.extraRules` entry added *before* upgrading, or
  it silently stops working — a NetworkPolicy drop is a connection timeout,
  not an error. Set `networkPolicy.egress.enabled: false` to opt out. See
  each chart's README "Upgrading: egress NetworkPolicy" section. (#2102)
- **BREAKING: several REST endpoints now return `snake_case` field names**
  instead of the Go struct's raw `PascalCase`, matching the documented wire
  convention. Secrets (`GetSecret`, `ListSecrets`, secret sharing, and the
  rest of the `SecretNode` family) are fixed in this wave (#2098); projects,
  roles, shares, and machine identities are the same class of fix and follow
  in subsequent PRs before this reaches a release. A client reading the old
  PascalCase keys (`ID`, `ProjectID`, `IsShared`, ...) off any of these
  routes needs to switch to the snake_case equivalents.

- **`keyorix-server-lean` is replaced by `keyorix-server-airgap`** (ADR-109
  step 6). The new AIR-GAPPED release variant (`-tags noaws,noazure,nogcp`)
  excludes every AWS/Azure/GCP SDK package (0 remaining, enforced by
  `scripts/airgap-dependency-guard.sh`) — Vault and Kubernetes stay, since
  on-prem Vault read-through and on-prem k8s are legitimate air-gapped uses.
  The old `lean` variant only ever excluded the AWS IAM rotation backend and
  the S3-compatible evidence sink (131 cloud SDK packages remained) — a
  narrower, different exclusion this release replaces rather than aliases. A
  `<ver>-airgap` image tag is also now published alongside the full
  `keyorix-server` image.

### Removed
- **The `/system` server-to-server proxy route tier is gone (ADR-108 Phase 6
  step 14c).** These 151 `...Proxy`-suffixed routes existed only to let a
  downstream Keyorix server booted with `storage.type: remote` (ADR-049)
  proxy requests to this server's real storage backend — with `RemoteStorage`
  and the old CLI's embedded mode both already removed, nothing could reach
  them. A misconfigured `storage.type: remote` now fails loudly at startup
  instead of silently doing nothing. The 5 routes actually used by the web
  dashboard and first-boot setup (`/system/info`, `/system/metrics`,
  `/system/auth-config`, `/system/encryption-config`, `/system/init`) are
  untouched — they were never part of this tier.

### Known gaps
- **Sharing a secret requires both the owner and the recipient to already hold
  an explicit role in the secret's project** — holding the global `admin` role
  from bootstrap is not enough, and `share create` fails with a bare `HTTP 403`
  and no explanation if either grant is missing. Documented in
  [`QUICK_START.md`](QUICK_START.md#sharing) and exercised by
  `scripts/smoke.sh`; not yet fixed at the API layer.

## v0.94.0 — 2026-09-17

### Security
- Bumped `digitorus/pkcs7`/`digitorus/timestamp` off a pinned 2023 commit
  carrying two BER-parser defects found by fuzzing and disclosed to the
  maintainer: a memory-exhaustion amplification (~130B input → ~1.8GB
  allocation) and an unrecovered index-out-of-range panic. Both are fixed
  upstream as of 2026-09-14. The strict-DER framing guard added in v0.92.1
  (#1848) already shielded both timestamp-parsing paths and stays in place
  as defence-in-depth; this removes the remaining reliance on that single
  mitigation by dropping the vulnerable dependency itself. (#1895)
- **A crash during DEK rotation could make every re-encrypted secret
  permanently undecryptable.** `RotateDEKWithSweep`'s re-encryption sweep
  commits the database under the new DEK, then renames the new key into
  place on disk; a crash (power loss, SIGKILL, OOM) in the window between
  that commit and the rename left the database encrypted under a key that
  existed only as a "pending" file, which startup's cleanup unconditionally
  deleted — total, unrecoverable loss of every secret touched by the
  rotation. Found by a new crash-consistency fuzzer
  (`FuzzDEKSweepCrashConsistency`) that interrupts the real rotation at
  each durability checkpoint. Fixed with a write-ahead redo marker plus
  recovery-on-startup (ADR-010 addendum): the marker becomes durable
  atomically with the re-encrypted rows, and startup promotes the pending
  key before initializing whenever the marker is present. (#1918)

### Fixed
- The login page threw `crypto.randomUUID is not a function` and blocked
  sign-in entirely over plain HTTP — `crypto.randomUUID()` is only defined
  in a secure context (HTTPS or localhost), which plain `http://<LAN-IP>`
  is not. Added a `crypto.getRandomValues()`-based UUIDv4 fallback, used by
  every caller. (#1882)
- The admin Users page rendered seven org-wide compliance sections (stale
  accounts, token hygiene, secret-hygiene debt, and more) above the actual
  user list on a page titled "User Management." The user list now sits
  directly under the header. (#1885)
- The dashboard's Security Alerts panel rendered every open anomaly inline
  — routinely hundreds — breaking the page layout. Capped to the 5 most
  recent, with a link to the full paginated view. (#1883)
- Creating a group could fail with a generic error that hid the real
  cause: untrimmed whitespace in the name tripped the server's identifier
  validator, and the modal never surfaced the server's actual message.
  Separately, the groups list read the wrong field from the API response
  and always rendered empty even when the group existed. Both fixed. (#1886)
- The Projects page's "Recent" section was based on last-*updated* time,
  not actual access — with a small project count this put most projects
  under "Recent" and the rest under "All Projects," backwards from what
  the sections imply. "Recent" is now based on the projects a user has
  actually opened. (#1887)

### Added
- Edit/rename a project's name and description from the projects list or
  the project page, without opening Settings. (#1884)
- Audit page: the RBAC Events tab now matches the real role/group/
  permission event types (it previously matched a non-existent prefix) and
  resolves actor/target ids to names at display time. The Projects list
  gained an explicit sort control; Service Accounts now shows an honest
  "under construction" state instead of an error, since the standalone
  backend isn't built yet; the roadmap page reflects current shipped
  state. (#1888)

### Changed
- Migrated the MongoDB dynamic-secrets engine and rotation executor off
  the deprecated `mongo-driver` v1 to v2. No behavior change; the existing
  SRV/dialer egress guards (G48) are preserved under the new driver. (#1881)

## v0.93.0 — 2026-09-14

### Security
- **Human SSO logins now use PKCE (RFC 7636, S256).** The OIDC
  authorization-code flow generates a per-login code verifier, sends its S256
  challenge on the authorization request, and replays the verifier on token
  exchange — defense-in-depth against authorization-code interception, on top
  of the existing confidential-client and single-use login-state protections.
  A login already in flight when you upgrade completes normally. (#1875)
- **SSO/OIDC/WebAuthn trust-seam hardening.** OIDC JWKS and discovery fetches
  are now guarded against resolving to link-local addresses (e.g. cloud
  instance-metadata endpoints); `allow_idp_initiated` is rejected at config
  validation, since Keyorix has no SAML replay cache to make it safe; a
  human-SSO provider's client ID can no longer double as a machine-federation
  audience on the same issuer; and WebAuthn relying-party origins are
  validated at startup. No auth bypass was found in the affected code — this
  closes narrow defense-in-depth gaps from an adversarial review. (#1874)
- **IdP-driven role auto-grants (SSO group mapping, SCIM) are now gated on the
  granted role's actual permissions, not its name.** The SSO and SCIM paths
  previously checked for an admin role by name or bypass flag; a custom role
  bundling the role-assignment permission under a non-canonical name could
  turn a self-service IdP group into an unchecked privilege path. Both paths
  now derive the ceiling from the role's real permission tier. (#1876)
- **The KEK-derivation PBKDF2 iteration count is now a single source of
  truth.** It previously lived as two independent `600000` literals with
  asymmetric guards; raising one without the other would have made
  `rotate-kek` fail closed with a confusing "old passphrase incorrect" error.
  No data-loss or exposure risk existed, but the two values can no longer
  drift apart. (#1877)
- **A session's positive auth-cache entry can no longer outlive the session
  itself.** The cache TTL was a flat 30 seconds regardless of the session's
  own expiry, so a session that expired server-side could keep authenticating
  on cache hits for up to 30 seconds afterward (revoke/logout/suspend were
  already immediate). The cache entry is now clamped to the session's own
  expiry. (#1878)
- DAST/security-header fixes: added the missing
  `X-Permitted-Cross-Domain-Policies: none` header and scoped the DAST scan to
  the web app instead of the CI runner host (#1860); normalized nuclei's SARIF
  `executionSuccessful` field so a clean scan no longer reports as a tool
  error in GitHub Code Scanning (#1862); and excluded the HSTS matcher from
  the plaintext DAST scan, since Keyorix correctly omits HSTS when TLS isn't
  terminated (#1863).

### Changed
- **New `lean` build tag drops the AWS IAM/S3 SDK footprint (~14% smaller
  binary) for installs that don't use the `aws-iam` rotation backend or the
  S3-compatible evidence sink.** Both features fail loudly, rather than
  silently, if a lean binary is deployed against a config that still names
  them. (#1865)
- **Release binaries and container images are now built with `-s -w`
  (stripped symbols/DWARF), shrinking `keyorix-server` from ~92MB to ~62MB.**
  Version/commit metadata injected via ldflags is unaffected; local
  `make build-*`/`make dev` builds keep full symbols for debugging. (#1864)

## v0.92.1 — 2026-09-12

### Security
- **RFC 3161 timestamp tokens are now validated as strict DER before decoding.**
  A malformed timestamp token (or TSA response) could previously drive the
  CMS/BER decoding path into excessive memory allocation on the notary verify
  path (audit-checkpoint anchoring and receipt verification). Keyorix now
  rejects any token that is not well-formed, definite-length DER — with bounded
  nesting depth and node count — before it reaches the decoder, closing that
  denial-of-service vector while still accepting every spec-compliant token
  (RFC 3161 §2.4.2 requires DER). (#1848)

### Fixed
- **Keyorix v0.92.0 could not start against an existing PostgreSQL database.**
  A migrations/audit startup ordering problem prevented boot against a
  pre-existing Postgres schema; upgrades against an existing database now boot
  cleanly. (#1850)
- Dependency updates: Go module patch group (#1855), npm patch group (#1858),
  and `sigs.k8s.io/controller-runtime` 0.24.1 → 0.25.0 (#1853).

## v0.92.0 — 2026-09-10

> **Scope note.** `v0.88.0` through `v0.91.0` were tagged without changelog
> entries, so everything below covers the whole range since `v0.87.4`
> (2026-07-07), not just the last tag. The full commit list is at
> https://github.com/keyorixhq/keyorix/compare/v0.87.4...v0.92.0 — this section
> is the curated subset an operator upgrading needs to read.

### Changed
- **gRPC is now labelled, in the product itself, as a partial data-plane
  interface — not an HTTP-equivalent API.** It exposes 13 services / 86 RPCs
  against 151 HTTP handler files, and the governance surface (classification,
  descriptions, access reviews, legal hold, SoD, anomaly configuration) is
  HTTP-only today. Nothing about the runtime changed: enforcement was already
  transport-agnostic, and the real risk was never a bypass but *silent
  under-configuration* — an object created over gRPC lands in the
  least-governed state, and until now nothing said so. `configs/keyorix.yaml.tpl`
  carries the notice, and `docs/adr-105-grpc-scope-and-parity.md` is the record.
  Field numbers 11–20 on `CreateSecretRequest` are reserved for the planned
  governance fields, so a future addition cannot collide with a number already
  spent.
- **API definitions become proto-first
  (`docs/adr-106-proto-first-api-definition.md`, supersedes ADR-074 decision 1).**
  Where two transports must agree, the agreement is generated rather than
  maintained by hand. Nothing is regenerated by this release; it sets the
  direction for the next transport change.
- **`storage.type: remote` (CLI-against-server) is documented as
  work-in-progress**, with a per-area coverage table derived from the source
  rather than hand-counted, and a test that fails when the documentation drifts
  from the code (`docs/REMOTE_CLI_SETUP.md`). Local/embedded mode — the default,
  and the single-machine and air-gapped story — is unaffected.
- **`QUICK_START.md` rewritten.** The previous version documented four commands
  that could not work, including `share create --recipient <email>` (the flag is
  `--recipient-id`, and it takes a numeric id) and a `docker-compose` file that
  does not exist in the repository; it also omitted `KEYORIX_MASTER_PASSWORD`,
  without which the default passphrase provider hard-fails, and never mentioned
  `keyorix system init`, which is the actual first step. Every command in it is
  now checked against the real cobra command tree by
  `internal/cli/quickstart_commands_test.go`, and the documented flow is
  *executed* end to end by `make smoke`.
- **BREAKING: `keyorix run` no longer injects secrets by default (#1816)** —
  every invocation must now pass `--var NAME=secret-ref` (recommended,
  repeatable — you choose the env var name for each secret) or the deprecated
  `--derive-names` (restores the old behavior: every secret in the project +
  environment is injected, with the env var name auto-derived from the
  secret's own name). Previously, whoever could **name** a project secret
  also controlled which env var it became in the launched process — including
  reserved ones like `LD_PRELOAD` or `DYLD_INSERT_LIBRARIES` — not just its
  value; see #1813 for the live PoC this was found with. If you have scripts,
  CI jobs, or Dockerfiles that call `keyorix run` with no `--var`/`--derive-names`
  flag, they will now fail fast with a clear error naming both options —
  update them to `--var` (preferred) or add `--derive-names` to keep the old
  behavior for now. Collision precedence also changed for the deprecated
  `--derive-names` path only: a derived secret name no longer overrides a
  value already present in the inherited environment (the inherited value
  wins instead) — a second, independent guard alongside the existing
  reserved-name filter (#1813). `--var`'s explicit names still override the
  inherited environment on collision, since that's the operator's expressed
  intent. See `keyorix run --help` and
  https://github.com/keyorixhq/keyorix/issues/1816 for the full reasoning.
- **BREAKING: `keyorix status` and `keyorix ping` now exit non-zero when the
  configured target is unhealthy or unreachable** — previously both commands
  always exited 0 regardless of what they found, reporting failure only via
  printed text ("❌ Unhealthy" / "❌ Failed"), so a script checking `$?` after
  either command could never detect an outage without parsing stdout. If you
  have automation that runs `keyorix status` or `keyorix ping` and previously
  ignored their exit code, verify it doesn't need to accommodate the new
  non-zero results. Full exit code contract below.
- **BREAKING: `keyorix status`/`keyorix ping` no longer construct or create
  anything when nothing is configured.** With no `keyorix.yaml`, no
  `KEYORIX_CONFIG_PATH`, and no `keyorix connect`/env-var remote target,
  `status` used to silently build an in-memory `storage.type: local` config
  on the spot and initialize storage against it — which, for a fresh
  `./secrets.db` path, **created the file**, then reported "Healthy" for a
  database the command had just created a moment earlier. That was a
  false-success pattern, not a graceful default. "Not configured" is now a
  first-class state distinct from "unhealthy": nothing is constructed,
  nothing is created, and the command exits 2 (usage/config error) — a
  script chaining `keyorix status && deploy` will no longer proceed on an
  unconfigured machine. An explicit `storage.type: local` config whose
  database file doesn't exist yet is now also reported as unhealthy (exit 1)
  rather than silently provisioned — `status` verifies an existing store, it
  doesn't create one. `status`/`ping` exit codes: 0 healthy, 1
  unhealthy/unreachable, 2 usage/config error (no config, or `ping` without
  remote storage configured).
- **BREAKING (targeting v0.92.0): every Keyorix Connect connector must declare
  `scope: project` or `scope: platform` (ADR-082)** — an existing deployment with
  `connect.enabled: true` and one or more configured connectors **will fail to boot**
  after upgrading unless every connector in `connect.connectors` gains an explicit
  `scope:` (and `project:` when `scope: project`). **There is no escape hatch and no
  deployment-wide bypass** — adding `scope:` to an existing connector takes minutes,
  and an unscoped connector would deny every read anyway once ownership enforcement
  evaluates it (see below), so a bypass would only defer the failure from boot time
  to read time, not restore access. Connector ownership is enforced on the read path
  as of this same change: a caller must be a member of the connector's owning
  project (or hold a matching `ConnectRefGrant`) to read through it — see
  `docs/adr-082-connect-connector-tenant-scoping.md`.
- **BREAKING (targeting v0.92.0): every `gcp-secret-manager` Keyorix Connect
  connector must set `project_id` (#431)** — an existing deployment with
  `connect.enabled: true` and one or more `gcp-secret-manager` connectors **will
  fail to boot** after upgrading unless every such connector gains an explicit
  `project_id`. Previously, an unset `project_id` only logged a startup warning and
  let the connector boot unpinned — since a GCP Secret Manager ref embeds its own
  project ID (unlike Vault's `address` or Azure Key Vault's `address` vault URL,
  which each already pin the connector to one backend), an unpinned connector could
  read a secret from **any** GCP project the ambient ADC identity can reach,
  regardless of which Keyorix project/scope (ADR-082) the connector itself is bound
  to — a confused-deputy gap. **There is no escape hatch**: add `project_id: <your
  GCP project>` to every `gcp-secret-manager` connector before upgrading (see
  `docs/CONFIGURATION.md`'s Keyorix Connect section for the exact field). The
  project-pin is now enforced twice — once at config-load time
  (`validateConnectGCPProjectID`) and again at read time inside
  `GCPSecretManagerConnector.GetSecret` (defense in depth; a ref naming a different
  project, or a connector somehow left unpinned despite the boot check, is refused
  before ever reaching the backend) — see `docs/adr-082-connect-connector-tenant-scoping.md`'s
  "Out of scope" section for how this closes a gap that ADR explicitly deferred.
- **BREAKING (targeting v0.92.0): a Keyorix Connect connector with an unrecognized
  `type` now fails boot instead of booting with that connector silently skipped
  (#1476)** — previously, `server/main.go`'s Connect-wiring loop logged a warning
  and continued for any `connect.connectors` entry whose `type` didn't match one
  of the four recognized backends (`aws-secrets-manager`, `gcp-secret-manager`,
  `azure-key-vault`, `vault`), so a typo'd or removed connector type produced a
  deployment that looked healthy but silently had one fewer working connector
  than configured. `type` is now validated at config-load time, before boot
  reaches the connector-wiring loop, and aggregates every offending connector
  into one error. **If you have a connector with a misspelled or unsupported
  `type`, fix it before upgrading** — this is the same fail-open shape ADR-082
  closed for a missing/invalid connector `scope` above.
- **BREAKING (targeting v0.92.0): `storage.type: remote` combined with
  `server.http.enabled` or `server.grpc.enabled` no longer boots (ADR-083)** —
  `storage.type: remote` is a CLI/client mode only; RemoteStorage never
  implemented the RBAC primitives a server needs to check ANY permission for
  ANY caller (`GetUserRoleIDsAt`, `GetUserGroupRoleIDsAt`, `RoleSetHasPermission`
  are all unconditional "not supported" stubs), so a server booted this way
  could never actually serve a permission-gated request — every request to
  every RBAC-gated route failed closed. If you were relying on this
  combination to run a "downstream Keyorix server" against `storage.type:
  remote`, it never functioned for ordinary API traffic; switch that
  deployment to `storage.type: local` or `storage.type: postgres`. The CLI's
  own client mode (`keyorix connect <server>`, or `storage.type: remote` in
  `~/.keyorix/cli.yaml` with no server enabled) is unaffected — see
  `docs/adr-083-remote-storage-cli-only.md`.
- **BREAKING (targeting v0.92.0): GCP KMS `kms_encryption_context` AAD wire format
  changed (crypto-gcpkms-01)** — `encContextAAD`'s canonicalisation of
  `kms_encryption_context` switched from an unescaped `"key=value\n"` join (where
  adversarial `=`/`\n` content in a key or value could let two structurally
  different context maps serialise to identical AdditionalAuthenticatedData,
  undermining the cross-install isolation the feature exists to provide) to a
  length-prefixed encoding that cannot collide. **Only installs configuring
  `kms_encryption_context` with a GCP KMS key provider are affected** — a KEK
  wrapped under the old AAD bytes will fail to decrypt after upgrading, since the
  new AAD no longer matches what it was wrapped under. To re-wrap: temporarily set
  `kms_allow_context_fallback: true`, run `keyorix encryption migrate-provider
  --to-kms-encryption-context=...` to re-wrap the KEK under the new AAD encoding,
  then **disable `kms_allow_context_fallback` again** (leaving it enabled makes
  the AAD binding advisory rather than enforced).
- **BREAKING: keyorix-operator default RBAC/watch scope narrowed to own-namespace-only
  (ADR-076)** — an unmodified `helm install deploy/helm/keyorix-operator` now binds a
  namespace-scoped `RoleBinding` in its own release namespace and watches only that
  namespace, instead of the previous default of a cluster-wide `ClusterRoleBinding`
  granting full CRUD on every Secret in the cluster. **Relied on the old default (set
  neither value)? Add `--set rbac.clusterScoped=true` to your `helm upgrade`** to preserve
  current behavior — without it, the operator stops reconciling `KeyorixSecret` CRs outside
  its own release namespace after the upgrade. **Already set `watchNamespaces`?**
  `rbac.clusterScoped` defaulted to `true` before this release, and a plain `helm upgrade`
  (without `--reset-values`) carries forward a release's previously-recorded values by
  default — so your install is very likely already in the now-rejected combination
  (`rbac.clusterScoped=true` + `watchNamespaces` set), and the upgrade will refuse to
  render at all: `rbac.clusterScoped=true and watchNamespaces=[...] are both set -- these
  are mutually exclusive (ADR-076)`. **Add `--set rbac.clusterScoped=false` explicitly to
  your `helm upgrade`** (or the equivalent in your values file) to clear it — this is a
  hard block on the upgrade, not a permissions change, until you do. Two opt-in modes cover
  broader deployments: `watchNamespaces: [ns, ...]` for a bounded multi-namespace instance,
  or `rbac.clusterScoped: true` for the original cluster-wide behavior — see the [operator
  docs](docs/k8s-operator.md#choosing-a-namespace-scope-adr-076) for detail. See ADR-076
  for the full rationale, including why this is the third attempt at this narrowing and
  what's different this time.
- **Frontend monorepo consolidation (ADR-070)** — `keyorix-web` (the dashboard)
  is folded into this repository at `web/`, full commit history preserved via
  `git subtree`. One `vX.Y.Z` tag now triggers both the server and web image
  builds in `docker-publish.yml`, closing the version-drift bug where the
  `docker-compose.yml`/Helm chart image pins assumed the two tracked the same
  tag when nothing enforced that. See ADR-070 for the full rationale and the
  CI/CD consolidation decisions (CodeQL, Sonar, SBOM, dependency review).

### Removed
- **`keyorix ping`** — removed as dead code: it was never registered as a
  runnable subcommand (only `keyorix status` was wired into the root command),
  so invoking `keyorix ping` has always produced "unknown command," regardless
  of this change. `keyorix status` already covers the same connectivity/
  response-time check, with a real exit-code contract (`0` healthy, `1`
  unhealthy/unreachable, `2` not configured) `ping` never had. Documentation
  that referenced `keyorix ping` has been updated to point to `status`.

### Added
- **`make smoke` — an executing first-run test.** `scripts/smoke.sh` runs the
  documented flow end to end in an isolated temp directory with its own `HOME`:
  `system init`, `project create`, `secret create`, `secret list`, `secret get`
  with a value round-trip, asserting embedded mode throughout (no server is
  started anywhere in it). It exists because the pre-existing
  `quickstart_commands_test.go` verifies that documented commands and flags
  *exist* and does not run them — which is precisely how a broken `system init`
  reached the documented first-run path with a green test suite. The two
  mechanisms now point at each other in their own headers.
- **FinOps billing report** — `GET /api/v1/admin/billing/report?from=&to=[&project_id=]`
  and `keyorix billing report --from --to [--project-id] [--format table|json]`.
  Per-project breakdown of secret counts, reads, writes, rotations, unique human users,
  and machine reads for a bounded date range. Gated behind the new `FeatureBilling =
  "billing"` license feature. Zero-activity projects are excluded from the output.
  ([#1227])
- **Dashboard stat-card trends** — the `DeploymentStatsSnapshot` GORM model is
  extended with four previously-missing metrics: `AuditLogins30d`,
  `AuditSecretReads30d`, `FailedAuthAttempts24h`, and `InactiveUsers`.
  `DashboardStats` gains prev+trend fields for all six deployment metrics;
  `saveDeploymentSnapshot` computes trends via `computeTrend`. GORM AutoMigrate
  handles the schema update with no migration file required. ([#1226])
- **Secret type update via CLI** — `keyorix secret update --type <new-type>` now
  actually changes a secret's type; the field is wired through
  `UpdateSecretRequest.Type` → core → HTTP handler → audit diff
  (`before`/`after`). Previously the flag was accepted but silently ignored.
  ([#1225])

### Fixed
- **`keyorix system init` could never generate a config, on any clean install.**
  ([#1839]) It read its template with `SafeReadFile(".", "keyorix_template.yaml")`
  — a file that does not exist anywhere in the repository (the shipped template
  is `configs/keyorix.yaml.tpl`), resolved against **the caller's working
  directory**. So the very first command a new user runs failed with
  `failed to read template file: no such file or directory`, and everything
  downstream failed with it: no config, so the server refused to boot. This was
  not a quirk of one machine — a binary on `$PATH` has no reason to be run from
  a directory containing repository files. The template is now embedded into the
  binary with `go:embed`, so `system init` is self-contained and
  cwd-independent. Found by a clean-checkout dress rehearsal, and now covered by
  `make smoke`.
- **Client mode (`storage.type: remote`) decoded several server responses
  incorrectly, returning empty results instead of data.** ([#1831], [#1832],
  [#1835], [#1836]) `ListRoles`, `GetRole`, `UpdateRole`, `GetUserRoles`,
  `GetGroupRoles`, `GetUserPermissions`, `ListSecretVersions`,
  `ListSharesBySecret`, `ListSharesByGroup` and `GetAuditLogs` each expected a
  bare array or a differently-named field where the server sends a wrapped
  envelope, and several request bodies were sent with the wrong casing. Machine-
  caller attribution (`#1573`) was also dropped across the wire on six fields.
  Two guards now hold this shut: one asserts client and server wire structs
  agree on every JSON key, the other that attribution fields survive the round
  trip. Both found real gaps on their first run, including one the guard's own
  author had just introduced.
- **Absolute `dek_path` / `salt_path` are bootable again.** ([#1827])
- **keyorix-operator `rbac.clusterScoped: false` never actually worked (ADR-076)** — this
  opt-out (added in [#1224]) bound namespace-scoped RBAC without ever telling the manager
  to narrow its own watch scope correspondingly, so it silently attempted a cluster-wide
  watch against namespace-scoped RBAC — in practice, repeated `Forbidden` errors on every
  namespace outside the release namespace, likely fatal to controller startup. Never
  worked correctly; fixed as part of ADR-076's broader scope-resolution rework before its
  first tagged release — `git tag --contains` confirms no released version ever shipped
  it (it landed three days after `v0.88.0`, the most recent tag at the time), so no
  affected versions to name.
- **SQLite RBAC grant-expiry timezone mismatch** — GORM formats `time.Time` using
  the process `Location`; mixed UTC/local `ExpiresAt` values broke SQLite string
  comparisons so grants appeared expired or perpetual depending on the host
  timezone. Fixed via `BeforeSave` hooks that normalise all `ExpiresAt` fields to
  UTC before write, and explicit UTC WHERE clauses for expiry queries. ([#1218])
- **DAST-identified security gaps** — CSP `frame-ancestors 'self'` on all HTML
  responses (closes clickjacking), `Cross-Origin-Opener-Policy: same-origin`,
  `Cross-Origin-Embedder-Policy: require-corp`, and a `Permissions-Policy` header
  removing access to camera/microphone/geolocation. ([#1217])
- **GitHub crash-report notifications on vCD fuzzing VMs** — GH token env-var
  lookup and `notified-*` marker cleanup so the fuzzing service correctly fires
  crash notifications on fleet VMs. ([#1222])

### Security
- **Optional `account_id` pin for `aws-secrets-manager` Keyorix Connect connectors**
  — the AWS sibling of the `gcp-secret-manager` `project_id` pin above, but with a
  narrower risk shape: a bare secret-name ref (the common case) is always resolved
  within the ambient credential's own AWS account by the Secrets Manager API itself,
  so it never carries a confused-deputy gap; only a full-ARN ref naming a DIFFERENT
  account is at risk, and only if that target account's own resource policy has
  separately granted cross-account access (a double opt-in, unlike GCP's
  single-opt-in ambient-reach gap). Because of that, `account_id` is **optional, not
  mandatory** — no existing deployment is broken by this change. When set,
  `validateConnectAWSAccountID` (`internal/config/config.go`) fails boot if it is
  not exactly 12 digits (the AWS account ID format), and
  `AWSSecretsManagerConnector.GetSecret` independently refuses any ARN-shaped ref
  naming a different account (defense in depth). When unset, `server/main.go` logs
  a startup recommendation rather than failing boot. See
  `docs/CONFIGURATION.md`'s Keyorix Connect section for the exact field and its
  documented scope boundary (a bare-name ref is never checked, by construction).
- **PAT scope enforcement, WebAuthn identity binding, template injection, K8s sync
  RBAC, TOTP anti-replay on proxy, operator Helm `clusterScoped`** — five
  security hardening items from the DAST/SAST backlog (PAT-SCOPE-002, WAUN-001,
  TMPL-002, K8SSYNC-007, and TOTP anti-replay on the remote-storage proxy path)
  closed in one bundle. ([#1224])

[#1827]: https://github.com/keyorixhq/keyorix/pull/1827
[#1831]: https://github.com/keyorixhq/keyorix/pull/1831
[#1832]: https://github.com/keyorixhq/keyorix/pull/1832
[#1835]: https://github.com/keyorixhq/keyorix/pull/1835
[#1836]: https://github.com/keyorixhq/keyorix/pull/1836
[#1839]: https://github.com/keyorixhq/keyorix/pull/1839
[#1217]: https://github.com/keyorixhq/keyorix/pull/1217
[#1218]: https://github.com/keyorixhq/keyorix/pull/1218
[#1222]: https://github.com/keyorixhq/keyorix/pull/1222
[#1224]: https://github.com/keyorixhq/keyorix/pull/1224
[#1225]: https://github.com/keyorixhq/keyorix/pull/1225
[#1226]: https://github.com/keyorixhq/keyorix/pull/1226
[#1227]: https://github.com/keyorixhq/keyorix/pull/1227

## v0.87.4 — 2026-07-07

CI-only patch release: pins the release workflow's cosign binary so signed release
artifacts publish again.

### Internal
- **cosign pinned to v2.5.2 for legacy `sign-blob` flags** — v0.87.3's fix traded one
  cosign v3.1.1 breakage for another: `sign-blob` started demanding
  `--signing-config`/`--use-signing-config` alongside `--new-bundle-format=false`, so the
  v0.87.3 release run failed at the same signing step and shipped without a GitHub
  Release (Docker images and the Helm chart still published fine both times). Rather than
  keep chasing v3.1.1's shifting flag requirements, `cosign-installer`'s `cosign-release`
  input is now pinned to `v2.5.2` — the last version that supported
  `--output-signature`/`--output-certificate` natively. ([#873])

[#873]: https://github.com/keyorixhq/keyorix/pull/873

## v0.87.3 — 2026-07-07

CI-only patch release: pins cosign's signing format so release artifacts publish again.

### Internal
- **cosign `sign-blob` pinned to the legacy bundle format** — the v0.87.2 release run
  failed at "Sign checksums.txt (keyless)": cosign now defaults to
  `--new-bundle-format=true` and silently drops `--output-signature`/`--output-certificate`,
  so no GitHub Release was created for that tag (Docker images and the Helm chart still
  published). `SECURITY.md` documents verification via the separate
  `checksums.txt.sig`/`.pem` files, so the workflow now pins
  `--new-bundle-format=false` to keep that verification flow working. (Superseded by
  [#873] once cosign v3.1.1 introduced a further flag requirement.) ([#872])

[#872]: https://github.com/keyorixhq/keyorix/pull/872
[#873]: https://github.com/keyorixhq/keyorix/pull/873

## v0.87.2 — 2026-07-07

A round-119 completeness audit closes 55 confirmed gaps where `storage.type: remote`
silently no-op'd or fully broke login/SSO/2FA/RBAC/compliance/dynamic-secrets flows,
plus a broad hardening bundle across degrade-on-error, TOCTOU, and access-control
paths, and new CodeQL/fuzzing/license-compliance CI gates.

### Fixed
- **Remote-storage completeness campaign: ~50 previously-stubbed `RemoteStorage` methods
  now proxy correctly under `storage.type: remote`** — a round-119 census traced every
  `RemoteStorage` method's real callers and found 55 confirmed, currently-reachable gaps
  that had silently accumulated across ~10 rounds of piecemeal fixing: SSO login
  (OIDC+SAML) was 100% broken, WebAuthn-as-2FA login was 100% broken, self-service
  access-requests were 100% broken, and most of RBAC/permission-catalog/Connect
  federated reads/project&environment management/dynamic-secrets/MFA
  enrollment/scheduler-lock/login-lockout accounting either failed open or errored out
  entirely when running against a remote storage backend. Each is now individually
  proxied and covered by a regression test. ([#793], [#802], [#810], [#811], [#812],
  [#823], [#827], [#828], [#830], [#831], [#835], [#836], [#837], [#838], [#839],
  [#840], [#841], [#842], [#846], [#847], [#848], [#849], [#850], [#851], [#852],
  [#853], [#854], [#860], [#861], [#862], [#863], [#864], [#865], [#866], [#867],
  [#868], [#869], [#870], [#871])
- **A completeness guard now pins every `RemoteStorage` stub to a reasoned
  classification** — `TestRemoteUnsupportedStubsAreAllowlisted` exact-matches every
  `remoteUnsupported(...)` call site against a fully-reasoned allowlist, classifying each
  as verified-permanent (with a citation) or a confirmed, backlog-tracked gap. A PR that
  adds a new unclassified stub, or fixes a listed gap without removing its entry, now
  fails CI immediately — closing the blind spot that let this round's 55 gaps
  accumulate unnoticed in the first place. ([#856])
- **`storage.type: remote` was fully broken for every proxied write** — the shared
  remote-storage response helper was missing the `"success"` key `sendSuccess` writes,
  so every successful proxied call was misread as a failure by the caller. ([#794])
- **Systemic fail-open across `GetCompliancePosture` closed** — a transient sub-query
  failure (legal hold, risk exceptions, SoD violations, dormant grants, and others)
  previously left the field at its "all clear" zero value instead of surfacing as
  degraded; every control now defers to an explicit unknown/degraded status instead of a
  false pass when its underlying query errors. ([#712], [#728], [#737], [#755], [#756],
  [#757], [#758], [#763], [#764], [#770], [#775], [#779], [#784], [#785], [#801], [#809])
- **Several long-running TOCTOU and race-condition fixes**: Shamir-reconstructed KEK
  verified against a real HMAC commitment ([#722]); rotation no-op detection stops
  spurious `LastRotatedAt` bumps ([#727]); pre-existing duplicate rows deduped before
  adding new unique indexes, closing an upgrade-time migration failure ([#761], [#766]);
  admin bootstrap password no longer leaks via `wget` argv ([#720]); evidence-pack
  generation is now one atomic snapshot ([#748]); reminder/notification dedup races
  closed ([#751], [#760]).
- **Validation and error-handling correctness**: CSV-formula-injection in audit export
  ([#749]); control-character/ANSI-escape injection in imported secret keys/values
  ([#742]); internal errors sanitized before reaching classify/rotate/restore/copy
  handlers ([#745]); user-creation and other handler validation errors now correctly
  return 400 instead of a generic 500 ([#858], [#859]); the audit high-water mark no
  longer embeds NUL bytes that corrupted persistence ([#857]).
- **`docker-compose` requires `KEYORIX_BOOTSTRAP_TOKEN` for auto-bootstrap**, closing an
  unauthenticated first-admin-seizure window in the bundled compose deployment path.
  ([#844])

### Security
- **RBAC / access-control hardening bundle**: `RequireRole` now unconditionally rejects
  machine/OIDC principals from human-only role checks ([#817]); a grant-time
  separation-of-duties preventive gate on role assignment ([#804]); `roles.read` now
  required to view a group's role grants ([#743]); dormant-role-grant detection counts
  write-tier activity and narrows masking between distinct admin-tier grants ([#732],
  [#770], [#801], [#809]); dead, scope-blind `CheckPermission` code path removed
  ([#741]).
- **Crypto / key-handling hardening**: evidence-signing key and audit-checkpoint key now
  derive from the KEK rather than the DEK ([#800], [#808]); local CLI key operations
  join the exclusive-DEK-lock coordination ([#783]); `rotate --dry-run` plus full
  sweep-result reporting ([#787]).
- **Supply-chain and CI hardening**: CodeQL analysis added for both Go modules
  ([#796]); native Go fuzz targets for Shamir, JWT, and rotation-ref parsing plus
  self-hosted continuous fuzzing ([#795], [#805]); `CONTRIBUTING.md` with enforced DCO
  sign-off ([#813]); a `checkov` IaC security-policy scan for the three Helm charts
  ([#814]); a `go-licenses` dependency license-compliance gate ([#822]); gitleaks scope
  narrowed to the checked-out branch ([#806]).
- **gRPC hardening**: outbound response size capped to match the inbound cap ([#788]);
  `ConnectService.ReadSecret` rejects an empty ref ([#776]); the unary interceptor chain
  reordered so metrics wraps auth correctly ([#778]); server-side keepalive reclaims
  idle connections ([#768]).
- **`TLSConfig.AllowedCiphers` now actually wired into HTTP + gRPC cipher suites** —
  the configured allowlist was previously validated but not enforced. ([#782])

### Internal
- Routine dependency bumps (AWS/Azure SDKs, `k8s.io/api`/`client-go`, `cobra`,
  `go-chi/chi`, and several GitHub Actions).
- Documentation refresh for `SECURITY.md`/`CONTRIBUTING.md`/`SECURITY-VERIFICATION.md`
  and several stale in-code comments closed out following this hardening pass ([#843],
  [#736], [#820], [#821], [#826]).

[#712]: https://github.com/keyorixhq/keyorix/pull/712
[#720]: https://github.com/keyorixhq/keyorix/pull/720
[#722]: https://github.com/keyorixhq/keyorix/pull/722
[#727]: https://github.com/keyorixhq/keyorix/pull/727
[#728]: https://github.com/keyorixhq/keyorix/pull/728
[#732]: https://github.com/keyorixhq/keyorix/pull/732
[#736]: https://github.com/keyorixhq/keyorix/pull/736
[#737]: https://github.com/keyorixhq/keyorix/pull/737
[#741]: https://github.com/keyorixhq/keyorix/pull/741
[#742]: https://github.com/keyorixhq/keyorix/pull/742
[#743]: https://github.com/keyorixhq/keyorix/pull/743
[#745]: https://github.com/keyorixhq/keyorix/pull/745
[#748]: https://github.com/keyorixhq/keyorix/pull/748
[#749]: https://github.com/keyorixhq/keyorix/pull/749
[#751]: https://github.com/keyorixhq/keyorix/pull/751
[#755]: https://github.com/keyorixhq/keyorix/pull/755
[#756]: https://github.com/keyorixhq/keyorix/pull/756
[#757]: https://github.com/keyorixhq/keyorix/pull/757
[#758]: https://github.com/keyorixhq/keyorix/pull/758
[#760]: https://github.com/keyorixhq/keyorix/pull/760
[#761]: https://github.com/keyorixhq/keyorix/pull/761
[#763]: https://github.com/keyorixhq/keyorix/pull/763
[#764]: https://github.com/keyorixhq/keyorix/pull/764
[#766]: https://github.com/keyorixhq/keyorix/pull/766
[#768]: https://github.com/keyorixhq/keyorix/pull/768
[#770]: https://github.com/keyorixhq/keyorix/pull/770
[#775]: https://github.com/keyorixhq/keyorix/pull/775
[#776]: https://github.com/keyorixhq/keyorix/pull/776
[#778]: https://github.com/keyorixhq/keyorix/pull/778
[#779]: https://github.com/keyorixhq/keyorix/pull/779
[#782]: https://github.com/keyorixhq/keyorix/pull/782
[#783]: https://github.com/keyorixhq/keyorix/pull/783
[#784]: https://github.com/keyorixhq/keyorix/pull/784
[#785]: https://github.com/keyorixhq/keyorix/pull/785
[#787]: https://github.com/keyorixhq/keyorix/pull/787
[#788]: https://github.com/keyorixhq/keyorix/pull/788
[#793]: https://github.com/keyorixhq/keyorix/pull/793
[#794]: https://github.com/keyorixhq/keyorix/pull/794
[#795]: https://github.com/keyorixhq/keyorix/pull/795
[#796]: https://github.com/keyorixhq/keyorix/pull/796
[#800]: https://github.com/keyorixhq/keyorix/pull/800
[#801]: https://github.com/keyorixhq/keyorix/pull/801
[#802]: https://github.com/keyorixhq/keyorix/pull/802
[#804]: https://github.com/keyorixhq/keyorix/pull/804
[#805]: https://github.com/keyorixhq/keyorix/pull/805
[#806]: https://github.com/keyorixhq/keyorix/pull/806
[#808]: https://github.com/keyorixhq/keyorix/pull/808
[#809]: https://github.com/keyorixhq/keyorix/pull/809
[#810]: https://github.com/keyorixhq/keyorix/pull/810
[#811]: https://github.com/keyorixhq/keyorix/pull/811
[#812]: https://github.com/keyorixhq/keyorix/pull/812
[#813]: https://github.com/keyorixhq/keyorix/pull/813
[#814]: https://github.com/keyorixhq/keyorix/pull/814
[#817]: https://github.com/keyorixhq/keyorix/pull/817
[#820]: https://github.com/keyorixhq/keyorix/pull/820
[#821]: https://github.com/keyorixhq/keyorix/pull/821
[#822]: https://github.com/keyorixhq/keyorix/pull/822
[#823]: https://github.com/keyorixhq/keyorix/pull/823
[#826]: https://github.com/keyorixhq/keyorix/pull/826
[#827]: https://github.com/keyorixhq/keyorix/pull/827
[#828]: https://github.com/keyorixhq/keyorix/pull/828
[#830]: https://github.com/keyorixhq/keyorix/pull/830
[#831]: https://github.com/keyorixhq/keyorix/pull/831
[#835]: https://github.com/keyorixhq/keyorix/pull/835
[#836]: https://github.com/keyorixhq/keyorix/pull/836
[#837]: https://github.com/keyorixhq/keyorix/pull/837
[#838]: https://github.com/keyorixhq/keyorix/pull/838
[#839]: https://github.com/keyorixhq/keyorix/pull/839
[#840]: https://github.com/keyorixhq/keyorix/pull/840
[#841]: https://github.com/keyorixhq/keyorix/pull/841
[#842]: https://github.com/keyorixhq/keyorix/pull/842
[#843]: https://github.com/keyorixhq/keyorix/pull/843
[#844]: https://github.com/keyorixhq/keyorix/pull/844
[#846]: https://github.com/keyorixhq/keyorix/pull/846
[#847]: https://github.com/keyorixhq/keyorix/pull/847
[#848]: https://github.com/keyorixhq/keyorix/pull/848
[#849]: https://github.com/keyorixhq/keyorix/pull/849
[#850]: https://github.com/keyorixhq/keyorix/pull/850
[#851]: https://github.com/keyorixhq/keyorix/pull/851
[#852]: https://github.com/keyorixhq/keyorix/pull/852
[#853]: https://github.com/keyorixhq/keyorix/pull/853
[#854]: https://github.com/keyorixhq/keyorix/pull/854
[#856]: https://github.com/keyorixhq/keyorix/pull/856
[#857]: https://github.com/keyorixhq/keyorix/pull/857
[#858]: https://github.com/keyorixhq/keyorix/pull/858
[#859]: https://github.com/keyorixhq/keyorix/pull/859
[#860]: https://github.com/keyorixhq/keyorix/pull/860
[#861]: https://github.com/keyorixhq/keyorix/pull/861
[#862]: https://github.com/keyorixhq/keyorix/pull/862
[#863]: https://github.com/keyorixhq/keyorix/pull/863
[#864]: https://github.com/keyorixhq/keyorix/pull/864
[#865]: https://github.com/keyorixhq/keyorix/pull/865
[#866]: https://github.com/keyorixhq/keyorix/pull/866
[#867]: https://github.com/keyorixhq/keyorix/pull/867
[#868]: https://github.com/keyorixhq/keyorix/pull/868
[#869]: https://github.com/keyorixhq/keyorix/pull/869
[#870]: https://github.com/keyorixhq/keyorix/pull/870
[#871]: https://github.com/keyorixhq/keyorix/pull/871
[#872]: https://github.com/keyorixhq/keyorix/pull/872

## v0.87.1 — 2026-07-04

CI-only patch release: fixes broken chart-signing authentication in the release
workflow.

### Internal
- **`release.yml` now authenticates to GHCR before cosign chart signing** — `publish-chart`
  failed on v0.87.0: all three Helm chart pushes succeeded, but the first cosign sign
  call failed with `UNAUTHORIZED` because `helm registry login` only populates Helm's
  own credential store, not the Docker config cosign reads registry auth from. A
  `docker/login-action` step now runs before the push+sign block, mirroring the
  already-working pattern `docker-publish.yml` uses for image signing. (v0.87.0's three
  charts remain live but unsigned in GHCR — not retroactively fixable without mutating
  an already-published tag.) ([#698])

[#698]: https://github.com/keyorixhq/keyorix/pull/698

## v0.87.0 — 2026-07-04

A large security-hardening campaign closes several CRITICAL/HIGH authorization and
account-takeover gaps (SSO JIT-provisioning takeover, repeated admin-rank-ceiling
bypasses, systemic compliance-posture fail-open), migrates session auth to httpOnly
cookies with CSRF protection, and fixes dozens of TOCTOU races and validation gaps
across RBAC, SCIM, SSO, dynamic secrets, and the operator.

### Added
- **Session auth migrates to an httpOnly cookie (`kx_session`) with double-submit
  CSRF** — session tokens no longer need to live in client-held storage, closing the
  XSS blast-radius on session theft; a `csrf_token` cookie plus `X-CSRF-Token` header
  protects state-changing requests now that auth is ambient. Admin impersonation was
  redesigned to swap sessions purely via cookies (`kx_admin_session`) without the
  server ever needing to recall a plaintext token from storage. Bearer-token auth
  keeps working alongside cookies during a bake-in period; removing the fallback is a
  deliberately deferred follow-up. ([#679])

### Security
- **SSO JIT-provisioning account takeover (CRITICAL)** — the existing-account lookup
  in SSO login had been hardened to require a verified email match, but the
  just-in-time provisioning branch reused an unguarded lookup and returned an existing
  account regardless of verification. With `auto_provision` enabled and an IdP that
  omits `email_verified` (e.g. Entra), an attacker asserting a victim's email with a
  fresh subject could be logged in as the victim, including admins, across identity
  providers. Provisioning now routes through the same verified-email guard as the
  existing-account path. ([#657])
- **Three more admin-rank-ceiling gaps closed (all HIGH)**: group restore reinstated
  role grants — including admin-tier roles — with no check on the restoring actor's
  own authority ([#568], part of #147); project/environment restore had the same gap,
  plus a query that never joined against the project's/environment's own
  soft-delete state, so a directly-bound role kept authorizing after the scope was
  deleted (#161); admin impersonation only checked a target's literal global-admin
  flag, missing a project-scoped or group-inherited admin (#165). All three now
  enforce a scope-aware authority ceiling before the elevated action proceeds.
  ([#588], [#616])
- **Systemic compliance-posture fail-open closed (HIGH)** — `GetCompliancePosture`'s
  `if err == nil { set }` pattern silently left a sub-query failure (legal hold, risk
  exceptions, SoD violations, and others) at its "all clear" zero value instead of
  surfacing as degraded; empirically proven to flip a real adverse state back to
  false on a dropped table mid-query. Every control now surfaces an explicit
  unknown/degraded status instead of a false pass. ([#610])
- **Startup/schema validation now actually runs on boot (HIGH)** — `ValidateStartup`
  and `Config.Validate()` were documented as running automatically but were never
  wired into `server/main.go`; an operator relying on
  `enable_file_permission_check: true` to catch a world-readable DEK/salt file got no
  warning at all. Also fixes a hardcoded config path (spurious failures under
  `KEYORIX_CONFIG_PATH`) and a startup check that unconditionally required a SQLite
  path even for postgres/remote deployments. ([#612])
- **DB-level email uniqueness closes a concurrent account-collision race (HIGH)** — a
  missing unique index on `users.email` meant concurrent signup/invite-accept calls
  with the same email could all succeed, leaving lookups to resolve to an arbitrary
  row; SCIM's email-uniqueness and last-admin-deactivation guards are also switched
  from fail-open to fail-closed on a transient lookup error. ([#614])
- **RBAC bundling and role-grant CRITICAL/HIGH fixes**: the actor must already hold a
  permission before bundling it into a role they grant ([#557]); every
  privilege-grant path now routes through one audited RBAC choke point ([#588]);
  `GetMachineRoleIDsAt` closed a soft-deleted-role gap ([#589]); SCIM Update/
  Deprovision/List restricted to SCIM-managed accounts ([#523]).
- **CI/supply-chain hardening across workflows, images, and the release pipeline**
  ([#543]), plus pinned/checksum-verified GitHub Action installs ([#668]).
- **`golang.org/x/net` bumped to v0.55.0 in the operator module**, closing 5
  published HIGH-severity CVEs (CVE-2026-25681, CVE-2026-27136, CVE-2026-33814,
  CVE-2026-39821, CVE-2026-42502) caught by the new Trivy image-scan CI gate.
  ([#696], [#697])

### Fixed
- Broad TOCTOU-race closures across invitation/access-request accept-vs-revoke
  ([#677]), project/user purge-vs-restore ([#678], [#680]), legal hold placement
  ([#593]), access-review decisions and campaign close ([#595], [#622]), break-glass
  revoke ([#596]), audit-checkpoint writes ([#601]), invite/delete-project races
  ([#599]), WebAuthn sign-counter updates ([#600]), and DEK rotation coordination
  with a live server ([#526], [#651]).
- SSO/SAML hardening: SAML/OIDC type-confusion panic and login-state TOCTOU fixed
  ([#606]); SSO identity scoped to its asserting provider, closing cross-provider
  takeover ([#517]); SAML email-fallback linking gated behind a per-provider opt-in
  ([#659]).
- Dynamic-secrets hardening: install-wide max-TTL ceiling with honest lease expiry
  ([#541]); admin authority required to bind a backend ([#524], [#551]); configs
  disabled and leases revoked on project deletion ([#646]).
- Session-refresh reuse-detection and WebAuthn clone-detection ([#656]); MFA/WebAuthn
  credential changes now require re-authentication ([#664]).
- httpOnly-cookie migration's Go toolchain bump (1.26.4 minimum) and Dependabot gomod
  coverage. ([#683], [#684])

### Internal
- CI supply-chain and container hardening: Trivy vulnerability scanning for
  published images ([#694]), a buildx-driver fix for broken image publishing
  ([#695]).

[#517]: https://github.com/keyorixhq/keyorix/pull/517
[#523]: https://github.com/keyorixhq/keyorix/pull/523
[#524]: https://github.com/keyorixhq/keyorix/pull/524
[#526]: https://github.com/keyorixhq/keyorix/pull/526
[#541]: https://github.com/keyorixhq/keyorix/pull/541
[#543]: https://github.com/keyorixhq/keyorix/pull/543
[#551]: https://github.com/keyorixhq/keyorix/pull/551
[#557]: https://github.com/keyorixhq/keyorix/pull/557
[#568]: https://github.com/keyorixhq/keyorix/pull/568
[#588]: https://github.com/keyorixhq/keyorix/pull/588
[#589]: https://github.com/keyorixhq/keyorix/pull/589
[#593]: https://github.com/keyorixhq/keyorix/pull/593
[#595]: https://github.com/keyorixhq/keyorix/pull/595
[#596]: https://github.com/keyorixhq/keyorix/pull/596
[#599]: https://github.com/keyorixhq/keyorix/pull/599
[#600]: https://github.com/keyorixhq/keyorix/pull/600
[#601]: https://github.com/keyorixhq/keyorix/pull/601
[#606]: https://github.com/keyorixhq/keyorix/pull/606
[#610]: https://github.com/keyorixhq/keyorix/pull/610
[#612]: https://github.com/keyorixhq/keyorix/pull/612
[#614]: https://github.com/keyorixhq/keyorix/pull/614
[#616]: https://github.com/keyorixhq/keyorix/pull/616
[#622]: https://github.com/keyorixhq/keyorix/pull/622
[#646]: https://github.com/keyorixhq/keyorix/pull/646
[#651]: https://github.com/keyorixhq/keyorix/pull/651
[#656]: https://github.com/keyorixhq/keyorix/pull/656
[#657]: https://github.com/keyorixhq/keyorix/pull/657
[#659]: https://github.com/keyorixhq/keyorix/pull/659
[#664]: https://github.com/keyorixhq/keyorix/pull/664
[#668]: https://github.com/keyorixhq/keyorix/pull/668
[#677]: https://github.com/keyorixhq/keyorix/pull/677
[#678]: https://github.com/keyorixhq/keyorix/pull/678
[#679]: https://github.com/keyorixhq/keyorix/pull/679
[#680]: https://github.com/keyorixhq/keyorix/pull/680
[#683]: https://github.com/keyorixhq/keyorix/pull/683
[#684]: https://github.com/keyorixhq/keyorix/pull/684
[#694]: https://github.com/keyorixhq/keyorix/pull/694
[#695]: https://github.com/keyorixhq/keyorix/pull/695
[#696]: https://github.com/keyorixhq/keyorix/pull/696
[#697]: https://github.com/keyorixhq/keyorix/pull/697

## v0.86.0 — 2026-06-27

Deployment-wide rotation planning lands (ADR-053), personal access tokens gain a
network allowlist (ADR-066), and a consolidated hardening batch closes an
unauthenticated-bootstrap seizure gap plus several transport-parity and
secrets-at-rest issues.

### Added
- **Deployment-wide rotation planning (ADR-053)** — `keyorix rotation plan
  --all-projects` rolls up the rotation plan across every project in one view;
  auto-rotation is now ordered by the secret dependency graph so dependents rotate
  after what they depend on, and secret soft-delete/restore/purge cascades through
  that same dependency graph. ([#503], [#505], [#507], [#508])
- **Network (IP/CIDR) allowlist for personal access tokens (ADR-066)** — a PAT can now
  be scoped to a set of source IPs/CIDRs; enforcement is closed over both HTTP and
  gRPC so a restricted PAT can't bypass the allowlist through the transport that
  doesn't check it. ([#502], [#504])
- **Cached certificate expiry refreshes on rotation (ADR-056)** — a rotated
  certificate's cached expiry no longer lags the real one. ([#509])
- **Configurable timezone and off-hours band for anomaly detection** — the
  `off_hours` anomaly rule now accounts for install timezone instead of assuming
  UTC, and the live detection window is excluded from its own statistical/ML
  baseline so a burst of activity can't suppress its own detection. ([#510], [#511])
- **Supply-chain-integrity control in the compliance posture/matrix (ADR-062 §7)**.
  ([#500])

### Security
- **Unauthenticated bootstrap seizure closed (HIGH)** — `POST /system/init` was
  gated only by a "no users yet" check, so any network-reachable fresh instance
  could be seized by whoever called it first. It now requires a bootstrap token
  (constant-time compare; auto-generated and logged on first boot, or set via
  `KEYORIX_BOOTSTRAP_TOKEN`), and enforces the password policy on the seeded admin.
  ([#518])
- **gRPC transport-parity gaps closed**: `ShareService.ListUserShares`/
  `ListSharedSecrets` ignored a PAT's scope restriction over gRPC (enforced on the
  equivalent HTTP routes); a PAT's IP allowlist is now enforced over gRPC as well,
  closing a transport bypass. ([#504], [#506])
- **KMS encryption-context binding for the wrapped KEK (AWS `EncryptionContext` /
  GCP AAD)**, opt-in and default-equivalent, so installs sharing one CMK can't
  unwrap each other's KEK (Azure unsupported — RSA-OAEP has no AAD). ([#516])
- **Session tokens and service-account credentials now hashed at rest** instead of
  stored in plaintext, alongside gating MFA/WebAuthn second-factor login on account
  state and revoking impersonation sessions when the impersonating admin is
  blocked. ([#516])
- **Durable, opt-in on-disk SIEM spool with replay** — a sustained SIEM outage no
  longer silently drops the off-box audit copy; `emitAudit` no longer swallows a
  persist error, and forwarded SIEM payloads carry `entry_hash`/`prev_hash` for
  downstream gap/forgery detection. ([#516])
- **Break-glass grants are always bounded, even when `MaxTTL` is unconfigured**, and
  the granted role is now locked under multi-party (M-of-K) approval so a second
  approver can't race a change to what's being approved. ([#513], [#512])

[#500]: https://github.com/keyorixhq/keyorix/pull/500
[#502]: https://github.com/keyorixhq/keyorix/pull/502
[#503]: https://github.com/keyorixhq/keyorix/pull/503
[#504]: https://github.com/keyorixhq/keyorix/pull/504
[#505]: https://github.com/keyorixhq/keyorix/pull/505
[#506]: https://github.com/keyorixhq/keyorix/pull/506
[#507]: https://github.com/keyorixhq/keyorix/pull/507
[#508]: https://github.com/keyorixhq/keyorix/pull/508
[#509]: https://github.com/keyorixhq/keyorix/pull/509
[#510]: https://github.com/keyorixhq/keyorix/pull/510
[#511]: https://github.com/keyorixhq/keyorix/pull/511
[#512]: https://github.com/keyorixhq/keyorix/pull/512
[#513]: https://github.com/keyorixhq/keyorix/pull/513
[#516]: https://github.com/keyorixhq/keyorix/pull/516
[#518]: https://github.com/keyorixhq/keyorix/pull/518

## v0.85.0 — 2026-06-24

A proactive license-expiry reminder, plus break-glass and federated-auth boundary tests.

### Added
- **Background license-expiry reminder** — an opt-in scheduler (`license_expiry`) that
  notifies install-wide admins when the offline commercial license is within its lead window
  of expiry or has already expired, so a silent lapse (which degrades commercial features to
  the community baseline) doesn't go unnoticed. It targets install-wide admins only
  (`super_admin` / `admin` / `system_admin`, not project-scoped admins), is deduped so it
  doesn't repeat on every tick, and is single-replica-gated in HA (ADR-039). The fail-safe
  gate and `GET /api/v1/license/status` are unaffected. (ADR-065 Phase 2c) ([#496])

### Internal
- Security-boundary tests: an expired break-glass emergency grant denies authorization end
  to end ([#494]), and federated machine-identity auth keeps cross-issuer bindings isolated
  (a token from one issuer can't satisfy a binding for another) ([#495], ADR-031).

[#494]: https://github.com/keyorixhq/keyorix/pull/494
[#495]: https://github.com/keyorixhq/keyorix/pull/495
[#496]: https://github.com/keyorixhq/keyorix/pull/496

## v0.84.0 — 2026-06-24

The first commercial-licensed feature, plus session-lifetime hardening.

### Added
- **`bundle import` is the first license-gated commercial feature (`airgap_updates`)** —
  staging an air-gap update bundle for rollout now requires a valid offline license carrying
  the `airgap_updates` feature; `bundle verify` stays free. The gate is fail-safe: a
  missing/expired/invalid license simply means the feature is off and import is refused with
  an actionable message — it never affects a running deployment. Gating strips nothing from
  community builds: import already requires the embedded update-signing key that only release
  builds carry. (ADR-065 Phase 2c, ADR-062) ([#491])

### Security
- **The absolute session-lifetime ceiling is enforced at validation** — a session is now
  rejected once it passes its absolute lifetime cap even if the access token itself has not
  expired, closing a window where a long-lived refresh chain could outlive the configured
  ceiling. ([#489])
- **A suspended account can no longer authenticate via a personal access token** — `SuspendUser`
  changes the account state and terminates the user's sessions but intentionally leaves
  `is_active` set, so a suspended user's existing PATs continued to authenticate. PAT validation
  now also rejects a blocked account state (mirroring session validation), so suspension
  immediately revokes access through every credential type, not only sessions. ([#492])

### Internal
- A regression test pinning that the SIEM-pull audit export carries the ADR-029 hash-chain
  links (so an external SIEM can independently verify tamper-evidence). ([#490])

[#489]: https://github.com/keyorixhq/keyorix/pull/489
[#490]: https://github.com/keyorixhq/keyorix/pull/490
[#491]: https://github.com/keyorixhq/keyorix/pull/491
[#492]: https://github.com/keyorixhq/keyorix/pull/492

## v0.83.0 — 2026-06-24

Offline commercial-license validation — the second air-gap mechanism, fail-safe by design —
plus secret-encryption chunk-ordering hardening.

### Added
- **Offline license validation (`keyorix license issue` / `install` / `status` + server
  enforcement)** — a paid air-gap tier needs entitlement that validates **with no
  phone-home**. A license is a compact `ed25519`-signed token (licensee, plan, features,
  expiry, optional deployment binding) verified locally against a public key embedded at
  build time. Enforcement is the deliberate **inverse of update bundles**: bundles are
  fail-closed, a license is **fail-safe** — a missing, expired, or invalid license degrades
  to the AGPL community baseline (no commercial features) with an admin warning and an audit
  event; it never denies access to existing secrets or stops the server, because
  availability is itself a security property for a secrets manager. The server loads the
  configured license at startup (a bad file never blocks boot), evaluates it freshly on
  every check, records the state as a startup audit event, and serves `GET
  /api/v1/license/status`. No shipped feature is gated on it — the gate is ready for future
  commercial-only capabilities. (ADR-065, ADR-062 Phase 2) ([#485], [#487])

### Security
- **Chunk position is authenticated in secret-value encryption** — chunked secret values now
  bind each chunk's position into its AEAD additional data, so a stored ciphertext can't be
  reordered, spliced, or truncated without detection. ([#484])

### Internal
- A regression test that DEK rotation preserves the AAD transplant binding (a rewrapped
  value stays bound to its identity). ([#486])

[#484]: https://github.com/keyorixhq/keyorix/pull/484
[#485]: https://github.com/keyorixhq/keyorix/pull/485
[#486]: https://github.com/keyorixhq/keyorix/pull/486
[#487]: https://github.com/keyorixhq/keyorix/pull/487

## v0.82.0 — 2026-06-24

Air-gapped, cryptographically-verifiable update bundles — the first build-on of the Phase 0
trust foundation — plus a security-test sweep over per-reference RBAC and secret-encryption
tamper-resistance.

### Added
- **Air-gap update bundles (`keyorix bundle build` / `verify` / `import`)** — a single,
  signed, offline-verifiable artifact for carrying a Keyorix release into an air-gapped or
  regulated environment (defence, finance, government; NIS2/DORA supply-chain integrity). A
  bundle is a gzip-tar whose `manifest.json` pins every component (images, charts, CRDs,
  binaries, migrations) by sha256, with a detached `ed25519` `manifest.sig`. `build` signs
  with an offline key; `verify` and `import` check the signature **offline** against the
  public key embedded in the binary at build time — trust follows a pinned chain, never a
  key shipped inside the bundle — then verify every component's digest. `import`
  additionally enforces **no-downgrade / `min_upgrade_from`** before staging the verified
  artifacts atomically, and prints the operator-controlled rollout steps (loading images
  into the internal registry and the Helm upgrade stay the operator's own steps). Everything
  **fails closed**: a plain (non-release) build embeds no keys, so verification refuses.
  Reads are size-bounded (decompression-bomb guard). Builds on the Phase 0 trust registry
  (`internal/trust`). (ADR-064, ADR-062 Phase 1) ([#479], [#482])

### Internal
- Security-boundary test sweep: Keyorix Connect per-reference RBAC has no admin bypass and
  no bare-prefix segment-boundary footgun ([#477], [#478], ADR-045); and the secret-
  encryption AEAD is tamper- and transplant-resistant, with no legacy-AAD downgrade bypass
  of the transplant binding ([#480], [#481]).

[#477]: https://github.com/keyorixhq/keyorix/pull/477
[#478]: https://github.com/keyorixhq/keyorix/pull/478
[#479]: https://github.com/keyorixhq/keyorix/pull/479
[#480]: https://github.com/keyorixhq/keyorix/pull/480
[#481]: https://github.com/keyorixhq/keyorix/pull/481
[#482]: https://github.com/keyorixhq/keyorix/pull/482

## v0.81.0 — 2026-06-23

A security-hardening release: the HTTP edge gets global security headers, a request
body-size cap, no panic-internals leakage, and the debug route removed from production;
per-account login lockout is now atomic under concurrency; and share self-removal works
end-to-end.

### Added
- **Share self-removal works end-to-end** — a recipient can now remove themselves from a
  secret share via `DELETE /api/v1/secrets/{id}/self-share` and the corresponding CLI
  command. The CLI command previously shipped as a non-functional placeholder; it is now a
  registered remote-only command backed by a real route, and the operation only removes the
  caller's own direct share (never a group share, never someone else's). ([#458])

### Security
- **Global security-headers middleware** — every response now carries `X-Content-Type-Options:
  nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and HSTS when TLS is
  enabled. ([#455])
- **Request body-size cap (DoS mitigation)** — requests are bounded by
  `http.MaxBytesReader` (10 MiB default, configurable), so an oversized or slow body can't
  exhaust server memory. ([#456])
- **Panic internals never reach the client** — the recovery middleware no longer has a
  development branch that could return the panic value or stack trace in the response; it
  always responds with a generic 500. ([#453])
- **Debug `/test-route` removed from the production router** — a leftover debug route is no
  longer registered. ([#460])

### Fixed
- **Per-account login lockout is atomic under concurrency** — failed-login counting now uses
  an atomic update, so concurrent attempts can't race past the lockout threshold. ([#474])

### Internal
- Group-inherited grant lifecycle boundary tests — expiry and membership transitions for
  permissions inherited through group shares. ([#475])

[#453]: https://github.com/keyorixhq/keyorix/pull/453
[#455]: https://github.com/keyorixhq/keyorix/pull/455
[#456]: https://github.com/keyorixhq/keyorix/pull/456
[#458]: https://github.com/keyorixhq/keyorix/pull/458
[#460]: https://github.com/keyorixhq/keyorix/pull/460
[#474]: https://github.com/keyorixhq/keyorix/pull/474
[#475]: https://github.com/keyorixhq/keyorix/pull/475

## v0.80.0 — 2026-06-23

SAML 2.0 single sign-on (Service Provider) lands as a working login path, three more
subsystems reach gRPC parity (audit-chain verify, break-glass, group management), SCIM
deprovisioning becomes atomic, and the HTTP surface gets response-cache and method
hardening — over a broad authorization- and concurrency-boundary test sweep.

### Added
- **SAML 2.0 single sign-on (Service Provider)** — Keyorix can now authenticate users
  against a SAML IdP, alongside the existing OIDC SSO. The SP is built on the vetted
  `crewjam/saml` + `goxmldsig` stack (no hand-rolled XML-DSig); the
  `/auth/saml/{provider}/{metadata,login,acs}` routes mirror the OIDC ones, and a SAML
  assertion maps to a user through the same identity-source-agnostic provisioning,
  group/role reconcile, and session path as OIDC. Opt-in and config-gated — no behaviour
  change without a SAML provider configured. (ADR-063; design [#446], SP core [#447],
  login flow + routes [#461])
- **Audit-chain verify, checkpoint & retention over gRPC** — the tamper-evident audit
  log's verify / checkpoint / retention operations are now first-class gRPC RPCs, matching
  the HTTP surface for programmatic compliance tooling. ([#443])
- **Break-glass emergency access over gRPC** — the break-glass request / approve / use flow
  is now available over gRPC. ([#445])
- **Group management over gRPC** — group CRUD and membership management reach gRPC parity.
  ([#448])
- **`WithTransaction` storage primitive; atomic SCIM deprovision** — a transaction
  primitive in the storage layer, used to make SCIM deprovisioning atomic so a partial
  failure can no longer leave a user half-removed. ([#454])

### Fixed
- **Expired time-bound shares no longer grant access** — `ListUserPermissions` now excludes
  time-bound shares past their expiry, closing a window where an expired share could still
  be enumerated as a live permission. ([#449])
- **Auth cache evicts the old token on refresh** — refreshing a token now evicts the prior
  entry from the auth cache, so a rotated token can't linger as a cached credential. ([#451])

### Security
- **`Cache-Control: no-store` on all API and SCIM responses** — secret material and
  directory data are never written to shared or intermediary caches. ([#469])
- **Web-UI static assets and the SPA fallback are GET/HEAD only** — mutating methods against
  static paths no longer fall through to the SPA handler. ([#470])

### Internal
- A broad authorization- and concurrency-boundary test sweep: cross-tenant and
  permission-granularity authorization ([#457], [#459]), HTTP↔gRPC authorization parity for
  secrets and sharing ([#462], [#463]), machine-identity no-admin-bypass ([#464]), and
  `-race` invariants for max-reads burn-after-read, the audit hash-chain, and the login
  rate-limiter ([#465], [#466], [#472]) — plus by-reference cross-project scope denial
  ([#471]), the group-share self-removal guard ([#467]), and a fix for two long-standing
  local-only `server/http` test flakes ([#468]).

[#443]: https://github.com/keyorixhq/keyorix/pull/443
[#445]: https://github.com/keyorixhq/keyorix/pull/445
[#446]: https://github.com/keyorixhq/keyorix/pull/446
[#447]: https://github.com/keyorixhq/keyorix/pull/447
[#448]: https://github.com/keyorixhq/keyorix/pull/448
[#449]: https://github.com/keyorixhq/keyorix/pull/449
[#451]: https://github.com/keyorixhq/keyorix/pull/451
[#454]: https://github.com/keyorixhq/keyorix/pull/454
[#457]: https://github.com/keyorixhq/keyorix/pull/457
[#459]: https://github.com/keyorixhq/keyorix/pull/459
[#461]: https://github.com/keyorixhq/keyorix/pull/461
[#462]: https://github.com/keyorixhq/keyorix/pull/462
[#463]: https://github.com/keyorixhq/keyorix/pull/463
[#464]: https://github.com/keyorixhq/keyorix/pull/464
[#465]: https://github.com/keyorixhq/keyorix/pull/465
[#466]: https://github.com/keyorixhq/keyorix/pull/466
[#467]: https://github.com/keyorixhq/keyorix/pull/467
[#468]: https://github.com/keyorixhq/keyorix/pull/468
[#469]: https://github.com/keyorixhq/keyorix/pull/469
[#470]: https://github.com/keyorixhq/keyorix/pull/470
[#471]: https://github.com/keyorixhq/keyorix/pull/471
[#472]: https://github.com/keyorixhq/keyorix/pull/472

## v0.79.0 — 2026-06-23

CLI ergonomics (machine-identity OIDC bindings, by-reference secret reads, richer
token listing), more reliable compliance-evidence delivery, and the cryptographic
foundation for air-gapped signing.

### Added
- **Machine-identity OIDC federation bindings in the CLI** — manage the bindings that
  map an external `(issuer, subject)` to a machine identity (ADR-031), so a workload can
  authenticate with a platform-issued JWT (e.g. a Kubernetes projected SA token) instead
  of a stored credential. The binding existed over HTTP and gRPC but had no CLI; operators
  can now wire it from the terminal. ([#438])
- **Read a secret by reference from the CLI** — `keyorix secret get --ref
  project/environment/name` reads a secret's value by a human-readable reference (ADR-059),
  completing CLI parity with the HTTP endpoint. Handy for scripts and automation; the read
  is scoped, counts toward `max_reads`, and is audited like any value read. ([#442])
- **`keyorix pat list` shows created / last-used / expiry** — the token list now surfaces
  `created_at`, `last_used_at`, and `expires_at`, so "which of my tokens are stale or about
  to expire?" is answerable from the CLI instead of the web UI or raw API. ([#440])
- **Air-gap signing trust foundation** — `internal/trust`, a verify-only, purpose-scoped
  `ed25519` public-key registry (fails closed) with trusted keys embedded at build time,
  plus `keyorix trust keygen` to mint a keypair and print the embed snippet. The base for
  air-gapped update bundles and offline licenses (ADR-062 Phase 0). No behaviour change —
  no callers yet, and a non-release build trusts no keys. ([#441])

### Fixed
- **Compliance evidence-pack delivery retries transient failures** — the daily
  evidence-pack webhook (ISO 27001 / SOC 2 continuous evidence) previously POSTed once and
  lost the pack on a brief receiver outage; it now retries transient failures, closing a
  gap in the continuous-evidence guarantee. ([#439])

[#438]: https://github.com/keyorixhq/keyorix/pull/438
[#439]: https://github.com/keyorixhq/keyorix/pull/439
[#440]: https://github.com/keyorixhq/keyorix/pull/440
[#441]: https://github.com/keyorixhq/keyorix/pull/441
[#442]: https://github.com/keyorixhq/keyorix/pull/442

## v0.78.0 — 2026-06-23

A read-only **MCP server** so AI agents can use Keyorix secrets safely, reliable
delivery for all operational-alert channels, CLI CSV export for auditors, and a design
for air-gapped updates + offline licensing.

### Added
- **MCP server for AI agents** — `keyorix-mcp`, a read-only Model Context Protocol server
  (stdio JSON-RPC 2.0) that lets an AI agent (Claude Desktop/Code, etc.) read Keyorix
  secrets through a least-privilege machine token. Tools: `keyorix_get_secret(ref)` (value
  by `project/environment/name`, via the by-reference endpoint) and
  `keyorix_list_secrets(environment?)` (references only, no values). No write tools, no
  network surface; every read goes through the usual scoped `secrets.read` / `max_reads` /
  suspension / audit, and values are never logged. Ships a Docker image and a configuration
  guide. (ADR-061) ([#433])
- **Reliable notification delivery for every channel** — the webhook, chat (Slack/Teams),
  and email (SMTP) operational-alert sinks (anomalies, break-glass, rotation/recert
  reminders — ISO 27001 A.5.5) now run on a shared delivery engine that **retries
  transient failures with exponential backoff** (permanent `4xx` not retried), is
  shutdown-aware, and exports Prometheus metrics so drops/failures are alertable. Replaces
  the previous fire-and-forget that silently lost an alert on a brief endpoint blip or a
  full queue. ([#432], [#434])
- **Compliance & inventory CSV export in the CLI** — `keyorix compliance controls --csv`
  (the control matrix) and `keyorix compliance inventory [--project <id>]` (the secret
  asset inventory, metadata only — no values) give auditors CLI parity with the dashboard
  for an air-gapped hand-off, instead of falling back to the raw HTTP API. ([#430])

### Design
- **Air-gapped updates & offline license validation** — a design (no behaviour change) for
  cryptographically-verifiable offline update bundles and fail-safe offline license
  validation (both `ed25519` with embedded pinned public keys), ready to build on the first
  air-gap prospect. (ADR-062) ([#435])

[#430]: https://github.com/keyorixhq/keyorix/pull/430
[#432]: https://github.com/keyorixhq/keyorix/pull/432
[#433]: https://github.com/keyorixhq/keyorix/pull/433
[#434]: https://github.com/keyorixhq/keyorix/pull/434
[#435]: https://github.com/keyorixhq/keyorix/pull/435

## v0.77.0 — 2026-06-23

A Kubernetes release: the secret-sync workstreams (orphan cleanup, an External Secrets
Operator integration, Kubernetes dynamic secrets, a by-reference read endpoint) and a
native CRD-based **operator** — plus time-bound secret shares and correct version
stamping in the published images.

### Added
- **Kubernetes sync orphan cleanup** — the `keyorix-k8s-sync` agent can now reap the
  Secrets it created once their mapping is removed, instead of leaving stale values
  behind forever. Opt-in (`cleanup: true` / `-cleanup`, **off by default**); ownership is
  recorded on-cluster via an `app.kubernetes.io/managed-by=keyorix-sync` label, so cleanup
  only ever lists/deletes Secrets the agent created and only in namespaces still in the
  config. A still-desired target survives a fetch failure, so a transient upstream error
  can't delete a live Secret. Adds a `deleted` outcome to the log line, `/status`, and the
  metrics; chart RBAC gains `list`/`delete`. (ADR-057) ([#426])
- **External Secrets Operator integration** — read Keyorix secrets into native Kubernetes
  Secrets through ESO's generic **Webhook** provider — no custom controller. Ships
  `deploy/eso/` manifests (`ClusterSecretStore`, `ExternalSecret`, token template) and a
  `docs/k8s-eso.md` guide. Reads go through Keyorix's scoped `secrets.read`, `max_reads`,
  suspension, and audit. ([#426])
- **Kubernetes dynamic secrets** — a `kubernetes` dynamic-secret backend that mints
  short-lived ServiceAccount tokens via the TokenRequest API (dependency-free `net/http`;
  in-cluster or explicit `api_server` config). Ephemeral like AWS STS / GCP — native
  expiry, `Revoke` is a no-op, `Renew` refused. (ADR-058) ([#426])
- **By-reference secret read** — `GET /api/v1/secrets/value?ref=project/environment/name`
  returns a secret's value by a human-readable reference (used by ESO and the operator),
  reusing the exact by-id read path: a scope resolver feeds the standard scoped
  `secrets.read` gate and the value is read through the same `max_reads` / suspension /
  audit machinery. The three-level reference is unambiguous (project names are globally
  unique). (ADR-059) ([#426])
- **Kubernetes operator (KeyorixSecret CRD)** — a `controller-runtime` operator that
  reconciles `KeyorixSecret` resources (`secrets.keyorix.io/v1alpha1`) into native
  Kubernetes Secrets and keeps them current — the native, `kubectl apply`-able delivery
  model alongside the sync agent and ESO. The target Secret is owned by the CR, so
  deleting it garbage-collects the Secret. Lives in its own Go module (`operator/`) so
  `controller-runtime`/`client-go` stay out of the server/CLI build; ships a Helm chart
  (`deploy/helm/keyorix-operator`) and a distroless image. (ADR-060) ([#429])
- **Time-bound secret shares** — a share can be given an expiry so access auto-lapses
  without manual revocation. ([#428])

### Fixed
- **Real version in container images** — the published images now embed the actual
  release version and commit (`VERSION`/`GIT_COMMIT` build args), so `keyorix --version`
  reports the tag from inside an image rather than `dev`. ([#427])

[#426]: https://github.com/keyorixhq/keyorix/pull/426
[#427]: https://github.com/keyorixhq/keyorix/pull/427
[#428]: https://github.com/keyorixhq/keyorix/pull/428
[#429]: https://github.com/keyorixhq/keyorix/pull/429

## v0.76.0 — 2026-06-23

Certificate lifecycle hardening — expiry monitoring and a hygiene control in the
compliance posture — rotation-plan parity across CLI and gRPC, and per-scheduler
health metrics for the background jobs.

### Added
- **Certificate-expiry monitoring** — an opt-in background scan (`certificate_expiry`)
  that parses certificate-typed secrets and notifies project admins of certificates
  **expired or expiring** within the lead window, using the certificate's *real*
  `notAfter` (ADR-054 parser) rather than the manual `expiration` field. Prevents the
  classic silent cert lapse / outage. One de-duplicated standing reminder per project,
  single-replica-gated. The scan reads cert values to extract only the expiry — never
  the value or private key, skips suspended secrets, doesn't count against `max_reads`.
  Default off. (ADR-055) ([#419])
- **CLI for the rotation plan** — `keyorix rotation plan <project-id>` prints a
  project's automated rotation plan (ADR-053) in the terminal: overdue/due-soon secrets
  batched into dependency-safe waves, most urgent first, each annotated with why it's
  due and what it must rotate after. Thin REST client over the existing endpoint.
  ([#420])
- **Certificate hygiene in the compliance posture** — the control matrix gains a
  **Certificate expiry hygiene** control (a gap when any certificate is expired; mapped
  to ISO 27001 / SOC 2 / NIS2 / ENS `op.exp.11`) plus a `certificates` posture figure
  (expired / expiring-soon / total / not-yet-evaluated). Fed by a cached cert `notAfter`
  (`SecretNode.cert_not_after`) populated as a side-effect of certificate inspection and
  the expiry scan — so the posture reports hygiene without decrypting on the dashboard
  path and without touching the create/rotate path. (ADR-056) ([#421])
- **gRPC for the rotation plan** — `ProjectService.GetProjectRotationPlan` exposes the
  automated rotation plan (ADR-053) over gRPC (read-only, scoped `secrets.read`),
  completing its surface parity with HTTP / CLI / web. ([#422])
- **Per-scheduler health metrics** — the ~14 background schedulers (anomaly detection,
  retention purge, auto-rotation, certificate-expiry scan, audit checkpoints, …) each
  export their outcome to Prometheus: `keyorix_scheduler_runs_total{scheduler,outcome}`
  (success / failure / **skipped**), a run-duration histogram, and last-run /
  last-success timestamp gauges, on the same `/metrics` endpoint. `skipped` (an HA
  follower not holding the single-writer lock, or a legal-hold stand-down) is tracked
  distinctly from `failure` so a follower replica never reads as broken — alert on
  `time() - keyorix_scheduler_last_success_timestamp_seconds{...}`. ([#423])

[#419]: https://github.com/keyorixhq/keyorix/pull/419
[#420]: https://github.com/keyorixhq/keyorix/pull/420
[#421]: https://github.com/keyorixhq/keyorix/pull/421
[#422]: https://github.com/keyorixhq/keyorix/pull/422
[#423]: https://github.com/keyorixhq/keyorix/pull/423

## v0.75.0 — 2026-06-23

A large security release: anomaly-detection ML, ENS compliance mapping, the full
secret dependency graph (tracking, impact, rotation order) across HTTP/CLI/gRPC/UI,
automated rotation planning, certificate inspection, plus observability and CLI parity.

### Added
- **Automated rotation planning** — `GET /api/v1/projects/{id}/rotation-plan` composes
  rotation status, secret risk, and the dependency graph (ADR-052) into an ordered,
  dependency-respecting **plan**: the project's overdue/due-soon secrets, batched into
  parallel-safe **waves** (each secret rotates after anything it depends on) and
  prioritised by **urgency** within a wave (overdue beats due-soon; more days past due +
  higher risk rank higher). Each entry carries human-readable reasons ("30 days
  overdue", "high risk", "rotate after db-password"). Deterministic and explainable —
  appropriate for an air-gapped security operation; an LLM advisor can later sit on top
  of the structured plan. (ADR-053) ([#413])
- **CLI for the secret dependency graph** — `keyorix secret deps list|add|rm|impact`
  and `keyorix rotation order <project-id>` bring the ADR-052 dependency graph to the
  terminal: declare/list/remove edges, see a secret's rotation blast radius, and print
  a project's safe rotation order. Thin REST clients over the existing endpoints,
  scoped server-side. ([#414])
- **gRPC surface for the secret dependency graph** — `SecretService.ListSecretDependencies`
  / `GetSecretImpact` and `ProjectService.GetProjectRotationOrder` expose the ADR-052
  dependency graph over gRPC (read-only), mirroring the HTTP/CLI surfaces with the same
  scoped `secrets.read` authorization. ([#415])
- **Certificate inspection** — `GET /api/v1/secrets/{id}/certificate` and
  `keyorix secret cert <id>` parse a certificate-valued secret's leaf X.509 cert and
  return its **public** metadata (subject, issuer, real `notAfter`/expiry, SANs, is-CA,
  self-signed, algorithms) for PKI hygiene. Never returns the value or any private key
  (only `CERTIFICATE` blocks are parsed), does **not** count against `max_reads`,
  respects suspension, and is audited (`secret.certificate_inspected`). Scoped
  `secrets.read`. (ADR-054) ([#416])
- **ML anomaly detection (Isolation Forest)** — an opt-in machine-learning pass that
  complements the existing rule-based access-anomaly detection. Each scan trains a
  per-secret Isolation Forest on the secret's 30-day access baseline and flags
  accesses whose joint pattern (hour, IP rarity, user rarity) is a multivariate
  outlier — catching what the binary rules miss: a **known-but-rare** actor or IP, and
  **combinations** that are unremarkable signal-by-signal. Pure-Go, no new
  dependencies; metadata only (no secret value is examined); deterministic (seeded).
  Flagged accesses emit an `ml_outlier` alert through the existing alert pipeline.
  Config-gated under `anomaly_alerts.ml` (default off). (ADR-050) ([#410])
- **ENS in the compliance control matrix** — every control in the live control matrix
  (`GET /api/v1/compliance/controls`, gRPC, and the `compliance-controls.csv` auditor
  export) now carries an `ens` reference to its Spanish *Esquema Nacional de Seguridad*
  (RD 311/2022) measure (`op.acc.*` / `op.exp.*` / `mp.info.*` / …) alongside ISO 27001
  / SOC 2 / NIS2 / DORA, with the same live pass/gap/not-configured status. Lets an ENS
  auditor pull the secret-management control set mapped to RD 311/2022 with its current
  state. Mappings are consistent with `docs/compliance/ENS-CONTROLS.md`. (ADR-051) ([#411])
- **Secret dependency tracking** — declare that one secret depends on another (e.g. an
  app token derived from a DB password, or a cert chain) and Keyorix maintains the
  per-project dependency graph. Answers two questions before a rotation: **impact /
  blast radius** (`GET /api/v1/secrets/{id}/impact` — the transitive dependents that
  break if you rotate it) and **rotation order** (`GET /api/v1/projects/{id}/rotation-order`
  — a safe sequence where each secret precedes anything depending on it). Manage edges
  via `GET/POST /secrets/{id}/dependencies` + `DELETE /secrets/{id}/dependencies/{depId}`,
  gated by scoped `secrets.read`/`secrets.write` and audited. Edges are confined to a
  single project + environment (matching Keyorix's environment-granular authorization)
  and the graph is kept acyclic (self-edges, duplicates, cross-project/-environment, and
  cycles are rejected). Metadata only — no secret value is read. This is the
  prerequisite for automated rotation planning; the topological order is the
  deterministic core of that. (ADR-052) ([#412])
- **gRPC metrics on `/metrics`** — gRPC request volume, outcomes, and cumulative
  handler time are now exported to Prometheus (`keyorix_grpc_requests_total{status}`
  and `keyorix_grpc_request_duration_seconds_total`) on the same endpoint as the
  HTTP metrics, instead of being reachable only via an authenticated RPC. ([#407])
- **CLI for dynamic-secret config classification and inspection** —
  `keyorix dynamic-secret get-config <id>` shows a single config (backend, TTLs,
  classification) and `keyorix dynamic-secret classify <id> --level <level>` sets
  its classification, matching the HTTP/gRPC surfaces. ([#408])

[#407]: https://github.com/keyorixhq/keyorix/pull/407
[#408]: https://github.com/keyorixhq/keyorix/pull/408
[#410]: https://github.com/keyorixhq/keyorix/pull/410
[#411]: https://github.com/keyorixhq/keyorix/pull/411
[#412]: https://github.com/keyorixhq/keyorix/pull/412
[#413]: https://github.com/keyorixhq/keyorix/pull/413
[#414]: https://github.com/keyorixhq/keyorix/pull/414
[#415]: https://github.com/keyorixhq/keyorix/pull/415
[#416]: https://github.com/keyorixhq/keyorix/pull/416

## v0.74.0 — 2026-06-22

Group lifecycle, audit completeness, and a few correctness fixes.

### Added
- **Groups can be soft-deleted and restored** — `DELETE /api/v1/groups/{id}` now
  soft-deletes (reversible) and `POST /api/v1/groups/{id}/restore` brings the
  group back with its prior role grants and memberships. A soft-deleted group
  authorizes nothing (role inheritance and group shares both exclude it), and its
  name is freed for reuse via a partial unique index. Audited as `group.deleted` /
  `group.restored`. ([#405])
- **Restore operations are audited** — restoring a secret, project, or environment
  now records `secret.restored` / `project.restored` / `environment.restored`, the
  inverse of the delete events. ([#402])

### Fixed
- **A secret's share list excludes expired shares** — `ListSecretShares` returned
  expired time-bound shares that no longer authorized, disagreeing with
  enforcement; it now filters them like every authorization path. ([#403])
- **Description length is bounded** — project, group, and rotation-policy
  descriptions are now capped (like secret descriptions) at the create/update
  choke points. ([#404])

[#402]: https://github.com/keyorixhq/keyorix/pull/402
[#403]: https://github.com/keyorixhq/keyorix/pull/403
[#404]: https://github.com/keyorixhq/keyorix/pull/404
[#405]: https://github.com/keyorixhq/keyorix/pull/405

## v0.73.1 — 2026-06-22

Security fix.

### Fixed
- **max_reads is now enforced atomically** — a limited-use secret could be read
  more than its `max_reads` cap under concurrent requests (a check-then-act race),
  and a storage error on the read-counter update failed open. Reads are now gated
  by a single atomic conditional update and fail closed, so concurrent reads can
  never collectively exceed the cap. ([#400])

[#400]: https://github.com/keyorixhq/keyorix/pull/400

## v0.73.0 — 2026-06-21

Complete audit coverage for governance mutations.

### Added
- **Role-definition changes are audited** — creating, updating, or deleting a role
  now records `role.created` / `role.updated` / `role.deleted` in the RBAC audit
  log, closing a gap where role definitions (which control what privileges exist)
  changed without a trace, even though role assignments were already audited.
  ([#396])
- **Group changes are audited** — `group.created` / `group.updated` /
  `group.deleted` on the API/CLI path, matching the SCIM provisioning path which
  already audited. ([#397])
- **Rotation-policy changes are audited** — `rotation_policy.created` /
  `.updated` / `.deleted`, so changes to a policy's rotation/compliance posture
  for its covered secrets are traceable. ([#398])

[#396]: https://github.com/keyorixhq/keyorix/pull/396
[#397]: https://github.com/keyorixhq/keyorix/pull/397
[#398]: https://github.com/keyorixhq/keyorix/pull/398

## v0.72.0 — 2026-06-21

Access visibility and operator controls over HTTP.

### Added
- **Group access visibility** — `GET /api/v1/groups/{id}/shared-secrets` lists the
  live secrets a group can reach via shares (skipping expired time-bound shares),
  the group counterpart to the per-user permissions view. ([#392])
- **User→machine migration over HTTP** —
  `POST /api/v1/projects/{id}/machine-identities/migrate-from-user` converts a
  service-account-shaped human user into a project machine identity and (unless
  `keep_user` is set) suspends the source user, so the conversion can be driven
  from automation or the dashboard, not just the CLI. Requires `roles.assign`
  (project) and `users.write`. ([#393])
- **On-demand job triggers** — a new `/api/v1/admin/jobs` group (`system.write`)
  dispatches the scheduled notification/alert jobs immediately instead of waiting
  for the next tick: `anomaly-alerts`, `rotation-reminders`,
  `expiry-reminders?lead_days=N`, and `compliance-digest`. ([#394])

[#392]: https://github.com/keyorixhq/keyorix/pull/392
[#393]: https://github.com/keyorixhq/keyorix/pull/393
[#394]: https://github.com/keyorixhq/keyorix/pull/394

## v0.71.0 — 2026-06-21

Just-in-time access, RBAC visibility, and naming-policy remediation.

### Added
- **Time-bound (JIT) role grants** — assigning a role now accepts an optional
  `expires_at`, so a grant can expire automatically instead of becoming standing
  privilege (emergency / contractor / on-call access). Works for users
  (`POST /api/v1/user-roles`) and groups (`POST /api/v1/groups/{id}/roles`); a
  set expiry must be in the future, persists on the grant, and is swept and
  audited by the existing JIT scheduler. CLI: `keyorix rbac assign-role --ttl 4h`.
  The group-roles response now carries each grant's expiry so clients can show
  remaining time. ([#387], [#388])
- **Bulk rename toward naming-policy conformance** —
  `POST /api/v1/projects/{id}/secrets/bulk-rename` renames policy-violating
  secrets in one call (the remediation for the name-conformance report). Each new
  name must satisfy the policy and not collide; a dry run reports what would
  change without touching anything; every rename is audited and never reveals a
  value. CLI: `keyorix secret bulk-rename` (dry-run by default; `--apply` to
  rename). ([#386])
- **User effective permissions** — `GET /api/v1/users/{id}/permissions` returns
  the de-duplicated permission set across a user's roles (excluding expired
  time-bound grants) — the "what can this user do" view for dashboards and access
  reviews. ([#389])
- **Custom environments on project create** — `POST /api/v1/projects` accepts an
  optional `environments` list to seed exactly those instead of the default
  development/staging/production set, for one-call infrastructure-as-code
  provisioning. ([#390])

### Fixed
- **CLI `project create --envs` honored in remote mode** — the flag posted a
  field the server ignored, so against a server the custom environments were
  silently dropped and the project got the default set. The CLI now sends the
  field the handler reads. ([#390])

[#386]: https://github.com/keyorixhq/keyorix/pull/386
[#387]: https://github.com/keyorixhq/keyorix/pull/387
[#388]: https://github.com/keyorixhq/keyorix/pull/388
[#389]: https://github.com/keyorixhq/keyorix/pull/389
[#390]: https://github.com/keyorixhq/keyorix/pull/390

## v0.70.0 — 2026-06-21

Per-secret usage visibility, and CLI commands that finally honor the configured
storage backend.

### Added
- **Per-secret read statistics** — `GET /api/v1/secrets/{id}/stats?days=N`
  returns a focused per-secret usage view: the durable lifetime read total and
  version count, plus a configurable recent window (reads, unique readers, last
  read time). Answers "is this secret actually used, and by whom lately?" in one
  scoped (`secrets.read`) call, beside `/{id}/access-log` and `/{id}/risk`, and
  never reveals the value. ([#382])

### Fixed
- **CLI commands honor `storage.type`** — ~17 `rbac`, `secret`, `share`, and
  `encryption` subcommands opened the database directly and hardwired SQLite, so
  against a Postgres deployment they silently operated on a stray local
  `secrets.db` instead of the real store. They now obtain storage through the
  factory (or a `*gorm.DB` helper that honors `storage.type`), so every command
  talks to the configured backend; SQLite stays supported for embedded/air-gapped
  use. ([#383])

[#382]: https://github.com/keyorixhq/keyorix/pull/382
[#383]: https://github.com/keyorixhq/keyorix/pull/383

## v0.69.0 — 2026-06-21

Operability: a real readiness probe and honest build identity.

### Added
- **Readiness probe** — `GET /readyz` verifies the database is reachable (200
  ready / 503 not-ready), so Kubernetes stops routing to a replica whose database
  is down and restores it on recovery. The Helm chart's readiness probe now
  targets `/readyz`; the liveness probe stays on `/health` (liveness must not
  depend on the database). ([#378])
- **`keyorix system info`** — a CLI command that shows the connected server's
  version, commit, runtime, uptime, and feature/security configuration. ([#380])

### Changed
- **Honest build identity** — `/health` and `/system/info` now report the real
  build version and commit (injected at build time) instead of hardcoded
  placeholders, and `/health` is a lightweight liveness signal that no longer
  fabricates dependency-health claims. ([#379])

[#378]: https://github.com/keyorixhq/keyorix/pull/378
[#379]: https://github.com/keyorixhq/keyorix/pull/379
[#380]: https://github.com/keyorixhq/keyorix/pull/380

## v0.68.0 — 2026-06-20

Compliance read surface: an on-demand digest and a control-matrix export.

### Added
- **On-demand compliance digest** — `GET /compliance/digest` returns the
  human-readable compliance summary (controls pass/gap, overdue recertifications,
  rotation gaps, unclassified secrets, open anomalies, risk exceptions, legal
  hold) that is otherwise broadcast to the notification channels on a schedule,
  so an admin can pull a point-in-time report; shown with a copy button on the
  Compliance page. ([#375])
- **Control-matrix CSV export** — `GET /compliance/controls.csv` downloads the
  control matrix (each control mapped to ISO 27001 / SOC 2 / NIS2 / DORA clauses
  with its live pass/gap status) for an auditor's spreadsheet, with a download
  button on the Compliance page. Completes the compliance-export family beside
  the audit-log, asset-inventory, and access-recertification CSVs. ([#376])

[#375]: https://github.com/keyorixhq/keyorix/pull/375
[#376]: https://github.com/keyorixhq/keyorix/pull/376

## v0.67.0 — 2026-06-20

Secret-name governance and an access-recertification export.

### Added
- **Secret naming-policy conformance** — the optional naming policy is enforced
  only at create time, so this surfaces existing secrets whose names violate the
  current policy (e.g. after it's added or tightened), per project
  (`GET /projects/{id}/secrets/name-conformance`, `keyorix secret
  name-conformance --project <id>`) and deployment-wide
  (`GET /secrets/name-conformance`, the same CLI command with `--project`
  omitted), with web panels on Project Settings and the Admin page. Each
  violation carries the exact reason create-time enforcement would give.
  ([#371], [#372])
- **Access-review campaign CSV export** — download a recertification campaign
  (ISO 27001 A.5.18) as a CSV record of every reviewed grant and its
  attest/revoke decision, for an auditor to archive
  (`GET /projects/{id}/access-review/campaigns/{campaignId}/export.csv`).
  Extends the compliance-export family beside the audit-log and asset-inventory
  CSVs. ([#373])

[#371]: https://github.com/keyorixhq/keyorix/pull/371
[#372]: https://github.com/keyorixhq/keyorix/pull/372
[#373]: https://github.com/keyorixhq/keyorix/pull/373

## v0.66.0 — 2026-06-20

Bulk environment promotion, deployment-wide hygiene, and a secret asset register.

### Added
- **Bulk environment promotion** — copy all of an environment's secrets into
  another environment in one call
  (`POST /projects/{id}/environments/{envId}/copy-secrets` and
  `keyorix secret copy-environment`), instead of promoting each secret by hand.
  ([#363], [#364])
- **Deployment-wide secret-hygiene rollup** — `GET /hygiene` (and
  `keyorix hygiene`) aggregate every project's hygiene posture
  (orphaned / recycle-bin / expiring / rotation-overdue counts) into a single
  deployment-wide view for admins. ([#365], [#366])
- **Secret asset inventory (CSV)** — a metadata-only asset register for auditors
  (ISO 27001 A.5.9): `GET /projects/{id}/secrets/inventory.csv` per project and
  `GET /secrets/inventory.csv` org-wide, exported from the web UI. Lists every
  live secret's metadata (name, environment, type, classification, owner,
  timestamps) and never reads or returns a value. ([#367], [#369])
- **Bulk-renew expiring secrets** — `POST /projects/{id}/secrets/extend-expiring`
  pushes the expiration of all soon-to-expire secrets out to a new window
  (default 90 days), surfaced as an "Extend all" button on the project's
  expiring-secrets panel. Only ever extends, never shortens. ([#368])

[#363]: https://github.com/keyorixhq/keyorix/pull/363
[#364]: https://github.com/keyorixhq/keyorix/pull/364
[#365]: https://github.com/keyorixhq/keyorix/pull/365
[#366]: https://github.com/keyorixhq/keyorix/pull/366
[#367]: https://github.com/keyorixhq/keyorix/pull/367
[#368]: https://github.com/keyorixhq/keyorix/pull/368
[#369]: https://github.com/keyorixhq/keyorix/pull/369

## v0.65.0 — 2026-06-19

Secret naming governance, machine-token hygiene, and richer search.

### Added
- **Secret naming policy** — an optional, operator-configured naming convention
  (regex + max length) enforced at create, plus `GET /secrets/policy` so clients
  can show the convention and pre-validate (surfaced as a hint in the web create
  form). Off by default. ([#357], [#358])
- **Machine-token hygiene** — `GET /machine-token-hygiene` (and
  `keyorix machine token-hygiene`) surface deployment-wide machine credentials
  that are expired-but-active or stale, with an admin web panel — completing
  credential hygiene across PATs, sessions, and machine tokens. ([#359], [#360])
- **Rotation-overdue in the project hygiene summary** — secrets past their
  rotation policy's interval are now counted in `GET /projects/{id}/hygiene`
  (and the CLI / web posture card). ([#356])
- **Richer secret search** — the secret list `?search=` now matches a secret's
  description and tags, not just its name. ([#361])

[#356]: https://github.com/keyorixhq/keyorix/pull/356
[#357]: https://github.com/keyorixhq/keyorix/pull/357
[#358]: https://github.com/keyorixhq/keyorix/pull/358
[#359]: https://github.com/keyorixhq/keyorix/pull/359
[#360]: https://github.com/keyorixhq/keyorix/pull/360
[#361]: https://github.com/keyorixhq/keyorix/pull/361

## v0.64.0 — 2026-06-19

Audit CSV export, access-change notifications, and secret promote/copy.

### Added
- **Audit log CSV export** — `GET /audit/export.csv` (and `keyorix audit export --csv`)
  download audit events as CSV for compliance hand-off, distinct from the JSON
  SIEM feed. ([#345], [#346])
- **Access-change notifications** — the affected user is now notified when a secret
  is shared with them, when ownership is transferred to them (with a single summary
  for bulk reassignment), and when their share is revoked — fanned out to group
  members for group shares. ([#347], [#348], [#349], [#350])
- **Copy a secret to another environment** — `POST /secrets/{id}/copy` (and
  `keyorix secret copy`) promote a secret's value and metadata into another
  environment of the same project (e.g. staging → production), with two-sided
  authorization. ([#353], [#354])
- **`keyorix secret expiring`** — list a project's expiring/expired secrets for
  renewal triage. ([#351])
- **`keyorix secret info`** — one-shot secret metadata summary (no value). ([#352])

[#345]: https://github.com/keyorixhq/keyorix/pull/345
[#346]: https://github.com/keyorixhq/keyorix/pull/346
[#347]: https://github.com/keyorixhq/keyorix/pull/347
[#348]: https://github.com/keyorixhq/keyorix/pull/348
[#349]: https://github.com/keyorixhq/keyorix/pull/349
[#350]: https://github.com/keyorixhq/keyorix/pull/350
[#351]: https://github.com/keyorixhq/keyorix/pull/351
[#352]: https://github.com/keyorixhq/keyorix/pull/352
[#353]: https://github.com/keyorixhq/keyorix/pull/353
[#354]: https://github.com/keyorixhq/keyorix/pull/354

## v0.63.0 — 2026-06-19

Secret descriptions and hygiene triage.

### Added
- **Secret description** — a free-text note on a secret (what it's for, its
  upstream, who to contact): settable at creation and via
  `PATCH /secrets/{id}/description`, plus `keyorix secret create --description`,
  `keyorix secret description`, and a description editor on the web detail view. ([#341], [#342])
- **List a project's expiring secrets** — `GET /projects/{id}/secrets/expiring?days=N`
  lists secrets expiring (or already expired) within the window, soonest-first,
  making the hygiene summary's expiring count actionable for renewal triage. ([#343])
- **CLI `project hygiene`** — `keyorix project hygiene <id>` prints a project's
  cleanup counts (orphaned / unused / expiring secrets, stale machine identities). ([#340])

[#340]: https://github.com/keyorixhq/keyorix/pull/340
[#341]: https://github.com/keyorixhq/keyorix/pull/341
[#342]: https://github.com/keyorixhq/keyorix/pull/342
[#343]: https://github.com/keyorixhq/keyorix/pull/343

## v0.62.0 — 2026-06-19

Secret tags and a project hygiene summary.

### Added
- **Secret tags** — free-form labels on a secret: `GET`/`PUT /secrets/{id}/tags`
  (normalized: trimmed, lowercased, de-duplicated, ≤20 tags, ≤50 chars), plus
  `keyorix secret tags --id N [--set a,b]` and a tag editor on the web secret
  detail view. ([#335], [#337])
- **Filter secrets by tag** — `GET /secrets?tag=prod&tag=tier1` (or
  `?tag=prod,tier1`) returns only secrets carrying every requested tag (AND). ([#336])
- **Project hygiene summary** — `GET /projects/{id}/hygiene` returns one-call
  counts of the project's outstanding cleanup signals (orphaned, unused, and
  expiring secrets; stale machine identities) for an at-a-glance posture. ([#338])

[#335]: https://github.com/keyorixhq/keyorix/pull/335
[#336]: https://github.com/keyorixhq/keyorix/pull/336
[#337]: https://github.com/keyorixhq/keyorix/pull/337
[#338]: https://github.com/keyorixhq/keyorix/pull/338

## v0.61.0 — 2026-06-18

Offboarding & incident response: cut off a departing or compromised user across
all three credential types they hold — owned secrets, personal access tokens, and
live sessions.

### Added
- **Orphaned-secret detection** — `GET /projects/{id}/secrets/orphaned` lists a
  project's secrets whose owner is no longer a live user (offboarding), plus
  `keyorix secret orphaned` and a project-settings alert in the web UI. ([#326], [#327])
- **Bulk owner reassignment** — `POST /projects/{id}/secrets/reassign-owner`
  re-homes every secret a departed user owned to a new owner in one call (each
  re-authorized and audited individually), plus `keyorix secret reassign-owner`
  and a per-former-owner "Reassign all" web action. ([#328], [#329])
- **Personal-access-token hygiene** — `GET /pat-hygiene?days=N` surfaces the
  deployment-wide non-revoked tokens that are expired-but-active or stale (token
  sprawl), plus `keyorix pat hygiene` and an admin web panel. ([#330], [#331])
- **Admin force-logout** — `POST /users/{id}/revoke-sessions` terminates all of a
  user's active sessions without changing their account state (suspected session/
  token theft), plus `keyorix user revoke-sessions` and a "Force log out" action
  on the user detail page. ([#332], [#333])

[#326]: https://github.com/keyorixhq/keyorix/pull/326
[#327]: https://github.com/keyorixhq/keyorix/pull/327
[#328]: https://github.com/keyorixhq/keyorix/pull/328
[#329]: https://github.com/keyorixhq/keyorix/pull/329
[#330]: https://github.com/keyorixhq/keyorix/pull/330
[#331]: https://github.com/keyorixhq/keyorix/pull/331
[#332]: https://github.com/keyorixhq/keyorix/pull/332
[#333]: https://github.com/keyorixhq/keyorix/pull/333

## v0.60.0 — 2026-06-18

Secret audit trail and a recycle bin for deleted secrets.

### Added
- **Per-secret audit trail** — `GET /secrets/{id}/audit?limit=N` lists a secret's
  lifecycle events (created, rotated, rolled-back, suspended/resumed, shared,
  owner-transferred, reclassified) newest-first, completing the investigation triad
  alongside the access inspector and access history. Metadata only — never a value. ([#321])
- **CLI `secret audit`** — `keyorix secret audit --id <id> [--limit N]` prints a
  secret's lifecycle events. ([#322])
- **Recycle bin** — `GET /projects/{id}/secrets/deleted?limit=N` lists a project's
  soft-deleted (restorable) secrets, newest-deleted first, so an operator can find
  what to restore (the existing restore route needs the secret's ID). ([#323])
- **CLI `secret trash` / `secret restore`** — `keyorix secret trash --project <id>`
  lists restorable secrets and `keyorix secret restore --id <id>` brings one back. ([#324])

[#321]: https://github.com/keyorixhq/keyorix/pull/321
[#322]: https://github.com/keyorixhq/keyorix/pull/322
[#323]: https://github.com/keyorixhq/keyorix/pull/323
[#324]: https://github.com/keyorixhq/keyorix/pull/324

## v0.59.0 — 2026-06-18

Secret investigation, project-wide incident response, and machine-identity hygiene.

### Added
- **Per-secret access history** — `GET /secrets/{id}/access-log?days=N` lists who has
  read a secret recently (accessor, IP, time), complementing the access inspector. ([#316])
- **Project-wide suspend / resume** — `POST /projects/{id}/secrets/suspend-all` and
  `/resume-all` freeze or restore value reads of every secret in a project (breach
  response). ([#317])
- **CLI investigation commands** — `keyorix secret access` (who can read) and
  `keyorix secret access-log` (who has read). ([#318])
- **Stale machine-identity detection** — `GET /projects/{id}/machine-identities/stale?days=N`
  surfaces active machine identities not authenticated within the window — abandoned
  credentials to revoke. ([#319])

[#316]: https://github.com/keyorixhq/keyorix/pull/316
[#317]: https://github.com/keyorixhq/keyorix/pull/317
[#318]: https://github.com/keyorixhq/keyorix/pull/318
[#319]: https://github.com/keyorixhq/keyorix/pull/319

## v0.58.0 — 2026-06-18

Incident response: suspend/resume a secret.

### Added
- **Suspend / resume a secret** — freeze value reads of a suspected-compromised
  secret without deleting it (versions, shares, and audit trail are preserved);
  reversible. A suspended secret refuses reads on every value path, even for the
  owner, while metadata/listing/management stay available. `POST /secrets/{id}/suspend`
  (optional reason) and `/resume` (scoped `secrets.write`, audited
  `secret.suspended` / `secret.resumed`), plus `keyorix secret suspend|resume`. ([#313], [#314])

### Fixed
- The secret-value quality policy is now enforced on `UpdateSecret` too, not just
  create and rotate — closing a path where a weak value could be set via update. ([#312])

[#312]: https://github.com/keyorixhq/keyorix/pull/312
[#313]: https://github.com/keyorixhq/keyorix/pull/313
[#314]: https://github.com/keyorixhq/keyorix/pull/314

## v0.57.0 — 2026-06-18

Secret governance: ownership transfer, value policy, access inspector, HTTP render.

### Added
- **Secret ownership transfer** — hand a secret to another user (recover orphaned
  secrets when an owner leaves). The current owner can transfer; an authorized caller
  can recover a secret whose owner is gone (the lookup fails closed on a transient
  error, so an active owner's secret can't be taken). `POST /secrets/{id}/transfer-ownership`,
  audited `secret.owner_transferred`. ([#307])
- **Secret-value quality policy** — an opt-in (off-by-default) gate that rejects weak/
  placeholder values (`changeme`, too-short, a configurable denylist) at create and
  rotate. The rejection reason never echoes the value. ([#309])
- **"Who can access" inspector** — `GET /secrets/{id}/access` lists every user who can
  read a secret (owner + direct + group shares, members expanded; expired shares
  excluded), for least-privilege review. ([#310])
- **HTTP template render** — `POST /projects/{id}/secrets/render` expands
  `${secret:<environment>/<name>}` references within a project, resolving only the
  caller's readable secrets. ([#306])

### Fixed
- Corrected an integration test's assertion against the paginated `/shares` response
  shape introduced in v0.54.0. ([#308])

[#306]: https://github.com/keyorixhq/keyorix/pull/306
[#307]: https://github.com/keyorixhq/keyorix/pull/307
[#308]: https://github.com/keyorixhq/keyorix/pull/308
[#309]: https://github.com/keyorixhq/keyorix/pull/309
[#310]: https://github.com/keyorixhq/keyorix/pull/310

## v0.56.0 — 2026-06-17

Secret templating: render config/`.env` files from live secrets.

### Added
- **Secret-reference templating** — a template can embed `${secret:<environment>/<name>}`
  placeholders that expand to a secret's current value (`$$` escapes a literal `$`).
  `keyorix secret render <template>` renders a file (or stdin) to stdout or `--output`,
  resolving only the secrets the caller can read and failing without partial output on a
  missing/forbidden reference — handy for generating a `.env` or config file. ([#303], [#304])

[#303]: https://github.com/keyorixhq/keyorix/pull/303
[#304]: https://github.com/keyorixhq/keyorix/pull/304

## v0.55.0 — 2026-06-17

Kubernetes sync agent: observability + distribution.

### Added
- **Prometheus metrics** — the sync agent serves `/metrics` (reconcile passes,
  per-outcome Secret counts, last-run timestamp, last-failed gauge); the Helm chart
  adds `prometheus.io/scrape` pod annotations. ([#301])
- **Agent Helm chart published to GHCR** — `keyorix-k8s-sync` is now pushed to
  `oci://ghcr.io/keyorixhq/charts/keyorix-k8s-sync` on release, so it can be installed
  with `helm install … oci://…` rather than only from a repo checkout. ([#300])

[#300]: https://github.com/keyorixhq/keyorix/pull/300
[#301]: https://github.com/keyorixhq/keyorix/pull/301

## v0.54.0 — 2026-06-17

Kubernetes integration: sync Keyorix secrets into native Kubernetes Secrets.

### Added
- **Kubernetes sync agent** (`keyorix-k8s-sync`) — a small in-cluster agent that
  materialises selected Keyorix secrets into native Kubernetes Secrets and refreshes
  them as the upstream values rotate. It authenticates to Keyorix with a
  machine-identity token and writes Secrets via the Kubernetes API (Server-Side Apply)
  using its service-account credentials — **no `client-go` dependency**. A reconcile
  creates/updates a target Secret only when its data changes and never writes a Secret
  partially if any value fails to fetch. ([#291], [#292], [#293], [#294])
- **Agent container image** — published to `ghcr.io/keyorixhq/keyorix-k8s-sync`
  alongside the server image. ([#295])
- **Helm chart** (`deploy/helm/keyorix-k8s-sync`) — deploys the agent with
  least-privilege RBAC (a `RoleBinding` to a `secrets` `get`/`create`/`patch`
  `ClusterRole` per target namespace), config, and the token sourced from an existing
  Secret. ([#296])
- **Health & probes** — the agent serves `/healthz`, `/readyz` (gated on the first
  successful reconcile), and `/status`; the chart wires liveness/readiness probes. ([#297])
- **`-once` and `-dry-run` modes** — run a single reconcile (a CI gate / Kubernetes
  `Job`; non-zero exit on failure) and preview what would change without writing. ([#298])

[#291]: https://github.com/keyorixhq/keyorix/pull/291
[#292]: https://github.com/keyorixhq/keyorix/pull/292
[#293]: https://github.com/keyorixhq/keyorix/pull/293
[#294]: https://github.com/keyorixhq/keyorix/pull/294
[#295]: https://github.com/keyorixhq/keyorix/pull/295
[#296]: https://github.com/keyorixhq/keyorix/pull/296
[#297]: https://github.com/keyorixhq/keyorix/pull/297
[#298]: https://github.com/keyorixhq/keyorix/pull/298

## v0.53.0 — 2026-06-17

Access-anomaly detection and secret-sharing lifecycle improvements.

### Added
- **Anomaly frequency-spike detection** — the access-anomaly detector now emits a
  `frequency_spike` alert when a secret's read count in the detection window clears an
  absolute floor and exceeds a multiple of its learned hourly baseline (activating the
  previously-computed-but-unused baseline). ([#286])
- **Anomaly alert filtering** — `GET /anomalies` accepts `?severity` and `?alertType`
  filters (AND-combined); the web alerts table gains an alert-type filter and renders
  humanized type labels. ([#289])
- **Editable share expiry** — `PUT /shares/{id}` accepts `expires_at` / `clear_expiry`
  so a time-bound share can be extended, shortened, or made permanent after creation;
  omitting both preserves the current expiry. ([#287])

### Fixed
- **`GET /shares` returns a proper paginated DTO** — the endpoint now returns shares
  with resolved recipient/creator names, the expiry, and `{data, total, page, pageSize,
  totalPages}` (with `?secretId` / `?recipientType` filters), instead of raw models —
  repairing the Sharing Management page, which rendered empty against a real backend. ([#288])

[#286]: https://github.com/keyorixhq/keyorix/pull/286
[#287]: https://github.com/keyorixhq/keyorix/pull/287
[#288]: https://github.com/keyorixhq/keyorix/pull/288
[#289]: https://github.com/keyorixhq/keyorix/pull/289

## v0.52.0 — 2026-06-17

Secret lifecycle: rollback, expiry reminders, and time-bound (JIT) shares.

### Added
- **Time-bound (expiring) secret shares** — a share can now carry an optional expiry
  (just-in-time access), mirroring time-bound role grants. An expired share authorizes
  nothing (filtered at the permission chokepoint and in the storage queries, so it neither
  grants access nor surfaces in "shared with me"); a past expiry is rejected at creation.
  Lapsed shares are reclaimed and audited (`share.expired`) by the JIT expiry scheduler.
  `POST /secrets/{id}/share` accepts an optional `expires_at`; the Share modal offers an
  "Access expires" preset (1h/24h/7d/30d). ([#284])
- **Secret version rollback** — restore a secret to a prior version's value, re-instated as
  a new version so history stays append-only and the rollback is itself undoable. Audited
  as `secret.rolled_back`; refuses rolling back to the current head. Exposed over HTTP
  (`POST /secrets/{id}/rollback`, scoped `secrets.write`), the web Version History view, and
  the `keyorix secret rollback` CLI command. ([#282], [#283])
- **Secret-expiry reminders** — an opt-in scheduler proactively notifies a project's
  approvers before (and once after) a secret with an expiration lapses, deduped on the
  unread reminder. Mirrors the rotation-reminder scheduler; single-replica-gated. ([#281])

[#281]: https://github.com/keyorixhq/keyorix/pull/281
[#282]: https://github.com/keyorixhq/keyorix/pull/282
[#283]: https://github.com/keyorixhq/keyorix/pull/283
[#284]: https://github.com/keyorixhq/keyorix/pull/284

## v0.51.0 — 2026-06-17

Rotation: Azure backend, failure alerts, status visibility.

### Added
- **Azure AD app-secret rotation** (ADR-047) — a generate-upstream backend completing the
  cloud trio (AWS IAM · GCP service-account keys · Azure): rotation mints a fresh client
  secret via Microsoft Graph and removes the app's prior secrets. Ambient Azure creds;
  fail-closed `allowed_refs`. ([#279])
- **Auto-rotation failure alerts** — a run that leaves any secret unrotated broadcasts one
  summary (names + reasons, never values) to the configured notification channel
  (Slack/Teams/webhook), so a silently-failed rotation is surfaced. ([#277])
- **Auto-rotation visibility in rotation status** — the rotation status read model now
  reports whether each covered secret self-rotates and via which backend; the web Secrets
  Health page shows a self-rotating count and an "Auto" badge on overdue items. ([#278])

[#277]: https://github.com/keyorixhq/keyorix/pull/277
[#278]: https://github.com/keyorixhq/keyorix/pull/278
[#279]: https://github.com/keyorixhq/keyorix/pull/279

## v0.50.0 — 2026-06-17

### Added
- **GCP service-account key rotation** (ADR-047) — a generate-upstream backend (like AWS
  IAM): rotation mints a fresh user-managed service-account key, deletes the account's
  prior user-managed keys, and stores the new key file. Credentials come from Application
  Default Credentials; fail-closed on a required `allowed_refs`. ([#275])

With this release, backend rotation spans **PostgreSQL · MySQL · MongoDB · Redis**
(password-set) and **AWS IAM · GCP service-account keys** (generate-upstream).

[#275]: https://github.com/keyorixhq/keyorix/pull/275

## v0.49.0 — 2026-06-17

### Added
- **MongoDB and Redis rotation backends** (ADR-047) — automated rotation can now rotate
  a MongoDB account (`updateUser`) or a Redis ACL user (`ACL SETUSER … resetpass`) in
  place, alongside PostgreSQL and MySQL. Both pass the username/password as typed/discrete
  values (injection-safe by construction) and are fail-closed on a required
  `allowed_refs`. ([#273])

Backend rotation now spans PostgreSQL · MySQL · MongoDB · Redis (password-set) and AWS
IAM (generate-upstream).

[#273]: https://github.com/keyorixhq/keyorix/pull/273

## v0.48.0 — 2026-06-16

More rotation backends (ADR-047).

### Added
- **MySQL rotation backend** — rotate a MySQL account's password in place
  (`ALTER USER … IDENTIFIED BY`), alongside PostgreSQL. Injection-safe, fail-closed on a
  required `allowed_refs`. ([#270])
- **Cloud-key rotation (AWS IAM)** — a *generate-upstream* backend: rotation mints a
  fresh IAM access key (deleting the user's prior keys) and stores the new
  `{access_key_id, secret_access_key}`, for credentials the cloud issues rather than
  accepts. Credentials come from the ambient AWS chain; same fail-closed `allowed_refs`.
  ([#271])

Backend rotation now spans PostgreSQL · MySQL (password-set) and AWS IAM (generate). The
auto-rotation toggle (incl. backend/ref) is also now manageable from the web console.

[#270]: https://github.com/keyorixhq/keyorix/pull/270
[#271]: https://github.com/keyorixhq/keyorix/pull/271

## v0.47.0 — 2026-06-16

Backend rotation executors (ADR-047) — rotate the upstream credential, not just the copy.

### Added
- **Backend rotation executors** — automated rotation can now rotate the **upstream**
  credential in place, so externally-owned secrets (not just Keyorix-generated values)
  can auto-rotate. A secret configured with a `rotation_backend` + `rotation_ref` has its
  new value applied upstream by the backend executor **before** it is stored in Keyorix,
  so the two never drift; if the upstream apply fails, nothing is stored. The first
  backend is **PostgreSQL** (`ALTER ROLE … WITH PASSWORD`, injection-safe). Configure
  via HTTP / gRPC / CLI `auto-rotate` (scoped `secrets.write`). ([#267], [#268])

### Security
- Rotation backends are **fail-closed**: each requires an `allowed_refs` allow-list (a
  backend without one is refused at registration and the executor refuses to rotate),
  bounding which upstream principals a rotation may touch; the named backend is validated
  when a secret is configured. Admin DSNs are operator-provided and env-sourced. ([#268])

[#267]: https://github.com/keyorixhq/keyorix/pull/267
[#268]: https://github.com/keyorixhq/keyorix/pull/268

## v0.46.0 — 2026-06-16

Automated secret rotation (ADR-046).

### Added
- **Automated rotation executor** — an opt-in scheduler that actually rotates secrets,
  not just tracks/reminds. A secret marked `auto_rotate` that is overdue under an active
  rotation policy has its value regenerated (a new version) automatically, audited as
  `secret.auto_rotated`. Opt-in per secret and only for Keyorix-owned (generated) values,
  so externally-managed credentials are never silently changed. ([#263])
- **Per-secret generated-value shape** — choose the rotated value's `length` (8–256,
  default 32) and `charset` (`alphanumeric` [default] / `lower_alphanumeric` / `hex` /
  `alphanumeric_symbols`) to meet a system's password requirements. ([#264])
- **Manage auto-rotation everywhere** — toggle it over HTTP (`PATCH
  /secrets/{id}/auto-rotate`), gRPC (`SecretService.SetSecretAutoRotate`), and the CLI
  (`keyorix secret auto-rotate`), all gated by scoped `secrets.write`. ([#263], [#265])

[#263]: https://github.com/keyorixhq/keyorix/pull/263
[#264]: https://github.com/keyorixhq/keyorix/pull/264
[#265]: https://github.com/keyorixhq/keyorix/pull/265

## v0.45.0 — 2026-06-16

Real-time audit streaming for SIEM consumers.

### Added
- **Gap-free audit-stream resume** — the gRPC `StreamAuditLogs` RPC accepts an optional
  `after_id`; a consumer that tracks its last-seen event id can reconnect from there,
  replaying the backlog before tailing live, so a disconnect loses no events. Omitting
  it keeps the head-start (tail-only) behavior. ([#261])

### Changed
- **`StreamAuditLogs` is now push-driven** — instead of polling the database on a fixed
  interval, an in-process broker wakes live tails the instant an audit event is written;
  the stream then drains new rows from its cursor (the database stays authoritative, so
  no event is lost). Delivery latency drops to ~immediate and steady-state poll load is
  removed; a long fallback ticker remains as a safety net. ([#260])

[#260]: https://github.com/keyorixhq/keyorix/pull/260
[#261]: https://github.com/keyorixhq/keyorix/pull/261

## v0.44.0 — 2026-06-16

Keyorix Connect per-reference RBAC — gRPC parity, group/glob support.

### Added
- **gRPC management of per-reference grants** — `ConnectService` gains
  `ListRefGrants` / `CreateRefGrant` / `DeleteRefGrant` (gated `roles.read` /
  `roles.write`), at parity with the HTTP `/connect/ref-grants` routes. ([#256])
- **Glob ref-grant patterns** — a grant pattern is a prefix by default, or a
  shell-style glob if it contains `*` `?` `[` (e.g. `prod/*/db`; `*` does not cross
  `/`). Existing prefix grants are unchanged; a malformed glob matches nothing. ([#258])

### Fixed
- **Per-reference grants honor group-derived roles** — ref-grant matching now resolves
  a caller's *effective* roles (direct **plus** group-derived for users,
  `machine_identity_roles` for machines), consistent with how `connect.read` itself is
  authorized. Previously a user whose granted role came via a group was wrongly denied.
  ([#257])

[#256]: https://github.com/keyorixhq/keyorix/pull/256
[#257]: https://github.com/keyorixhq/keyorix/pull/257
[#258]: https://github.com/keyorixhq/keyorix/pull/258

## v0.43.0 — 2026-06-16

Fine-grained authorization for Keyorix Connect.

### Added
- **Per-reference RBAC for Keyorix Connect** (ADR-045) — scope *which roles* may read
  *which references* on a connector with a `(role, connector, ref_prefix)` allowlist,
  refining the global `connect.read` permission and the uniform per-connector
  `allowed_refs`. Enforced in the core read path, so it covers both the HTTP and gRPC
  surfaces, and applies to user and machine-identity callers alike. Opt-in and
  backward compatible: a connector with no grants is unchanged; once it has any grant
  it is **deny-by-default** (only a caller holding a role with a matching ref-prefix
  may read), and denied reads are audited. Manage grants at
  `GET/POST/DELETE /api/v1/connect/ref-grants` (gated by `roles.read` / `roles.write`).
  ([#254])

[#254]: https://github.com/keyorixhq/keyorix/pull/254

## v0.42.0 — 2026-06-16

Keyorix Connect reaches full surface coverage — every cloud secret store, every transport.

### Added
- **Azure Key Vault Connect connector** — read-through federation now supports Azure
  Key Vault alongside AWS Secrets Manager, GCP Secret Manager, and HashiCorp Vault.
  `ref` is the secret name (optionally `name/version`); the vault URL is the
  connector's `address`. Credentials come from `DefaultAzureCredential` (managed /
  workload identity / env / CLI), never from config, and the per-connector
  `allowed_refs` prefix guardrail applies. No new dependency. ([#252])
- **gRPC ConnectService** — Keyorix Connect is now reachable over gRPC at parity with
  the HTTP `/connect` routes (`ListConnectors`, `ReadSecret`), gated by the dedicated
  `connect.read` permission. Values are proxied on demand and never persisted. ([#251])

With this release Keyorix Connect spans **4 stores × 2 transports** — AWS SM / GCP SM /
Azure KV / Vault, over HTTP and gRPC, all gated by `connect.read` and audited.

[#251]: https://github.com/keyorixhq/keyorix/pull/251
[#252]: https://github.com/keyorixhq/keyorix/pull/252

## v0.41.0 — 2026-06-16

Least-privilege for Keyorix Connect + upgrade-safe permission seeding.

### Added
- **`connect.read` permission** — Keyorix Connect now has its own permission instead
  of reusing `secrets.read`, so granting native secret-read access no longer implies
  read access to external stores (ADR-044). It ships granted to `admin` /
  `system_admin`. ([#249])
- **Idempotent RBAC permission reconciliation on startup** — new canonical
  permissions added in a release are now seeded into already-initialised installs
  automatically (created and granted to their baseline roles), so an upgrade no longer
  leaves a new permission unheld by any role. Additive and **non-clobbering**:
  existing permissions' grants are never altered, preserving operator customizations;
  a no-op on a pre-bootstrap install. ([#249])

### Changed
- The Keyorix Connect routes (`/connect/*`) now require `connect.read` instead of
  `secrets.read`. **Upgrade note:** a non-admin principal that used Connect via
  `secrets.read` must be granted `connect.read`; admins/`system_admin` receive it
  automatically on first start after upgrade. ([#249])

[#249]: https://github.com/keyorixhq/keyorix/pull/249

## v0.40.0 — 2026-06-16

Keyorix Connect adds HashiCorp Vault.

### Added
- **Keyorix Connect — HashiCorp Vault backend** (ADR-043): a `vault` connector reads
  a secret path via Vault's HTTP API and returns its data, completing the
  AWS / GCP / Vault trio. KV v2 is detected and unwrapped; KV v1 returns the data map
  as-is. Configure with `address` and `token_env` (default `VAULT_TOKEN`, read from
  the environment); the per-connector `allowed_refs` prefix allowlist applies as for
  the other backends. Read-only, gated by `secrets.read`, audited
  `connect.secret_read`. ([#247])

### Notes
- No new dependency (a Vault KV read is a single authenticated HTTP GET). A dedicated
  `connect.read` permission, caching, and per-reference scoping remain follow-ups.

[#247]: https://github.com/keyorixhq/keyorix/pull/247

## v0.39.0 — 2026-06-16

Keyorix Connect: read secrets from external stores through Keyorix.

### Added
- **Keyorix Connect — read-through federation** (ADR-043, opt-in, off by default). A
  new read-only API proxies an authorized, audited read of a secret's *current* value
  from an external store, without importing or persisting it — so teams reach existing
  external secrets through Keyorix's RBAC and audit trail. Backends:
  **AWS Secrets Manager** and **GCP Secret Manager**. Configure connectors under
  `connect.connectors`; `GET /api/v1/connect/{name}/secret?ref=…` returns the value
  (gated by `secrets.read`, audited `connect.secret_read`). Backend credentials come
  from the ambient identity chain (AWS env/instance-profile/IRSA; GCP ADC), never from
  config. An optional per-connector `allowed_refs` prefix allowlist bounds the
  readable set on top of the backend's IAM scope. ([#243], [#244])

### Fixed
- **RFC 3161 checkpoint anchors stay verifiable after the TSA cert expires** — anchor
  verification (ADR-029) now validates the timestamp-authority chain as of the token's
  asserted time rather than the current clock, so a stored anchor does not become
  unverifiable once its TSA signing certificate lapses. ([#245])

### Notes
- Connect is read-only (no import/sync); the external store stays authoritative.
  Vault, caching, and a dedicated `connect.read` permission are planned follow-ups.

[#243]: https://github.com/keyorixhq/keyorix/pull/243
[#244]: https://github.com/keyorixhq/keyorix/pull/244
[#245]: https://github.com/keyorixhq/keyorix/pull/245

## v0.38.0 — 2026-06-16

Hardware-sealed master key, plus secret-ownership and lockout-visibility fixes.

### Added
- **TPM 2.0 hardware-sealed KEK provider** — `key_provider.type: tpm` seals the
  key-encryption key to the host TPM 2.0 (`tpm_device`, default `/dev/tpmrm0`). A
  random KEK is generated and sealed on first start; only the sealed blob
  (`wrapped_key_path`) touches disk and it is unsealable only on that machine's TPM,
  so the KEK can't be recovered from a stolen disk alone. `KEYORIX_MASTER_PASSWORD`
  is not required; move an existing install on with `migrate-provider --to-type tpm`.
  This completes the KEK-custody set: passphrase · file · env · exec · Shamir · TPM ·
  AWS/GCP/Azure KMS. ([#241])

### Fixed
- **Ownerless (machine-created) secrets are owned by nobody** — secrets created by a
  machine identity carry `OwnerID 0`; the owner-equality gates compared that directly
  to the actor id, so a machine actor (id 0) matched every ownerless secret and was
  treated as its owner (owner permission + share/revoke). Ownership now requires a
  non-zero, matching id on both sides. ([#239])

### Changed
- **Admin visibility of login lockout** — the user API now exposes
  `login_locked_until` while a per-account lockout is active, so an admin can see a
  locked-out account and clear it (`POST /users/{id}/unlock`). ([#240])

### Notes
- Additive/opt-in; no schema changes. The TPM sealed blob is bound to one host — back
  up the data under a portable provider, as a TPM clear/replacement makes it
  unrecoverable.

[#239]: https://github.com/keyorixhq/keyorix/pull/239
[#240]: https://github.com/keyorixhq/keyorix/pull/240
[#241]: https://github.com/keyorixhq/keyorix/pull/241

## v0.37.0 — 2026-06-16

Split-custody master key + MFA recovery-code self-service.

### Added
- **Shamir K-of-N split-custody KEK provider** — a new `key_provider.type: shamir`
  splits the 32-byte key-encryption key into **N Shamir shares** with a **K-of-N**
  threshold, so no single custodian holds it and at least K must combine their shares
  to unseal — separation of duties for the master key (ISO 27001 / NIS2). Generate
  with `keyorix encryption shamir-split --shares N --threshold K` (the KEK is never
  printed or stored — only the shares are); supply ≥ K shares at startup via
  `shamir_share_files` / `shamir_share_env`, or move an existing install on with
  `migrate-provider --to-type shamir`. The KEK is framed before splitting so a
  sub-threshold or wrong set of shares fails closed (it does not silently establish a
  wrong key). ([#236])
- **MFA recovery-code regeneration + remaining count** — a user can now see how many
  recovery codes remain (`GET /auth/mfa/recovery-codes`) and generate a fresh set
  (`POST /auth/mfa/recovery-codes/regenerate`) after re-authenticating with a current
  authenticator code or their password. Regenerating replaces the whole set (so old
  or leaked codes are revoked) and returns the new codes once. Audited
  `mfa.recovery_codes_regenerated`. ([#237])

### Notes
- Both additive and opt-in/self-service. `shamir` adds no schema change; the MFA
  change adds no schema change. ⚠️ For `shamir`, losing more than N-K shares makes the
  KEK — and all data — permanently unrecoverable; store and back up shares separately.

[#236]: https://github.com/keyorixhq/keyorix/pull/236
[#237]: https://github.com/keyorixhq/keyorix/pull/237

## v0.36.0 — 2026-06-15

Independently verifiable audit trail: anchor checkpoints to a trusted timestamp
authority.

### Added
- **External-notary anchoring of audit checkpoints (RFC 3161)** — each signed
  audit checkpoint (ADR-029) can now be anchored to a trusted timestamp authority
  (TSA), producing an independent, third-party-signed proof that the checkpoint
  existed at a point in time — a proof the server cannot forge or backdate, even by
  an attacker holding the data-encryption key. The TSA token is stored on the
  checkpoint and re-verifiable offline. Configure via `audit.checkpoint_notary`
  (`enabled`, `url`, `timeout`, `ca_cert_path`); anchoring is best-effort and never
  blocks checkpointing. The anchor (asserted time + TSA) is shown by
  `keyorix audit checkpoint`. ([#234])

### Notes
- Additive (three nullable `audit_checkpoints` columns) and opt-in. Verification
  requires `ca_cert_path` (the TSA's trust anchor): the token signer is chained to
  it with the time-stamping EKU, so an untrusted/self-signed token is rejected, and
  verification fails closed when no trust anchor is configured.

[#234]: https://github.com/keyorixhq/keyorix/pull/234

## v0.35.0 — 2026-06-15

KEK flexibility + gRPC parity: resolve the KEK from any command, and pull
compliance posture over gRPC.

### Added
- **`exec` KEK provider** — a new `key_provider.type: exec` resolves the
  key-encryption key by running an operator-configured command (`exec_command`,
  an argv run **without a shell**) and reading the KEK (raw 32 bytes, or
  hex/base64) from its stdout. It's the universal escape hatch for any external
  secret store Keyorix has no built-in client for — 1Password (`op read`), sops
  (`sops -d`), Vault (`vault read -field`), or a CSI/sidecar helper. Runs at
  startup (fail-closed, 30s timeout); `KEYORIX_MASTER_PASSWORD` is not required.
  `keyorix encryption migrate-provider --to-type exec --to-exec-command …`
  re-wraps an existing install's DEK onto it. ([#231])
- **ComplianceService over gRPC** — the compliance posture
  (`GetCompliancePosture`) and the evaluated control matrix
  (`GetComplianceControls`, mapped to ISO 27001 / SOC 2 / NIS2 / DORA clauses)
  are now available over gRPC in addition to HTTP/CLI, so auditors' automation
  can pull the deployment's control posture on the same authenticated channel.
  Read-only, gated by `system.read`. ([#232])

### Notes
- Both additive and opt-in/parity. No schema changes. The `exec` command is
  trusted deployment config (like `file_path`/`env_var`), run without a shell.

[#231]: https://github.com/keyorixhq/keyorix/pull/231
[#232]: https://github.com/keyorixhq/keyorix/pull/232

## v0.34.0 — 2026-06-15

Brute-force hardening: per-account login lockout.

### Added
- **Per-account login lockout** (`security.login_lockout`, opt-in, default off) —
  brute-force protection distinct from the per-IP rate limiter (ADR-040). After
  `max_attempts` failed password logins within `window`, the account is locked for a
  cooldown that backs off exponentially across repeated lockouts (`base_cooldown` ×
  2ⁿ, capped at `max_cooldown`). It binds to the **account** (not the IP), so rotating
  source IPs cannot evade it; while locked, even a correct password is refused (the
  lock is checked before the bcrypt compare, so no work is spent on a guess). A
  successful login clears the counter and an admin can clear a lock immediately with
  `POST /api/v1/users/{id}/unlock` (`users.write`), which does not change
  `account_state`. The lock auto-expires on read — no scheduler. `account.locked` /
  `account.unlocked` are audited. ([#229])

### Notes
- Additive migration (four nullable/defaulted `users` columns); safe on existing DBs.
  Because the lock binds to the account, a known username can be kept locked by
  failing logins — keep `base_cooldown`/`max_cooldown` short (documented in
  `CONFIGURATION.md`); the lock always self-heals and an admin can clear it.

[#229]: https://github.com/keyorixhq/keyorix/pull/229

## v0.33.0 — 2026-06-15

The multi-cloud dynamic-secrets release: GCP and Azure join AWS STS.

### Added
- **GCP and Azure dynamic-secret backends** — two new cloud-IAM backends alongside
  `aws-sts`: `gcp` mints a short-lived service-account access token via the IAM
  Credentials API (`{"service_account":...,"scopes":[...],"lifetime_seconds":N}`), and
  `azure` acquires a short-lived Azure AD (Entra) token via DefaultAzureCredential
  (`{"scopes":[...]}`). Both return the token in the issued credential's `fields`
  (`access_token` / `expiration`). Like AWS STS they are self-expiring — revoke is a
  no-op, renew is refused, and they issue with the auto-revoke sweeper off (the cloud
  provider enforces expiry). Credentials for the mint call come from the ambient
  identity (GCP ADC / Azure DefaultAzureCredential), never from Keyorix config. ([#227])

### Notes
- Additive: new backend types only; no schema changes, no new Go module
  (GCP via the existing `google.golang.org/api`, Azure via the existing identity SDK).

[#227]: https://github.com/keyorixhq/keyorix/pull/227

## v0.32.0 — 2026-06-15

The cloud-IAM dynamic-secrets release: mint short-lived AWS credentials on demand.

### Added
- **AWS STS dynamic-secret backend** — a new `aws-sts` backend for dynamic secrets
  mints short-lived AWS credentials via `sts:AssumeRole` (alongside the existing
  postgres/mysql/mongodb/redis database backends). Issuing a lease returns
  `access_key_id` / `secret_access_key` / `session_token` (surfaced via the API, gRPC,
  and CLI). The config's encrypted "admin DSN" carries a small JSON blob
  (`{"role_arn":...,"region":...,"duration_seconds":...}`); the optional creation
  template is an inline STS session policy that scopes the assumed role down. AWS
  credentials for the AssumeRole call come from the standard chain (env /
  instance-profile / IRSA). STS credentials self-expire, so revoke is a no-op and
  renew is refused (issue a new lease); AWS enforces the expiry, so issuing does not
  require the auto-revoke sweeper. ([#225])

### Notes
- Additive: a new backend type + an optional `fields` map on issued credentials; no
  schema changes. GCP and Azure cloud backends are planned follow-ups.

[#225]: https://github.com/keyorixhq/keyorix/pull/225

## v0.31.0 — 2026-06-15

The gRPC-parity release: the newer subsystems are now scriptable over gRPC too.

### Added
- **gRPC ProjectService** — list/get/create/update/delete projects and list
  environments over gRPC, with the same scoped authorization as the HTTP/CLI
  surface (`secrets.read`/`write`/`delete`). ([#221])
- **gRPC MachineIdentityService** — machine identities and their bearer-token
  credentials over gRPC: list/create/transition/classify identities and
  issue/list/revoke/classify tokens (the raw token is returned once). ([#222])
- **gRPC DynamicSecretService** — dynamic-secret configs and lease lifecycle over
  gRPC: list/get/create/classify configs and issue/list/revoke/renew/revoke-all
  leases (the issued credential is returned once; the admin DSN is never
  returned). ([#223])

### Notes
- Additive — new gRPC services alongside the existing HTTP+CLI; no schema changes.
- All new RPCs authenticate via the existing interceptor (session / PAT / machine
  token) and enforce the same RBAC the HTTP routes do.

[#221]: https://github.com/keyorixhq/keyorix/pull/221
[#222]: https://github.com/keyorixhq/keyorix/pull/222
[#223]: https://github.com/keyorixhq/keyorix/pull/223

## v0.30.0 — 2026-06-15

The IdP-driven-RBAC & legal-hold release: let the IdP grant roles, and place
indefinite holds on archived evidence.

### Added
- **SSO group → role mapping** — `group_role_map` on an SSO provider maps an IdP
  group-claim value to a Keyorix system role (e.g. `keyorix-admins` → `system_admin`),
  so the IdP can drive role assignment directly on login without pre-granting roles.
  Authoritative only over the mapped roles (a user gains the roles their asserted
  groups map to and loses any mapped role they no longer qualify for; unmapped/manual
  grants are untouched); an absent groups claim is a no-op. Audited as
  `auth.sso_roles_synced`. ([#217])
- **S3 Object Lock legal hold on the evidence sink** — `evidence_delivery.object_store
  .legal_hold` places an indefinite S3 Object Lock legal hold on each uploaded
  evidence pack and signature (no expiry; cleared only out-of-band by a principal with
  `s3:PutObjectLegalHold`), for litigation/investigation preservation. Independent of
  the retention `lock_mode`. ([#218])

### Notes
- Both additive and opt-in (off unless configured). No schema changes.
- ⚠️ Any IdP group named in `group_role_map` becomes a privilege grant — map only
  groups governed by IdP administrators (a group → `system_admin` confers global admin).

[#217]: https://github.com/keyorixhq/keyorix/pull/217
[#218]: https://github.com/keyorixhq/keyorix/pull/218

## v0.29.0 — 2026-06-15

The immutable-evidence release: lock archived compliance evidence as WORM.

### Added
- **S3 Object Lock (WORM) on the evidence object-store sink** — each scheduled
  evidence pack and its detached signature can be uploaded with an S3 Object Lock
  retention (`governance` or `compliance` mode + a retain-until window), so archived
  evidence cannot be overwritten or deleted before it expires — tamper-resistant
  evidence an auditor can rely on. The bucket must be created with Object Lock
  enabled; configure via `evidence_delivery.object_store.{lock_mode,lock_retain_days}`.
  ([#215])

### Notes
- Additive and opt-in (object lock is off unless `lock_mode` is set). No schema changes.

[#215]: https://github.com/keyorixhq/keyorix/pull/215

## v0.28.0 — 2026-06-15

The classification-coverage release: data-sensitivity labels now span every
secret-bearing surface, not just static secrets.

### Added
- **Classify dynamic-secret configs** — a dynamic-secret config (ADR-035) carries a
  data-classification label (public/internal/confidential/restricted), set at create
  or via `PATCH /dynamic-secrets/configs/{id}/classification`, so the credentials it
  mints have a sensitivity tier. ([#212])
- **Classify machine identities & credentials** — machine identities (ADR-023) and
  their bearer-token credentials (ADR-030) carry a classification label too, set at
  create/issue or via `PATCH …/machine-identities/{id}/classification` and
  `…/tokens/{tokenId}/classification` (a token defaults to its identity's tier). Adds
  `keyorix machine create --classification`. ([#213])
- **Classification posture coverage** — the compliance posture's classification
  section now tallies dynamic configs, machine identities, and machine credentials by
  level alongside static secrets (in the evidence pack and `keyorix compliance
  report`), so an auditor sees sensitivity coverage across all of them. ([#212], [#213])

### Notes
- All additive — new indexed columns only; classification defaults to unclassified.

[#212]: https://github.com/keyorixhq/keyorix/pull/212
[#213]: https://github.com/keyorixhq/keyorix/pull/213

## v0.27.0 — 2026-06-15

The federated-identity-lifecycle & evidence-durability release: let your IdP onboard
and group users on first login, and archive signed evidence to immutable object storage.

### Added
- **SSO just-in-time (JIT) user provisioning** — with `auto_provision` enabled on a
  provider, a first SSO login whose verified identity matches no existing account
  creates one on the spot (active, passwordless, with a configurable `default_role`
  baseline) instead of being refused, so an IdP that isn't wired for SCIM push can
  still onboard users on demand. The IdP subject is stored as the account's
  `externalId` for later reconciliation; audited as `auth.sso_jit_provisioned`.
  ([#208])
- **SSO native-group sync** — with `group_sync` enabled, each SSO login reconciles the
  user's native Keyorix group memberships from the IdP's groups claim (the IdP is
  authoritative — memberships are added for asserted groups and removed for
  non-asserted ones), so group-based access follows the IdP without a separate SCIM
  push. Only existing native groups are touched; the claim name is configurable
  (`groups_claim`); an absent claim is a safe no-op. Audited as
  `auth.sso_groups_synced`. ([#210])
- **S3-compatible object-storage evidence sink** — scheduled compliance evidence packs
  can now be delivered to an object-storage bucket (AWS S3, MinIO, Cloudflare R2,
  Backblaze B2, GCS interop) in addition to a local dir and/or webhook, so evidence can
  land in immutable / object-locked (WORM) storage an auditor pulls from. The pack and
  its detached signature are uploaded; credentials resolve via the standard AWS chain.
  Configure via `evidence_delivery.object_store`. ([#209])

### Security
- SSO no longer trusts an email an IdP explicitly marks unverified
  (`email_verified: false`) for account matching or provisioning; an absent claim
  stays trusted (it is optional in OIDC and some enterprise IdPs omit it). ([#208])

### Notes
- All additive — no schema changes; every new behaviour is opt-in and off by default.

[#208]: https://github.com/keyorixhq/keyorix/pull/208
[#209]: https://github.com/keyorixhq/keyorix/pull/209
[#210]: https://github.com/keyorixhq/keyorix/pull/210

## v0.26.0 — 2026-06-15

The federated-identity & alerting release: sign in through your IdP, get compliance
pushed to your team channels, and prove your evidence is authentic.

### Added
- **Human SSO login via OIDC (RFC 6749 authorization-code flow)** — users sign in
  through their identity provider (Okta, Entra ID, …) and Keyorix mints the same
  session a password login would, so an IdP-provisioned (passwordless) user can
  actually sign in. The id_token is fully verified (signature against the issuer's
  JWKS, issuer, audience, expiry, and the nonce); the identity maps to a Keyorix
  account by the SCIM `externalId` then email (no auto-provisioning; suspended users
  refused). Endpoints discovered from the issuer; configure via `sso`. The web login
  page gains "Sign in with <provider>" buttons. ([#203])
- **Slack and Microsoft Teams notification channels** — the in-app notifications
  Keyorix creates (approvals, anomaly alerts, rotation/recertification reminders,
  break-glass) can now be delivered to a Slack or Teams channel via an incoming
  webhook, alongside email/webhook. Configure via `notifications.{slack,teams}`.
  ([#204])
- **Scheduled compliance digest** — an opt-in scheduler periodically broadcasts a
  posture + control-matrix summary (controls pass/gap, overdue recertifications,
  rotation gaps, unclassified secrets, open anomalies, active risk exceptions) to the
  configured notification channels — continuous monitoring without opening the
  console. Configure via `compliance_digest`. ([#205])
- **Signed, verifiable evidence packs (ISO 27001 / SOC 2)** — each scheduled evidence
  export is HMAC-signed with a DEK-derived key the database/DBA does not hold; a
  detached `.sig` is written next to the pack (and the signature rides the webhook in
  an `X-Keyorix-Evidence-Signature` header). `keyorix compliance verify` (and `POST
  /compliance/evidence/verify`) prove an archived pack is authentic and unmodified.
  Requires encryption enabled. ([#206])

### Notes
- Additive schema only (an `sso_login_states` table) — safe on existing databases.
- SSO logins bypass Keyorix-local MFA: the IdP is the authenticator.

[#203]: https://github.com/keyorixhq/keyorix/pull/203
[#204]: https://github.com/keyorixhq/keyorix/pull/204
[#205]: https://github.com/keyorixhq/keyorix/pull/205
[#206]: https://github.com/keyorixhq/keyorix/pull/206

## v0.25.0 — 2026-06-15

The enterprise-compliance release: an auditor-ready control matrix, a governed risk
register, and SCIM provisioning for IdP-driven identity lifecycle.

### Added
- **Compliance control matrix (ISO 27001 / SOC 2 / NIS2 / DORA)** — every control
  Keyorix enforces is now mapped to its clause references across the four regimes,
  with a **live status** (pass / gap / not-configured) derived from the posture.
  `GET /compliance/controls`, embedded in the evidence pack, `keyorix compliance
  controls`, and a control-matrix panel in the web console. ([#198])
- **Risk register / exceptions (ISO 27001 A.5.8)** — record a **governed, time-bound
  acceptance** of a known control gap (an SoD violation, an un-rotated secret, …):
  an owner, a justification, and a required expiry. Active exceptions surface in the
  posture and the evidence pack, so an auditor sees an accepted-with-a-deadline risk
  rather than an ungoverned gap. `GET/POST/DELETE /risk-exceptions`, `keyorix risk
  list|add|revoke`, and a register panel in the web console. ([#199])
- **SCIM 2.0 provisioning (RFC 7644)** — an opt-in `/scim/v2` endpoint group lets an
  IdP (Okta, Entra ID, …) **provision, update, deactivate, and deprovision users and
  sync groups** automatically, authenticated by a static bearer token. Users:
  Create/List/Get/Replace/PATCH(active)/Delete + `ServiceProviderConfig`; Groups:
  Create/List/Get/Replace/PATCH(members)/Delete. Configure via `scim`. ([#200], [#201])

### Notes
- Additive schema only (a `risk_exceptions` table; an `external_id` column on
  `users`) — safe on existing databases.
- A SCIM `userName` (typically an email/UPN) maps to the user's email and a compliant
  alphanumeric Keyorix username is derived from it; the IdP's `externalId` is stored
  for reconciliation. Provisioned users have no usable password (SSO / out-of-band).
- The Keyorix web console gains the control-matrix and risk-register panels on the
  Compliance page (keyorix-web).

[#198]: https://github.com/keyorixhq/keyorix/pull/198
[#199]: https://github.com/keyorixhq/keyorix/pull/199
[#200]: https://github.com/keyorixhq/keyorix/pull/200
[#201]: https://github.com/keyorixhq/keyorix/pull/201

## v0.24.0 — 2026-06-14

The operationalisation release: compliance controls run on a schedule, reach people
where they work, and deliver evidence off-box.

### Added
- **Scheduled access recertification (ISO 27001 A.5.18)** — an opt-in scheduler that
  enforces a review cadence: it finds projects overdue for review (never reviewed,
  or last reviewed longer ago than the configured window) and either auto-opens a
  recertification campaign or reminds the project's admins to, and nudges admins of
  in-flight campaigns with pending items. The cadence also drives a new
  "projects overdue" figure in the compliance posture. Configure via
  `recertification`. ([#192])
- **External notification channels (ISO 27001 A.5.5 / SOC 2)** — the in-app
  notifications Keyorix creates (approvals, anomaly alerts, rotation/recertification
  reminders, break-glass) can now be **fanned out to email and/or a webhook**,
  best-effort and asynchronously (a slow channel never blocks the triggering action).
  Configure via `notifications.{webhook,email}`. ([#193], [#194])
- **Off-box evidence delivery (ISO 27001 / SOC 2)** — scheduled compliance-evidence
  delivery can now **POST the evidence pack to a webhook** in addition to (or instead
  of) a local directory, so evidence survives the node without a mounted volume.
  Configure via `evidence_delivery.webhook`. ([#195])
- **Data-classification filter on the secrets API (ISO 27001 A.5.12)** — `GET
  /secrets` accepts a `classification` query parameter (`public|internal|
  confidential|restricted|unclassified`). ([#196])

### Notes
- No schema changes — every feature builds on existing tables.
- The Keyorix web console gains a classification column, filter, and bulk-classify on
  the secrets list, and surfaces the recertification-overdue count and the configured
  data-retention windows on the Compliance page (keyorix-web).

[#192]: https://github.com/keyorixhq/keyorix/pull/192
[#193]: https://github.com/keyorixhq/keyorix/pull/193
[#194]: https://github.com/keyorixhq/keyorix/pull/194
[#195]: https://github.com/keyorixhq/keyorix/pull/195
[#196]: https://github.com/keyorixhq/keyorix/pull/196

## v0.23.0 — 2026-06-14

The retention release: data is kept exactly as long as policy requires, and the
evidence that proves it is delivered automatically.

### Added
- **Per-record-type data-retention policies (ISO 27001 A.5.33 / GDPR
  storage-limitation / DORA)** — configurable retention windows for the compliance
  records that previously accumulated forever: anomaly alerts, closed
  recertification campaigns (and their items), the break-glass register, and
  resolved access requests (and their approvals). An opt-in scheduler hard-deletes
  records past their window — never touching active/open/pending rows, cascading to
  dependent rows, and **respecting legal hold** (an active hold preserves
  everything). The audit trail (append-only) and soft-deleted rows (the separate
  ADR-032 purge) are deliberately never touched. Each `*_days` window defaults to
  `0` = keep forever; the configured windows join the compliance posture and
  `keyorix compliance report` as A.5.33 evidence. ([#189])
- **Scheduled compliance-evidence delivery (ISO 27001 / SOC 2 continuous
  evidence)** — an opt-in scheduler that periodically generates the auditor evidence
  pack and writes it as a timestamped JSON file to a configured directory for
  off-box archival, emitting a `compliance.evidence_exported` audit event each run
  (so the export is itself in the tamper-evident trail and is SIEM-forwarded).
  Configure via `evidence_delivery`. ([#190])

### Notes
- No schema changes — both features build on existing tables.
- The Keyorix web console gains a per-secret data-classification badge and inline
  level picker on the secret-detail view (keyorix-web), closing the A.5.12
  classification loop the compliance posture already reported on.

[#189]: https://github.com/keyorixhq/keyorix/pull/189
[#190]: https://github.com/keyorixhq/keyorix/pull/190

## v0.22.0 — 2026-06-14

The detection-and-preservation release: proactive alerting on access anomalies and
a legal hold that preserves records under investigation.

### Added
- **Proactive anomaly alerting (NIS2 detection & response)** — detected access
  anomalies (off-hours / new-IP / new-user access to secrets) are now pushed out
  rather than just persisted: an in-app alert to the project's admins **and** a
  `security.anomaly_detected` audit event that the SIEM forwarder picks up (so
  anomalies reach the SOC). Each anomaly is announced once. Opt-in via the
  `anomaly_alerts` config (which also makes the existing scan schedule
  configurable); the open-anomaly count joins the compliance posture. ([#186])
- **Legal hold (ISO 27001 A.5.34 / eDiscovery / DORA)** — a deployment-wide
  litigation/investigation hold that, while active, **blocks every background
  hard-delete job** (the retention purge, the JIT role-grant-expiry sweep, the
  login-attempt prune) so records subject to hold are preserved. Storage-backed and
  runtime-toggleable (place it now, no restart); the guard fails safe (skips a purge
  if hold status can't be read). `GET/POST/DELETE /api/v1/legal-hold` and `keyorix
  legal-hold status|place|lift` (status `system.read`; place/lift `system.write`);
  placing/lifting is audited and the hold status joins the compliance posture. ([#187])

### Notes
- Additive schema only (new `legal_holds` table; an `alerted` column on
  `anomaly_alerts`) — safe on existing databases.
- The Keyorix web console gains an open-anomalies tile and a legal-hold banner with
  a place/lift control on the Compliance page (keyorix-web).

[#186]: https://github.com/keyorixhq/keyorix/pull/186
[#187]: https://github.com/keyorixhq/keyorix/pull/187

## v0.21.0 — 2026-06-14

### Added
- **Dual-control (N-of-M) approval for access requests (ISO 27001 A.5.3 / SOX)** —
  an access request can now require multiple **distinct** approvers before the role
  is granted, so no single admin can unilaterally grant access. Configure the
  threshold with `dual_control.required_approvals` (default 1 = single approval).
  Below the threshold the request stays pending; the listing shows the M-of-K
  progress, remaining approvers are notified, and each sign-off is audited. A
  requester can never approve their own request (maker ≠ checker). The web console
  shows the approval progress on the pending-requests view. ([#184])

[#184]: https://github.com/keyorixhq/keyorix/pull/184

## v0.20.0 — 2026-06-14

The compliance-reporting & data-classification release: turn the controls Keyorix
enforces into the artifacts an auditor (ISO 27001 / SOC 2 / NIS2 / DORA) consumes —
a single posture, an evidence pack, separation-of-duties detection, and secret
data classification.

### Added
- **Controls-posture report** — `GET /api/v1/compliance/posture` and `keyorix
  compliance report` roll up the deployment's control posture into one structured
  object: audit-trail integrity (chain verified, checkpointed), access governance
  (review-campaign coverage, dormant role grants, SoD violations), rotation hygiene
  (overdue / due-soon), identity (second-factor coverage), emergency access
  (break-glass usage), and data classification (secrets per sensitivity level).
  Gated by `system.read`. ([#177], [#180], [#182])
- **Auditor evidence pack** — `GET /api/v1/compliance/evidence` and `keyorix
  compliance export [--output FILE]` bundle the posture with the records that
  substantiate it (the audit-chain anchor, the access-review campaigns, the
  break-glass register, the overdue rotations, and the SoD violations) as a
  timestamped, archivable JSON. ([#178], [#180])
- **Separation of duties (ISO 27001 A.5.3 / SOX)** — define toxic permission
  combinations (two permissions one principal must not hold together) and detect
  every user who effectively holds both sides. `GET/POST/DELETE /api/v1/sod/policies`
  + `GET /api/v1/sod/violations`; `keyorix sod policy …` and `keyorix sod
  violations`. ([#179])
- **Secret data classification (ISO 27001 A.5.12 / A.5.13)** — label a secret with
  its sensitivity (`public` / `internal` / `confidential` / `restricted`), at
  creation or via `PATCH /api/v1/secrets/{id}/classification` and `keyorix secret
  classify`. The label is audited, filterable, and counted in the classification
  posture. ([#181])

### Notes
- Additive schema only (new tables `sod_policies`; a nullable `classification`
  column on `secret_nodes`) — safe on existing databases.
- The Keyorix web console gains a live **Compliance** posture dashboard surfacing
  the controls posture, SoD violations, and classification coverage (keyorix-web).

[#177]: https://github.com/keyorixhq/keyorix/pull/177
[#178]: https://github.com/keyorixhq/keyorix/pull/178
[#179]: https://github.com/keyorixhq/keyorix/pull/179
[#180]: https://github.com/keyorixhq/keyorix/pull/180
[#181]: https://github.com/keyorixhq/keyorix/pull/181
[#182]: https://github.com/keyorixhq/keyorix/pull/182

## v0.19.0 — 2026-06-14

The access-recertification / least-privilege / incident-response release (ISO 27001
A.5.18, SOC 2 CC6.2–6.3, NIS2/DORA): review who can reach a project's secrets, act
on it, time-bound it, run it on a schedule, spot stale access, and break the glass
in an emergency.

### Added
- **Project access review (ISO 27001 A.5.18)** — `GET /api/v1/projects/{id}/access-review`
  and `keyorix access-review` enumerate every grant of access to a project's secrets:
  role-based standing access (the role + the highest secrets action it confers) plus
  the per-secret grants — ownership and direct/group shares. The `source` of each
  grant is reported. Gated by `roles.read` at the project scope. ([#169], [#170])
- **Attest / revoke recertification (A.5.18)** — close the review loop: `POST
  …/access-review/{attest,revoke}` and the `keyorix access-review attest|revoke`
  subcommands certify a grant as reviewed-and-kept, or remove it (the underlying
  role assignment or share). Both are audited (`access_review.attested`/`.revoked`);
  attest needs `roles.read`, revoke `roles.assign`. ([#171])
- **Just-in-time / time-bound role grants** — role grants can carry an expiry and
  stop authorizing **the instant they pass** (the authorization queries filter on
  expiry — not sweep-dependent). Access-request approval can grant time-bound
  (`grant_ttl` on the resolve API, `keyorix request review --ttl`), and an opt-in
  HA-gated `jit_access_expiry` sweeper reclaims expired rows, auditing each as
  `role.expired`. ([#172])
- **Periodic access-review campaigns (A.5.18 "review at planned intervals")** —
  turn the point-in-time review into a tracked cycle: open a campaign (snapshots
  current access into per-grant items), attest/revoke each, then close it as the
  evidence record. `…/access-review/campaigns[/…]` endpoints +
  `keyorix access-review campaign open|list|show|decide|close`. ([#173])
- **Dormant / unused-access detection** — the review annotates each user grant with
  the principal's last secret access in the project (from the audit trail); a grant
  never used (or stale ≥90 days) is flagged as dormant standing access to prune. New
  `last_used_at` on review entries + a `LAST-USED` CLI column. ([#174])
- **Break-glass emergency access (NIS2/DORA incident response)** — opt-in,
  self-service `POST …/break-glass` + `keyorix break-glass`: immediately self-grant
  a configured emergency role, time-bound and auto-expiring, with a mandatory
  justification, a loud audit event (`break_glass.activated`), and an admin alert —
  recorded as a queryable activation for post-hoc review, with admin early-revoke.
  Configured via the `break_glass` block (off by default). ([#175])

### Notes
- New config blocks: `jit_access_expiry` (expiry sweeper) and `break_glass`
  (emergency access) — both opt-in, documented in CONFIGURATION.md.
- Additive schema only (new tables: `access_review_campaigns`,
  `access_review_items`, `break_glass_activations`; nullable `expires_at` on role
  grants) — safe on existing databases.
- The Keyorix web console gains a project **Access Review** tab surfacing the
  review, attest/revoke, dormancy, and the campaign cycle (keyorix-web).

[#169]: https://github.com/keyorixhq/keyorix/pull/169
[#170]: https://github.com/keyorixhq/keyorix/pull/170
[#171]: https://github.com/keyorixhq/keyorix/pull/171
[#172]: https://github.com/keyorixhq/keyorix/pull/172
[#173]: https://github.com/keyorixhq/keyorix/pull/173
[#174]: https://github.com/keyorixhq/keyorix/pull/174
[#175]: https://github.com/keyorixhq/keyorix/pull/175

## v0.18.0 — 2026-06-13

### Added
- **`keyorix audit` CLI** — operate the tamper-evident audit trail (ADR-029) from
  the terminal: `verify` (re-walk the hash chain; non-zero exit on tampering;
  `--json` emits the external anchor), `logs` (interactive filtered query for
  investigation/spot-checks), `export` (NDJSON SIEM pull), and `checkpoint` (write
  a signed checkpoint on demand). ([#152], [#155], [#157])
- **Signed in-DB audit checkpoints (ADR-029)** — an opt-in, HA-gated scheduler
  (`audit_checkpoints.enabled`) signs the verified audit-chain head with an HMAC
  keyed by a DEK-derived key the database/DBA does not hold, so tail-truncation /
  genesis re-seed becomes detectable **on-box** (not just via the off-box anchor).
  Surfaced as `checkpointed` on `GET /audit/verify`. Requires encryption. ([#153])
- **`keyorix rotation` CLI** — manage rotation policies (NIS2/ISO A.5.15) from the
  terminal: `list` / `create` / `show` / `delete` and `status` (overdue / approaching
  covered secrets). ([#156])
- **Personal access tokens & machine identities over gRPC** — gRPC authentication
  now has full parity with HTTP (session + PAT + machine): `kx_pat_` carries its
  ADR-042 least-privilege restriction onto the gRPC context, and `kx_machine_`
  authenticates a machine principal with machine RBAC and no admin bypass. ([#158], [#159])
- **`expires_before` filter on `GET /api/v1/secrets`** — list secrets already
  expired or expiring before a given RFC3339 time (for "expiring secrets" views and
  scripts). ([#167])

### Fixed
- **Owned-secrets listing** used `created_by == username` (a fragile string proxy)
  instead of `owner_id`, the canonical ownership the permission model enforces —
  CLI-created secrets were invisible to their owner and a deleted-then-reused
  username could mis-attribute ownership. Now filters by `owner_id`. ([#163])
- **Rotation evaluation** silently capped at 1000 secrets per policy, so overdue
  secrets in projects with more than 1000 went unreported by the reminder scheduler
  and the status/evaluate views — now pages through all of them. ([#164])
- **Dashboard "expiring secrets" warning** capped at 100, silently dropping
  expiring secrets for users with more than 100 — now uses an expiration filter and
  pages through all. ([#165])
- **`keyorix run`** injected only the first 1000 secrets as env vars (subprocess
  silently misconfigured), and **`keyorix secret get --name`** could not find a
  secret beyond the first 1000 — both now page through all. ([#166])

### Security / Hardening
- **PAT non-funnelled authz guards (ADR-042)** — `core.IsGlobalAdmin` and
  `middleware.RequireRole` now fail closed for a PAT-restricted request, so
  least-privilege scoping holds even on the two authz paths that do not funnel
  through `core.Authorize`. ([#154])
- **Tenant-isolation scope-boundary tests** — SQL-level tests pinning user-RBAC
  role resolution, machine-RBAC resolution, and secret-listing project/environment
  isolation, including the cross-project/cross-environment leak guards (so a
  regression of the `AND`/`OR` SQL precedence fails CI). ([#160], [#161], [#162])

[#152]: https://github.com/keyorixhq/keyorix/pull/152
[#153]: https://github.com/keyorixhq/keyorix/pull/153
[#154]: https://github.com/keyorixhq/keyorix/pull/154
[#155]: https://github.com/keyorixhq/keyorix/pull/155
[#156]: https://github.com/keyorixhq/keyorix/pull/156
[#157]: https://github.com/keyorixhq/keyorix/pull/157
[#158]: https://github.com/keyorixhq/keyorix/pull/158
[#159]: https://github.com/keyorixhq/keyorix/pull/159
[#160]: https://github.com/keyorixhq/keyorix/pull/160
[#161]: https://github.com/keyorixhq/keyorix/pull/161
[#162]: https://github.com/keyorixhq/keyorix/pull/162
[#163]: https://github.com/keyorixhq/keyorix/pull/163
[#164]: https://github.com/keyorixhq/keyorix/pull/164
[#165]: https://github.com/keyorixhq/keyorix/pull/165
[#166]: https://github.com/keyorixhq/keyorix/pull/166
[#167]: https://github.com/keyorixhq/keyorix/pull/167

## v0.17.0 — 2026-06-13

### Added
- **Rotation-reminder scheduler** — an opt-in background job
  (`rotation_reminders.enabled`) that proactively notifies project admins (in-app)
  of secrets overdue or approaching their rotation deadline under an active
  rotation policy, turning the reactive rotation-health views into proactive
  nudges (a NIS2/ISO credential-rotation-hygiene control). One standing reminder
  per project per admin, de-duplicated while unread; single-replica-gated in HA.
  Default off; `schedule` (Go duration) controls the cadence (default 24h). ([#150])

[#150]: https://github.com/keyorixhq/keyorix/pull/150

## v0.16.0 — 2026-06-13

### Added
- **`keyorix pat` CLI** — create, list, and revoke personal access tokens from the
  terminal (previously web-UI/API only). `pat create` surfaces the full ADR-042
  least-privilege model via flags: `--scope` (repeatable permission allowlist),
  `--project-id`, and `--environment-id` (which requires `--project-id`); the raw
  token is printed exactly once. Completes the PAT least-privilege story across
  backend, web UI, and CLI. ([#148])

[#148]: https://github.com/keyorixhq/keyorix/pull/148

## v0.15.0 — 2026-06-13

Migration reach and least-privilege completion. No config or schema changes
(the PAT scoping column is an additive, default-off migration).

### Added
- **Import from Google Cloud Secret Manager** — `keyorix secret import --source gcp
  --gcp-project <id>` is the fourth live migration source after Vault, AWS Secrets
  Manager and Azure Key Vault, completing big-3 cloud coverage. Authenticates with
  Application Default Credentials, reads each secret's latest enabled version, and
  explodes JSON values per field. Credentials stay CLI-side; the GCP SDK links into
  the CLI binary only. ([#145])
- **Per-environment PAT confinement** — a personal access token can now be confined
  to a single environment (`environment_scope` on `POST /auth/tokens`), the third
  and final least-privilege scoping axis alongside the permission allowlist and
  project confinement (ADR-042). A token scoped to an environment may act only on
  that environment's secrets — e.g. a staging-only CI credential. Enforced before
  the admin bypass, so it bounds even an admin's own token. Existing tokens are
  unaffected. ([#146])

[#145]: https://github.com/keyorixhq/keyorix/pull/145
[#146]: https://github.com/keyorixhq/keyorix/pull/146

## v0.14.0 — 2026-06-13

Dynamic-secrets expansion: a fourth backend and full CLI lifecycle coverage.

### Added
- **Redis dynamic-secrets engine** (`backend_type: redis`) — the fourth dynamic-
  secrets target after PostgreSQL, MySQL and MongoDB. It mints a short-lived Redis
  **ACL user** (`ACL SETUSER kx_dyn_<random> on >password <rules>`) and drops it on
  revoke (`ACL DELUSER`). The admin DSN is a Redis URI (`redis://…` / `rediss://…`)
  for a user holding the `+acl` command; the creation template is whitespace-
  separated ACL rule tokens (`~app:* +@read +@write`). Username/password are passed
  as discrete RESP arguments, so credential injection is structurally impossible.
  Like MySQL/MongoDB, Redis ACL users have no native expiry — enable the auto-revoke
  sweeper. ([#142], ADR-035)
- **`keyorix dynamic-secret create`** — register a dynamic-secrets target config
  from the CLI (previously API/UI-only). The privileged admin DSN is read from
  `KEYORIX_DYNAMIC_ADMIN_DSN` or a hidden prompt — never a flag, so it can't leak
  into shell history. The CLI now covers the full lifecycle: create → issue →
  leases → renew → revoke → revoke-all, across all four backends. ([#143])

[#142]: https://github.com/keyorixhq/keyorix/pull/142
[#143]: https://github.com/keyorixhq/keyorix/pull/143

## v0.13.3 — 2026-06-13

Further security/correctness fixes from the access-control & integrity audit. No
new features; no config or schema changes.

### Fixed
- **OIDC/JWKS: bounded stale-key fallback** (ADR-031). On a transient JWKS refetch
  failure the resolver fell back to a cached signing key with no age bound, so a
  key the issuer rotated out (e.g. because it was compromised) could keep verifying
  federation tokens indefinitely while the issuer's JWKS endpoint was unreachable.
  The fallback is now bounded to a short grace window past the cache TTL; beyond it
  a failed refetch fails closed. (Affects deployments using OIDC/Kubernetes-JWT
  federation.) ([#138])
- **Audit log: tamper-evidence anchor** (ADR-029). On-box chain re-verification
  could not detect tail-truncation or a genesis re-seed (a shorter, self-consistent
  chain still verifies), and the documented "SIEM export anchors the head"
  mitigation was not actually wired — the export omitted the chain hashes.
  `GET /audit/verify` now returns the chain `head_hash`/`head_id`, and
  `GET /audit/export` now carries each event's `prev_hash`/`entry_hash`, so an
  off-box observer can detect truncation. ([#139])

### Internal
- Added a router-wide regression guard asserting a read-only persona cannot succeed
  at any mutating route — preventing the access-control privilege-escalation class
  fixed in v0.13.2 from recurring. ([#140])

[#138]: https://github.com/keyorixhq/keyorix/pull/138
[#139]: https://github.com/keyorixhq/keyorix/pull/139
[#140]: https://github.com/keyorixhq/keyorix/pull/140

## v0.13.2 — 2026-06-13

Authorization-hardening fixes from a systematic adversarial audit of the access
control across HTTP, gRPC, and account provisioning. No new features; no config or
schema changes. Recommended for any deployment that enables gRPC or exposes the
admin API to non-super-admin personas.

### Fixed
- **Account-provisioning privilege escalation** (ADR-028). `POST /api/v1/users`
  (atomic provisioning, which can grant a system role + project assignments) was
  gated only by `users.read`, so a global read-only persona could create a
  `system_admin` and escalate to full admin. It now requires `users.write` and
  authorizes each grant at its scope. The password-reset / account-setup link now
  also evicts the subject's other sessions, so a self-service reset locks out a
  stolen session (matching change-password). ([#134])
- **`/users` and `/groups` route privilege escalation.** `PUT`/`DELETE`/`restore`
  on `/users/{id}` and all `/groups` CRUD + membership routes inherited only the
  group-level `users.read`; a read-only persona could edit/delete users and — via
  group membership, which confers the group's roles — escalate. User mutations now
  require `users.write`; group CRUD `users.write`; group membership `roles.assign`.
  ([#135])
- **gRPC cross-project privilege escalation & install-wide reads.** The Role,
  User, Audit and System gRPC services authorized against the flat (global)
  permission union, so a permission held at one project counted everywhere — a
  project admin could assign roles into any project, and project-scoped read
  permissions could read install-wide data. Every gRPC RPC now authorizes through
  scoped RBAC, identical to HTTP. (Affects deployments with gRPC enabled.) ([#136])

[#134]: https://github.com/keyorixhq/keyorix/pull/134
[#135]: https://github.com/keyorixhq/keyorix/pull/135
[#136]: https://github.com/keyorixhq/keyorix/pull/136

## v0.13.1 — 2026-06-12

Security/correctness fixes from an internal audit of the credential & crypto
subsystems. No new features; no config or schema changes.

### Fixed
- **Crash-durable key-material writes** (ADR-041) — every write of unrecoverable
  key material (the wrapped DEK on first run / rotation / KEK-provider migration,
  the KMS-wrapped KEK blob, and the KEK salt) is now `fsync`'d before returning,
  and each promote-`rename` is followed by a directory `fsync`. Previously these
  used `os.WriteFile`, leaving the bytes in the page cache; a power failure after
  `migrate-provider` reported success — and after the operator retired the old KEK
  — could lose the new wrapped DEK and orphan all ciphertext irreversibly. The
  data path and on-disk formats are unchanged. ([#131])
- **Dynamic-secrets lease fail-opens** (ADR-035) — (1) issuing from a backend with
  no database-level expiry (MySQL, MongoDB) is now refused while the auto-revoke
  sweeper is disabled, so a lease's advertised TTL is always enforced rather than
  silently never expiring; (2) if cleaning up a just-minted role after an aborted
  issue fails, a `revoke_failed` lease is recorded and audited so the orphaned
  credential is visible to an operator instead of being permanent and
  untrackable. ([#132])

[#131]: https://github.com/keyorixhq/keyorix/pull/131
[#132]: https://github.com/keyorixhq/keyorix/pull/132

## v0.13.0 — 2026-06-12

### Added
- **Personal access token least-privilege scoping** (ADR-042) — a PAT can now be
  minted **weaker than its owner**. At creation it may carry an optional permission
  allowlist (exact like `secrets.read`, the catch-all `*`, or a prefix like
  `secrets.*`) and/or a single-project confinement (`project_scope`). The
  restriction is a **filter that only ever narrows** the token below its owner —
  never an escalation, since the owner's live RBAC still runs after it. It is
  enforced at the single authorization chokepoint (before role resolution and the
  admin bypass), so it bounds even a global admin's own token across every
  authorization path. `POST /api/v1/auth/tokens` accepts `scopes` and
  `project_scope`; existing and unrestricted tokens are unaffected (full
  inheritance remains the default). Closes the last over-privileged-credential gap
  after machine identities (ADR-030). ([#129], ADR-042)

[#129]: https://github.com/keyorixhq/keyorix/pull/129

## v0.12.0 — 2026-06-12

### Added
- **MongoDB dynamic-secrets engine** (`backend_type: mongodb`) — the third dynamic-
  secrets target after PostgreSQL and MySQL, behind the same `CredentialEngine`
  interface. It mints `kx_dyn_<random>` users in the target's `admin` database
  (`createUser`) and drops them on revoke (`dropUser`, idempotent). The admin DSN is
  a MongoDB connection URI and the creation template is a JSON role spec
  (`{"roles": [{"role": "readWrite", "db": "app"}]}`); the username/password are
  passed as typed BSON values, so credential injection is structurally impossible.
  Like MySQL, MongoDB users carry no native expiry, so enable the auto-revoke
  sweeper for MongoDB targets. ([#127], ADR-035)

[#127]: https://github.com/keyorixhq/keyorix/pull/127

## v0.11.0 — 2026-06-12

KMS follow-ups: a third cloud backend for the wrapping key, plus zero-downtime
provider migration.

### Added
- **Azure Key Vault KEK provider** (`type: azure-kms`) — the third KMS backend for
  the KEK wrapping key, after AWS and GCP, behind the same `KMSClient` interface. It
  envelopes the KEK with the vault key's `wrapKey`/`unwrapKey` operations
  (RSA-OAEP-256); credentials come from `DefaultAzureCredential` (env / managed
  identity / workload identity) and the key is inherently pinned by name.
  ([#123], ADR-041)
- **`keyorix encryption migrate-provider`** — move an existing install between KEK
  providers (e.g. password → a cloud KMS) by **re-wrapping the DEK under the target
  provider's KEK without re-encrypting any data** — fast and with no database lock,
  unlike a DEK rotation. It backs up the previous wrapped DEK, verifies the target
  provider round-trips a probe before keeping the change, and prints the config block
  to apply. Migrating `--to-type password` also rotates the master passphrase.
  ([#125], ADR-041)

[#123]: https://github.com/keyorixhq/keyorix/pull/123
[#125]: https://github.com/keyorixhq/keyorix/pull/125

## v0.10.0 — 2026-06-12

The bring-your-own-KMS release.

### Added
- **KMS-backed KEK providers** — the key-encryption key's *wrapping* key can now
  live in a cloud KMS/HSM via envelope encryption: only the KMS-wrapped KEK blob
  is stored on disk and it is unwrapped via KMS at startup, so the wrapping key
  never exists in plaintext on the host. Both **AWS KMS** (`type: aws-kms`) and
  **GCP KMS** (`type: gcp-kms`) are supported, behind a common interface; startup
  is fail-closed if the KMS is unreachable. Joins the existing password / file /
  env providers. ([#120], [#121], ADR-041)
- **Dynamic-secret incident kill switch** — `keyorix dynamic-secret revoke-all
  <config-id>` (and `POST …/configs/{id}/revoke-all`) revokes every active lease
  from a config at once, for when a target database or config is compromised.
  ([#119], ADR-035)

[#119]: https://github.com/keyorixhq/keyorix/pull/119
[#120]: https://github.com/keyorixhq/keyorix/pull/120
[#121]: https://github.com/keyorixhq/keyorix/pull/121

## v0.9.0 — 2026-06-12

### Added
- **`keyorix dynamic-secret` CLI** — issue and manage on-demand database
  credentials (ADR-035) from the terminal: `list`, `issue <config-id>`,
  `leases <config-id>`, `renew <lease-id>`, `revoke <lease-id>` (aliases:
  `dynamic-secrets`, `dyn`). The issued username/password is shown once on
  `issue`. Config creation stays API/UI-only (it takes the privileged admin DSN).
  ([#117], ADR-035)

[#117]: https://github.com/keyorixhq/keyorix/pull/117

## v0.8.0 — 2026-06-12

### Added
- **Cluster-wide login rate limiting** — brute-force protection now counts failed
  attempts in the database rather than per-process memory, so the 10-attempts /
  15-minutes-per-IP limit holds across HA replicas (the old in-memory limiter
  enforced it independently on each replica). Covers every login surface —
  password, TOTP, WebAuthn second-factor, and passwordless. ([#114], ADR-040)

### Changed
- CI hygiene: the `lint` (golangci-lint) and `gitleaks` jobs are green and
  meaningful again — a `.gitleaks.toml` allowlist scopes the scanner to real
  source/config (away from sample-credential fixtures in demos/docs/tests), and
  the linter config keeps the bug-catching checks while dropping pure-style noise.
  Several genuine issues those linters surfaced were fixed. ([#115])

[#114]: https://github.com/keyorixhq/keyorix/pull/114
[#115]: https://github.com/keyorixhq/keyorix/pull/115

## v0.7.0 — 2026-06-12

Passwordless authentication and high-availability deployment.

### Added
- **Passwordless (usernameless) passkey login** — a registered passkey alone signs
  a user in, with no password. Registration now creates a discoverable credential,
  and login requires user verification (PIN/biometric), so a single gesture proves
  both possession and the user. Joins the existing password, password+TOTP, and
  password+passkey options. ([#112], ADR-036)
- **High-availability deployment** — Keyorix can now run as multiple stateless API
  replicas behind a load balancer. The background schedulers (anomaly detection,
  retention purge, dynamic-secrets auto-revoke) are gated by a PostgreSQL advisory
  lock so each runs on a single replica at a time instead of duplicating work on
  every replica. With the file/env KEK providers (v0.6.0) for shared keys, this
  completes the multi-replica story. ([#111], ADR-039)

[#111]: https://github.com/keyorixhq/keyorix/pull/111
[#112]: https://github.com/keyorixhq/keyorix/pull/112

## v0.6.0 — 2026-06-12

Key-management flexibility and a more complete dynamic-secrets engine: bring your
own KEK source (file/KMS/env), mint on-demand MySQL credentials, and cap or renew
leases — plus a full configuration reference.

### Added
- **Pluggable KEK providers** — the key-encryption key can now be sourced from a
  passphrase (default, unchanged), a **file** (a mounted CSI/sealed secret or KMS
  sidecar output), or an **environment variable** (KMS/secret-manager injection),
  via `storage.encryption.key_provider`. The default `password` provider is
  byte-identical to prior releases, so existing keys keep working with no
  migration. ([#106], ADR-038)
- **Dynamic secrets for MySQL** — on-demand MySQL accounts alongside the existing
  PostgreSQL engine, behind the same API (`backend_type: mysql`). ([#107], ADR-035)
- **Dynamic-secret lease lifecycle** — a per-config **max-TTL ceiling** that caps
  a credential's lifetime regardless of the TTL a caller requests, and **lease
  renewal** (`POST /dynamic-secrets/leases/{id}/renew`) to extend an active lease
  up to that ceiling instead of re-issuing. ([#109], ADR-035)
- **Configuration reference** — `docs/CONFIGURATION.md` documents every
  `keyorix.yaml` block (encryption/KEK providers, MFA, WebAuthn, dynamic secrets,
  OIDC, sessions, …) with examples, defaults, and environment variables. ([#108])

### Fixed
- The shipped `production.yaml` example used cron syntax for `purge.schedule`,
  which is parsed as a Go duration and silently fell back to the 24h default;
  corrected to a duration with a clarifying comment. ([#108])

[#106]: https://github.com/keyorixhq/keyorix/pull/106
[#107]: https://github.com/keyorixhq/keyorix/pull/107
[#108]: https://github.com/keyorixhq/keyorix/pull/108
[#109]: https://github.com/keyorixhq/keyorix/pull/109

## v0.5.0 — 2026-06-12

The authentication & dynamic-secrets release: phishing-resistant passkeys, MFA
you can mandate (deployment-wide or per-project), and on-demand database
credentials that expire on their own.

### Added
- **Dynamic secrets (PostgreSQL)** — on-demand, short-lived database credentials
  in the HashiCorp Vault database-secrets-engine model. Register a target with an
  admin DSN and an optional creation template; callers issue a lease that mints a
  fresh role on the target, returned once, and an opt-in sweeper auto-revokes
  every lease at expiry. The admin DSN and each issued credential are encrypted
  at rest and never returned by the API. ([#102], ADR-035)
- **WebAuthn / passkeys** — opt-in, phishing-resistant second factor alongside
  TOTP: origin-bound public-key assertions with no exportable shared secret and
  FIDO clone detection. Self-service registration of security keys / platform
  authenticators, and a two-step login that reuses the existing single-use
  challenge (no half-authenticated session is ever created). ([#103], ADR-036)
- **Deployment-mandated MFA** — `security.require_mfa` confines an interactive
  session without a second factor to the enrolment endpoints until the user
  enrols. Non-interactive credentials (personal access tokens, machine tokens,
  OIDC) are exempt so automation is never broken. ([#101], ADR-034)
- **Per-project MFA policy** — a project can require MFA for access to its scoped
  resources even when the deployment-wide policy is off, giving risk-proportionate
  step-up on a single install. A passkey or TOTP satisfies either mandate. ([#104], ADR-037)

### Security
- **Per-project MFA covers every project-scoped path** — a pre-merge security
  review found that secret *creation* authorised in-handler (the create route
  carries no path scope) and initially bypassed the per-project MFA gate; all
  in-handler-authorised mutations (secret create, dynamic-secret lease
  issue/revoke, rotation-policy create) now enforce it uniformly, with a
  regression test. ([#104])

[#101]: https://github.com/keyorixhq/keyorix/pull/101
[#102]: https://github.com/keyorixhq/keyorix/pull/102
[#103]: https://github.com/keyorixhq/keyorix/pull/103
[#104]: https://github.com/keyorixhq/keyorix/pull/104

## v0.4.0 — 2026-06-12

The security-hardening release: a new second factor, four subsystem security
audits with the findings fixed, and an auditor-ready evidence package.

### Added
- **Multi-factor authentication (TOTP)** — per-user opt-in second factor with a
  two-step login (a short-lived single-use challenge gates session issuance),
  single-use recovery codes, and the TOTP secret encrypted at rest. ([#99], ADR-034)
- **"Leave Vault in 5 minutes" demo** — a one-command, self-contained demo that
  stands up Keyorix + a throwaway Vault and migrates live secrets. ([#86])
- **Security verification & ENS evidence docs** — `SECURITY-VERIFICATION.md`
  (audits, fixes, CI gates) and `ENS-CONTROLS.md` (Spain's Esquema Nacional de
  Seguridad mapping), alongside the existing NIS2/DORA/ISO statement. ([#95], [#96])

### Security
Found by four subsystem security audits (auth/crypto/RBAC, HTTP, token/OIDC,
storage/remote-client), each fix regression-tested:
- **Cross-project privilege escalation / IDOR** — project-nested lifecycle routes
  (access-request approval, membership/machine-identity transitions, environment
  restore, invitation revoke/resend) acted on objects in a different project than
  the one the caller was authorised for. Now reconciled and rejected. ([#92], [#93])
- **Suspend/deactivate now revokes active sessions** — previously a suspended user
  kept access until their token expired. ([#87])
- **gRPC scoped RBAC** — secret and share operations over gRPC now enforce the same
  project-scoped permissions as HTTP (was the flat global set). ([#88], [#90])
- **Remote-client TLS secure-by-default** — an omitted `tls_verify` no longer
  disables certificate verification on the API channel. ([#97])
- **OIDC `jwks_uri` requires https** — signing keys are no longer fetched over
  plaintext. ([#94])
- **DEK-rotation completeness** — the re-encryption sweep is now ordered so a
  rotation can't skip rows and leave secrets under the old key. ([#89])

[#86]: https://github.com/keyorixhq/keyorix/pull/86
[#87]: https://github.com/keyorixhq/keyorix/pull/87
[#88]: https://github.com/keyorixhq/keyorix/pull/88
[#89]: https://github.com/keyorixhq/keyorix/pull/89
[#90]: https://github.com/keyorixhq/keyorix/pull/90
[#92]: https://github.com/keyorixhq/keyorix/pull/92
[#93]: https://github.com/keyorixhq/keyorix/pull/93
[#94]: https://github.com/keyorixhq/keyorix/pull/94
[#95]: https://github.com/keyorixhq/keyorix/pull/95
[#96]: https://github.com/keyorixhq/keyorix/pull/96
[#97]: https://github.com/keyorixhq/keyorix/pull/97
[#99]: https://github.com/keyorixhq/keyorix/pull/99

## v0.3.0 — 2026-06-11

The "adopt Keyorix" release: a complete path to bring your secrets in, install
the CLI, run it in CI, and deploy to Kubernetes.

### Added
- **Live secret migration** — `keyorix secret import --source {vault|aws|azure}`
  pulls secrets directly from a running HashiCorp Vault, AWS Secrets Manager, or
  Azure Key Vault (in addition to the existing file imports). Credentials stay
  client-side; the source is read-only. ([#79])
- **CI/CD integration** — a reusable GitHub Action
  (`keyorixhq/keyorix/integrations/github-action`) that injects secrets into a
  workflow as masked environment variables, plus GitLab CI and CircleCI
  examples. ([#82])
- **Kubernetes Helm chart** (`deploy/helm/keyorix`) — deploy the server + web UI
  + PostgreSQL to a cluster; bundled or external database; optional ingress;
  `helm test` hook. Published to `oci://ghcr.io/keyorixhq/charts` on release.
  ([#83], [#84])
- **Release pipeline** — a tagged workflow that cross-compiles and publishes the
  CLI + server binaries (with checksums) and the Helm chart on every `vX.Y.Z`
  tag. ([#81], [#84])

### Fixed
- **`install.sh`** downloaded assets under the wrong names (hyphens vs the
  published underscores), so it never worked against a real release. Corrected
  the names and added SHA-256 checksum verification. ([#80])
- A `.gitignore` pattern (`keyorix`) matched any nested directory of that name,
  silently hiding the new Helm chart from git. ([#83])

[#79]: https://github.com/keyorixhq/keyorix/pull/79
[#80]: https://github.com/keyorixhq/keyorix/pull/80
[#81]: https://github.com/keyorixhq/keyorix/pull/81
[#82]: https://github.com/keyorixhq/keyorix/pull/82
[#83]: https://github.com/keyorixhq/keyorix/pull/83
[#84]: https://github.com/keyorixhq/keyorix/pull/84

## v0.2.0 — 2026-04-27

Earlier release (binaries published out-of-band, before the automated pipeline).

## v0.1.0 — 2026-04-20

Initial tagged release.
