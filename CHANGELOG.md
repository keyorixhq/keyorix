# Changelog

All notable changes to Keyorix are documented here. This project follows
[Semantic Versioning](https://semver.org/).

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
