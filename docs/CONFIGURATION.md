# Keyorix configuration reference

This is the operator reference for `keyorix.yaml`. Every block is optional unless
noted; an absent block uses the documented default. Secrets (DB password, master
passphrase, SIEM/SMTP tokens) should come from **environment variables**, not the
file — see [Environment variables](#environment-variables).

The config file is located via, in order: an explicit path argument, then
`KEYORIX_CONFIG_PATH`, then `keyorix.yaml` in the working directory.

## Contents

- [Environment variables](#environment-variables)
- [environment](#environment) · [locale](#locale) · [server](#server) · [storage](#storage)
- [storage.encryption + key_provider](#encryption--kek-providers) (ADR-004, ADR-038)
- [secrets](#secrets) · [security + require_mfa](#security) (ADR-034)
- [webauthn](#webauthn) (ADR-036) · [dynamic_secrets](#dynamic_secrets) (ADR-035)
- [oidc](#oidc) (ADR-031) · [session](#session) · [password_policy](#password_policy) (ADR-025)
- [soft_delete + purge](#soft_delete--purge) (ADR-032) · [data_retention](#data_retention) (A.5.33) · [recertification](#recertification) (A.5.18) · [notifications](#notifications) · [compliance_digest](#compliance_digest) · [evidence_delivery](#evidence_delivery) · [rotation_reminders](#rotation_reminders) · [audit_checkpoints](#audit_checkpoints) (ADR-029) · [jit_access_expiry](#jit_access_expiry) · [break_glass](#break_glass) · [audit.siem](#auditsiem)
- [scim](#scim) (RFC 7644) · [sso](#sso) (OIDC) · [membership](#membership) (ADR-022) · [credential_delivery](#credential_delivery) (ADR-028)

---

## Environment variables

Sensitive values are read from the environment when set, overriding any value in
the file:

| Variable | Used for |
|---|---|
| `KEYORIX_MASTER_PASSWORD` | KEK passphrase (required for the default `password` key provider) |
| `KEYORIX_CONFIG_PATH` | path to the config file |
| `KEYORIX_DB_PASSWORD` | PostgreSQL password |
| `KEYORIX_API_KEY` | API key for remote-client mode |
| `KEYORIX_SIEM_TOKEN` | SIEM push token (`audit.siem`) |
| `KEYORIX_SCIM_TOKEN` | SCIM provisioning bearer token (`scim`) |
| `KEYORIX_SSO_<NAME>_CLIENT_SECRET` | per-provider OIDC client secret (`sso`) |
| `KEYORIX_SMTP_PASSWORD` | SMTP relay password (`credential_delivery.smtp`) |
| `KEYORIX_DOMAIN` | substituted into `server` origins in the shipped example configs |
| _(operator-named)_ | the raw KEK, when `key_provider.type: env` (see [key_provider](#encryption--kek-providers)) |

---

## environment

```yaml
environment: production   # development | staging | production
```

## locale

```yaml
locale:
  language: en
  fallback_language: en
```

## server

```yaml
server:
  http:
    enabled: true
    port: "8080"
    protocol_versions: ["1.1", "2.0"]
    swagger_enabled: false        # keep false in production
    web_assets_path: /app/web/dist
    domain: keyorix.example.com   # effective domain (also the WebAuthn RP ID basis)
    allowed_origins:
      - https://keyorix.example.com
    tls:
      enabled: false              # commonly terminated at a reverse proxy
      auto_cert: false            # ACME/autocert when true
    ratelimit:
      enabled: true
      requests_per_second: 50
      burst: 100
  grpc:
    enabled: true
    port: "9090"
    protocol_versions: ["2.0"]
    reflection_enabled: false     # keep false in production
    tls:
      enabled: false
    ratelimit:
      enabled: true
      requests_per_second: 25
      burst: 50
```

## storage

```yaml
storage:
  type: local                     # local (SQLite) | postgres | remote
  database:
    # SQLite:
    path: /app/data/keyorix.db
    # PostgreSQL (recommended for production) — set type: postgres above:
    # dsn: "host=db user=keyorix dbname=keyorix port=5432 sslmode=require"
    # password: ""                # prefer KEYORIX_DB_PASSWORD
    max_open_conns: 25
    max_idle_conns: 5
    conn_max_lifetime_minutes: 30
```

`type: remote` points the CLI at a Keyorix server over the API; see the remote
section of the client config. Remote TLS verification is **on by default** —
an omitted `tls_verify` does not disable certificate checks.

---

## Encryption & KEK providers

Envelope encryption (ADR-004): a per-process **DEK** encrypts secrets/tokens and
is stored on disk wrapped by a **KEK**. `key_provider` selects where the KEK comes
from (ADR-038). When `encryption.enabled` is true and no `key_provider` is set,
the default `password` provider is used.

```yaml
storage:
  encryption:
    enabled: true
    dek_path: /app/keys/data.key  # wrapped DEK (never the raw key)
    salt_path: /app/keys/kek.salt # KEK salt (password provider only)

    # key_provider — default is "password" when omitted.
    key_provider:
      type: password              # password | file | env | aws-kms | gcp-kms | azure-kms

      # type: file — read raw key material from a path (mounted CSI/sealed
      # secret, KMS sidecar output). Accepts 32 raw bytes, hex, or base64.
      # file_path: /etc/keyorix/kek.key

      # type: env — read the KEK (hex or base64) from the named env var's value.
      # env_var: KEYORIX_KEK

      # type: aws-kms / gcp-kms / azure-kms — envelope-wrap the KEK with a cloud
      # KMS/HSM key (ADR-041); the wrapping key stays in the KMS/HSM. Credentials
      # come from the standard cloud environment (AWS: env/instance-profile/IRSA;
      # GCP: ADC; Azure: DefaultAzureCredential / managed identity).
      # kms_key_id: arn:aws:kms:eu-west-1:123456789012:key/abcd-…                  # aws-kms
      # kms_key_id: projects/p/locations/eu/keyRings/r/cryptoKeys/keyorix-kek      # gcp-kms
      # kms_key_id: https://myvault.vault.azure.net/keys/keyorix-kek               # azure-kms
      # wrapped_key_path: keys/kek.kms
```

- **`password`** (default): KEK = PBKDF2-SHA256(`KEYORIX_MASTER_PASSWORD`, salt,
  600 000). Requires `KEYORIX_MASTER_PASSWORD`. This is byte-identical to all
  prior releases — existing `dek.key` files keep working.
- **`file`** / **`env`**: the KEK is externally managed (e.g. injected by a KMS,
  CSI driver, or sealed/SOPS secret). `KEYORIX_MASTER_PASSWORD` is **not** required.
- **`aws-kms`** / **`gcp-kms`** / **`azure-kms`** (ADR-041): the KEK is a random key
  **wrapped by a cloud KMS/HSM key**; only the wrapped blob is on disk
  (`wrapped_key_path`), unwrapped via the KMS at startup. The wrapping key never
  leaves the KMS/HSM. `kms_key_id` is an AWS key ID/ARN/alias, a GCP crypto-key
  resource name, or an Azure Key Vault key identifier URL.
  `KEYORIX_MASTER_PASSWORD` is **not** required. Startup needs the KMS reachable
  (fail-closed).

> Rotating the **DEK** (`keyorix encryption rotate`) re-encrypts all rows under a
> new DEK and is independent of the provider.
>
> **Switching providers** (e.g. password → a cloud KMS) is
> `keyorix encryption migrate-provider --to-type <type> … --confirm` (ADR-041): it
> re-wraps the DEK under the target provider's KEK **without re-encrypting any
> data** (fast, no DB lock), verifies the target unwraps it, and keeps a backup of
> the previous wrapped DEK. Migrating `--to-type password` reads the new passphrase
> from `KEYORIX_NEW_MASTER_PASSWORD` and doubles as a master-passphrase rotation.
> After it succeeds, update `key_provider` in this config to the target before the
> next restart (the command prints the exact block).

If `encryption.enabled` is false, secrets and tokens are stored in **plaintext** —
acceptable only for local development.

---

## secrets

```yaml
secrets:
  chunking:
    enabled: true
    max_chunk_size_kb: 64
    max_chunks_per_secret: 100
  limits:
    max_secrets_per_user: 10000
```

## security

File-permission self-checks, plus the **deployment-wide MFA mandate** (ADR-034).

```yaml
security:
  enable_file_permission_check: true
  auto_fix_file_permissions: true
  allow_unsafe_file_permissions: false
  require_mfa: false              # true = mandate a second factor for interactive login
```

With `require_mfa: true`, an interactive (session-authenticated) user **without** a
second factor is confined to the MFA-enrolment endpoints until they enrol. A TOTP
secret **or** a passkey satisfies it. Non-interactive credentials — personal
access tokens, machine tokens, OIDC — are **exempt** so automation is never broken.
Per-project MFA (ADR-037) is set per project via the API
(`PUT /projects/{id}` `{ "require_mfa": true }`), independent of this flag.

---

## webauthn

Phishing-resistant passkeys / FIDO2 as a second factor (ADR-036). Disabled by
default; when off, the passkey endpoints return 501 and login is unchanged.

```yaml
webauthn:
  enabled: true
  rp_id: keyorix.example.com           # effective domain, no scheme/port
  rp_display_name: Keyorix             # shown by the authenticator
  rp_origins:                          # full origins permitted to authenticate
    - https://keyorix.example.com
```

`rp_id` must be the registrable domain serving the app; `rp_origins` must include
the exact origin(s) the browser uses. A passkey satisfies `require_mfa`.

---

## dynamic_secrets

On-demand, short-lived database credentials (ADR-035). The API
(`/api/v1/dynamic-secrets/...`) is always served when the server runs; this block
only controls the **auto-revoke sweeper** that drops leases at expiry.

```yaml
dynamic_secrets:
  sweep_enabled: true            # revoke active leases past their TTL
  sweep_interval: "1m"           # cadence (Go duration); default 1m
```

Targets are registered via the API — or from the terminal with
`keyorix dynamic-secret create` (the admin DSN is read from the
`KEYORIX_DYNAMIC_ADMIN_DSN` env var or a hidden prompt, never a flag) — with an
admin DSN, a backend type (`postgres`, `mysql`, `mongodb`, or `redis`), an optional
creation template, and a default TTL. The creation template form depends on the
backend:
- SQL backends (`postgres`, `mysql`) — an SQL grant template using `{{name}}`.
- `mongodb` — a JSON role spec (`{"roles": [{"role": "readWrite", "db": "app"}]}`);
  the admin DSN is a MongoDB connection URI.
- `redis` — whitespace-separated ACL rule tokens (`~app:* +@read +@write`); the
  admin DSN is a Redis URI (`redis://:pass@host:6379/0`, or `rediss://…` for TLS)
  for a user that holds the `+acl` command.

> **Enable the sweeper for MySQL, MongoDB and Redis targets.** Their accounts have
> no `VALID UNTIL` equivalent, so a lease TTL is enforced *only* by the sweeper —
> issuing is refused while it is disabled. PostgreSQL roles additionally carry a
> DB-level expiry (belt-and-suspenders).

---

## oidc

Machine-identity federation: trust external OIDC issuers (e.g. Kubernetes
projected service-account tokens) and map verified JWTs to machine identities
(ADR-031). Disabled = OIDC auth off.

```yaml
oidc:
  enabled: true
  issuers:
    - name: prod-k8s
      issuer: https://kubernetes.default.svc          # must equal the JWT `iss`
      jwks_uri: https://kubernetes.default.svc/openid/v1/jwks   # https required
      audiences: ["keyorix"]                            # JWT `aud` must contain one
```

## session

Short-lived access tokens with silent refresh. Absent = a 24h access window and no
absolute ceiling (refreshable indefinitely — the legacy behaviour).

```yaml
session:
  access_ttl: "30m"     # access-token window before a refresh is needed (default 24h)
  absolute_ttl: "12h"   # hard cap on total session lifetime; "" or "0" = no ceiling
```

## password_policy

Password rules (ADR-025). Absent = conservative built-in defaults; when present,
the install's values fully replace them.

```yaml
password_policy:
  min_length: 12
  require_uppercase: true
  require_lowercase: true
  require_digit: true
  require_special: true
  reject_personal_info: true
  reject_common_passwords: true
  history_count: 5        # disallow reuse of the last N passwords
  max_age_days: 90        # 0 = no maximum age
```

---

## soft_delete & purge

Soft delete with a retention window, and an opt-in purge scheduler that hard-deletes
expired soft-deleted rows (ADR-032).

```yaml
soft_delete:
  enabled: true
  retention_days: 90      # grace period before a purge may remove (default 30)

purge:
  enabled: true
  schedule: "24h"         # Go duration between purge runs (default 24h)
```

## data_retention

An opt-in background scheduler that enforces **per-record-type retention windows**
on the compliance records Keyorix would otherwise accumulate indefinitely (ISO 27001
A.5.33 / GDPR storage-limitation / DORA record-keeping). Each `*_days` value is a
retention window in days; **`0` (the default) keeps that record type forever**. The
job hard-deletes records past their window, never touches active/open/pending rows,
and cascades to dependent rows (campaign items, request approvals).

It is **legal-hold-gated** — while a hold is active nothing is purged — and
single-replica-gated (ADR-039). Two things it deliberately never deletes: the
**audit trail** (append-only tamper-evidence, ADR-029) and **soft-deleted rows**
(those are the separate ADR-032 `purge` above).

```yaml
data_retention:
  enabled: true
  schedule: "24h"                     # Go duration between runs (default 24h)
  anomaly_alerts_days: 90             # access-anomaly alerts, on detected_at
  closed_access_reviews_days: 730     # closed recertification campaigns + items, on closed_at
  break_glass_days: 365               # non-active emergency-access activations, on created_at
  resolved_access_requests_days: 365  # terminal-state access requests + approvals, on resolved_at
```

The configured windows surface in the compliance posture (`keyorix compliance report`
→ "Data retention") as evidence that storage-limitation is actively enforced.

## recertification

An opt-in background scheduler that enforces an **access-recertification cadence**
(ISO 27001 A.5.18, "review access rights at planned intervals"). On each run it
walks every project and finds those **due for review** — never reviewed, or whose
most-recent review campaign closed more than `cadence_days` ago — that have no
campaign currently open. For each due project: when `auto_open` is true it opens a
fresh recertification campaign (system-actored, snapshotting current access);
otherwise it sends the project's admins an in-app reminder to open one. It also
nudges admins of an in-flight campaign that still has pending items. Reminders
de-dupe against an unread one, so they don't pile up. Single-replica-gated (ADR-039);
opening a campaign is a create, not a delete, so it runs even under a legal hold.

The cadence also drives the compliance posture's **projects-overdue** count (and
`keyorix compliance report` → Access governance → "overdue for recert"), so the
overdue signal is visible to auditors even before you enable `auto_open`.

```yaml
recertification:
  enabled: true
  schedule: "24h"        # Go duration between runs (default 24h)
  cadence_days: 90       # a project is due this many days after its last campaign closed (default 90)
  auto_open: false       # true = auto-open a campaign for overdue projects; false = remind admins only
```

## notifications

External delivery channels for the in-app notifications Keyorix already creates —
access-request approvals, anomaly alerts, rotation and recertification reminders, and
break-glass activations (ISO 27001 A.5.5 / SOC 2 operational alerting). Each
notification is still written to the in-app bell; when a channel is enabled it is
**also** fanned out, best-effort and asynchronously (a slow or down endpoint drops
rather than stalling the triggering action).

Two channels are available; enable either or both (both → each notification is
delivered to all). The **webhook** channel POSTs each notification as a JSON body
(`{user_id, email, type, title, message, project_id, link}`) to `endpoint`,
optionally bearer-authenticated. The **email** channel sends a plaintext message to
the recipient via the operator's SMTP relay (same settings as `credential_delivery`).

```yaml
notifications:
  webhook:
    enabled: true
    endpoint: "https://hooks.example.com/keyorix"
    token: ""                    # prefer the KEYORIX_NOTIFY_WEBHOOK_TOKEN env var
    insecure_skip_verify: false  # TLS verification off — self-signed endpoints only
  email:
    enabled: true
    host: "smtp.example.com"
    port: 587
    username: "keyorix"
    password: ""                 # prefer the KEYORIX_NOTIFY_SMTP_PASSWORD env var
    from: "keyorix@example.com"
    tls: "starttls"              # starttls | implicit | none(dev-only)
  slack:
    enabled: true
    webhook_url: ""              # prefer the KEYORIX_NOTIFY_SLACK_WEBHOOK env var
  teams:
    enabled: true
    webhook_url: ""              # prefer the KEYORIX_NOTIFY_TEAMS_WEBHOOK env var
```

The **slack** and **teams** channels POST to an incoming-webhook URL (Slack: a
`{text}` message; Teams: a MessageCard). The webhook URL embeds the platform's secret
token, so set it via the env var.

> Secrets are read from `KEYORIX_NOTIFY_WEBHOOK_TOKEN` / `KEYORIX_NOTIFY_SMTP_PASSWORD`
> / `KEYORIX_NOTIFY_SLACK_WEBHOOK` / `KEYORIX_NOTIFY_TEAMS_WEBHOOK` when set, falling
> back to the YAML value — keep secrets out of the config file.

## compliance_digest

An opt-in scheduler that periodically **broadcasts a compliance summary** to the
configured notification channels (Slack/Teams/webhook) — a continuous-monitoring
digest of the control matrix + posture: controls pass/gap, projects overdue for
recertification, rotation gaps, unclassified secrets, open anomalies, and active risk
exceptions. It's a single broadcast per run (one message to the channel), and a no-op
when no [`notifications`](#notifications) channel is configured. Single-replica-gated
(ADR-039).

```yaml
compliance_digest:
  enabled: true
  schedule: "168h"   # Go duration between digests (default 24h; e.g. 168h = weekly)
```

## evidence_delivery

An opt-in background scheduler that periodically generates the **auditor evidence
pack** (the same bundle as `keyorix compliance export` / `GET /compliance/evidence`
— the posture plus the records that substantiate it) and writes it as a timestamped
JSON file to `output_dir`, for off-box archival/backup (ISO 27001 / SOC 2 continuous
evidence). Files are named `keyorix-evidence-<UTC-timestamp>.json` (mode `0600`; the
directory is created `0700` if absent).

Each export also emits a `compliance.evidence_exported` audit event, so an installed
[`audit.siem`](#auditsiem) forwarder receives the delivery signal too. Read-only, so
it runs even while a legal hold is active. Single-replica-gated (ADR-039).

Deliver to a local directory, an off-box **webhook** (POST of the pack JSON), an
**S3-compatible object store**, or any combination. At least one target must be
configured when enabled; when several are set the pack fans out to all of them.

```yaml
evidence_delivery:
  enabled: true
  schedule: "24h"                           # Go duration between exports (default 24h)
  output_dir: "/var/lib/keyorix/evidence"   # local archive; omit to deliver off-box only
  webhook:
    enabled: true
    endpoint: "https://evidence.example.com/keyorix"
    token: ""                               # prefer the KEYORIX_EVIDENCE_WEBHOOK_TOKEN env var
    insecure_skip_verify: false             # TLS verification off — self-signed endpoints only
  object_store:
    enabled: true
    bucket: "acme-compliance-evidence"      # required when enabled
    prefix: "keyorix/evidence/"             # optional key prefix
    region: "eu-west-1"
    endpoint: ""                            # optional — set for S3-compatible stores (MinIO/R2/…)
    use_path_style: false                   # set true for MinIO and some gateways
```

> The off-box targets let evidence survive the node without a mounted volume. A file
> write is the primary durable target (its failure is fatal); an off-box delivery
> failure is recorded in the audit note but does not fail the export when a file was
> also written. The webhook token is read from `KEYORIX_EVIDENCE_WEBHOOK_TOKEN` when
> set.
>
> **Object store.** Works with AWS S3 and S3-compatible stores (MinIO, Cloudflare R2,
> Backblaze B2, GCS interop) — point `endpoint` at the store and set `use_path_style:
> true` where required. The pack is uploaded to `<prefix><filename>` and, when signed,
> the detached signature to `<prefix><filename>.sig`. **Credentials are never taken in
> Keyorix config**: they resolve via the standard AWS credential chain
> (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env vars, shared config, or
> instance/workload identity). Point the bucket at object-lock / immutable storage for
> WORM-grade evidence retention.

When **encryption is enabled**, each exported pack is **signed**: a detached
`<file>.json.sig` is written next to it (and the webhook delivery carries the
signature in the `X-Keyorix-Evidence-Signature` header). The signature is an HMAC
keyed by a DEK-derived key the database/DBA does not hold, so an archived pack's
authenticity is provable later — verify with `keyorix compliance verify --file
<pack>` (it asks the server, which recomputes the HMAC; a signature made under a
pre-rotation DEK is reported as unverifiable rather than tampered).

## rotation_reminders

An opt-in background scheduler that notifies project admins (in-app) of secrets
**overdue or approaching** their rotation deadline under an active rotation policy —
proactive rotation hygiene (a NIS2/ISO control). One standing reminder per project
per admin; once read, a still-overdue secret nudges again on the next run.
Single-replica-gated (ADR-039) so admins aren't notified N times in HA.

```yaml
rotation_reminders:
  enabled: true
  schedule: "24h"         # Go duration between reminder runs (default 24h)
```

## audit_checkpoints

An opt-in background scheduler that signs the audit hash-chain head (ADR-029) so
**tail-truncation and genesis re-seed are detectable on-box**, not just via an
off-box anchor. Each run records a `(chained_events, head_id, head_hash)`
checkpoint with an HMAC keyed by a DEK-derived key the database/DBA does not hold;
`keyorix audit verify` (and `GET /audit/verify`) then enforce the live chain
against the latest checkpoint. Single-replica-gated (ADR-039).

**Requires encryption enabled** — the signing key is derived from the DEK, so with
encryption off the scheduler logs a warning and does nothing.

```yaml
audit_checkpoints:
  enabled: true
  schedule: "12h"         # Go duration between checkpoint writes (default 24h)
```

## jit_access_expiry

An opt-in background sweeper for **just-in-time / time-bound access**. A role grant
can carry an expiry — set it by approving an access request with a TTL (`keyorix
request review --action approve --ttl 4h …`, or `grant_ttl` on the resolve API).
An expired grant **stops authorizing immediately** (the authorization queries
filter on expiry, so access is denied the moment the TTL passes — independent of
this sweep); the sweeper then reclaims the rows and writes a `role.expired` audit
event for each. Single-replica-gated (ADR-039).

Leaving this disabled does not weaken enforcement — expired grants are still
denied at authorization time — it only means the expired rows linger until a
sweeper (anywhere) runs.

```yaml
jit_access_expiry:
  enabled: true
  schedule: "1h"          # Go duration between expiry sweeps (default 1h)
```

## break_glass

Opt-in **self-service emergency access** (incident response — NIS2/DORA). When
enabled, any authenticated user can `POST /api/v1/projects/{id}/break-glass` (or run
`keyorix break-glass activate`) to **immediately** self-grant the configured
emergency role at that project — no approval. The activation is **time-bound** (it
auto-expires via the JIT mechanism, so it stops authorizing on its own), requires a
**written justification**, is **loudly audited** (`break_glass.activated`), and
**alerts the project's admins**. Each activation is a queryable record for post-hoc
review (`GET …/break-glass`, `keyorix break-glass list`).

Deliberately not RBAC-gated — the point is access the caller does *not* have — so
the controls are: it must be enabled here, every use is justified + audited +
alerted, the grant expires, and an admin can revoke it early.

```yaml
break_glass:
  enabled: true
  emergency_role: "project_admin"   # role granted on activation
  default_ttl: "4h"                 # grant lifetime when none is requested
  max_ttl: "24h"                    # ceiling on a requested TTL
```

## dual_control

**N-of-M approval (dual control)** for access-request grants (ISO 27001 A.5.3 /
SOX): instead of one admin's approval granting the role immediately, a request
requires `required_approvals` **distinct** approvers — and never the requester
(maker ≠ checker) — before the role is granted. Each sign-off is audited; the
request listing shows the M-of-K progress and remaining approvers are notified. A
value of `1` (the default) keeps the single-approval behaviour.

```yaml
dual_control:
  required_approvals: 2   # distinct approvers needed per access request (default 1)
```

## anomaly_alerts

**Proactive alerting** for detected access anomalies (NIS2 detection & response).
Anomaly detection (off-hours / new-IP / new-user access to secrets) always runs on
the scan schedule; when this is enabled, each **newly detected** anomaly is also
pushed out — an in-app alert to the project's admins **and** a
`security.anomaly_detected` audit event (which the SIEM forwarder picks up, so
anomalies reach your SOC). Each anomaly is announced once. Single-replica-gated
(ADR-039). Opt-in (default off — detection still runs and alerts are visible via
`keyorix anomalies list` / the API, just not pushed).

```yaml
anomaly_alerts:
  enabled: true
  schedule: "1h"          # Go duration between scan+alert passes (default 1h)
```

## audit.siem

Native push of audit events to a SIEM. The token is read from `KEYORIX_SIEM_TOKEN`
when set, so it need not be written to the file.

```yaml
audit:
  siem:
    enabled: true
    provider: splunk            # splunk | datadog | webhook
    endpoint: https://siem.example.com/services/collector
    # token: ""                 # prefer KEYORIX_SIEM_TOKEN
    insecure_skip_verify: false # never true in production
```

## scim

SCIM 2.0 provisioning (RFC 7644). When enabled, Keyorix serves `/scim/v2` so an
identity provider (Okta, Entra ID, …) can **provision, update, deactivate, and
deprovision users** automatically. The endpoints are authenticated by a single
**static bearer token** the IdP presents — separate from the session/PAT auth — and
emit SCIM-format JSON, not the API envelope.

A SCIM `userName` (typically an email/UPN) maps to the user's email; a compliant
alphanumeric Keyorix username is **derived** from it, and the IdP's `externalId` is
stored for reconciliation. Provisioned users have no usable password (they sign in
via SSO or set one out-of-band) and start in `pending_first_login`; SCIM
`active:false` (or DELETE) suspends the account and terminates its sessions.

Both the **Users** and **Groups** resources are supported (plus
`ServiceProviderConfig`): groups map to native Keyorix groups (displayName → name),
with PUT replacing the full member set and PATCH adding/removing members.

```yaml
scim:
  enabled: true
  token: ""        # prefer the KEYORIX_SCIM_TOKEN env var — the IdP's bearer token
```

> Set `token` only via `KEYORIX_SCIM_TOKEN`. Point your IdP's SCIM connector at
> `https://<host>/scim/v2` with that token as the bearer credential.

## sso

Human single-sign-on login via **OIDC** (authorization-code flow). When enabled, the
login page offers a "Sign in with <provider>" button: the user authenticates at their
IdP and Keyorix mints the same session a password login would — so an IdP-provisioned
([`scim`](#scim)) user, who has no password, can actually sign in. SSO logins bypass
Keyorix-local MFA (the IdP is the authenticator).

Each provider's endpoints are **discovered** from its issuer
(`/.well-known/openid-configuration`), so only the issuer + client credentials +
redirect URL are needed. On callback Keyorix verifies the id_token (signature against
the issuer's JWKS, issuer, audience = `client_id`, expiry, and the nonce it issued)
and maps the identity to a Keyorix user — by the IdP subject (matched against the SCIM
`externalId`) first, then by email. By default there is **no auto-provisioning**: the
account must already exist (provision it via SCIM or invite). A suspended user is
refused.

```yaml
sso:
  enabled: true
  providers:
    - name: okta                 # also the URL slug: /auth/sso/okta/login
      issuer: https://your-tenant.okta.com
      client_id: 0oa...
      client_secret: ""          # prefer the KEYORIX_SSO_OKTA_CLIENT_SECRET env var
      redirect_url: https://keyorix.example.com/auth/sso/okta/callback
      scopes: [openid, profile, email]
      auto_provision: false      # JIT-create an account on first login (default off)
      default_role: system_viewer # baseline role for JIT-provisioned users
```

> The client secret is read from `KEYORIX_SSO_<NAME>_CLIENT_SECRET` (name upper-cased,
> e.g. `KEYORIX_SSO_OKTA_CLIENT_SECRET`). Register the `redirect_url` exactly as above
> at the IdP. A provider whose discovery fails at startup is skipped with a warning,
> not fatal.

**Just-in-time (JIT) provisioning.** Set `auto_provision: true` on a provider to
JIT-create a Keyorix account the first time an identity that matches no existing user
signs in — useful when an IdP isn't wired for SCIM push. The account is created
**active** and passwordless (the IdP is the authenticator), with the IdP subject
stored as its `externalId` for future reconciliation, and is granted `default_role`
(`system_viewer` when unset; an unknown role grants nothing — least-privilege on
misconfiguration). The JIT creation is audited as `auth.sso_jit_provisioned`. The IdP
must return an `email` claim (request the `email` scope), or the login is refused. A
later SCIM push for the same `externalId` reconciles to the same account. Leave
`auto_provision` off to require that accounts be provisioned ahead of time.

> **Email trust.** An email an IdP explicitly marks unverified (`email_verified:
> false`) is not used to match an existing account or to provision a new one — only
> the subject (`externalId`) match applies for that login. An absent `email_verified`
> claim is treated as trusted (it is optional in OIDC; some enterprise IdPs such as
> Entra ID omit it for a configured, trusted issuer).

## membership

Project-membership onboarding mode (ADR-022).

```yaml
membership:
  validation_mode: allowlist    # open | allowlist (default) | idp
```

## credential_delivery

How a brand-new principal receives their first-credential setup link (ADR-028).

```yaml
credential_delivery:
  mode: smtp                    # auto | smtp | out_of_band | log
  setup_token_ttl: "24h"        # single-use link lifetime (default 24h)
  base_url: https://keyorix.example.com   # required for any link-producing mode
  smtp:
    host: smtp.example.com
    port: 587
    username: keyorix@example.com
    # password: ""              # prefer KEYORIX_SMTP_PASSWORD
    from: keyorix@example.com
    tls: starttls               # starttls | implicit | none (dev only)
```

`out_of_band` / `log` return or log the link instead of emailing it (useful when no
mail relay is available). A link-producing mode with an empty `base_url` is a
misconfiguration — link minting refuses it rather than emitting a relative link.
