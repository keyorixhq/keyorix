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
- [soft_delete + purge](#soft_delete--purge) (ADR-032) · [audit.siem](#auditsiem)
- [membership](#membership) (ADR-022) · [credential_delivery](#credential_delivery) (ADR-028)

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

Targets are registered via the API with an admin DSN, a backend type
(`postgres`, `mysql`, `mongodb`, or `redis`), an optional creation template, and a
default TTL. The creation template form depends on the backend:
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
