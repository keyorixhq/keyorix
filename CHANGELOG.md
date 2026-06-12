# Changelog

All notable changes to Keyorix are documented here. This project follows
[Semantic Versioning](https://semver.org/).

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
