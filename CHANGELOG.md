# Changelog

All notable changes to Keyorix are documented here. This project follows
[Semantic Versioning](https://semver.org/).

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
