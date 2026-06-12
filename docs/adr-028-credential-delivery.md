# ADR-028 — Credential Delivery: Email Transport, Setup Tokens, and Out-of-Band Provisioning

**Status:** Proposed (June 5, 2026)
**Decision:** Introduce a single credential-delivery subsystem that backs every "get a new principal their first credential" flow. It has two interchangeable delivery channels — **operator-configured SMTP email** (via a vetted library) and **admin out-of-band display** (link / one-time password shown once on screen, audited) — sitting behind one `CredentialDelivery` interface, and a single **single-use, hashed-at-rest, TTL'd setup-token** mechanism that the invitation-accept (ADR-024), admin-direct-creation (ADR-025), and resend flows all share. **No password and no reusable credential is ever placed in an email.**

## Context

Three already-designed flows are blocked on the same missing primitive — a way to get a brand-new principal their first credential:

- **Invitation acceptance** (ADR-024) — the `project_invitations` record exists, but its own model comment says *"the email/setup-link consumption (accept) is a follow-up."* There is no link to send and no endpoint to consume.
- **Admin direct user creation** (ADR-025) — the "direct user creation dialog" and "credential delivery: SMTP one-time setup link" / "admin out-of-band display" items are explicitly deferred to "credential-delivery infra."
- **Resend setup link** (ADR-025) — `keyorix user resend-setup-link` is parked behind "SMTP/setup-link infra."

Today the codebase has **zero** email/SMTP scaffolding. ADR-024 and ADR-025 both gesture at "email if configured" and "admin-handled credential delivery" without defining either. This ADR defines both, once, so the three flows above become thin producers on top of shared infrastructure rather than three half-built mechanisms.

Two facts about the ICP shape the design:

1. **Self-hosted, often air-gapped.** Keyorix is on-prem. A meaningful fraction of high-security/regulated buyers have **no outbound SMTP**. For them, email delivery is dead weight and the *only* viable path is an admin relaying a setup link or a one-time password out of band. Out-of-band is therefore a **first-class peer**, not a fallback bolted on later.
2. **The buyer owns the mail server.** When SMTP *is* available, it is the operator's own relay. We do not integrate a SaaS email API (SendGrid/Postmark) as a dependency — that would contradict the anti-lock-in, data-stays-on-prem positioning. SMTP is operator-configured.

This ADR does **not** cover in-app/Slack/Teams notifications (those are the separate, already-listed "inviter notifications" / "access request notifications" items) — only the delivery of *credentials* to *new* principals.

## Decision

### Part A — The setup token

A new `setup_tokens` table is the single source of "this bearer string lets one principal establish their first credential." It serves all three producers.

```
setup_tokens:
  id
  token_hash        (sha256 of the random token; the plaintext is shown once, never stored)
  purpose           (enum: invitation_accept | account_setup | password_reset_link)
  subject_user_id   (nullable — null until an account exists, e.g. invitation by email)
  subject_email     (the email the token was minted for; used to bind acceptance)
  invitation_id     (nullable; set for purpose = invitation_accept)
  state             (enum: active | consumed | expired | superseded)
  expires_at        (default: 24h, configurable per install)
  created_by        (the admin/inviter who minted it; 0 = self-service password reset)
  created_at
  consumed_at       (nullable)
```

Properties — these are non-negotiable security invariants:

- **Random 256-bit token**, base64url-encoded, generated with `crypto/rand`. The plaintext is returned to the caller exactly once (to embed in a link or display out of band) and **never persisted**. Only `sha256(token)` is stored; lookup is by hash. This mirrors the existing session-token and PAT handling (ADR-027) — constant-time, hashed-at-rest.
- **Single-use.** Consuming a token transitions it `active → consumed` in the same transaction that materializes its effect (creates the session / accepts the invitation / sets the password). A replay finds `consumed` and is rejected.
- **Short TTL.** Default 24h, configurable via `credential_delivery.setup_token_ttl`. A lazy-expire check (mirroring the ADR-024 invitation/access-request lazy expiry) flips overdue tokens to `expired` on read.
- **One active token per (purpose, subject).** Minting a new token for the same subject+purpose supersedes any prior `active` one (`active → superseded`). This makes "resend" safe: the old link dies the instant a new one is issued.
- **HTTPS-only delivery.** The link embeds the token in the path/fragment; it is only ever sent over the operator's TLS endpoint. The token is a bearer credential — treated with the same care as a session token.

The token is purpose-scoped: an `invitation_accept` token can *only* drive invitation acceptance, never a password reset, even if the raw string leaked into the wrong endpoint.

### Part B — The delivery interface

One interface, selected by config, mirroring the established SIEM-connector pattern (`internal/audit/siem`):

```go
// CredentialDelivery delivers a setup link (or one-time secret) to a new principal.
// Implementations never see the password; they transport the single-use link only.
type CredentialDelivery interface {
    // DeliverSetupLink delivers the link to the recipient. For out-of-band mode it
    // returns the link to the caller (for the admin to relay) instead of sending.
    DeliverSetupLink(ctx context.Context, req SetupLinkRequest) (DeliveryResult, error)
    Name() string
}

type SetupLinkRequest struct {
    RecipientEmail string
    DisplayName    string
    Link           string   // fully-formed https URL containing the single-use token
    Purpose        string
    InstallName    string   // e.g. "Acme Corporation Keyorix"
    Message        string   // optional inviter note
    AssignmentSummary string // "developer on mobile-app, viewer on payment-svc"
}

type DeliveryResult struct {
    Channel    string // "smtp" | "out_of_band"
    Delivered  bool   // true if actually sent; false if returned for manual relay
    LinkForAdmin string // populated only for out_of_band — the link to show the admin
}
```

Three implementations:

1. **`SMTPDelivery`** — sends a minimal email via a vetted SMTP library (**`wneessen/go-mail`**, chosen over stdlib `net/smtp` for correct implicit-TLS on 465, STARTTLS, and auth negotiation — TLS correctness is not something to hand-roll in a security product). Connection is operator-configured. Email content (Part D) is plaintext + minimal inline HTML, **no remote resources, no tracking pixels**.
2. **`OutOfBandDelivery`** — sends nothing; returns the link in `DeliveryResult.LinkForAdmin` so the create-user / invite API response carries it back to the admin UI/CLI, which displays it once with a copy button. Also covers the "admin out-of-band display" of a one-time password (Part E).
3. **`LogDelivery`** — dev/test only; writes the link to the server log with a loud warning. Never selected when `enabled` and `mode != log`.

Selection is by `credential_delivery.mode`:
- `smtp` — use SMTP; error at send time if SMTP is unreachable (the admin sees "couldn't send; here's the link to relay manually" — i.e. graceful degradation to out-of-band).
- `out_of_band` — never attempt SMTP; always return the link to the admin. Correct default for air-gapped installs.
- `auto` (default) — SMTP if `credential_delivery.smtp` is configured, else out-of-band. Zero-config installs degrade safely.

### Part C — Configuration

```yaml
credential_delivery:
  mode: auto                      # auto | smtp | out_of_band | log
  setup_token_ttl: 24h            # single-use setup/invite link lifetime
  base_url: "https://keyorix.acme.internal"   # used to build absolute setup links
  smtp:
    host: smtp.acme.internal
    port: 587
    username: keyorix@acme.internal
    # password via KEYORIX_SMTP_PASSWORD env (never in yaml — same convention as DB password)
    from: "Acme Keyorix <keyorix@acme.internal>"
    tls: starttls                 # starttls | implicit | none(dev-only)
```

`base_url` is required for any link-producing mode; the server refuses to mint a link without it (a relative link is a misconfiguration, not a fallback). The SMTP password follows the existing `GetPassword()`/env convention (`KEYORIX_SMTP_PASSWORD`), never stored in yaml.

### Part D — Email content (when SMTP is used)

Contains: inviter/admin name, install name, the optional `message`, the assignment summary, and the single-use link. Plain language, one call to action.

It does **NOT** contain: any password, any reusable token beyond the single-use link, any remote image/CSS/JS, any tracking pixel or click-tracking redirect. Regulated buyers' mail gateways flag those, and they are a privacy/exfil surface. The email is self-contained text + minimal inline HTML.

Acceptance flow: click link → landing page validates the token (`GET /auth/setup/{token}` returns the assignment summary, no secrets) → user sets their own password (subject to the ADR-025 password policy) or SSO-resolves if an IdP is configured → `POST /auth/setup/consume` consumes the token, materializes the invitation/account in one transaction, and lands the user logged in.

### Part E — Out-of-band credential display

For `out_of_band` mode and for admin-direct-creation without email, the admin gets one of two artifacts, shown **once**, on screen:

- **Setup link** (preferred) — the `LinkForAdmin` URL. Admin relays it via their own secure channel. Same single-use token; the password is still set by the end user.
- **One-time password** (when the admin opts to set an initial password) — generated server-side, shown once, and the account is forced into `password_reset_required` (ADR-025 account state) so it must be changed on first login.

Both displays fire a discrete audit event (`credential.displayed_out_of_band`) capturing *which admin viewed a credential for which subject* — a deliberate compliance signal, because out-of-band display is the one path where a human briefly sees a credential.

### Part F — Audit events

- `setup_token.issued` — purpose, subject email, issuer, expiry. (No token, not even the hash.)
- `setup_token.consumed` — token id, resulting user id, materialized effect.
- `setup_token.expired` — automatic on lazy-expire.
- `setup_link.delivered` — channel (`smtp`/`out_of_band`), delivered bool, recipient. (No token.)
- `credential.displayed_out_of_band` — admin id, subject id, artifact type (`link`/`one_time_password`).

All carry `actor_type` (ADR-023) and integrate with the ADR-023 audit filtering, so "show me every credential issued this quarter and how it was delivered" is a single query — directly serving NIS2 Article 21 / DORA Article 30.

### Part G — API and CLI surface

```
# Public (unauthenticated, like /auth/login — registered at the root router, not /api/v1)
GET  /auth/setup/{token}        -> validate token, return assignment summary (no secrets) or 410 if dead
POST /auth/setup/consume        -> body {token, password}; consumes token, returns session

# Admin (authenticated) — link is returned inline when mode resolves to out_of_band
POST /api/v1/users                       (ADR-025 direct creation; response carries LinkForAdmin in OOB mode)
POST /api/v1/users/{id}/resend-setup-link
POST /api/v1/projects/{id}/invitations/{invId}/resend   (ADR-024 invitation resend)
```

```
keyorix user resend-setup-link --id <id> [--by <admin-email>]
keyorix invite resend <invitation-id> [--by <admin-email>]
```

In out-of-band mode every one of these returns the link as CLI/JSON output for the admin to relay — symmetric with the dashboard, and the only path that works air-gapped.

### Abuse / rate limiting

- Resend is throttled: minimum interval between issues for the same subject (default 60s) and a daily cap (default 10). Exceeding returns 429; an audit event records the throttle.
- Token-validation endpoints (`GET /auth/setup/{token}`) are rate-limited per IP to blunt enumeration; tokens are 256-bit so enumeration is infeasible regardless, but the limit caps noise.

## Consequences

**Positive:**
- One mechanism, three producers — invitation-accept, admin-creation, and resend stop being three separately half-built features.
- Air-gapped installs are first-class: `out_of_band` mode is fully functional with zero mail infrastructure.
- The "never email a password / never email a reusable token" invariant is enforced structurally (the email only ever carries a single-use, short-TTL, hashed-at-rest link).
- Out-of-band display audit event gives compliance reviewers the one signal that matters: who saw a credential.
- SMTP via a vetted library means TLS is correct by default rather than hand-rolled.

**Negative / accepted:**
- One new table (`setup_tokens`), one new config block, one new third-party dependency (`wneessen/go-mail`). The dependency is justified: correct SMTP TLS/auth is exactly the kind of thing not to own.
- A landing/setup page must be built on the frontend (the "accept" half of ADR-024 and the first-login of ADR-025). This ADR defines its contract; the page itself is frontend follow-up work.

**Risks:**
- **Setup link is a bearer credential.** A leaked link before consumption grants account establishment. Mitigations: 24h default TTL, single-use, superseded-on-reissue, HTTPS-only, hashed at rest, audited consumption. Same risk class as ADR-024's "stale invitation as credential surface," handled the same way.
- **SMTP misconfiguration silently drops invites.** Mitigation: `mode: smtp` surfaces send failures to the admin synchronously and degrades to returning the link for manual relay rather than failing closed with no recourse.
- **Out-of-band one-time password seen by admin.** A human briefly sees a credential. Mitigation: forced `password_reset_required` on first login (the admin-seen password is single-use), plus the `credential.displayed_out_of_band` audit event. Setup link (no admin-seen password) is the preferred artifact and the documented default.

## Conditions to revisit

- **SaaS email provider support.** If a hosted/SaaS Keyorix offering ships (currently deferred until 3 on-prem customers per the backlog's deferred list), an API-based provider implementation of `CredentialDelivery` slots in behind the same interface. Not before.
- **Inbound email (reply-to-approve).** Out of scope. Revisit only with a concrete customer workflow.
- **Per-user email notification preferences.** This ADR delivers *credentials* (always sent — you cannot opt out of getting your own setup link). General *notifications* (ADR-024's inviter/access-request notifications) carry their own opt-out and are a separate track.

## Security hardening (audit follow-up, 2026-06-13)

Two fixes from an internal audit of this subsystem:

- **`POST /users` privilege escalation closed.** The atomic-provisioning route
  (which can grant a system role + project assignments) was gated only by the
  group-level `users.read`, so a global read-only persona (`system_auditor` holds
  `users.read`) could create a user with `role: "system_admin"` and escalate to
  global admin. It is now gated by `users.write` (matching the sibling
  `POST /invitations`), and the handler additionally authorizes the caller for
  `roles.assign` at each grant's scope (global for a system role, per-project for a
  project assignment) so atomic provisioning can never hand out more access than
  the caller could assign directly — closing the cross-project/privesc class on
  this newer route.
- **Password-set consume now evicts other sessions.** `completePasswordSetup`
  (account_setup / password_reset_link) minted a new session but left the subject's
  existing sessions untouched, so a self-service password reset failed to lock out
  an attacker holding a stolen session. It now drops all of the subject's other
  sessions (keeping the freshly minted one), matching `ChangePassword`'s
  invalidate-other-devices invariant.

## Related ADRs

- **ADR-024** — Invitation and access-request flows (the invitation producer; this ADR provides the link/consume mechanism 024 deferred).
- **ADR-025** — Account state machine + local-account provisioning (the admin-creation producer; `password_reset_required` state drives the one-time-password path here).
- **ADR-027** — Personal access tokens (establishes the hashed-at-rest, constant-time bearer-token handling this ADR reuses for setup tokens).
- **ADR-023** — Machine identities + audit `actor_type` (audit events here carry `actor_type`; machine identities are admin-provisioned and do **not** use setup tokens).
