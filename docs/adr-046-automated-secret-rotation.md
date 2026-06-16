# ADR-046: Automated secret rotation

## Status

Accepted.

## Context

Keyorix already had the *policy* and *visibility* halves of rotation: a
`RotationPolicy` defines how often a secret should rotate (`interval_days`, scope),
`GetRotationStatus` / `EvaluateRotationPolicies` classify covered secrets as
ok/due-soon/overdue, and the rotation-reminder scheduler notifies admins. But nothing
actually *rotated* anything — a human still had to call `RotateSecret` with a new value.

For secrets whose value Keyorix owns (generated tokens/passwords with no external
system to coordinate), that manual step is pure toil and a gap in rotation hygiene
(NIS2 / ISO 27001 A.5 / SOC 2).

## Decision

Add an opt-in **automated-rotation executor** that regenerates the value of
auto-rotate-enabled secrets when they fall overdue under an active policy.

- **Per-secret opt-in.** `SecretNode.AutoRotate` (default false) marks a secret as
  Keyorix-owned and safe to regenerate. It is toggled via
  `PATCH /api/v1/secrets/{id}/auto-rotate` (gated by scoped `secrets.write`) and the
  change is audited (`secret.auto_rotate_configured`).
- **Executor.** `RunAutoRotation` walks active policies → covered secrets; for each
  secret that is both `AutoRotate` and overdue (`days_since_last_rotation ≥
  interval_days`) it generates a fresh value and rotates it (a new version), auditing
  `secret.auto_rotated`. Best-effort per secret (a failure is logged and skipped, never
  aborting the run); a secret covered by multiple policies rotates at most once per run.
- **Generated value.** 32 characters over a 62-symbol alphanumeric set from
  `crypto/rand` (~190 bits), alphanumeric-only so a consumer reading it back never
  trips over shell/URL metacharacters.
- **Scheduler.** Opt-in `auto_rotation` block (default off; default interval 1h),
  single-replica-gated (ADR-039) so a secret rotates once per tick in HA. Distinct from
  `rotation_reminders`, which only notifies.

## Why opt-in and only "owned" secrets

Auto-rotation changes the stored value **without touching any upstream system**. For a
secret that mirrors an external credential (a cloud key, a DB password managed
elsewhere), silently regenerating the Keyorix copy would desynchronize it from the real
credential and break consumers. So auto-rotation is strictly opt-in per secret, and the
opt-in is the operator's assertion that *this value is Keyorix's to regenerate*.
Consumers that fetch the current value from Keyorix on each use then pick up the new
value automatically — which is the intended pattern.

## Alternatives considered

- **Rotate everything a policy covers**: rejected — unsafe for externally-owned
  secrets (see above). The per-secret opt-in is the safety boundary.
- **Pluggable rotation "executors" per backend** (rotate the upstream credential too,
  Vault-style): the powerful general case, but it needs per-system integrations and
  credentials. Deferred; the generated-value path covers Keyorix-owned secrets — the
  common toil — with no new trust surface. This ADR leaves room for backend executors
  later (the opt-in + scheduler are reusable).
- **A generator spec per secret** (length/charset): now supported — a secret may set
  `rotation_length` (8–256, default 32) and `rotation_charset` (one of `alphanumeric`
  [default] / `lower_alphanumeric` / `hex` / `alphanumeric_symbols`) via the toggle
  endpoint, so the generated value can meet a system's password requirements. Defaults
  preserve the original 32-char alphanumeric behavior; an unknown charset fails the
  request (and, defensively, falls back to alphanumeric at generation — never an empty
  alphabet). A full template language was rejected as overkill for v1.

## Consequences

- Keyorix-owned secrets can now rotate on schedule with zero human action, fully
  audited.
- New per-secret column `auto_rotate` (additive migration) and an opt-in scheduler;
  both off by default, so existing installs are unchanged.
- Management of the flag is available over HTTP / gRPC / CLI / web.
- **Failure alerting:** a silently-failed auto-rotation is a security event, so each run
  that leaves any secret unrotated broadcasts one summary (secret names + reasons, never
  values) to the configured notification channel (Slack/Teams/webhook), in addition to
  the per-failure audit events. No-op when no channel is wired.
