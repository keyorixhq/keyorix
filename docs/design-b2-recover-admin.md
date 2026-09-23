# Design: `keyorix-server admin recover-admin`

**Status:** Draft for review (Andrei). Implements ADR-108 decision 2
(`docs/adr-108-cli-server-split.md`, decision B.2). No code in this PR.

**Scope note on what already exists vs. what this introduces.** ADR-108
assumes a `keyorix-server admin` subcommand group with an "exclusive admin
lock" (#2016). As of this writing neither exists: `internal/cli` has no
`admin/` package, and there is no `cmd/keyorix-server` binary directory (the
server binary is built from `server/`, see `server/Makefile`). This design
therefore also specifies the minimum shape of that scaffolding — just enough
to carry `recover-admin` — not the full #2016 framework. Two more decision-2
requirements have no existing primitive either: a global/bulk session-revoke
(only per-user `RevokeUserSessions`, `internal/core/account_sessions.go:38`,
exists today) and an offline-to-online notification handoff (notification
sinks are wired only inside a running server process, `internal/core/
service.go:700-712`, with no outbox). Both are called out below as new work,
not reused mechanisms.

## 1. Threat model

| Actor / scenario | Can they recover an admin? | Why / mitigation |
|---|---|---|
| Host root, no recovery key, key mode default (required) | No | `recover-admin` refuses without a verified key. Root can read the DB and the KEK-wrapped secrets, but the recovery-key hash is a one-way verifier (§2) — root cannot derive the key from it, only overwrite it (see rotation-by-root, below). |
| Host root, no recovery key, keyless mode explicitly enabled | Yes, by design | This is the labs/demo escape hatch (§5). It collapses "host access" and "admin access" into one trust boundary, which is exactly what default mode exists to avoid. Loud, auditable, and cannot be turned on remotely. |
| Someone with the recovery key but no host access | No | `recover-admin` is a local subcommand, not a network endpoint (ADR-108 B). A key with no shell on the host is inert. This is the second factor: knowing the key alone is as useless as having the host alone. |
| Malicious insider with both host root and the recovery key | Yes — and that is accepted, not solved | This is the ceiling, not a gap: two independent factors (something you are — the host — and something you have — the key) is the strongest practical bar for a local break-glass tool. The residual control is *detectability*: the audit chain entry and the admin notification (§4) make the act visible and attributable, even though it cannot be prevented. Rotating the key immediately after any personnel change that had access to it is an operational control, not a code control (see open question Q2 for whether to also enforce it). |
| Root deletes/corrupts the recovery-key row directly in the DB, bypassing the CLI | Denies future recovery, doesn't grant one | This is just destruction, not a bypass: an attacker with DB write access can already do far more damage than blank out one hash column. It's listed for completeness, not because it's a distinct new capability root gains. |
| Old recovery key replayed after rotation | Rejected | Verification checks against the *current* stored hash only; rotation overwrites that row in place (§2). There is no "any key that ever existed" acceptance path, so a captured-then-rotated-away key stops working the instant rotation completes, not on some grace period. |
| KEK in a KMS/HSM vs. a KEK file on the host | Materially different threat models — say so plainly | With `key_provider.type: file` (`internal/config/config.go:603+`), the KEK lives on the same host as everything it protects: root already has everything, and `recover-admin`'s two-factor design buys nothing against that specific actor (it still buys something against a stolen recovery key alone, or a compromised non-root process). With `aws-kms`/`gcp-kms`/`azure-kms`/`tpm`, root can read ciphertext but cannot unwrap secrets without also compromising the external KMS/HSM boundary — here the recovery-key requirement is doing real, additional work, because host compromise alone is no longer sufficient to read secrets *or* to mint a new admin session. This should be stated directly in the recovery-key install-time output and in the admin docs, not left implicit: **"On a local-KEK-file install, this recovery key does not protect your secrets from root — it protects your admin account from anyone who is not you."** |

## 2. The recovery key

**Generation.** `crypto/rand`, 256 bits, following the codebase's existing
convention for high-entropy one-time secrets rather than inventing a new one:
compare `GenerateBootstrapToken` (`internal/core/auth_bootstrap.go:424`) and
MFA recovery codes (`generateRecoveryCodes`, `internal/core/mfa.go:556`, a
33-char no-ambiguous-glyph alphabet, grouped `XXXXX-XXXXX`). Recommend the
same grouped, no-ambiguous-glyph encoding here — it is print/typo tolerant,
which matters because this key is meant to be written down and stored offline
(password manager, sealed envelope), not copy-pasted from a terminal history.

**Server-side storage: verifier only, plain SHA-256 — not Argon2id.** The
codebase already draws this line and it's the right one to keep: bcrypt
(cost 12, `internal/core/bcrypt_cost.go`) and PBKDF2 (600k iterations,
`internal/crypto/password_provider.go:15-24`) are reserved for *low-entropy,
user-chosen* secrets (passwords, passphrase-derived KEKs) where a slow KDF
resists brute force. PATs (`sha256Hex(raw)`, `internal/core/pat.go:76`) and
MFA recovery codes (`internal/core/mfa.go`) are already-high-entropy random
values, hashed with plain SHA-256 — a slow KDF adds nothing when the input
space is 2²⁵⁶, and would only slow down the legitimate verification path
during an incident. The recovery key fits the second category exactly: store
`sha256(raw_key)` plus `created_at`, `rotated_at`, `key_version` (a monotonic
counter, so audit events can say *which* generation of key was used, useful
when tracing an insider-with-both-factors scenario). Compare with
`crypto/subtle.ConstantTimeCompare`, not `==` — call this out explicitly in
the implementation PR's review checklist (§6), it is an easy miss.

**Shown once, at install.** Generated during first-run bootstrap (same moment
`GenerateBootstrapToken` already exists for the first-admin claim), printed to
stdout/TTY exactly once, never written to a log file or the audit chain in
plaintext. The install output should carry the plain-language KEK caveat from
§1's threat-model table.

**Rotation.** A new `keyorix-server admin recover-admin rotate-key`
subcommand: generates a new key, overwrites the stored hash and bumps
`key_version` in one write (under the exclusive admin lock, §3, so a
concurrent `recover-admin` run can't observe a half-rotated state), prints the
new key once, writes an audit event, and fires the same admin-notification
path as a recovery event (§4) — a key rotation is exactly the kind of event
every admin should see, not just recovery itself.

**Lost key.** If the key is lost but at least one admin session still works,
rotation is just a normal admin-initiated action (still requires host access,
since it's the same CLI subcommand — this is intentional, not an oversight:
there is no network path to rotate it either). If the key is lost *and* every
admin account is locked out, this design does not attempt to provide a way
back in — that would mean either a plaintext copy of the key exists somewhere
(defeats the verifier-only storage decision) or a host-root-only bypass exists
(defeats the two-factor model this whole feature is for). The documented
answer is: restore from a backup taken before the loss, or accept data loss
and re-bootstrap. This is stated as a limitation, not solved — see open
question Q1.

## 3. What `recover-admin` does

**Invocation.** `keyorix-server admin recover-admin --user <email-or-id>
--recovery-key -` (key read from stdin, never a CLI arg, to keep it out of
shell history and `ps`). Requires an existing account matching `--user` —
this subcommand **restores** an admin, it does not **create** one from
nothing (see Q3 for why account-creation-from-zero is deliberately excluded
from this design).

**Cases it covers**, all through the same code path (the recovery act is
identical regardless of *why* the account is inaccessible):
- last global admin deactivated (interacts with `GuardLastAdminDeactivation`,
  `internal/core/scim.go:500` — recovery re-activates, it does not need to
  pass through or weaken that guard, since the guard only fires on
  *deactivation*);
- admin's password is lost with no working recovery path;
- admin's MFA device is lost with no working recovery codes left
  (`MFARecoveryCodesRemaining`, `internal/core/mfa.go:217`).

**What it resets, on the target account only:**
- reactivates the account if deactivated;
- clears the password hash and sets `require_password_reset = true`, reusing
  the existing forced-reset flag (`internal/core/account_state.go:230`) —
  next login requires setting a new password before anything else;
- clears MFA enrollment (secret + recovery codes) and forces re-enrollment on
  next login, rather than leaving old MFA state that the person who *lost*
  the device can no longer satisfy anyway;
- revokes every session belonging to that user
  (`RevokeUserSessions`, `internal/core/account_sessions.go:38`, called
  directly through the storage layer since the admin CLI already has a direct
  DB handle per the CLI-storage-factory pattern, `docs/adr-049-cli-storage-
  via-factory.md` — no HTTP round-trip needed or wanted here).

**What it never touches:** any other user's account, role, or session; group
membership beyond what's needed to confirm the target already holds (or is
being restored to) a global-admin role; project data; secrets; the KEK or its
wrapping. It changes exactly one account's authentication state and nothing
else — this is the blast-radius argument for why per-user session revoke is
enough by default rather than a system-wide revoke (see Q4).

**Post-recovery state:** account active, no password set (forced reset
pending), no MFA enrolled (forced re-enrollment pending), zero live sessions.
The very first thing the recovered admin can do is log in, set a password,
and enroll MFA — there is no window where the account is usable without both.

## 4. Audit and notification

**Audit event content:** actor (host OS user/uid running the command — there
is no Keyorix identity to attribute this to, by definition, since the
scenario is "no working admin session"), target user, action
(`recover_admin_password_reset` / `recover_admin_mfa_reset` /
`recover_admin_reactivate`, whichever subset applied), recovery-key
`key_version` used, timestamp, hostname. Written through the same
`LogAuditEvent` path the server itself uses (`internal/storage/store/
local_audit_chain.go:165`) — this already works from an offline CLI process
for `storage.type: local` or `postgres` (the CLI constructs a `Storage`
directly via the factory, same as any other admin subcommand); it is *not*
expected to work for `storage.type: remote`, but that's moot here since
`recover-admin` only ever runs against a directly-reachable local/postgres
backend, never through the API.

**If the audit chain itself is broken.** `VerifyAuditChain` (`local_audit_
chain.go:275`) already detects a broken link; there is deliberately no
auto-repair (`refuseIfAuditChainBroken`, line 466), because silently
"fixing" a chain that may reflect tampering would destroy the evidence.
`recover-admin` should inherit that same posture rather than inventing a new
one: verify the chain before acting; if it's broken, still perform the
recovery (refusing to recover an admin because of an unrelated integrity
fault would be a worse outcome — see the auth-boundary lockout-vs-bypass
asymmetry: recovery is the recoverable, visible side of that tradeoff), but
write the new audit entry as an explicitly-marked chain restart (a new
segment whose first entry records "prior chain verification failed at row
N" instead of chaining onto the broken tail) and print a loud stderr warning
naming the broken row. This makes "recovery happened while the audit trail
was already compromised" itself part of the permanent record, instead of a
detail an operator has to separately notice.

**Notifying admins.** Decision 4 requires notifying **all** admins on every
use, including when the server is down at the moment of recovery — and this
is the one requirement with no existing mechanism to reuse.
`notifyWithSeverity` (`internal/core/notifications.go:73`) persists an
in-app `Notification` row and best-effort dispatches to sinks
(`NotificationSink`, `internal/core/service.go:692`), but those sinks are
wired only when a server process starts (`server/main.go`), and delivery is
explicitly fire-and-forget with no queue. An offline `recover-admin` run has
no live sink to dispatch to. Recommended fix, sized into this work rather
than deferred: write the in-app `Notification` row directly (visible to every
admin at next login, no new mechanism needed for that half) **and** write a
small pending-external-notification outbox row in the same transaction;
extend the server's existing startup sequence to drain that outbox through
the configured sinks once, before or alongside normal startup, using the
existing per-channel retry config (`NotificationRetryConfig`,
`internal/core/notification_retry.go`) so a flaky webhook doesn't block boot.
This is new code, not a reuse — see effort estimate (§8) and Q5.

## 5. Keyless mode

Enabled only via a config field (e.g. `security.recover_admin.keyless_mode:
true`), read at server startup — never via any API or CLI-over-network path,
so an attacker who has compromised the admin API cannot silently downgrade
the install's security by flipping this remotely. Concretely: no HTTP
handler and no gRPC RPC ever writes this config key; it changes only via a
host-side config-file edit followed by a server restart. The implementation
PR's review checklist (§6) should include a grep-based guard test enumerating
every code path that can reach this config value, in the spirit of the
existing idiom-completeness lesson from the `/system`-proxy campaign — an
incomplete enumeration ("it can only be set via X") has been wrong before in
this codebase when a second idiom for the same effect existed and wasn't
checked for.

Flagged loudly and repeatedly wherever an operator or auditor would look:
- a startup warning logged every time the server boots with keyless mode on,
  not just the first time;
- a boolean surfaced in `/system/info` so a customer's own compliance
  scanning can catch a misconfigured install;
- an audit event written at every server startup while keyless mode is
  enabled, so the tamper-evident chain itself carries a durable, repeated
  record that this install has been running in the weaker mode — an auditor
  reading the chain doesn't have to trust a point-in-time config dump.

## 6. Tests and adversarial-review checklist (for the implementation PR)

- Recovery-key verification uses `crypto/subtle.ConstantTimeCompare`, not a
  short-circuiting comparison — a timing-channel finding here is exactly the
  kind of thing this codebase has caught before in similar checks.
- Two concurrent `recover-admin` (or one `recover-admin` racing one
  `rotate-key`) invocations: the exclusive admin lock must serialize them;
  test the lock actually blocks a second acquirer rather than merely
  documenting that it should.
- Old key is rejected immediately after `rotate-key` completes — no grace
  window, no cached-hash staleness.
- `recover-admin` interaction with `GuardLastAdminDeactivation`: confirm
  recovery re-activation is unaffected by (does not need to bypass) that
  guard, and add a case to the existing guard's test suite rather than a
  standalone one, per the standing "extend the registry test" practice.
- Keyless-mode reachability: a guard test enumerating every config-load and
  every HTTP/gRPC handler, asserting none of the latter can set or flip the
  flag — state explicitly in the test's doc comment which call shapes it
  recognizes, so a reviewer can judge completeness rather than trust it.
- Broken-audit-chain path: `recover-admin` run against a DB with a
  deliberately corrupted chain row still completes the recovery, still marks
  the new entry as a chain restart, and does not attempt any auto-repair of
  the broken segment.
- Notification outbox: drains exactly once per pending row on startup; a
  crash mid-drain and restart does not double-send; an unreachable webhook
  sink does not block server boot past its configured retry/backoff budget.
- Fuzz targets: recovery-key decode/format parsing (malformed groupings,
  wrong length, bad checksum char if one is added); the audit event's
  canonical-field encoding with adversarial field content (the existing
  `canonical(fields)` hashing in `local_audit_chain.go` is a natural fuzz
  target regardless of this feature, and `recover-admin` is a new caller of
  it); config parsing for every combination of `keyless_mode` × KEK provider
  type, since the local-KEK-file case changes the threat model narrative in
  §1 and a config fuzzer is cheap insurance against a parsing bug silently
  accepting an unintended combination.

## 7. Open questions for Andrei

1. **Lost key + zero working admins: acceptable to leave unsolved?**
   Recommend yes — document it as "restore from backup or re-bootstrap,"
   don't build a bypass. Building any path around this defeats the two-factor
   model §1 exists to provide.
2. **Should recovery-key rotation be time-enforced** (e.g. a server-side
   staleness warning after N days), or purely manual? Recommend manual-only
   for the MVP; revisit only if a regulated customer asks for it, per the
   "don't design for hypothetical future requirements" default.
3. **Should `recover-admin` support creating a brand-new admin account when
   literally none exist** (vs. only restoring an existing, possibly
   deactivated, one)? Recommend no for this PR — account creation raises
   separate identity-provenance questions (what email, what initial role
   scope) that are a bigger decision than recovery, and every case in
   decision 3 (deactivated / lost password / lost MFA) already implies an
   existing account row. Revisit only if a real "the only admin account was
   deleted, not deactivated" incident occurs.
4. **Per-user session revoke vs. a new global revoke-all primitive.**
   Recommend per-user only, matching the "touches exactly one account"
   design in §3 — a system-wide revoke is a bigger, separately-reviewable
   primitive (it doesn't exist anywhere in the codebase today) and recovery
   from a single compromised/locked-out admin doesn't need to log out every
   other legitimate session on the install.
5. **The notification outbox in §4 is new work with no existing pattern to
   copy.** Recommend building the minimal version described (one outbox
   table, drained once at startup) rather than deferring decision 4's
   "notify even when down" requirement — it's explicitly decided already,
   not optional.
6. **Confirm Shamir M-of-N stays deferred**, per ADR-108's own text — this
   design assumes a single recovery key throughout.
7. **Exact key length/encoding** — recommend 256 bits, grouped alphanumeric
   (matching the MFA-recovery-code encoding already in the codebase) rather
   than inventing a new format.

## 8. Effort estimate

Rough sizing for the implementation PR series, one engineer, assuming this
design is accepted as-is:

| Piece | Estimate |
|---|---|
| `admin` CLI subcommand scaffolding + exclusive lock (new — #2016 baseline) | 3–5 days |
| `recover-admin` + `rotate-key` command logic | 3–4 days |
| Audit event integration incl. broken-chain-restart handling | 1–2 days |
| Notification outbox (new) + startup drain | 3–5 days |
| Keyless mode: config, startup warning, `/system/info`, reachability guard | 2–3 days |
| Tests, fuzz targets, adversarial review pass | 3–5 days |
| **Total** | **~3–4 weeks** |
