# G80 overnight handoff — raw-storage-bypass triage (2026-08-23 → 2026-08-24)

## The number

**35 of 58 real, all 35 human-reachable — within the guard's stated reach, with five
categories unexamined (see below).**

The 58 is a corrected, reproducible count, not the 59 recorded in
`docs/g80-remediation-notes.md`'s #1547 entry. Per the amended brief, resolving that
discrepancy was done first: `scripts/analysis/raw_storage_bypass_enumerate.go` (AST-based,
committed) and an independent regex-based cross-check both produce **145 total flagged
call sites / 87 read-shaped / 58 write-shaped**, not 149/90/59. Two hypotheses for the
gap (multi-line method chains; variable/interface dispatch) were checked directly and
ruled out — see `docs/g80-raw-storage-bypass-enumeration.md` for the full resolution.
**149/90/59 could not be reproduced and is the number that should be treated as wrong**;
145/87/58 is what this handoff's numbers are built from. `docs/g80-raw-storage-bypass-blind-spots.md`
names five categories this guard structurally cannot see, so "58" is a reach-scoped
count, not a claim about the total size of this bug class:

- (a) multi-line chains — fixed by the AST tool, not a live blind spot
- (b) variable/interface dispatch — tracked for simple local aliases, 0 current instances, not exhaustive
- (c) wrapper-mediated calls (helper functions a handler calls, not the handler's own body) — real, confirmed present, not chased
- (d) the read-shaped naming heuristic — real, confirmed both directions (safe false-positives found; no dangerous false-negatives found *yet*)
- (e) non-handler layers (gRPC services, CLI commands, background jobs) — real, 20 files with raw storage calls entirely outside this guard's view, not examined

Of the 58 (within that reach):

- **9** `no-independent-ceiling` (not a finding)
- **13** `documented-exception` (not a finding, deliberate and commented)
- **1** `unresolved` (`TransitionMembershipProxy`, already filed as #1546)
- **35 are `real`** — a genuine ceiling bypass
- **Of those 35, all 35 (100%) are `human-reachable`.**

This is the opposite of what the 7-item sample (resolved before tonight) suggested. Every
one of those 7 was safe (3 no-ceiling + 4 documented-exception), which read as "this bug
class is mostly noise." It was not: of the 50 candidates actually investigated tonight,
**70% are real**, and **every real one is reachable by a normal human session** — any
account holding `system.write`, or (per `router.go:1078-1081`) any admin-tier role at all,
since admin-tier roles unconditionally bypass permission checks. These are not
node-credential-only relay bugs. A logged-in human admin can trigger every one of them
today, over HTTP, with no client automation required beyond knowing the endpoint.

**The stopping rule's 11%-ish informal estimate (7 safe / 58 total, extrapolated) was
wrong, badly, in the dangerous direction.** Flagging this explicitly per the task's stop
condition: the true positive rate among the unresolved remainder was ~70%, not ~12%.

**Why it was wrong: the early estimate was biased by construction, not a random
sample.** The 7 pre-resolved cases (`ClearProjectSecretOwnershipProxy`,
`DeleteSecretACLsByUserAndProjectProxy`, `DeleteExpiredRoleGrantsProxy`,
`CreateUserWithRoleGrantsProxy`, `RemoveGlobalAdminRoleGuardedProxy`, `DeleteProjectProxy`,
`DeleteProjectIfEmptyProxy`) got resolved FIRST specifically because they were the
cheapest to resolve — each one either has no core-level ceiling at all (nothing to trace)
or a short, already-written justification comment sitting right next to the call site.
Nobody picks the hard-to-classify 51 first; the easy 7 get triaged first precisely because
they're easy, which means a sample built from "what's been resolved so far" is
selected for cheapness, not drawn at random from the 58. The 70% figure from tonight's
actual investigation of the remaining 50 (verified further via the 5-item escalation-delta
re-check, all 5 held up) is the number to treat as representative, not the informal
7-item extrapolation.

## Human-reachable findings — DO NOT FIX TONIGHT, READ THIS FIRST

35 real, human-reachable findings below (full table further down). Nothing has been
fixed — this was classification only, per instruction. The five most severe, roughly by
blast radius:

1. **`CreateMachineIdentityCredentialProxy`** (`machine_identities_proxy.go:469`) — a
   `system.write` caller (non-admin) can submit an attacker-chosen `TokenHash` for an
   **existing** machine identity, with none of `IssueMachineToken`'s
   `requireMachinePrivilegeCeiling` check. If that machine identity already holds
   admin-tier roles, this is a direct, unauthenticated-token-mint privilege escalation to
   admin. Worst finding of the night.
2. **`CreateWebAuthnCredentialProxy` / `DeleteWebAuthnCredentialProxy` /
   `SetUserWebAuthnEnabledProxy`** (`webauthn_proxy.go:171,336,382`) — all three skip
   `requireReauth`, the check that's supposed to make WebAuthn credential changes
   unreachable by a bearer token alone. A caller can implant an attacker-controlled
   passkey on **any account**, strip a real user's passkeys, or silently flip
   `webauthn_enabled` (2FA downgrade or bogus force-enable) — full account-takeover
   surface.
3. **`CreateAccessRequestProxy` / `UpdateAccessRequestProxy`**
   (`access_request_proxy.go:170,249`) — `State` is caller-writable with no restriction.
   A caller can self-approve a restricted-secret access request in one call, bypassing
   `ApproveSecretAccessRequest`'s admin-authority check and maker≠checker dual-control
   entirely.
4. **`CreateMFAStepUpGrantProxy`** (`mfa_stepup_proxy.go:60`) — creates an MFA step-up
   grant (which satisfies the restricted-secret MFA gate) for any `UserID` with an
   attacker-chosen expiry and **zero TOTP/recovery-code verification**.
5. **`UpdateUserIfActiveStateMatchesProxy`** (`users_active_transition_proxy.go:119`) —
   skips `guardLastAdminDeactivation` (can deactivate the install's last global admin,
   locking out the whole install) and skips the PAT/session revocation that's supposed to
   accompany deactivation (a "deactivated" user's live tokens keep working).

Also real + human-reachable, not fixed: `UpdateProjectProxy` (silently disables a
project's MFA requirement without `roles.assign`, no audit — ADR-037 violation),
`RestoreProjectProxy` (resurrects admin-tier role grants on restore with zero authority
check — same shape as the already-fixed C1/`RemoveGlobalAdminRoleGuardedProxy` bug),
`CreateInvitationProxy` (bypasses the escalation-by-proxy guard on admin-role invites),
4x retention-purge proxies that skip `legalHoldGuard` (destroy compliance evidence during
an active legal hold), `DeleteSecretDependencyProxy` (skips peer-endpoint authorization,
the #G32 defense), plus 20 more listed in the full table below (machine-identity
lifecycle, dynamic-secret lease/config, connect-ref grants, break-glass, access-review
campaign force-close, login-lockout).

**None of these are fixed. None are PRs. This is flagged, not remediated, per this
session's explicit no-fix instruction and the "human-reachable: fix it now" stopping-rule
clause is deliberately NOT applied tonight — that decision belongs to Andrei in the
morning, not to an unsupervised overnight session touching authorization code.**

## Full table

Three sibling files, same directory:

- `docs/g80-raw-storage-bypass-enumeration.md` — the reproducible 58-candidate baseline
  and the 149→145 / 59→58 discrepancy resolution, with the committed generator script
  at `scripts/analysis/raw_storage_bypass_enumerate.go` (run it yourself to reproduce).
- `docs/g80-raw-storage-bypass-blind-spots.md` — the five categories this guard cannot
  see, named per the amended brief.
- `docs/g80-raw-storage-bypass-triage.md` — the complete 58-row triage table with
  file:line evidence and verdict/reach for every candidate.

## Notes, not blockers

- **`gh` auth needs a device-flow login, whenever convenient — not gating anything.**
  `gh auth status` reports "the token in keyring is invalid," no `GH_TOKEN`/`GITHUB_TOKEN`
  fallback. `gh auth refresh -h github.com` blocks on an interactive device-flow
  authorization (visit a URL, enter a code) that can't be completed unsupervised — the
  earlier TLS/cert failure was a separate, sandbox-caused issue, now confirmed unrelated.
  **This does not gate anything**: the repo docs (`docs/g80-raw-storage-bypass-triage.md`,
  `docs/g80-tracking-issue-draft.md`, this file) are the actual tracking artifact and are
  already committed-ready. File the GitHub issue and post the #1547 comment whenever the
  device flow is convenient — `! gh auth refresh -h github.com`, then `gh issue create`
  (strip the draft's "Filing status" section first) and `gh issue comment 1547` with the
  same body. **Correction on scope, unrelated to the auth issue**: earlier in the night I
  described this as posting "to #1547 on Slack" — that's wrong, #1547 is a GitHub issue
  (same numbering as #1542/#1545/#1546), not a Slack channel. Plan is one tracking issue
  (not 35), grouped by shared fix pattern (16 distinct patterns for the 35 findings, now
  ranked by severity with a launch line — see `docs/g80-tracking-issue-draft.md`), plus a
  comment on #1547 with the same architectural framing.
- **"58" vs. the previously-recorded "59" — RESOLVED, not a caveat anymore.** The
  original triage pass (above) flagged this as an open discrepancy; a follow-up amendment
  to tonight's brief asked for it to be resolved before further triage, so it was. Two
  independent implementations of the guard's stated detection logic (a regex/line-scan
  version and `scripts/analysis/raw_storage_bypass_enumerate.go`, an AST-based version
  immune to line-wrapping by construction) both produce exactly 145/87/58, not 149/90/59.
  Multi-line chains and variable/interface dispatch were checked directly and ruled out
  as the cause. **149/90/59 could not be reproduced and should be treated as the wrong
  figures**; 145/87/58 is now the committed, reproducible baseline
  (`docs/g80-raw-storage-bypass-enumeration.md`) and every number in this handoff is
  built from it. Five categories the guard still cannot see are named in
  `docs/g80-raw-storage-bypass-blind-spots.md` — not chased tonight, per instruction.
- **Uncommitted state found in this worktree at session start**: `docs/g80-remediation-notes.md`
  had uncommitted edits (the #1547 measurement paragraph — 149/59/52/7-resolved numbers)
  and an untracked `server/middleware/auth_userid_invariant_test.go` (a P3 invariant test
  pinning #1545's `UserID==0`-is-machine-only assumption). These predate tonight's session
  and were treated as ground truth / starting context, not touched further. Recommend
  committing them (they look complete and correct) before or alongside whatever lands
  from tonight's findings.

## Noticed but not chased (one line each, per the stopping rule)

- `dynamic_secrets_proxy.go` has at least 2 more raw-storage call sites
  (`CreateDynamicSecretConfig`, list/count methods) not in tonight's write-shaped set
  because they're read-shaped or not flagged by the wrapped-method heuristic — worth
  a second pass if this bug class gets a dedicated remediation wave.
- The `audit_ingest_proxy.go:43-55` comment (found by the batch-B agent) is itself an
  acknowledgment, in the codebase's own words, that `/system` routes are reachable by any
  `system.write` holder directly — this same reasoning should probably be added as a
  standing note near `RequireNodeCredentialOrPermission`'s definition so the next person
  auditing this surface doesn't have to rediscover it handler-by-handler.
- Several `real` findings share one exact shape (skip a `legalHoldGuard`/`requireReauth`/
  `guardLastAdminDeactivation`-style "resolve the ceiling list server-side, don't trust
  the caller" check) — a single guard test analogous to
  `TestNoUnjustifiedRawStorageBypass` but keyed on "core wrapper calls a named
  ceiling-check helper the raw proxy doesn't call" might catch this whole family
  mechanically instead of one-by-one. Not built tonight — a new guard is explicitly out
  of scope for this session per instructions.
- `TransitionMembershipProxy` (#1546) reach is still genuinely unresolved (not touched
  further tonight, per instructions) — it remains the one line item in the "unresolved"
  bucket.

## Single next action for Andrei

**Do not merge or deploy anything with `storage.type: remote` configured against an
untrusted operator until at least the top 5 findings above are fixed** (or the
`/system` route group's permission model is tightened so `system.write` doesn't imply
"can call every raw-storage proxy in this group unaudited"). Then: fix `gh auth`, file
the 35 issues (content is drafted), post the table to #1547, and triage which of the 35
gets a dedicated PR first — `CreateMachineIdentityCredentialProxy` is the one to start
with; it's a direct privilege-escalation path, not just a policy/audit gap.
