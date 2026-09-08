# ADR-104: Security remediation timelines — published commitment vs. internal target

## Status

Accepted.

Policy layer alongside [ADR-067](adr-067-release-lifecycle-support-policy.md).
ADR-067 decided *which versions* get a fix and *for how long* (the support
period). This ADR decides *how fast a fix ships once a severity is
confirmed* — a different commitment class, orthogonal to support-period
length. Public expression of the published half of this policy lives in
[`SECURITY.md`](../SECURITY.md) § Remediation Timelines.

**Authority is split by section, deliberately, not held by one document:**
`SECURITY.md` is authoritative for the **published** table — it's the
customer-facing document, read by the audience the commitment is for, and
if the two ever disagree on a published figure, `SECURITY.md` is current
and this ADR's copy is stale. This ADR is authoritative for the
**internal-target** table and the **CRITICAL definition** — neither is
published anywhere else, so there is nothing for them to drift out of sync
with. Neither document restates the other's own section from scratch;
`SECURITY.md` does not carry internal targets at all, and this ADR's
published-table copy exists only "for the record" per the note above, not
as a second live source.

## Context

Keyorix is maintained by one person, with no on-call rotation and no funded
team. `SECURITY.md` already publishes two commitments — acknowledge a
report within 48 hours, initial assessment within 7 days — and those are
correct and unchanged by this ADR. What's missing is the next commitment
class entirely: once a report is confirmed and triaged to a severity, how
long until a fix actually reaches an installable release. That gap was
visible in practice before this ADR: PR #1789 (last-admin lockout via a PAT
confused deputy) sat merged and correct on `main`, unreachable by any
operator, for days, with nothing published that says how long that's
supposed to take.

A published SLA is a promise from an organisation with redundancy — the
reader assumes there's a team, a backup, a rotation. There isn't. A miss is
observable in a public repository (an open PR referencing a CVE, a stale
advisory, a customer asking in public), and a missed *published* commitment
does more damage than a modest one that's always beaten. Two consequences
follow directly:

1. **The published numbers must be sized for the worst realistic month**
   (illness, a family emergency, a week at a conference), not the best one.
   A number that only works when nothing else goes wrong is not a
   commitment, it's a hope with a deadline attached.
2. **Anything tighter that's merely aspirational must be kept out of the
   published surface entirely** — not softened, not hedged, kept out — so
   that hitting it is a bonus and missing it is not a broken promise.

That's the reasoning behind the split in this ADR. It's stated here in one
place specifically so a future editor doesn't "helpfully" merge the two
tables — the split is the point, not an oversight to tidy up.

### Two other timelines that use similar-looking numbers and are not this one

To avoid the exact confusion this note exists to prevent:

- **`SECURITY.md`'s existing 7-day *initial assessment*** is about
  triage — confirming a report is real and roughly how bad it is. It is not
  a remediation commitment and this ADR does not change it.
- **ADR-067's own follow-up list** (§ Follow-ups) names a future "24h/72h/
  14-day ENISA reporting chain" — that is a *regulatory notification*
  timeline to authorities for actively-exploited vulnerabilities under the
  CRA, not yet documented or implemented anywhere. It is a different
  commitment, to a different audience (a regulator, not a customer), and
  its "14 days" is a coincidence of both numbers being drawn from the same
  general problem space, not a shared figure. When that runbook is written,
  it should cross-reference this ADR to make the distinction explicit
  rather than risk the same collision landing in prose instead of just in
  two ADRs' section headers.

### Reconciling with the pre-1.0 posture

`SECURITY.md` states Keyorix is pre-1.0 and has not declared a support
period under the CRA — that sentence is about *which versions remain
patchable at all and for how long* (ADR-067's subject). The remediation
timelines below are a *different, narrower* commitment: given that a
version IS the one receiving fixes (today, unconditionally, the latest
release — see `SECURITY.md`'s Supported Versions table), how fast does a
confirmed fix reach it. A project can have zero declared support period and
still commit to a remediation speed once it's actively fixing something;
the two are independent axes, and pre-1.0 status affects the first, not the
second. The published section below is written as **a current operating
commitment, not a CRA-declared support period** — that phrase is used
verbatim in `SECURITY.md` so a non-lawyer reader doesn't have to infer the
distinction.

## Decision

### Published (in `SECURITY.md`, this ADR's copy is for the record only)

Sized for the worst realistic month, not the best one. This is what a
customer may rely on.

| Class | Commitment |
|---|---|
| Acknowledge a report | 48 hours *(already published, unchanged)* |
| Initial assessment | 7 days *(already published, unchanged)* |
| CRITICAL | Mitigation or workaround guidance within 7 days; fixed release within 14 days |
| HIGH | Fixed release within 30 days |
| MEDIUM / LOW | Next scheduled release |
| Release cadence | **Not published** — see "Cadence is deliberately not published yet" below |

### Internal targets (not published, not promised to anyone)

Tighter, aspirational, tracked for our own use. A miss here has no external
consequence and should be treated as ordinary triage information, not an
incident.

| Class | Internal aim |
|---|---|
| CRITICAL | 24 hours to workaround guidance; fixed release within 5 business days |
| HIGH | Fixed release within 10 business days |
| MEDIUM / LOW | Next scheduled release (same as published — no internal/external gap for this tier) |

If these internal numbers are ever consistently beaten by a wide, durable
margin, that is the trigger to *revise the published numbers* in
`SECURITY.md` deliberately — not to publish the internal table as-is. Any
tightening of the published commitment goes through the same review this
ADR itself got, not a quiet edit.

### Cadence is deliberately not published yet

The draft this ADR revises proposed a published monthly-minor cadence. It
is not adopted. The repository went four weeks with zero tags pushed
immediately before that draft was written — a cadence claim written the
same month it wasn't met is not evidence, it's a hope. Per this ADR:
**release cadence remains an internal working agreement, not a published
commitment, until it has been hit three consecutive times.** Three, not
one, because a single on-time month after a miss proves the miss was
noticed, not that the underlying capacity exists. Once three consecutive
months hit the internal aim, publishing a cadence becomes a decision to
revisit — this ADR does not pre-approve it; it only names the bar.

### CRITICAL, defined narrowly enough that a 14-day commitment is safe

**CRITICAL: remote, unauthenticated compromise of stored secret values, or
of the authentication boundary itself, requiring no valid credential of any
kind and no prior account state.**

Both halves of "requiring no valid credential of any kind" matter and are
independently sufficient to keep a finding out of this tier:

- If exploitation requires *any* authentication material — a full-strength
  session, a scoped-down PAT, a since-revoked-but-technically-still-typed
  password, a machine credential, even a deliberately restricted one — it
  is not CRITICAL under this definition, regardless of what that credential
  then lets the holder do.
- If exploitation requires the target to be in some prior state that only
  an already-provisioned account can be in (suspended, deprovisioned, mid
  password-reset), it is not CRITICAL either, even if the eventual access
  is unrestricted — the attacker needed something about that specific
  account first.

"Compromise of stored secrets" means reading or deriving actual secret
*values* — not metadata, not knowing a secret exists, not a timing
side-channel about whether one does. "Compromise of the authentication
boundary" means forging or bypassing authentication outright — minting a
valid session/token without ever presenting a real credential, or a
cryptographic verification (JWT/OIDC signature, PBKDF2-wrapped key)
accepting something it should reject.

Everything that clears CRITICAL's bar but still represents a genuine
authenticated bypass, escalation, or control-integrity failure is HIGH —
that tier is intentionally the larger bucket. Narrow CRITICAL, wide HIGH is
the design, not an accident: it's what makes 14 days survivable for one
person.

#### Worked examples, both from this repository's own history

**#1742 — account-takeover via blank `AccountState` → HIGH, not CRITICAL.**
A suspended or deprovisioned account could be silently reactivated for
login because `AccountLoginBlocked` read a blank/unrecognized
`account_state` as "not blocked" (fail-open). Serious, and — per the
release-prep work that preceded this ADR — already exploitable in the
currently shipped version. But exploiting it requires the account to
already exist in a specific prior state (suspended/deprovisioned) *and*
requires whoever logs back in to hold that account's own already-known
credentials — there is no path from zero credentials to a working session
through this bug alone. It fails the "no prior account state" clause
outright. **HIGH.**

**#1789 — last-admin lockout via PAT confused deputy → HIGH, not CRITICAL.**
An actor holding a restricted PAT — deliberately scoped away from admin
authority — could deactivate the install's last global admin, because the
guard asked a function about the *target's* admin status that was built to
answer a question about the *acting caller*. Severe: it strands the whole
installation with no administrator, recoverable only via direct DB
intervention. But it requires an authenticated actor already holding a
valid (if restricted) PAT — it fails "requiring no valid credential of any
kind" outright, and separately, it's an availability/control-integrity
failure (denial of administration), not a secrets-compromise or an
authentication-boundary bypass — it doesn't clear either half of the
"compromise of X" clause either. Two independent reasons it's not CRITICAL,
not one. **HIGH.**

**Illustrative CRITICAL example (hypothetical, not a real finding — included
because the published tier needs at least one concrete positive case to be
legible, and none of this pass's real findings happen to clear the bar):**
an unauthenticated caller presenting no credential at all is able to submit
a request to the OIDC/JWKS verification path that Keyorix accepts as a
validly-signed session token — no password, no PAT, no prior account,
nothing. That clears both halves: no credential of any kind, and a direct
authentication-boundary bypass. **This is the shape CRITICAL exists for.**
The fact that neither #1742 nor #1789 — both genuinely severe — clears it
is the definition working as intended, not a sign it's drawn wrong.

### Who decides

Severity classification against the CRITICAL definition above is made once,
at merge time, by whoever fixed the issue together with the maintainer —
not re-litigated later at release-cut time. It is recorded as a row in
`docs/security-closures.tsv` (the existing closure-ledger convention),
which is also how a reader can check whether a given published timeline was
actually met, rather than taking that on trust. Publishing a release
(cutting the tag) remains the maintainer's call, always, regardless of
which SLA tier a fix falls under — this ADR sets the target, it does not
remove the human gate on when a tag actually goes out.

## Consequences

**Positive.** The published table is a number a solo maintainer can
actually hit in a bad month, which is what makes it trustworthy rather than
aspirational marketing copy. The internal/published split means tightening
practice over time doesn't require walking back a public commitment — it
only ever moves the published number down, never up, and only after a
demonstrated track record (the three-consecutive-months rule for cadence
is the template for how future tightening should be justified generally).
A narrow CRITICAL definition means the rare 14-day commitment stays
credible precisely because it almost never fires — both real severe
findings checked against it land in the wider HIGH tier, which has running
room built in (30 days, one person, one release cycle).

**Negative.** A narrow CRITICAL tier means some findings a reader might
intuitively call "critical" in conversation are formally HIGH with a
30-day published commitment instead of 14 — #1789 (an installation-wide
admin lockout) is the sharpest case of this, and the definition's own
worked example says so plainly rather than quietly. That is a deliberate
trade for keeping the 14-day tier credible, not an oversight; it should be
revisited only if a future CRITICAL-shaped finding is found to slip through
HIGH's wider net in practice, not on the basis of this one example feeling
under-classified in hindsight.

## Follow-ups

- Revisit publishing a release cadence once three consecutive months hit
  the internal target (see "Cadence is deliberately not published yet").
- The ENISA 24h/72h/14-day regulatory reporting chain (ADR-067 §
  Follow-ups) should, when written, explicitly cross-reference this ADR to
  keep its own "14 days" from being read as the same commitment.
- If remediation capacity is ever funded beyond one person (a hire, a
  contractor), this ADR's "who decides" and internal-target numbers are the
  first section to revisit — the published numbers should not move until
  the internal ones have proven durable under the new capacity, same rule
  as the cadence bar above.
