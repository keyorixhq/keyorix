# Stateful sequence fuzzing: design and pre-registered success rule

Status: written BEFORE the first sweep. Results are appended below under
"Results", never edited into this section.

## Question

The single-step harness (`REPORT.md`) compares the layers and the reference model
on one operation from a fresh world. It cannot see bugs that need state: a
revocation that does not revoke, a cache that outlives a grant, a suspension that
one route ignores, a group removal that leaves access behind. This harness runs
bounded SEQUENCES of authorisation-changing steps and checks the same three
layers (core, REST, gRPC) after every step.

## Steps modelled (8)

role.grant, role.revoke, user.suspend, user.reactivate, group.add, group.remove
(through the API on all layers where an RPC exists), custom.perm.toggle (store
mutators, moves the role->permission cache generation) and grant.expire (the fake
clock: the subject's grants move into the past). Actors: global admin, project
admin, custom-role user, viewer, no-role user. Subjects: no-role, viewer, custom,
project admin, expired-grant user. Scopes: A, B, global.

## Oracles

* O-S: the step's layers agree; for grant/revoke the outcome equals the model's
  decision on the world before the step.
* O-E: an allowed step left the state it names; a denied step changed nothing
  (digest of the authorisation tables equal).
* O-P: after every step all eight probe principals read the secret value of each
  project on each layer (byref and byid); each layer must equal the model on its
  own database, and layers must agree.

The model is the single-step model (`model_test.go`), plus the account state read
from the database. It reads the grant tables, so O-E is the independent intent
check.

## Self-test (must pass before any sweep result counts)

* Control: the baseline (zero steps) probes are clean, and the hand-written benign
  sequences are clean. A non-clean control means a harness/model gap to fix first;
  it is not a finding.
* Plants (in the harness, never in production code): `revoke-noop` (the REST leg
  reports success without revoking), `revoke-noop-held-grant` (no leg carries out the
  revoke of a grant the viewer holds in the fixture: one step, and every leg and
  the model agree), `revoke-noop-held-grant-4020` (the same no-op revoke, answering
  the #4020 signature: REST 404, gRPC `Internal`), `stale-allow` (the gRPC probe still allows a revoked
  principal), `suspend-ignored` (the REST probe allows a suspended principal) and
  `step-5xx` (the REST leg answers 500 on a revoke). Each plant must be detected
  by its designated sequence with the named oracle class, the same sequence
  without the plant must be clean, and the triage that FuzzAuthzSeq and the
  sweep use (`seqVerdict`) must fail the run on it.

## Run

On the Mac only (shared machine): `GOMAXPROCS=2`, one test process.

1. Deterministic sweep: seeds 1..N, N = 600 sequences of 1..8 steps
   (`AUTHZSEQ_SWEEP=1 AUTHZSEQ_N=600`), time cap 30 minutes.
2. Native fuzzing: `FuzzAuthzSeq`, `-parallel 2 -fuzztime 10m`.

## Classification of a finding

After shrinking (delete steps while the class survives) every finding is replayed
as a single step in a fresh world.
* same class alone: `single-step` (known behaviour or model gap; not counted);
* class only in the sequence: candidate `sequence-dependent`; the minimal
  sequence goes to the private file, never to a PR.
A candidate is then read against the code to decide product bug versus model gap.

Exception (added in review, before any result below was re-counted): a class
that always fails is never `single-step`, however it reproduces. That is every
over-allow (a transport allows what the model, another leg or the state denies),
every O-E intent class (`revoked-row-still-present`, `granted-row-missing`,
`account-state-not-*`, `group-row-*`, `reactivated-user-cannot-log-in`,
`denied-step-changed-state`) and `O-S:other`. The model reads the same tables,
so a revocation that does not revoke shows only in O-E, and the single-step
harness has no effect oracle: "the step alone reproduces it" does not mean it is
covered elsewhere. FuzzAuthzSeq and the sweep share one triage (`seqVerdict`).

`O-S:other` is a step on which a transport answered a server error (a 5xx, gRPC
`Internal`/`Unknown`/`Unavailable`, or any detail not known to be a client
error). A step whose only Other answers are client errors (REST 4xx, gRPC
`InvalidArgument`/`AlreadyExists`/`FailedPrecondition`/`OutOfRange`; for
example a project-tier role granted at global scope: REST 400, gRPC
`InvalidArgument`) is `O-S:other-client`: it is triaged like any other class, and
when no leg allowed it the state must be unchanged on every leg. Core's
`untyped-error` does not decide either way (core maps errors by identity only).
`TestSeqClientErrorSplit` pins the split.

## Pre-registered success rule

Success is EITHER
(a) at least one sequence-dependent candidate that survives shrinking and the
    single-step replay and is not one of the findings already recorded as D1-D8 or
    M1-M3 (compared by mechanism, in the private notes), OR
(b) a clean run: at least 500 sequences executed with zero candidate findings,
    and every step kind executed with consensus "allowed" at least once and
    consensus "denied" at least once (the model covers all listed operations).

Otherwise the result is recorded as "did not pay off" (for example: the run is
dominated by `single-step` noise, a kind is never allowed, or the control fails).
A clean run (b) is a statement about THIS state space and the 8 steps above only.

## Results (2026-11-06, Mac, GOMAXPROCS=2)

### Self-test

Control (zero steps and five benign sequences) clean; the four harness plants
of that run (`revoke-noop`, `stale-allow`, `suspend-ignored`, `step-5xx`) each
detected with the named oracle class, and the same sequences clean without the
plant. `revoke-noop-held-grant` and the check that `seqVerdict` fails on every plant
were added in review; at the commit before the always-fail exception,
`revoke-noop-held-grant` is detected but triaged `single-step` and the run passes.
`AUTHZSEQ_SELFTEST=1 go test ./server/authzdiff -run 'TestSeqControl|TestSeqPlantsAreDetected'`.

Harness issues found and fixed while getting the control clean (not product
findings; recorded because they shape what the result means):

* The auth cache is process-global and tombstones a suspended user's token hash,
  so worlds must not share token strings: every subject logs in afresh on each
  leg, and a reactivated user logs in again (suspension revokes sessions).
* The per-IP invalid-token limiter (burst 10, 1/s, process-global, keyed by the
  constant test peer) turns repeated probes with a rejected token into 429 /
  ResourceExhausted. Those probes are recorded as n/a, and a suspended
  principal is probed once per account-state change, throttled.
* Account state is enforced by the transports, not by core's read path, so the
  core leg is not an oracle for a suspended principal; likewise ops whose core
  entry has `core_refusal: none` (matrix.json) are state-synced on core rather
  than run with the real actor (ID-2).
* The model ignored `user_groups.project_id`: in the store's group-role
  resolution (`GetUserGroupRoleIDsAt`), a group membership scoped to project B
  confers the group's roles only in B (`models.UserGroup`). A sequence
  (group.add at B, then expire the direct grant) exposed it as an
  `O-P:over-denial`; read against the code it is a model gap, not a product bug.
  The model's group-role resolution now respects the scope. The single-step
  suite was re-run after the change. The model's `memberOf` applies the same
  scope, which is stricter than the product's project-membership check
  (`IsProjectMember` ignores `user_groups.project_id`); that direction fails
  closed here (it would show as a reported over-allow), and the sequence probes
  (value reads) do not reach `memberOf`.

### Sweep, final run (model fixed)

Seeds `1_000_000 + 0..599`, one process:

| | |
|---|---|
| sequences | 600 (2,345 steps, 78,871 probes, 17 min 22 s) |
| sequence-dependent candidates | 0 |
| single-step bucket (same class when the failing step runs alone) | 197 |
| step kinds executed allowed / denied | role.grant 57/222, role.revoke 8/296, user.suspend 70/232, user.reactivate 73/232, group.add 66/96, group.remove 61/207; custom.perm.toggle 300 and grant.expire 286 (state steps always apply) |

The 197 single-step cases are two behaviours, both reproduced by the single step
alone from a fresh world: (1) 120 x `O-S:layers-disagree`, group.add by a project
admin: core allows, the REST gate (which also requires `users.read`) denies;
(2) 77 x `O-S:step-vs-model`, role.revoke of a grant the subject does not hold:
every transport answers not-found, the model says the actor is authorised. Neither
is sequence-dependent.

Correction (review): in (2) REST answers 404 but gRPC answers `Internal`
(`mapRoleError` has no case for `storage.ErrRoleNotAssigned`, #4020), so the
step also carries an `O-S:other`; the report above picked the first finding,
`O-S:step-vs-model`. The same gap exists for a grant the subject already holds
(`storage.ErrRoleAlreadyAssigned`: core untyped error, REST 409, gRPC
`Internal`), which native fuzzing hit within seconds once `O-S:other` always
failed. Both are one known-open tolerance, `O-S:known-other-4020`, matched only
on those two exact signatures (the step kind, the model allowing it, and every
leg's outcome and detail) and only when the #4020 precondition held on every leg
before the step: the revoked grant was absent, the granted one already present
(`TestSeqKnownOtherIsNarrow`). A revoke of a held grant that does nothing is
therefore `O-S:other` and always fails (plant `revoke-noop-held-grant-4020`).
It is removed when #4020 is fixed. A tolerated step must still leave the state unchanged on every leg, and it
still ends the sequence. (1) is neither an over-allow, an O-E class nor
`O-S:other` (`TestSeqClassKey`).

An earlier run of the same seeds with the pre-fix model (288 + 312 sequences)
likewise had 0 candidates; a further 40 sequences (indices 900-939) produced the
one candidate described above (the model gap), which is why the model was fixed
and the 600 re-run.

### Against the pre-registered rule

Rule (b) is met for this state space: 600 >= 500 sequences, zero candidates,
every API step kind executed with consensus allowed at least once and denied at
least once. State-only steps (permission toggle, grant expiry) cannot be denied;
they are counted as executed.

Rule (a) was not met: no new sequence-dependent disagreement beyond the
single-step ones. The method did not find a defect in this state space; it found
three harness/model issues and confirmed that the layers, the grant tables and
the intent checks stay in step through 2,345 state changes.

### Limits (what a clean run does not say)

* Only the 8 step kinds and 5 actors / 5 subjects / 3 scopes above; no project
  delete/restore, no machine-identity or PAT steps, no secret-level shares or
  ACLs (outside the model's domain), no seal/unseal (not exposed in-process).
* A step whose layers disagree ends its sequence (the worlds diverge), and a third
  of the sequences hit one of the two known single-step behaviours, so their later
  steps were not explored. A follow-up should model those two behaviours instead of
  stopping.
* Probes are secret-value reads only (by ref and by id). Existence leaks through
  lists and 403-versus-404 differences are not probed.
* Run time is the real clock; expiry is moved by editing `expires_at`, not by an
  injected clock.
* The model reads the grant tables, so the independent intent checks (O-E) cover
  only the relations named in `buildCall`.
* A suspended principal is probed only right after a suspend or reactivate step,
  and only at project A by ref (the invalid-token limiter). A later step on a
  suspended subject (for example suspend the viewer, then grant it a role at B)
  is not probed for that subject, so a suspension that one route ignores for a
  newly granted role or a cache is outside the oracle.
* group.remove removes only global memberships (core passes project 0, REST and
  gRPC send no project, and the effect check reads `project_id = 0`). A
  project-scoped membership created by group.add at A or B is never removed, so
  a group removal that leaves access behind is exercised only for global
  memberships.
