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
  reports success without revoking), `stale-allow` (the gRPC probe still allows a
  revoked principal) and `suspend-ignored` (the REST probe allows a suspended
  principal). Each plant must be detected by its designated sequence with the
  named oracle class, and the same sequence without the plant must be clean.

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

Control (zero steps and five benign sequences) clean; the three harness plants
(`revoke-noop`, `stale-allow`, `suspend-ignored`) each detected with the named
oracle class, and the same sequences clean without the plant.
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
* The model ignored `user_groups.project_id`: a group membership scoped to
  project B confers the group's roles only in B (`models.UserGroup`). A sequence
  (group.add at B, then expire the direct grant) exposed it as an
  `O-P:over-denial`; read against the code it is a model gap, not a product bug.
  The model now respects the scope. The single-step suite was re-run after the
  change.

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
