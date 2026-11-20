- **INV-AUTHZDIFF-v5ext3-bulk-secret-gates** The authorization gate of `bulk.delete`,
`bulk.rename`, `bulk.suspend`, and `resume.all` is bound into the differential
and checked against the independent reference model.

`bulk.delete`: secrets.delete@project router gate. Core enforces the same
permission via the per-item RBAC fallback in CheckSecretPermission (#r124).
Additionally, `BulkDeleteSecrets` calls `GetSecretWithPermissionCheck` before
the delete step — this requires `secrets.read` (or ownership/ACL-read), which
is NOT captured by the router model (the model checks only the authorization
gate permission, not data-access prerequisites). Machine actors: `BulkDeleteSecrets`
treats `actorID=0` as the CLI caller, skipping permission checks → item IS
deleted; core leg returns `errNotAuthzLayer` (not an authorization layer for
machine actors).

`bulk.rename`, `bulk.suspend`, `resume.all`: secrets.write@project router gate.
Same per-item RBAC fallback shape. Machine actors: `BulkRenameSecrets`,
`SuspendProjectSecretsWithOptions`, and `ResumeProjectSecrets` return an error
immediately for `actorID=0` → HTTP 400/500. Machine actors return
`errNotAuthzLayer` for all three ops.

`resume.all` requires a pre-suspended fixture secret (perProject.suspendedSecretID,
`s-resume-fixture`, suspended via `SuspendSecret` in the V5EXT3 seed) so the
admin positive control gets n≥1 from `ResumeProjectSecrets`.

DIFFERENTIAL PLANT LIMITATION: Router gate removal for all four ops cannot be
detected via differential plants. The per-item RBAC fallback (#r124) mirrors
the router gate check for every user-actor principal — removing the router gate
changes the HTTP status code (403→200+empty-result) but not the harness
outcome classification (both map to `denied`). No case crosses the allowed/denied
boundary, so the differential harness sees nothing new. This was confirmed
dynamically (control sweep with gate removed produced 0 new unexplained cases).

Guard:
  1. `TestV5ext3StrictSweep` (server/authzdiff/sweep_v5ext3_test.go, always-on):
     strict sweep over curated variations for all 4 ops; zero uncalibrated,
     zero unexplained. Verifies the RBAC gate boundary (custom with/without
     perm, via group, machine lacks) for both router and per-item checks acting
     in concert.
  2. `TestBulkSecretRouterGatesPresent` (server/authzdiff/sweep_v5ext3_test.go,
     always-on): structural check that the four router gate anchor strings exist
     exactly once in `server/http/router.go`. RED when any gate registration is
     absent or misnamed.

Waivers:
  - The former `known-10` (machine+holds for bulk.rename/suspend/resume.all →
    REST 400/500) is gone: those ops refuse a machine actor typed (403) and the
    model marks them human-only (#4514).
  - The former `known-11` (bulk.delete with a secrets.delete-only user → per-item
    GET refused) is gone: the model requires secrets.read for a user actor
    (`requirement.userPerms`, #4515).

What these guards do NOT verify:
  - Per-item ownership grants (no RBAC secrets.delete/write, but owner of the
    secret): core allows via ownership, REST router gate denies → documented
    EXPECTED-DIFFERENCE, not an invariant violation.
  - `bulk.rotate` (BulkRotateSecrets): deferred, fixture-blocked.
  - SCIM, MFA step-up: deferred, fixture-blocked.
