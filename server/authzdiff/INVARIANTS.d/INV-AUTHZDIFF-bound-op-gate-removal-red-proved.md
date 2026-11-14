- **INV-AUTHZDIFF-bound-op-gate-removal-red-proved** Every bound op is calibrated
  (its admin positive control is `Allowed` on every participating layer, else the
  case is `uncalibrated` and a strict sweep fails) and, where the harness's power
  to catch a dropped authorization check on that op's shape is claimed, that claim
  is backed by a planted-defect self-test: a `plants_test.go` entry removes the
  real gate via `-overlay` (the working tree is never edited) and asserts the
  restricted sweep produces at least `minUnexplained` cases in the plant's
  `bucket` (default `unexplained`) on that op alone, with the same sweep WITHOUT
  the overlay producing zero cases in that bucket. A plant whose bucket is
  `unexplained` proves a strict sweep FAILS on the defect; a plant whose bucket
  is a waiver proves only that the harness RECORDS it there. A model rule that
  could not be red-proved this way is not committed as an oracle.
  Why: "a guard nobody has watched fail is not a guard" and "validate a mechanism
  against a failure that actually happened" (root `CLAUDE.md`). The break-glass
  plant (`breakglass-activate-membership-gate-removed`, bucket `unexplained`)
  removes `ActivateBreakGlass`'s `IsProjectMember` refusal — the self-elevation
  gate whose earlier "holds the install baseline counts as membership" form was
  the #284-era bug — so core, REST and gRPC (neither transport has a gate of its
  own) over-allow every non-member the `memberOnly` model rule denies, and a
  strict sweep fails. The reassign-owner plant (`reassign-owner-core-gate-removed`,
  bucket `known-04`) removes `ReassignOwnedSecrets`' own `roles.assign@project`
  gate, the #G10 "denial masked as a silent no-op" regression; REST still gates
  that route at the router, so the core-only over-allow lands in the known-04
  waiver. The harness records that regression but does NOT fail a strict sweep
  on it.
  Guard: `TestPlantsAreDetected` (CI job `authzdiff-plants`, opt-in
  `AUTHZDIFF_PLANTS=1`); `TestV5StrictSweep` (default `go test`, skipped under
  `-short`) runs the deterministic strict sweep over the V5 bindings and fails on
  any uncalibrated or `unexplained` case; `TestInvalidArgsFailAdminControl` and the
  `uncalibrated` failure path of `TestAuthzDiffSweep`/`FuzzAuthzDiff`. Does NOT
  fail on a gate removed at a layer all present transports still gate (a
  defence-in-depth-only regression, such as reassign-owner's core gate): that
  case is recorded as known-04, see `partition_test.go`'s known-04 note.
