### Testing
- authzdiff cross-layer differential harness now covers the bulk secret-owner
  reassignment route (`POST /api/v1/projects/{id}/secrets/reassign-owner`,
  core `ReassignOwnedSecrets`). Its single project-scope `roles.assign` gate
  (the #G10 fix) is checked on the core and REST legs against the independent
  reference model. A permanent planted-defect self-test
  (`reassign-owner-core-gate-removed`) proves the harness still records a
  dropped core gate, as the known-04 waiver ("core allows, every transport
  denies"): REST keeps its router gate, so a strict sweep does not fail on it.
- authzdiff now also covers self-service break-glass activation
  (`POST /api/v1/projects/{id}/break-glass` and the gRPC RPC
  `BreakGlassService.ActivateBreakGlass`, core `ActivateBreakGlass`). Neither
  transport carries a permission gate of its own — the entire authorization is
  core's — so all three legs are checked against a new independent model rule
  (`memberOnly`): only a USER who is a member of the project NOW (a role scoped
  to that project, direct or via a live group — never a global/install-wide
  role, the #284-era fix), and never a restricted PAT. A machine actor
  (reaching core as `userID==0`) is refused with a validation error and
  absorbed by the partition's existing machine mapping-gap waiver, never a
  disagreement. A permanent planted-defect self-test
  (`breakglass-activate-membership-gate-removed`) proves a strict sweep fails
  when that membership gate is dropped.
- authzdiff coverage rises from 89 to 91 of 211 in-scope REST operations and
  from 34 to 35 of 46 in-scope gRPC operations.
