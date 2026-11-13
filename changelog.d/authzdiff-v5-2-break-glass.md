### Testing
- authzdiff cross-layer differential harness now covers self-service break-glass
  activation (`POST /api/v1/projects/{id}/break-glass`, core
  `ActivateBreakGlass`). The route carries no router permission gate — the entire
  authorization is core's — so the core and REST legs are checked against a new
  independent model rule (`memberOnly`): only a USER who is a member of the
  project NOW (a role scoped to that project, direct or via a live group — never
  a global/install-wide role, the #284-era fix), and never a restricted PAT. A
  machine actor (reaching core as `userID==0`) is refused with a validation
  error on both legs and absorbed by the partition's existing machine
  mapping-gap waiver, never a disagreement. A permanent planted-defect self-test
  (`breakglass-activate-membership-gate-removed`) proves the harness still fires
  when that membership gate is dropped. REST coverage rises from 90 to 91 of 211
  in-scope operations.
