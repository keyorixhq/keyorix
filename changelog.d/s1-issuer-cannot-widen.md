### Testing
- **authzdiff differential now covers the #4332 user-caller machine-token
  ceiling.** The cross-layer authorization model (`server/authzdiff`) applied the
  machine-token target-permission ceiling only to machine callers; keyorix#4332
  extended core's ceiling to user callers, so the clean tree showed 8 over-denial
  cases on `machine.token.issue` (model allowed, every leg denied). The reference
  model now holds a user caller to the same target-coverage rule (exempting a
  global admin), and a `fix-4332-user-target-ceiling-removed` plant keeps a red
  differential case for it — the twin of the existing `fix-3993` machine-caller
  plant. Fixes a stale oracle, not a core defect: core is correctly denying.
  Part of the S1 "an issuer cannot widen" sweep
  (`docs/findings/2026-11-15-issuer-cannot-widen-sweep.md`), which confirmed every
  credential/permission-grant path is enforced or a documented exception.
