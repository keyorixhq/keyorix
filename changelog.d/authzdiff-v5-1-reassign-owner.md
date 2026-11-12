### Testing
- authzdiff cross-layer differential harness now covers the bulk secret-owner
  reassignment route (`POST /api/v1/projects/{id}/secrets/reassign-owner`,
  core `ReassignOwnedSecrets`). Its single project-scope `roles.assign` gate
  (the #G10 fix) is checked on the core and REST legs against the independent
  reference model, and a permanent planted-defect self-test
  (`reassign-owner-core-gate-removed`) proves the harness still fires when that
  gate is dropped. REST coverage rises from 89 to 90 of 211 in-scope operations.
