### Testing
- authzdiff cross-layer differential harness now covers the bulk secret-owner
  reassignment route (`POST /api/v1/projects/{id}/secrets/reassign-owner`,
  core `ReassignOwnedSecrets`). Its single project-scope `roles.assign` gate
  (the #G10 fix) is checked on the core and REST legs against the independent
  reference model (clean sweep: no unexplained case). The route is gated at both
  the router and in core, so dropping either gate alone is not observable and no
  planted-defect self-test is claimed for it. REST coverage rises from 89 to 90 of 211 in-scope operations.
