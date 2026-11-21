### Testing
- **Audit-log truthfulness for DENIED operations (`FuzzDeniedOpAuditNeverSuccess`, AUD1).**
  New fuzz target in `server/faultops` that reuses `FuzzMixedPrincipalAuthority`'s
  independent authorization reference model to drive random
  (principal, operation, target-project) triples the model denies, and asserts
  the compliance-critical direction the existing audit fuzzers did not cover: a
  denied, no-effect operation must never leave a `Success=true` audit row (a
  FALSE-SUCCESS audit certifies an unauthorized action as completed). Soundness-
  gated on "non-audit state unchanged" so it only asserts where a success record
  would genuinely be false. A ground-truth census (`TestDeniedOpAuditCensus`)
  documents that Keyorix today does not audit mutation/authorization denials at
  all (secret-value *read* denials remain audited via `AuditSecretValueReadDenials`),
  a reviewed completeness baseline rather than a per-run failure.
