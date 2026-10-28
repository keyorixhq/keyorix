- **INV-CORE-scim-revocation-readback-after-commit** A SCIM group write that is a pure member
  removal (`PatchSCIMGroup` with no add and no rename, `ReplaceSCIMGroup` whose member set only
  shrinks) is a revocation on the owed path (INV-CORE-revocation-audit-owed), and the read-back
  of the group and its members for the response (`readSCIMGroupState`) runs AFTER its commit,
  never inside its transaction: a failed statement there would roll the revocation back (and on
  Postgres aborts the transaction, so catching it inside `fn` is not enough). A read-back failure,
  a panic included, is `ErrSCIMGroupStateUnavailable` with the removal applied; SCIM PATCH answers
  204 No Content, PUT the SCIM error. A write that can widen access reads the state inside its
  transaction (fail closed).
  Why: REVIEW-3775 F1, a read-back fault left the removed member in the group with its roles.
  Guard: `server/http/handlers` `TestSCIM_GroupRevocationNotRolledBackByReadBack` (PATCH remove
  and PUT shrink x the read-back's GetGroup and ListGroupMembers x 4 error classes and a panic;
  reads the membership afterwards).
  Not covered: `TestSCIMOpsFaultSweep` sweeps only the catalog shapes of PUT/PATCH, which widen;
  no static guard stops a new read inside a revocation transaction.
