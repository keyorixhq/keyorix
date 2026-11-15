- **INV-AUDITVERIFY-retention-anchor-fail-closed** The retention-anchor codec
  (`retention.go`) fails closed and the two v1 entry points never disagree.
  `ParseRetentionAnchorValue` parses the `audit_retention_anchor` value (the point the chain
  is re-anchored from after a sanctioned purge) in either layout, rejecting a zero `RowID` or
  a negative `PurgedEvents` ("no anchor"), and never panics on arbitrary bytes; a well-formed
  value round-trips to the exact fields it was built from. A v1 value `ParseRetentionAnchorValue`
  accepts is also accepted by `ParseRetentionAnchor` with identical fields, and vice versa.
  The codec is NOT an authenticator: `SigMatches`/`SignRetentionAnchor*` check the HMAC
  separately. Why: the anchor is read back from a DB text column and gates where the chain
  walk resumes; a parser that accepted a zero row id or disagreed with itself could re-anchor
  the chain at a point the signature never covered. Guard: `FuzzRetentionAnchorParse`
  (auditverify, I7 small-parser sweep).
