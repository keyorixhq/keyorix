### Testing
- **Full-identity SAML XSW differential (`FuzzSAMLFullIdentity`, `internal/saml`).**
  The existing structure-aware SAML fuzz oracles (`FuzzParseResponseXSW` and the
  S1/S2/S3 differential) all assert only on the derived `Subject`. The new target
  starts from one genuinely-signed response whose every identity field holds a
  DISTINCT value (NameID, email, name, two groups) and, on ANY acceptance by
  `(*Provider).ParseResponse`, requires the WHOLE derived identity — `Subject`,
  `Email`, `Name` and `Groups` (as a set) — to equal the signed one. It adds
  attribute-targeted mutations on top of the shared structural engine:
  comment-truncation inside the signed email/group/name `AttributeValue` text,
  injection of an unsigned `AttributeStatement` granting an elevated group, and
  (ops 21-23) an unsigned copy of the signed assertion (same fresh IssueInstant, bearer
  `SubjectConfirmation`, conditions, issuer, audience, NameID, email and name) with one
  extra group, placed first, last, or wrapping the signed assertion in its `Advice`. Ops 21-23 generate the shape the Subject-only oracles pass
  clean: the real ACS handler (`internal/core.(*KeyorixCore).CompleteSAML`) maps
  `info.Groups` to Keyorix roles, so an accepted response that keeps the signed NameID
  but carries a different group set would be a privilege escalation. Deterministic
  tests (`full_identity_xsw_test.go`) pin the oracle: it fires on forged results in
  every field (subject, email, name, groups added/swapped/dropped) and stays silent on
  the pristine signed identity and on a rejection; the pristine fixture must verify;
  every op must change the document; ops 21-23 fed through a deliberately naive
  first/last-assertion reader reach the oracle's groups check, and the forged assertion,
  signed with the IdP key, passes the library's own assertion validation (so the groups
  check is reachable); and every op, run
  through the real parser, is rejected or yields exactly the signed identity.
  Registered in `scripts/fuzzing/targets.d/`.
