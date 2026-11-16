### Testing
- **Full-identity SAML XSW differential (`FuzzSAMLFullIdentity`, `internal/saml`).**
  The existing structure-aware SAML fuzz oracles (`FuzzParseResponseXSW` and the
  S1/S2/S3 differential) all assert only on the derived `Subject`. The new target
  starts from one genuinely-signed response whose every identity field holds a
  DISTINCT value (NameID, email, name, two groups) and, on ANY acceptance by
  `(*Provider).ParseResponse`, requires the WHOLE derived identity — `Subject`,
  `Email`, `Name` and `Groups` (as a set) — to equal the signed one. It adds
  attribute-targeted mutations on top of the shared structural engine:
  comment-truncation inside the signed email/group/name `AttributeValue` text, and
  injection of an unsigned `AttributeStatement` granting an elevated group. This
  closes the privilege-escalation XSW gap the Subject-only oracles leave: the real
  ACS handler (`internal/core.(*KeyorixCore).CompleteSAML`) maps `info.Groups` to
  Keyorix roles, so an accepted response that keeps the signed NameID but carries an
  injected group would be an escalation the prior oracles pass clean. The oracle's
  comparison is red/green-proven (fires on a simulated XSW-vulnerable extractor that
  reads attributes regardless of signature; silent on the real parser, which rejects
  every injection). Registered in `scripts/fuzzing/targets.d/`.
