### Testing
- Added a SAML response/assertion validation differential fuzz suite for
  `internal/saml` that compares `(*Provider).ParseResponse` against independent
  offline references (crewjam/saml and goxmldsig) across structural and byte-level
  response mutations, covering accept/reject agreement, identity provenance, and
  bounded work on hostile XML.
