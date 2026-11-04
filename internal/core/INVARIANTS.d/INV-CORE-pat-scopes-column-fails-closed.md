- **INV-CORE-pat-scopes-column-fails-closed** A PAT's stored scopes column (`scopes`) is decoded by ONE
  codec, `rules.DecodePATScopes`: the exact empty column `""` is "unscoped, the owner's rights" (the only
  encoding `CreateOwnPAT` writes for it; pre-ADR-042 rows read NULL → `""`); any other column that does not
  name at least one scope (whitespace only, unparseable JSON, `null`, `[]`, a blank entry) decodes to the
  `PATScopeCorrupted` sentinel, which grants nothing, so the token is refused until it is re-issued.
  The decoder must not trim the column before the `""` test: a whitespace-only column resolved to no
  restriction, i.e. the owner's full rights (the same gap #3840 closed for the CIDR codec,
  INV-CORE-token-cidr-column-fails-closed). `encoding/json` still accepts a real allowlist padded with
  whitespace.
  Guard: `internal/core/rules` `TestDecodePATScopes_UnscopedByDesignVsWhitespaceCorrupted` (the
  `exact_empty_column_is_unscoped_by_design` subtest against the `whitespace_only_*_fails_closed` ones) and
  the `FuzzDecodePATScopes` oracle, which unmarshals the raw untrimmed column; `internal/core`
  `TestValidatePATToken_WhitespaceOnlyScopesColumnIsNotOwnerEquivalent` (through `ValidatePATToken` and
  `CurrentPATRestriction`).
  Not covered: no static guard stops a new consumer from decoding the scopes column itself.
