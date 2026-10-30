- **INV-CORE-token-cidr-column-fails-closed** A token's stored CIDR allowlist (PAT
  `allowed_cidrs`, machine credential `AllowedCIDRs`) is decoded by ONE codec,
  `rules.DecodePATCIDRs`: an empty column is "no network restriction" (the only encoding
  `EncodePATCIDRs` / `IssueMachineToken` write for it); a non-empty column that does not name at
  least one CIDR (unparseable JSON, `null`, `[]`, a blank entry) decodes to the corrupted sentinel,
  which no source IP matches, so the token is refused from every network until it is re-issued.
  `machineRestrictionFrom` read `null` / `[]` as unrestricted and dropped the IP pin (#3396); the
  middleware's `len(AllowedCIDRs) > 0` check reads an empty list as "no restriction", so the decoder
  must never return one for a non-empty column.
  Guard: `internal/core/rules` `TestDecodePAT_NonEmptyColumnThatNamesNothingFailsClosed`,
  `TestPATCodec_RoundTripUnchanged`; `internal/core`
  `TestMachineRestrictionFrom_ColumnNamingNoCIDRFailsClosed`,
  `TestMachineRestrictionFrom_EmptyColumnAndRealAllowlistUnchanged`; `server/http`
  `TestMachineToken_StoredCIDRsNamingNothing_RefusedAtMiddleware` (validation and cache-hit
  re-check, SQLite and PostgreSQL).
  Not covered: no static guard stops a new token type from decoding its column itself.
