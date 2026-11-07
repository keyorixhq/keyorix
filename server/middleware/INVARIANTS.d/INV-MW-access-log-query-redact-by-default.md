- **INV-MW-access-log-query-redact-by-default** The access log (text and JSON formats, and the
  panic-context line) never contains a query-string value unless BOTH the parameter name is in
  the `loggableQueryKeys` allowlist AND the raw value matches that key's own grammar: digits
  only (pagination, counts, ids), `true|false|1|0` (switches), a date/time shape starting with a
  digit, or a short (<=32) lowercase enum with no `kx_` prefix. Keyorix PATs, machine tokens and
  the oracle canary match none of these under any key. Every other value is logged as
  `[redacted]`, bare tokens and odd key names are replaced entirely, and the allowlist never
  carries a name that can hold a secret, reference or person identifier. Not covered: a short
  all-lowercase secret sent under an enum key. The handler still receives the original request;
  only the cloned log request is redacted. Why: #4013, a denylist of known-sensitive routes
  cannot see a credential a caller places in a query on any other route, and an allowlisted
  name alone let `?format=<secret>`, `?page=1;api_key=<secret>` and `?status=x%26token%3D<secret>`
  through. Guard: `server/middleware/logger_query_test.go:TestRedactSensitiveURI_QueryRedactedByDefault`,
  `TestRedactSensitiveURI_AllowlistedValueShapeChecked`,
  `TestRedactSensitiveURI_NoCredentialShapeSurvivesUnderAnyAllowlistedKey` (iterates every
  allowlisted key) and `TestLogger_NeverLogsArbitraryQuerySecret`.
