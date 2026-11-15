### Testing
- **Hostile-response fuzz oracles for the Connect hardened HTTP client.** Added four
  pure-function fuzz targets over `internal/connect/hardened_client.go` — the shared
  outbound-response layer the Azure Key Vault (Azure-identity-authenticated) and
  Vault/AWS Secrets Manager connectors route every response through: `FuzzScrubbedErrorBody`
  (O-SCRUB — the scrubbed error body is always valid JSON of a fixed shape whose code is
  charset-bounded and never invented), `FuzzValidErrorCode` (O-CODE — differential against an
  independent regexp), `FuzzCappedBodyReader` (O-CAP — content-length boundary delivers exactly
  `min(len,cap)` bytes and flags oversize) and `FuzzErrorBodyScrubRoundTrip` (O-RT — content-type/
  content-length/transfer-encoding rewrite on error statuses, pass-through on success). Each
  oracle is red/green proven against a planted defect; no production code changed. Guards new
  `INV-CONNECT-hardened-response-scrub`.
