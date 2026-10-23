- **INV-HTTP-crypto-inventory-metadata-only** `GET /api/v1/compliance/crypto-inventory`
  (JSON and CycloneDX CBOM) returns metadata only: algorithm, size, dates, locations and a
  risk score. Never key bytes, PEM bodies, a private-key file's content or the stored
  recovery-key hash. It is gated by `audit.read` (system_admin and system_auditor), and every
  successful read writes exactly one `compliance.crypto_inventory_read` audit event carrying
  counts only; a rejected request (401, 400) discloses nothing and records nothing. The
  exporter cannot carry a key by construction: `cryptoinventory.Asset` has no field for key
  material and the CBOM `relatedCryptoMaterialProperties` struct has no `value` field. A TLS
  certificate file is read for its CERTIFICATE block only; a private key in the same file is
  skipped unparsed.
  Why: RD-CBOM-1; the inventory maps where every key lives, so it must stay a locator and
  never a source of the key.
  Guard: `server/http/handlers` `TestCryptoInventoryHandler_NoKeyMaterialInResponses`,
  `TestCryptoInventoryHandler_IsAudited`; `internal/cryptoinventory`
  `TestBuild_NeverEmitsKeyMaterial`, `TestAssetJSONHasNoSecretFields`,
  `TestCBOM_Structure`; the `audit.read` gate is pinned by `TestRouteInventoryIsCurrent`
  (`scripts/e2e/routes.json`, `gate_perms: permAuditRead`).
  **Not covered**: file paths and KMS key IDs are disclosed to `audit.read` holders (the
  `system.read` sibling `/system/encryption-config` omits them); an `audit.read` machine
  token can read the inventory like any other compliance endpoint.
