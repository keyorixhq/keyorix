### Added
- **Crypto inventory / CBOM covers the listed gaps.** `GET /api/v1/compliance/crypto-inventory` and `keyorix crypto inventory` now list SAML IdP signing certificates, the database TLS client certificate (from the dsn's `sslcert`) and CA bundle, and backup archive encryption, each with algorithm, size, created/expiry and the existing quantum-risk score. WebAuthn passkeys are listed per COSE public-key algorithm (ES256/RS256/EdDSA, and ML-DSA when present) using the existing per-user credential listing; no storage method was added. The CBOM still validates against CycloneDX 1.6.

### Changed
- **DEK `created_at` in the crypto inventory** is read from a `dek.created_at` system_metadata row (PostgreSQL), written when the DEK epoch is seeded and in the transaction that makes a rotated DEK current, and used only when it names the epoch's current DEK (a failed or interrupted rotation does not re-date the old DEK). Otherwise it falls back to the key file's mtime and is flagged `created_at_estimated` (CBOM property `keyorix:created-at-estimated`).
- **Backup archive asset fails closed with Shamir share files.** When `shamir_share_files` are configured (primary or fallback provider), `admin backup` archives those plaintext shares, so the inventory no longer credits the archive as AES-256-GCM: the asset is scored unknown (medium) and a warning suggests `shamir_share_env`.

### Documentation
- `docs/post-quantum-transport.md`: the Java SDK negotiates X25519MLKEM768 on JDK 25.0.5 (checked by hand against a Go test server); Caddy and nginx front-proxy checks are marked pending e2e VM. The RD-CBOM design note's coverage-gap list is updated.
