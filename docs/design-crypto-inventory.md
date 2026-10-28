# Design note: crypto inventory, CycloneDX CBOM and quantum-risk score (RD-CBOM-1)

Status: R&D prototype. Code: `internal/cryptoinventory`, `server/http/handlers/crypto_inventory.go`,
`cli/cmd/crypto.go`, `web/src/pages/compliance/CryptoInventoryPanel.tsx`.

## What it does

Answers "which keys and certificates does this Keyorix hold or depend on, how strong are they, when do they
expire, where do they live, and which would a quantum computer break?" without ever touching key material.

- **Inventory** (`cryptoinventory.Build`): one `Asset` per key or certificate: KEK (by provider), DEK, admin
  recovery-key verifier, each enabled TLS listener's certificate, the three HKDF-derived HMAC keys (audit
  checkpoint, evidence, backup manifest), WebAuthn passkey public keys, OIDC issuer verification keys. Each
  carries type, algorithm, size, created, expiry and a storage description. Keyorix signs no JWTs (sessions
  are opaque hashed tokens), so "JWT keys" are the external issuers' verification keys, listed as such.
- **Risk score** (`Policy.Assess`, 0-100): Mosca's inequality. A key is at risk when the time it must stay
  secure (X: remaining life, or an assumed lifetime when it never expires) plus the time to migrate off it
  (Y) exceeds the time until a cryptographically relevant quantum computer (Z, the horizon). Classical
  public-key algorithms (RSA, ECDSA, Ed25519, ECDH) start at 60 because Shor's algorithm breaks them at any
  size; 256-bit symmetric and hash/HMAC primitives start at 5 because Grover only halves their strength; an
  unclassifiable algorithm fails closed to 40. The lifetime term raises the score up to 100 when X + Y runs
  past the horizon. Levels: 70+ high, 40-69 medium, below 40 low.
- **Configuration** (`crypto_inventory`, see `docs/CONFIGURATION.md`): `quantum_horizon` default 2035-01-01
  (NIST IR 8547 draft disallows classical public-key algorithms after 2035), `migration_years` default 3,
  `unbounded_lifetime_years` default 10. The settings change the reported score only; nothing is enforced.
- **CBOM** (`Inventory.CBOM`): CycloneDX 1.6 with one `cryptographic-asset` component per asset plus shared
  `algorithm` components; the risk result rides as `keyorix:*` properties. `TestCBOM_ValidatesAgainstOfficialSchema`
  validates against the official schema vendored in `internal/cryptoinventory/testdata/cyclonedx-1.6/`
  (Apache-2.0, license and provenance alongside).
- **Surfaces**: `GET /api/v1/compliance/crypto-inventory[?format=json|cbom]` (`audit.read`, audited as
  `compliance.crypto_inventory_read`), `keyorix crypto inventory [--format table|json|cbom] [--output FILE]`,
  and a read-only table on the Compliance page.

## Safety properties

No key material in any output: `Asset` has no field that could hold it, the CBOM struct has no `value` field,
a TLS file is read for its CERTIFICATE block only (a private key in the same file is skipped unparsed), key
files are never opened (the DEK file is `os.Stat`ed for its mtime), and the recovery-key hash is not read
into the output. Pinned by INV-HTTP-crypto-inventory-metadata-only.

## New vs state of the art

- Source-code scanners (for example IBM's CBOMkit) produce a CBOM of the cryptography an application's code
  *uses*. This produces one for the keys a running secrets manager *holds*, from its live configuration and
  state, across every key class (KEK, DEK, certificates, derived keys, passkeys) in one document.
- Secrets managers expose per-key metadata through their own APIs, but, to our knowledge, none scores their
  own key custody for quantum exposure or exports it as a CBOM. The combination of a lifetime-versus-horizon
  score with a standard CBOM is the new part; the score itself is Mosca's well-known model, applied per key.
- Flagging the *wrapping* algorithm of a stored KEK (azure-kms wraps with RSA-OAEP, so a copied wrapped KEK is
  exposed to harvest-now-decrypt-later while an AES-256 KMS wrap is not) is the kind of finding a code scan
  cannot make.

## Technical risks

1. **The score is a heuristic, not a cryptanalytic claim.** The horizon and the assumed lifetime of a
   never-expiring key are policy inputs. Reports must show the policy used (the JSON and CBOM both do).
2. **Coverage gaps, listed rather than hidden.** Closed by RD-CBOM-TAILS-1: SAML (the IdP signing
   certificates Keyorix trusts, read from the provider's metadata; Keyorix holds no SAML signing key of its
   own), the database TLS client certificate (only when the `dsn` carries `sslcert`) and CA bundle
   (`ssl_root_cert` or the dsn's `sslrootcert`; `system` roots have no file to read), and backup archive
   encryption (stated as it is: the archive container is not encrypted, secret values travel as stored
   ciphertext and the DEK wrapped under the KEK). WebAuthn is now listed per credential public-key algorithm,
   by walking the users with the existing per-user credential listing (no new storage method; capped at 5000
   users, falling back to one generic asset with a warning). The DEK `created_at` is the `dek.created_at`
   system_metadata row (PostgreSQL), `"<fingerprint> <RFC 3339 time>"`, written when the DEK epoch is seeded
   and inside the rotation sweep transaction that makes a new DEK current, and used only when its fingerprint
   is the settled epoch's (a lifted rotation fence never re-dates the old DEK). Without a matching row it
   falls back to the key file's mtime marked `created_at_estimated`; that mtime also moves on KEK rewrap.
   Backup archive encryption scores unknown (medium) when encryption is disabled or Shamir share files (which
   `admin backup` archives) are configured. CA bundles are capped at 16 certificates and IdP signing
   certificates at 8, each with a warning past the cap; with `sslmode=disable` no database TLS file is listed.
   Still open: a client certificate supplied by `PGSSLCERT` or libpq's default path is not discovered; for a
   deployment that predates the epoch, `dek.created_at` dates the upgrade (the seed), not the DEK's creation;
   AWS and GCP KMS wrapping keys are assumed symmetric; autocert certificates are assumed ECDSA P-256;
   derived HMAC keys have no creation date.
3. **Locator disclosure.** File paths and KMS key IDs go to `audit.read` holders, more than the `system.read`
   `/system/encryption-config` sibling shows. Acceptable for the auditor role; recorded in the invariant.
4. **Audit write is best-effort**, like the sibling compliance reads: a failed audit insert is logged but
   the response is still served. A fail-closed variant is a follow-up if the endpoint leaves prototype status.
5. **Per-replica view.** The inventory reads the answering replica's configuration; replicas configured
   differently would each report their own.
6. **Schema drift.** CycloneDX will move past 1.6. The vendored 1.6 copy keeps tests deterministic and offline;
   moving versions means replacing all three schema files together.
