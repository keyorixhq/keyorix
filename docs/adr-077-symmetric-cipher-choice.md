# ADR-077: Symmetric cipher and key-derivation choice (AES-256-GCM + PBKDF2)

## Status

Accepted, as-built. This is a backfill ADR: the decision was made and shipped long
before the ADR series started (the encryption layer predates ADR-010, the earliest
numbered ADR in this repo) and was never separately written up. Recorded now per
the M2 "ADR backfill" backlog item, to close the gap rather than leave the
rationale undocumented.

## Context

Every secret value, and a growing list of other sensitive at-rest fields (MFA TOTP
seeds, session tokens, PATs, password-reset tokens, dynamic-secret configs/leases,
chunked-secret streams), needs an authenticated symmetric cipher. The requirements
were, from the start:

- **Authenticated encryption** — tampering with ciphertext must be detectable, not
  just confidentiality. A bare block cipher (AES-CBC) fails this on its own and
  needs a separate MAC, which is exactly the class of construction (encrypt-then-MAC
  done by hand) that produces padding-oracle and other composition bugs when
  implemented wrong.
- **No third-party crypto dependency** for the core primitive, consistent with the
  air-gapped/sovereign deployment story (ADR-048's CGO-free driver work is driven by
  the same "static binary, few external moving parts" wedge) — Go's standard library
  already ships a constant-time, audited AES-GCM implementation.
- **Envelope encryption**, not direct passphrase-to-ciphertext: a per-install Data
  Encryption Key (DEK) encrypts secret values; a passphrase- or provider-derived Key
  Encryption Key (KEK) wraps the DEK. This is what makes DEK rotation (ADR-010) and
  pluggable key sources (ADR-038) possible without re-touching every encrypted row.

## Decision

**Cipher: AES-256-GCM**, via Go's standard library (`crypto/aes` + `crypto/cipher`),
for both layers of the envelope:

- **Secret values and other sensitive fields** (`internal/encryption/encryption.go`):
  `NewEncryptionService` requires a 32-byte key, builds an AES cipher +
  `cipher.NewGCM`, and tags the ciphertext's `EncryptionMetadata.Algorithm` with the
  constant `"AES-256-GCM"` — checked again on decrypt so a metadata/algorithm
  mismatch fails loudly rather than silently misinterpreting bytes. Nonces are fresh
  12 bytes from `crypto/rand` per encryption, stored base64 in the metadata, and
  nonce length is validated before `gcm.Open` to avoid a panic on corrupt input.
- **DEK wrapping** (`internal/encryption/keymanager_lifecycle.go`, `wrapKey`/
  `unwrapKey`): an independent AES-256-GCM call, output format `nonce(12B) ||
  ciphertext` via `gcm.Seal(nonce, nonce, plainKey, nil)`.

**AAD (Additional Authenticated Data) binds ciphertext to its logical context**, so a
ciphertext copied to a different row (a different secret, project, or version)
fails to decrypt even though the raw bytes are otherwise valid. The canonical form
for secret values, `SecretAAD(secretID, projectID, versionNumber)`, produces
`"keyorix:v2:<secretID>:<projectID>:<versionNumber>"`; parallel domain-separated AAD
helpers exist for MFA, sessions, PATs, password-reset tokens, and dynamic-secret
data. `EncryptionMetadata.AADVersion` records which scheme produced a given row:
`"v2"` is current (project-scoped, post namespace→project migration); an absent
version is legacy/no-AAD; `"v1"` (`secretID:namespaceID:versionNumber`) predates the
project migration and is no longer produced, kept only so old rows still decrypt.

**Key derivation: PBKDF2-HMAC-SHA256** (`golang.org/x/crypto/pbkdf2` — the one
non-stdlib crypto dependency this layer takes) derives the passphrase-mode KEK.
Default iteration count is `DefaultKEKIterations = 600000`, explicitly documented
in-code as matching current OWASP guidance and replacing a prior, weaker default of
100,000. Salt is 32 random bytes, generated once per install and persisted
(plaintext, by design — a salt is not a secret) at `keys/kek.salt`.

**Pluggable key sources, not just a passphrase** (ADR-038, `internal/crypto/`):
`KeyProvider` is a two-method interface (`KEK() ([]byte, error)`, `Name() string`);
implementations exist for password (default), file, env, AWS/Azure/GCP KMS
(ADR-041), TPM, exec (shell out to a key-delivery sidecar), and Shamir secret
sharing across N keyholders, plus a composing `MultiKeyProvider`. Whichever source
is configured, it only ever has to produce 32 bytes (`KEKSize`) — everything
downstream (AES-256-GCM, AAD, versioning) is identical regardless of where the KEK
came from.

**Rejected/not considered further:** ChaCha20-Poly1305 appears in this codebase
only for TLS cipher-suite configuration (`internal/config/tls_ciphers.go`), an
unrelated concern (transport, not at-rest) — it was never evaluated as the at-rest
AEAD, since AES-256-GCM already satisfies every requirement above with zero
additional dependencies and has hardware acceleration (AES-NI) on essentially every
target deployment platform, an advantage ChaCha20-Poly1305 exists specifically to
avoid needing.

## Consequences

- **Positive.** Every at-rest encrypted field goes through one audited stdlib
  primitive with one AAD-binding discipline, rather than each subsystem picking its
  own scheme. DEK rotation (ADR-010) and key-source pluggability (ADR-038/041) both
  build cleanly on the envelope shape described here without touching the cipher
  itself.
- **Negative / accepted tradeoff.** AES-256-GCM's 12-byte nonce space is only safe
  under the standard "never reuse a nonce with the same key" discipline — this repo
  relies on `crypto/rand` freshness per call rather than a counter, which is correct
  but means nonce uniqueness is probabilistic, not structurally guaranteed. Not
  revisited here because the birthday-bound risk at this key's usage volume is
  negligible and switching to a counter-based nonce would require persisting nonce
  state, a larger change with no clear benefit.
- Documented for buyers in `docs/SECURITY.md` and `docs/compliance/SECURITY-FAQ.md`,
  both of which already describe this scheme at a summary level — this ADR is the
  engineering-level record those documents point back to.
