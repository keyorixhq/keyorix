- **INV-ENCRYPTION-no-key-commitment-gap** Neither `wrapKey`/`unwrapKey` (AAD nil, output
  nonce||DEK||tag, no key id) nor `aead.EncryptionService` (AAD = row identity, `Metadata.KeyVersion`
  unauthenticated) is key-committing: a GHASH key-multi-collision opens under two keys. Crafting one
  needs both keys, or a candidate key set (e.g. a passphrase dictionary plus the PBKDF2 salt) and an
  open/fail oracle under the real key. Known defence-in-depth gap, not reachable below instance admin:
  the KEK is the operator's, and only operator-run paths (startup, restore) unwrap a key file, so no
  remote party has such an oracle; an endpoint that unwraps or restores caller-supplied key material
  would re-open this. On PostgreSQL only (`dekEpochApplies` is false on SQLite) the DEK epoch
  fingerprint also differs for the two DEKs of a partitioned blob; the verdict does not rest on it.
  Guard: `key_commitment_fuzz_test.go`: `FuzzKeyCommitmentDeny` (K1-sealed never opens under K2),
  `FuzzKeyCommitmentPartition`, `TestKeyCommitment_PartitionedCiphertext_DocumentedGap` and
  `TestKeyCommitment_NoKeyIDOrVersionBinding` (pins; they go red when a binding is added, flip them
  to the deny direction then). The seal-site inventory and the search that established it are in that
  file's header. **Not covered**: pqwrap keyset v1 (committed by its keyset HMAC and DEK KCV, kek_id
  not in the slot AAD), pqwrap legacy-60 `openLegacy`/`SealLegacy` (AAD nil, no key id: same gap as
  wrapKey; pqwrap has no production importer today), the pqwrap hybrid envelope (recipient key id
  in the AAD), the CLI encrypted export
  `cli/cmd/secret_export_encrypt.go` (AES-GCM, AAD nil; one RSA-OAEP-wrapped key per envelope and no
  sender authentication, so a two-key open gives nothing extra), KMS KEK blobs, reachability (argued,
  not tested).
