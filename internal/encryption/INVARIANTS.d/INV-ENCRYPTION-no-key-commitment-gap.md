- **INV-ENCRYPTION-no-key-commitment-gap** Neither `wrapKey`/`unwrapKey` (AAD nil, output
  nonce||DEK||tag, no key id) nor `aead.EncryptionService` (AAD = row identity, `Metadata.KeyVersion`
  unauthenticated) is key-committing: a GHASH key-multi-collision opens under two keys. Crafting one
  needs both keys, or a candidate key set (e.g. a passphrase dictionary plus the PBKDF2 salt) and an
  open/fail oracle under the real key. Known defence-in-depth gap, not reachable below instance admin:
  the KEK is the operator's, and only operator-run paths (startup, restore) unwrap a key file, so no
  remote party has such an oracle; an endpoint that unwraps or restores caller-supplied key material
  would re-open this. On PostgreSQL only (`dekEpochApplies` is false on SQLite) the DEK epoch
  fingerprint also differs for the two DEKs of a partitioned blob and the epoch guard refuses the
  wrong-key DEK (`key_commitment_epoch_db_test.go`, real PostgreSQL, SKIP line without
  `KEYORIX_TEST_PG_DSN`); the verdict does not rest on it.
  Guard: `key_commitment_fuzz_test.go`: `FuzzKeyCommitmentDeny` (K1-sealed never opens under K2),
  `FuzzKeyCommitmentPartition` (oracle (b) `kcPartitionViolation`, red-proofed in both directions by
  `TestKeyCommitmentPartition_RedProof`), `TestKeyCommitment_PartitionedCiphertext_DocumentedGap` and
  `TestKeyCommitment_NoKeyIDOrVersionBinding` (pins; they go red when a binding is added, flip them
  to the deny direction then). The seal-site inventory and the search that established it are in that
  file's header. pqwrap keyset v1: `key_commitment_pqwrap_test.go` (`FuzzPQWrapKEKSlotDeny`,
  `FuzzPQWrapKEKSlotPartition`, `TestKeyCommitmentPQWrap_RedProof`): the KEK slot's AAD is header ||
  slot index and does NOT cover `kek_id`; the keyset MAC covers it and, with the DEK KCV, is what
  commits a keyset to its KEK (a partitioned slot is refused at the KCV or the MAC, never opened under
  two KEKs); a KEK holder can relabel `kek_id` by recomputing the MAC (pinned). KMS KEK blobs: the key
  a blob is decrypted under is chosen by configuration, never by the blob (`awskms` KeyId + context,
  `gcpkms` Name + AAD, `azurekms` configured name + MAC-checked version; see the per-provider tests).
  **Not covered**: pqwrap keysets with hybrid recipient slots, pqwrap legacy-60
  `openLegacy`/`SealLegacy` (AAD nil, no key id: same gap as wrapKey; pqwrap has no production importer
  today), the pqwrap hybrid envelope (recipient key id in the AAD), the CLI encrypted export
  `cli/cmd/secret_export_encrypt.go` (AES-GCM, AAD nil; one RSA-OAEP-wrapped key per envelope and no
  sender authentication, so a two-key open gives nothing extra), what a real KMS embeds in a
  ciphertext (not exercisable without the cloud), the legacy Azure envelope with no MAC (its version is
  unauthenticated by design), the epoch check on SQLite (it does not apply there), reachability beyond
  the two callers that load a `dek.key` (argued, not tested).
