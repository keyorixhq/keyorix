- **INV-ENCRYPTION-no-key-commitment-gap** Neither `wrapKey`/`unwrapKey` (AAD nil, output
  nonce||DEK||tag, no key id) nor `aead.EncryptionService` (AAD = row identity, `Metadata.KeyVersion`
  unauthenticated) is key-committing: a GHASH key-multi-collision opens under two attacker-known
  keys. Known defence-in-depth gap, not reachable below instance admin (the attacker would need the
  operator's KEK; restore unwraps with the operator's KEK and the DEK epoch fingerprint differs for
  the partitioned DEK). Guard: `key_commitment_fuzz_test.go`: `FuzzKeyCommitmentDeny` (K1-sealed never
  opens under K2), `TestKeyCommitment_PartitionedCiphertext_DocumentedGap` and
  `TestKeyCommitment_NoKeyIDOrVersionBinding` (pins; they go red when a binding is added, flip them
  to the deny direction then). **Not covered**: pqwrap, KMS KEK blobs, reachability (argued, not tested).
