- **INV-ENCRYPTION-shamir-commitment-binds-new-kek** The DEK is never wrapped under a
  Shamir-reconstructed KEK that was not checked against a commitment: `migrate-provider
  --to-type shamir` refuses unless `--to-shamir-commitment` is the 32-byte hex value
  `shamir-split` printed. A blank `shamir_commitment` counts as unset everywhere (the
  provider logs the #429 warning, the insecure-settings registry reports
  `insecure_omit_shamir_commitment_check`), and one of the wrong length is refused. Why:
  Shamir interpolation is linear, so a holder of threshold-1 genuine shares can forge one
  more share that sets the KEK (#429); REVIEW-ENCRYPTIONOPS-1 F5/F6. Guard:
  `internal/encryptionops/review_encryptionops_shamir_test.go`
  (`TestMigrateProviderWithConfig_Shamir_ForgedShareWithoutCommitmentRefused` forges the
  share), `internal/crypto/shamir_commitment_blank_test.go`,
  `internal/config/insecure_shamir_blank_commitment_test.go`. **Not covered**: a running
  install whose split predates #429 still unseals without a commitment (warned at every
  start, by design).
