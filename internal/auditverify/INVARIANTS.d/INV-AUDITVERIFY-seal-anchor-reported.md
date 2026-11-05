- **INV-AUDITVERIFY-seal-anchor-reported** Every authenticated seal that names an anchor is
  reported with a check of that anchor against the run's `--anchor`: the SHA-256 of the
  supplied file must equal the recorded digest, the file must authenticate, and it must
  certify a head past the last surviving row before a gap (or past a truncation's surviving
  head), the rule `accept-loss --anchor` applies. Only `matches` confirms it. A digest-only
  (`--anchor-sha256`) anchor that is not `matches`, and every `unpinned` span a seal recorded,
  is listed in `NotProven`. The check never changes the verdict: another file is no evidence
  against the seal, and the file is cross-checked against the live chain on its own. Why:
  before AUDIT-VERIFY-ONLINE-1 nothing ever compared an `--anchor-sha256` digest with a file,
  and the `unpinned` rows of #3802 were stored but never shown. Guard:
  `TestSealAnchorCheck_DigestOnly` (and `_Postgres`),
  `TestSealAnchorCheck_AnchorBeforeTheLossDoesNotCover`,
  `TestSealAnchorCheck_VerifiedAtAcceptance` (seal_anchor_check_test.go), server/admin
  `TestVerifyAudit_SealAnchorDigestAndUnpinnedReported`.
