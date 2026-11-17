- **INV-CORE-audit-seal-loss-classified-by-type** `planAuditGaps` (`audit_seal_accept.go`)
  tells a lost row from a modified one using the verifier's typed fields and the stored rows,
  never the verifier's reason text. On a walk from the chain start the storage walk's
  `LinkBroken` must be set. A walk pinned after a sealed gap never carries it, so there the
  resume row's `prev_hash` must differ from the `HeadHash` of the verified chain before it.
  `LinkBroken` is also set for an earliest row that does not match the retention re-anchor;
  with no verified row before the break and an anchor present, that is refused. `LinkBroken`
  comes from the storage walk only (`VerifyAuditChain`/`VerifyAuditChainSegment`), merged by
  `walkAuditChainGaps`; no request field sets it. Why: AUDIT-GUARDS-TAILS-NOV-1 item 1, a
  reworded verifier message must not change an accept-loss verdict. Guard:
  `audit_seal_link_broken_typed_test.go` (`TestAuditSeal_LinkBrokenAcceptedWithRewordedReason`,
  `_PinnedGapAcceptedWithRewordedReason`, `_LinkTextWithoutLinkBrokenRefused`,
  `_PinnedModifiedRowRefused`, `_ReanchorMismatchRefusedDespiteLinkBroken`).
