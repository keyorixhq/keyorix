- **INV-HTTP-soak-audit-chain-complete** After a sustained stream of audited HTTP
  operations, the audit hash chain is intact and complete: `VerifyAuditChain` reports
  `Valid` with no `FirstBrokenID` (no gap, no duplicate, no tamper), every stored event
  is accounted for by the walk (`ChainedEvents + UnchainedEvents == COUNT(audit_events)`,
  so nothing sits outside the verified chain), the stored-event count never decreases
  across the run, and it is at least the number of mutations driven (every successful
  privileged mutation left at least one attributable event — a skipped audit write drops
  below this bound). Why: the audit trail is the tamper-evidence NIS2/DORA compliance
  leans on; a silently-dropped or unchained event is invisible to a return-value check
  (the mutation still reports success) and only the absence of the effect reveals it.
  Guard: `soak_bounded_growth_test.go` (`TestSoakBoundedGrowth`'s `verifyAuditChain`
  oracle) and `soak_bounded_growth_fuzz_test.go` (`FuzzSoakOperationSequence` re-verifies
  chain validity after every fuzzer-chosen operation ordering). Not covered: an exact 1:1
  operation↔event mapping (the bound is `mutations ≤ events`, since some operations emit
  zero or several events); and the signed-checkpoint/anchor layer (this harness wires no
  audit-checkpoint key, so it verifies the on-box hash chain, not external anchoring).
