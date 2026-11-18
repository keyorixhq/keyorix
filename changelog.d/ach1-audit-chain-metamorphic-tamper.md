### Testing
- **Metamorphic audit-chain tamper fuzzer (`FuzzAuditChainMetamorphicTamper`).**
  Builds a fresh, valid, fully-checkpointed audit chain through the real writer,
  applies one fuzz-driven structured mutation from a family (byte-flip,
  timestamp change, delete, truncate-tail, duplicate-id0, content-reorder,
  splice-from-another-log, replace-last-N, numeric nudge, plus two VALID
  controls) and asserts the offline verifier's metamorphic relation: any
  mutation that changes the authenticated 16-column read-set must drive
  `auditverify.Verify` off VALID (or to a typed error), while a change confined
  to the unauthenticated `machine_identity_id` column or a true no-op must stay
  VALID. Generalizes `differential_test.go`'s fixed tamper matrix into a
  random-chain, random-mutation fuzzer. The oracle decision has a two-direction
  red/green proof (`TestMetamorphicOracle_RedGreen`) and a per-family live
  detection proof (`TestMetamorphicOracle_EndToEnd_PerFamily`,
  `TestMetamorphicOracle_Controls_StayValid`). A secondary `resguard` tripwire
  (absolute wall + alloc ceilings) bounds Verify work on mutated artifacts.
